//! HTTP client for the daemon's structured view REST surface. The token is
//! always sent as a bearer header, never in the URL.

use std::time::Duration;

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::{header, Method, StatusCode};
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::discovery::DaemonEndpoint;
use super::passphrase_session::{self, PassphraseSessionCache};
use crate::acp::elicitations::ElicitationResolution;
use crate::acp::protocol::{
    ApprovalDecisionWire, FilesResponse, PromptRequest, ReplayResponse, ResolveApprovalRequest,
    SwitchAgentRequest, SwitchAgentResponse, SwitchProviderRequest, SwitchProviderResponse,
};
use crate::acp::transcript::TranscriptRow;
use crate::daemon::AoeErrorCode;
use crate::plugin::ui_state::UiSnapshot;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Escapes bytes that could break out of one URL path segment while leaving a
/// dotted plugin fqid intact.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'%')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// An active plugin command as the daemon reports it. The structured view
/// resolves keybinds against this because a remote daemon's plugins may not
/// exist locally.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PluginCommandView {
    pub fqid: String,
    pub plugin_id: String,
    #[serde(default)]
    pub keybinds: Vec<String>,
    #[serde(default)]
    pub action: Option<aoe_plugin_api::ClientAction>,
}

#[derive(serde::Deserialize)]
struct PluginCommandsEnvelope {
    commands: Vec<PluginCommandView>,
}

/// Wire mirror of the daemon's `/acp/prompt` disposition.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct PromptDispatchWire {
    /// An empty body from an older daemon means `sent`.
    #[serde(default)]
    pub disposition: PromptDispositionWire,
    /// Present only on `queued`.
    #[serde(default)]
    pub queued_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptDispositionWire {
    #[default]
    Sent,
    Steered,
    Queued,
}

/// At or under the server's `MAX_REPLAY_PAGE`, so it is never clamped.
pub const REPLAY_PAGE_SIZE: u64 = 1000;

#[derive(Debug, Clone)]
pub struct HttpClient {
    http: reqwest::Client,
    endpoint: DaemonEndpoint,
    /// False for plaintext HTTP to a non-loopback host: no credential may be sent.
    credentials_allowed: bool,
    passphrase_session: PassphraseSessionCache,
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("transport error: {0}")]
    Transport(reqwest::Error),
    #[error("structured view session {0} not found on the daemon")]
    SessionNotFound(String),
    /// The approval or elicitation already resolved server-side, so the card
    /// can clear quietly (#1821).
    #[error("approval already resolved")]
    ApprovalGone,
    #[error("daemon is read-only (started with --read-only); request refused")]
    ReadOnly,
    /// Worded for every auth mode, not only token auth (#1525).
    #[error("daemon rejected the request (401); restart `aoe serve` or check `--auth` mode")]
    Unauthorized,
    /// A refusal the daemon named with a safe `AoE-Error-Code`.
    #[error("{}", refusal_message(*.0))]
    Refused(AoeErrorCode),
    /// A resolve 404 without `pending_target_gone`: the card may or may not still be
    /// pending, so the caller keeps it and re-reads the daemon's pending set.
    #[error("daemon could not confirm the pending request; refreshing")]
    PendingUnconfirmed,
    #[error("daemon returned HTTP {status}")]
    Server { status: StatusCode },
    #[error(transparent)]
    Daemon(#[from] crate::daemon::DaemonClientError),
}

fn refusal_message(code: AoeErrorCode) -> &'static str {
    match code {
        AoeErrorCode::AccessPolicyDenied => {
            "daemon refused the request: host or origin not allowed"
        }
        AoeErrorCode::CityhallMode => "this action is disabled in CityHall client mode",
        AoeErrorCode::LifecycleLocked => "daemon lifecycle is locked; try again shortly",
        AoeErrorCode::TlsRequired => "daemon requires HTTPS; use an https:// endpoint",
        AoeErrorCode::ReadOnly => "daemon is read-only; request refused",
        AoeErrorCode::PendingTargetGone => "pending request already resolved",
    }
}

impl From<reqwest::Error> for HttpError {
    /// The URL is dropped: a base path can itself carry a secret.
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error.without_url())
    }
}

/// Which endpoint family a request belongs to, deciding what a 404 means.
#[derive(Clone, Copy)]
enum Scope<'a> {
    /// A 404 is a missing session.
    Session(&'a str),
    /// Daemon-wide: a 404 is an absent route (older daemon).
    Global,
}

/// `GET` and `PATCH /api/log-level` answers; each leaves out the fields the other owns.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct LogFilterReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    pub current: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reloadable: Option<bool>,
    pub ephemeral: bool,
}

impl HttpClient {
    pub fn new(endpoint: DaemonEndpoint) -> Result<Self, HttpError> {
        let url = crate::daemon::parse_base_url(&endpoint.base_url)?;
        let http = crate::daemon::credentialed_client_builder(&url)
            .user_agent(concat!("aoe-acp-client/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            credentials_allowed: crate::daemon::require_secure_credential_transport(&url).is_ok(),
            endpoint,
            passphrase_session: PassphraseSessionCache::default(),
        })
    }

    /// Bare, unauthenticated request: callers rebuild this on every attempt
    /// (see `send`), so it stays cheap data (method + path), not a
    /// once-usable `RequestBuilder`.
    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{path}", self.endpoint.base_url);
        self.http.request(method, url)
    }

    /// Attach whichever credential is available via `send_authed` (retrying
    /// once on a stale cached passphrase session), then classify the
    /// response by `scope`.
    async fn send(
        &self,
        build: impl Fn() -> reqwest::RequestBuilder,
        scope: Scope<'_>,
    ) -> Result<reqwest::Response, HttpError> {
        let res = self.send_authed(build).await?;
        finish(res, scope).await
    }

    /// Like `send`, but retries once after a passphrase step-up if the
    /// daemon reports `elevation_required`: plugin-mutation endpoints
    /// (enable/disable, worker restart) require an elevated session whenever
    /// the caller isn't loopback-trusted (e.g. a passphrase daemon reached
    /// behind a proxy, or a remote one reached directly), and nothing else
    /// in the CLI ever re-confirms the passphrase on its own.
    async fn send_elevated(
        &self,
        build: impl Fn() -> reqwest::RequestBuilder,
        scope: Scope<'_>,
    ) -> Result<reqwest::Response, HttpError> {
        let res = self.send_authed(&build).await?;
        let status = res.status();
        if status.is_success() {
            return Ok(res);
        }
        // Elevation is named only in the error body, which is never read. A 403 with no
        // safe code and a passphrase to confirm gets one step-up attempt.
        let unnamed_forbidden = status == StatusCode::FORBIDDEN
            && AoeErrorCode::from_response(status, res.headers()).is_none();
        let original = classify_error(status, res.headers(), scope);
        if !unnamed_forbidden || self.endpoint.resolved_passphrase().is_none() {
            return Err(original);
        }
        if let Err(error) =
            passphrase_session::elevate(&self.endpoint, &self.passphrase_session).await
        {
            tracing::debug!(target: "acp.client.http", "step-up failed: {error}");
            return Err(original);
        }
        let res = self.send_authed(&build).await?;
        finish(res, scope).await
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        scope: Scope<'_>,
    ) -> Result<T, HttpError> {
        let res = self.send(|| self.request(Method::GET, path), scope).await?;
        Ok(res.json().await?)
    }

    /// POST/PATCH/DELETE to a session endpoint, discarding the body.
    async fn session_call(
        &self,
        method: Method,
        session_id: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(), HttpError> {
        let full_path = format!("/api/sessions/{session_id}{path}");
        let build = || {
            let request = self.request(method.clone(), &full_path);
            match &body {
                Some(body) => request.json(body),
                None => request,
            }
        };
        self.send(build, Scope::Session(session_id)).await?;
        Ok(())
    }

    /// One unbounded page (the server's default bound applies). The status
    /// probe uses `since=u64::MAX` for metadata only; history consumers use
    /// [`replay_paged`](Self::replay_paged).
    pub async fn replay(&self, session_id: &str, since: u64) -> Result<ReplayResponse, HttpError> {
        let path = format!("/api/sessions/{session_id}/acp/replay?since={since}");
        self.get_json(&path, Scope::Session(session_id)).await
    }

    pub async fn replay_page(
        &self,
        session_id: &str,
        since: u64,
        limit: u64,
    ) -> Result<ReplayResponse, HttpError> {
        let path = format!("/api/sessions/{session_id}/acp/replay?since={since}&limit={limit}");
        self.get_json(&path, Scope::Session(session_id)).await
    }

    /// Fetch bounded pages from `since`, capped at the first page's
    /// `highest_seq` (later events arrive over the WS), stopping at a
    /// retention gap. Returns the pages and whether a gap was reported.
    async fn collect_pages(
        &self,
        session_id: &str,
        since: u64,
        page_size: u64,
        view_rows: bool,
    ) -> Result<(Vec<ReplayResponse>, bool), HttpError> {
        let view = if view_rows { "&view=rows" } else { "" };
        let mut pages = Vec::new();
        let mut cursor = since;
        let mut cap = None;
        loop {
            let path = format!(
                "/api/sessions/{session_id}/acp/replay?since={cursor}&limit={page_size}{view}"
            );
            let page: ReplayResponse = self.get_json(&path, Scope::Session(session_id)).await?;
            let cap = *cap.get_or_insert(page.highest_seq);
            let (lost, next, has_more) = (page.lost, page.next_cursor, page.has_more);
            pages.push(page);
            if lost {
                return Ok((pages, true));
            }
            match next {
                Some(next) if has_more && next > cursor && next < cap => cursor = next,
                _ => return Ok((pages, false)),
            }
        }
    }

    /// Every frame from `since` in one response; see `collect_pages`.
    pub async fn replay_paged(
        &self,
        session_id: &str,
        since: u64,
        page_size: u64,
    ) -> Result<ReplayResponse, HttpError> {
        let (pages, lost) = self
            .collect_pages(session_id, since, page_size, false)
            .await?;
        let last = pages.last().expect("at least one page");
        let (highest_seq, lowest_seq) = (last.highest_seq, last.lowest_seq);
        Ok(ReplayResponse {
            frames: pages.into_iter().flat_map(|page| page.frames).collect(),
            lost,
            highest_seq,
            lowest_seq,
            next_cursor: None,
            has_more: false,
            rows: None,
        })
    }

    /// Server-folded transcript rows from `since`. Pages fold in isolation, so
    /// rows are reconciled by id across page seams.
    pub async fn replay_rows_paged(
        &self,
        session_id: &str,
        since: u64,
        page_size: u64,
    ) -> Result<(Vec<TranscriptRow>, bool), HttpError> {
        let (pages, lost) = self
            .collect_pages(session_id, since, page_size, true)
            .await?;
        let mut rows = Vec::new();
        for row in pages
            .into_iter()
            .flat_map(|page| page.rows.unwrap_or_default())
        {
            crate::acp::transcript::upsert_transcript_row(&mut rows, row);
        }
        Ok((rows, lost))
    }

    /// Workspace files for the composer's `@`-mention picker.
    pub async fn files(&self, session_id: &str) -> Result<FilesResponse, HttpError> {
        let path = format!("/api/sessions/{session_id}/acp/files");
        self.get_json(&path, Scope::Session(session_id)).await
    }

    /// Returns whether the daemon sent, steered, or queued the prompt.
    pub async fn prompt(
        &self,
        session_id: &str,
        text: &str,
        no_revive: bool,
    ) -> Result<PromptDispatchWire, HttpError> {
        let body = PromptRequest {
            text: text.to_string(),
            attachments: Vec::new(),
            prompt_id: None,
            no_revive,
            queued_prompt_id: None,
        };
        let path = format!("/api/sessions/{session_id}/acp/prompt");
        let res = self
            .send(
                || self.request(Method::POST, &path).json(&body),
                Scope::Session(session_id),
            )
            .await?;
        Ok(res.json::<PromptDispatchWire>().await.unwrap_or_default())
    }

    /// The daemon-wide plugin UI snapshot (#2402).
    pub async fn plugin_ui_state(&self) -> Result<UiSnapshot, HttpError> {
        self.get_json("/api/plugins/ui-state", Scope::Global).await
    }

    pub async fn plugin_commands(&self) -> Result<Vec<PluginCommandView>, HttpError> {
        let envelope: PluginCommandsEnvelope = self
            .get_json("/api/plugins/commands", Scope::Global)
            .await?;
        Ok(envelope.commands)
    }

    /// Fire-and-forget dispatch of an action-less plugin command.
    pub async fn invoke_plugin_command(
        &self,
        fqid: &str,
        session_id: &str,
    ) -> Result<(), HttpError> {
        let path = format!(
            "/api/plugins/commands/{}/invoke",
            utf8_percent_encode(fqid, PATH_SEGMENT)
        );
        let body = serde_json::json!({ "session_id": session_id });
        self.send(
            || self.request(Method::POST, &path).json(&body),
            Scope::Global,
        )
        .await?;
        Ok(())
    }

    /// Toggled through the daemon so its plugin host reconciles workers live.
    pub async fn set_plugin_enabled(
        &self,
        plugin_id: &str,
        enabled: bool,
    ) -> Result<(), HttpError> {
        let path = format!("/api/plugins/{plugin_id}/enabled");
        let body = serde_json::json!({ "enabled": enabled });
        self.send_elevated(
            || self.request(Method::POST, &path).json(&body),
            Scope::Global,
        )
        .await?;
        Ok(())
    }

    /// Reload plugins from disk and replace this plugin's worker.
    pub async fn restart_plugin_worker(&self, plugin_id: &str) -> Result<(), HttpError> {
        let path = format!("/api/plugins/{plugin_id}/worker/restart");
        self.send_elevated(|| self.request(Method::POST, &path), Scope::Global)
            .await?;
        Ok(())
    }

    pub async fn cancel(&self, session_id: &str) -> Result<(), HttpError> {
        self.session_call(Method::POST, session_id, "/acp/cancel", None)
            .await
    }

    /// The daemon-owned prompt queue, ordered by `seq`. The native view never
    /// enqueues itself: the daemon parks prompts posted to `/acp/prompt`.
    pub async fn queue_list(
        &self,
        session_id: &str,
    ) -> Result<Vec<crate::daemon::QueuedPromptEntry>, HttpError> {
        let path = format!("/api/sessions/{session_id}/queue");
        self.get_json(&path, Scope::Session(session_id)).await
    }

    /// Replace a queued prompt's text in place. The client-minted id is
    /// encoded as one path segment.
    pub async fn queue_edit(
        &self,
        session_id: &str,
        prompt_id: &str,
        text: &str,
    ) -> Result<(), HttpError> {
        let path = format!("/queue/{}", utf8_percent_encode(prompt_id, PATH_SEGMENT));
        let body = serde_json::json!({ "text": text });
        self.session_call(Method::PATCH, session_id, &path, Some(body))
            .await
    }

    pub async fn queue_clear(&self, session_id: &str) -> Result<(), HttpError> {
        self.session_call(Method::DELETE, session_id, "/queue", None)
            .await
    }

    /// "Auto-name now": the daemon answers once the title one-shot finishes, with
    /// its failure reason on error.
    pub async fn smart_rename(&self, session_id: &str) -> Result<(), HttpError> {
        let path = format!("/api/sessions/{session_id}/smart-rename");
        let timeout = crate::session::smart_rename::RENAME_DEADLINE + DEFAULT_TIMEOUT;
        self.send(
            || self.request(Method::POST, &path).timeout(timeout),
            Scope::Session(session_id),
        )
        .await?;
        Ok(())
    }

    /// The result echoes over the WS as `CurrentModeChanged` or
    /// `ModeSwitchFailed`.
    pub async fn set_mode(&self, session_id: &str, mode_id: &str) -> Result<(), HttpError> {
        let body = serde_json::json!({ "mode_id": mode_id });
        self.session_call(Method::POST, session_id, "/acp/mode", Some(body))
            .await
    }

    /// A rejection echoes over the WS as `ConfigOptionSwitchFailed`.
    pub async fn set_config_option(
        &self,
        session_id: &str,
        config_id: &str,
        value: &str,
    ) -> Result<(), HttpError> {
        let body = serde_json::json!({ "config_id": config_id, "value": value });
        self.session_call(Method::POST, session_id, "/acp/config-option", Some(body))
            .await
    }

    /// Switch a terminal session to the structured view. Idempotent.
    pub async fn acp_enable(&self, session_id: &str) -> Result<(), HttpError> {
        self.session_call(Method::POST, session_id, "/acp/enable", None)
            .await
    }

    /// Switch a structured session back to a terminal. Idempotent.
    pub async fn acp_disable(&self, session_id: &str) -> Result<(), HttpError> {
        self.session_call(Method::POST, session_id, "/acp/disable", None)
            .await
    }

    /// Hand the session to another ACP backend, keeping the transcript.
    pub async fn switch_agent(
        &self,
        session_id: &str,
        target: &str,
        model: Option<&str>,
        reason: Option<&str>,
    ) -> Result<SwitchAgentResponse, HttpError> {
        let body = SwitchAgentRequest {
            target: target.to_string(),
            model: model.map(str::to_string),
            reason: reason.map(str::to_string),
        };
        let path = format!("/api/sessions/{session_id}/acp/switch-agent");
        let res = self
            .send(
                || self.request(Method::POST, &path).json(&body),
                Scope::Session(session_id),
            )
            .await?;
        Ok(res.json().await?)
    }

    /// Re-route the session to another LLM provider, keeping the transcript.
    pub async fn switch_provider(
        &self,
        session_id: &str,
        provider: &str,
    ) -> Result<SwitchProviderResponse, HttpError> {
        let body = SwitchProviderRequest {
            provider: provider.to_string(),
        };
        let path = format!("/api/sessions/{session_id}/acp/switch-provider");
        let res = self
            .send(
                || self.request(Method::POST, &path).json(&body),
                Scope::Session(session_id),
            )
            .await?;
        Ok(res.json().await?)
    }

    async fn resolve(
        &self,
        session_id: &str,
        kind: &str,
        nonce: &str,
        body: &impl serde::Serialize,
    ) -> Result<(), HttpError> {
        let path = format!("/api/sessions/{session_id}/acp/{kind}/{nonce}");
        let res = self
            .send_authed(|| self.request(Method::POST, &path).json(body))
            .await?;
        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        Err(classify_resolve_error(status, res.headers(), session_id))
    }

    /// `option_id` names an option chosen through the option picker.
    pub async fn resolve_approval(
        &self,
        session_id: &str,
        nonce: &str,
        decision: ApprovalDecisionWire,
        option_id: Option<String>,
    ) -> Result<(), HttpError> {
        let body = ResolveApprovalRequest {
            decision,
            option_id,
        };
        self.resolve(session_id, "approvals", nonce, &body).await
    }

    pub async fn resolve_elicitation(
        &self,
        session_id: &str,
        nonce: &str,
        resolution: &ElicitationResolution,
    ) -> Result<(), HttpError> {
        self.resolve(session_id, "elicitations", nonce, resolution)
            .await
    }

    /// The shared session list, authenticated like every other request: a cached
    /// passphrase-login session, else bearer token, else a fresh passphrase login, else
    /// none, with the same single 401 retry as `send_authed`.
    pub async fn list_sessions(
        &self,
        state: Option<crate::session::SessionScope>,
    ) -> Result<crate::daemon::SessionsEnvelope, HttpError> {
        let has_passphrase = self.endpoint.resolved_passphrase().is_some();
        let cached = has_passphrase && self.passphrase_session.get(&self.endpoint).is_some();
        let bearer_first = self.endpoint.resolved_token().is_some() && !cached;
        match self.list_sessions_once(state, false).await {
            Err(HttpError::Unauthorized) if has_passphrase && (cached || bearer_first) => {
                self.passphrase_session.invalidate(&self.endpoint);
                self.list_sessions_once(state, true).await
            }
            result => result,
        }
    }

    async fn list_sessions_once(
        &self,
        state: Option<crate::session::SessionScope>,
        force_session: bool,
    ) -> Result<crate::daemon::SessionsEnvelope, HttpError> {
        let base_url = &self.endpoint.base_url;
        let has_passphrase = self.endpoint.resolved_passphrase().is_some();
        let cached = has_passphrase && self.passphrase_session.get(&self.endpoint).is_some();
        let token = self
            .endpoint
            .resolved_token()
            .filter(|_| !(has_passphrase && (force_session || cached)));
        let client = if let Some(token) = token {
            crate::daemon::DaemonClient::new(base_url, Some(&token))
        } else if has_passphrase {
            let session = self.ensure_passphrase_session().await?;
            crate::daemon::DaemonClient::with_session(
                base_url,
                &session.cookie,
                &session.binding_secret,
            )
        } else {
            crate::daemon::DaemonClient::new(base_url, None)
        }?;
        client
            .list_sessions(state)
            .await
            .map_err(|error| match error {
                crate::daemon::DaemonClientError::Status { status, code, .. }
                    if status == StatusCode::UNAUTHORIZED || code.is_some() =>
                {
                    classify_coded(status, code, Scope::Global)
                }
                error => HttpError::Daemon(error),
            })
    }

    /// Title, resolved agent, and path roots, from the shared session list.
    pub async fn session_view_info(
        &self,
        session_id: &str,
    ) -> Result<crate::acp::session_paths::SessionViewInfo, HttpError> {
        let envelope = self.list_sessions(None).await?;
        envelope
            .sessions
            .into_iter()
            .find(|session| session.id == session_id)
            .map(crate::acp::session_paths::SessionViewInfo::from)
            .ok_or_else(|| HttpError::SessionNotFound(session_id.to_string()))
    }

    /// The compaction reminder percentage, or `None` when off. Read from the
    /// daemon because a remote daemon's config differs from this host's (#3253).
    pub async fn compaction_reminder(&self) -> Result<Option<u8>, HttpError> {
        #[derive(serde::Deserialize)]
        struct ReminderAbout {
            acp_compaction_reminder: bool,
            acp_compaction_reminder_percent: u8,
        }
        let about: ReminderAbout = self
            .get_json("/api/about", Scope::Session("<about>"))
            .await?;
        Ok(about
            .acp_compaction_reminder
            .then_some(about.acp_compaction_reminder_percent)
            .filter(|pct| (1..=99).contains(pct)))
    }

    /// The daemon's notice display policy, for the same reason as
    /// [`Self::compaction_reminder`].
    pub async fn notice_policy(&self) -> Result<crate::session::config::NoticePolicy, HttpError> {
        #[derive(serde::Deserialize)]
        struct NoticeAbout {
            acp_notice_display: crate::session::config::NoticeDisplay,
            acp_notice_timeout_secs: u32,
        }
        let about: NoticeAbout = self
            .get_json("/api/about", Scope::Session("<about>"))
            .await?;
        Ok(crate::session::config::NoticePolicy {
            display: about.acp_notice_display,
            timeout_secs: about.acp_notice_timeout_secs,
        })
    }

    /// Cheapest authenticated probe: separates a down host (transport error)
    /// from misconfigured auth (401).
    /// The daemon's tracing filter, replaced first when `patch` is given.
    pub async fn log_level(
        &self,
        patch: Option<&serde_json::Value>,
    ) -> Result<LogFilterReply, HttpError> {
        let res = match patch {
            None => {
                self.send(
                    || self.request(Method::GET, "/api/log-level"),
                    Scope::Global,
                )
                .await?
            }
            Some(body) => {
                self.send(
                    || self.request(Method::PATCH, "/api/log-level").json(body),
                    Scope::Global,
                )
                .await?
            }
        };
        Ok(res.json().await?)
    }

    pub async fn health_check(&self) -> Result<(), HttpError> {
        let res = self
            .send_authed(|| self.request(Method::GET, "/api/sessions"))
            .await?;
        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        Err(classify_error(status, res.headers(), Scope::Global))
    }

    fn auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.endpoint.resolved_token() {
            Some(token) => builder.header(header::AUTHORIZATION, format!("Bearer {token}")),
            None => builder,
        }
    }

    /// Attach whichever credential is available. A cached passphrase-login session wins
    /// over a bearer token (a daemon that requires both factors rejects the bearer alone);
    /// otherwise a bearer token when one resolves, else the passphrase session, logging in
    /// on first use. `force_session` skips the bearer. Neither resolving (`--auth=none`)
    /// leaves the request untouched. Refuses before any send when the transport would
    /// expose the credential.
    async fn authed_builder(
        &self,
        builder: reqwest::RequestBuilder,
        force_session: bool,
    ) -> Result<(reqwest::RequestBuilder, Credential), HttpError> {
        let has_token = self.endpoint.resolved_token().is_some();
        let has_passphrase = self.endpoint.resolved_passphrase().is_some();
        let cached = has_passphrase && self.passphrase_session.get(&self.endpoint).is_some();
        if (has_token || has_passphrase) && !self.credentials_allowed {
            return Err(crate::daemon::DaemonClientError::InsecureCredentialTransport.into());
        }
        if has_token && !(force_session || cached) {
            return Ok((self.auth(builder), Credential::Bearer));
        }
        if has_passphrase {
            let session = self.ensure_passphrase_session().await?;
            let builder = builder
                .header(header::COOKIE, session.cookie)
                .header("X-Aoe-Device-Binding", session.binding_secret);
            return Ok((builder, Credential::Session { cached }));
        }
        Ok((builder, Credential::None))
    }

    async fn ensure_passphrase_session(
        &self,
    ) -> Result<passphrase_session::PassphraseSession, HttpError> {
        if let Some(session) = self.passphrase_session.get(&self.endpoint) {
            return Ok(session);
        }
        passphrase_session::login(&self.endpoint, &self.passphrase_session).await
    }

    /// Build, authenticate, and send a request via `build`. A 401 is retried once through
    /// a fresh passphrase login when a *cached* session was stale (rotated passphrase,
    /// expired or evicted session), or when a bearer token alone was refused and a
    /// passphrase resolves (a daemon that also requires the second factor). A first-ever
    /// login failure is not retried: the credential itself is wrong.
    async fn send_authed(
        &self,
        mut build: impl FnMut() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, HttpError> {
        let (request, credential) = self.authed_builder(build(), false).await?;
        let response = request.send().await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        match credential {
            Credential::Session { cached: true } => {
                self.passphrase_session.invalidate(&self.endpoint)
            }
            Credential::Bearer if self.endpoint.resolved_passphrase().is_some() => {}
            _ => return Ok(response),
        }
        let (request, _) = self.authed_builder(build(), true).await?;
        Ok(request.send().await?)
    }
}

/// Which credential `authed_builder` attached.
enum Credential {
    None,
    Bearer,
    /// `cached` is false when this call performed the login.
    Session {
        cached: bool,
    },
}

async fn finish(res: reqwest::Response, scope: Scope<'_>) -> Result<reqwest::Response, HttpError> {
    let status = res.status();
    if status.is_success() {
        return Ok(res);
    }
    Err(classify_error(status, res.headers(), scope))
}

/// Status plus the safe `AoE-Error-Code` header decide the error. The body is never read,
/// so a stalled or reflecting server can neither delay nor steer classification.
fn classify_error(status: StatusCode, headers: &header::HeaderMap, scope: Scope<'_>) -> HttpError {
    classify_coded(status, AoeErrorCode::from_response(status, headers), scope)
}

fn classify_coded(status: StatusCode, code: Option<AoeErrorCode>, scope: Scope<'_>) -> HttpError {
    if status == StatusCode::UNAUTHORIZED {
        return HttpError::Unauthorized;
    }
    // `pending_target_gone` is only valid on a resolve operation, which has its own classifier.
    let code = code.filter(|code| *code != AoeErrorCode::PendingTargetGone);
    match (code, scope) {
        (Some(AoeErrorCode::ReadOnly), _) => HttpError::ReadOnly,
        (Some(code), _) => HttpError::Refused(code),
        (None, Scope::Session(session_id)) if status == StatusCode::NOT_FOUND => {
            HttpError::SessionNotFound(session_id.to_string())
        }
        (None, _) => HttpError::Server { status },
    }
}

/// Only the resolve endpoints mint `ApprovalGone`, and only for a 404 the daemon coded
/// `pending_target_gone`. Any other 404 leaves the card to the authoritative refresh.
fn classify_resolve_error(
    status: StatusCode,
    headers: &header::HeaderMap,
    session_id: &str,
) -> HttpError {
    if status != StatusCode::NOT_FOUND {
        return classify_error(status, headers, Scope::Session(session_id));
    }
    match AoeErrorCode::from_response(status, headers) {
        Some(AoeErrorCode::PendingTargetGone) => HttpError::ApprovalGone,
        _ => HttpError::PendingUnconfirmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::client::discovery::Source;

    async fn authorization(endpoint: DaemonEndpoint) -> Option<String> {
        let client = HttpClient::new(endpoint).unwrap();
        let request = client
            .authed_builder(client.request(Method::GET, "/api/sessions"), false)
            .await
            .unwrap()
            .0
            .build()
            .unwrap();
        request
            .headers()
            .get(header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap().to_string())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn auth_header() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let base = "http://127.0.0.1:8080".to_string();
        assert_eq!(
            authorization(DaemonEndpoint::new(
                base.clone(),
                Some("tok".into()),
                Source::Env
            ))
            .await,
            Some("Bearer tok".into())
        );
        assert_eq!(
            authorization(DaemonEndpoint::new(base.clone(), None, Source::Env)).await,
            None
        );
        // A local daemon's rotated token file wins over the discovered one.
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("serve.token");
        let rotated = "b".repeat(64);
        std::fs::write(&token_path, &rotated).unwrap();
        let local = DaemonEndpoint::new(base, Some("a".repeat(64)), Source::LocalDaemon)
            .with_local_token_path(token_path);
        assert_eq!(
            authorization(local).await,
            Some(format!("Bearer {rotated}"))
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn authed_builder_sends_no_credential_without_token_or_passphrase() {
        // --auth=none: neither a token nor a passphrase resolves, so the
        // request must go out exactly as built, matching pre-passphrase
        // behavior.
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let client = HttpClient::new(DaemonEndpoint::new(
            "http://127.0.0.1:8080".into(),
            None,
            Source::Env,
        ))
        .unwrap();
        let request = client
            .authed_builder(client.http.get("http://127.0.0.1:8080/api/sessions"), false)
            .await
            .unwrap()
            .0
            .build()
            .unwrap();
        assert!(request.headers().get(header::AUTHORIZATION).is_none());
        assert!(request.headers().get(header::COOKIE).is_none());
    }

    #[tokio::test]
    async fn authed_builder_prefers_bearer_token_over_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let passphrase_path = dir.path().join("serve.passphrase");
        std::fs::write(&passphrase_path, "hunter2").unwrap();
        let daemon_endpoint = DaemonEndpoint::new(
            "http://127.0.0.1:8080".into(),
            Some("tok".to_string()),
            Source::LocalDaemon,
        )
        .with_local_passphrase_path(passphrase_path);
        let client = HttpClient::new(daemon_endpoint).unwrap();

        let request = client
            .authed_builder(client.http.get("http://127.0.0.1:8080/api/sessions"), false)
            .await
            .unwrap()
            .0
            .build()
            .unwrap();
        assert_eq!(
            request.headers().get(header::AUTHORIZATION).unwrap(),
            "Bearer tok"
        );
        assert!(request.headers().get(header::COOKIE).is_none());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn authed_builder_sends_cached_passphrase_session_as_cookie() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let dir = tempfile::tempdir().unwrap();
        let passphrase_path = dir.path().join("serve.passphrase");
        std::fs::write(&passphrase_path, "hunter2").unwrap();
        let daemon_endpoint =
            DaemonEndpoint::new("http://127.0.0.1:8080".into(), None, Source::LocalDaemon)
                .with_local_passphrase_path(passphrase_path);
        let client = HttpClient::new(daemon_endpoint).unwrap();
        client
            .passphrase_session
            .set_for_test(passphrase_session::PassphraseSession {
                cookie: "aoe_session=abc123".to_string(),
                binding_secret: "the-binding-secret".to_string(),
            });

        let request = client
            .authed_builder(client.http.get("http://127.0.0.1:8080/api/sessions"), false)
            .await
            .unwrap()
            .0
            .build()
            .unwrap();
        assert!(request.headers().get(header::AUTHORIZATION).is_none());
        assert_eq!(
            request.headers().get(header::COOKIE).unwrap(),
            "aoe_session=abc123"
        );
        assert_eq!(
            request.headers().get("X-Aoe-Device-Binding").unwrap(),
            "the-binding-secret"
        );
    }

    fn coded(code: Option<&str>) -> header::HeaderMap {
        let mut headers = header::HeaderMap::new();
        if let Some(code) = code {
            headers.insert(AoeErrorCode::HEADER, code.parse().unwrap());
        }
        headers
    }

    #[test]
    fn error_classification() {
        let session = Scope::Session("s-1");
        let resolve = |status, code| classify_resolve_error(status, &coded(code), "s-1");
        assert!(matches!(
            resolve(StatusCode::NOT_FOUND, Some("pending_target_gone")),
            HttpError::ApprovalGone
        ));
        // A generic or old-server 404 never clears a card, whatever its body said.
        for code in [None, Some("unknown"), Some("read_only")] {
            assert!(matches!(
                resolve(StatusCode::NOT_FOUND, code),
                HttpError::PendingUnconfirmed
            ));
        }
        assert!(matches!(
            resolve(StatusCode::FORBIDDEN, Some("read_only")),
            HttpError::ReadOnly
        ));
        // The shared classifier never mints ApprovalGone.
        assert!(matches!(
            classify_error(StatusCode::NOT_FOUND, &coded(Some("pending_target_gone")), session),
            HttpError::SessionNotFound(s) if s == "s-1"
        ));
        assert!(matches!(
            classify_error(StatusCode::NOT_FOUND, &coded(None), Scope::Global),
            HttpError::Server { .. }
        ));
        assert!(matches!(
            classify_error(StatusCode::UNAUTHORIZED, &coded(Some("read_only")), session),
            HttpError::Unauthorized
        ));
        for (status, code, want) in [
            (StatusCode::FORBIDDEN, "read_only", None),
            (
                StatusCode::FORBIDDEN,
                "access_policy_denied",
                Some(AoeErrorCode::AccessPolicyDenied),
            ),
            (
                StatusCode::FORBIDDEN,
                "cityhall_mode",
                Some(AoeErrorCode::CityhallMode),
            ),
            (
                StatusCode::CONFLICT,
                "lifecycle_locked",
                Some(AoeErrorCode::LifecycleLocked),
            ),
            (
                StatusCode::UPGRADE_REQUIRED,
                "tls_required",
                Some(AoeErrorCode::TlsRequired),
            ),
        ] {
            let error = classify_error(status, &coded(Some(code)), Scope::Global);
            match want {
                Some(want) => assert!(matches!(error, HttpError::Refused(c) if c == want)),
                None => assert!(matches!(error, HttpError::ReadOnly)),
            }
        }
        // Unknown, status-inconsistent or body-only evidence stays generic.
        for (status, code) in [
            (StatusCode::FORBIDDEN, None),
            (StatusCode::FORBIDDEN, Some("elevation_required")),
            (StatusCode::CONFLICT, Some("read_only")),
            (StatusCode::INTERNAL_SERVER_ERROR, Some("tls_required")),
        ] {
            assert!(matches!(
                classify_error(status, &coded(code), session),
                HttpError::Server { .. }
            ));
        }
        let mut duplicate = coded(Some("read_only"));
        duplicate.append(AoeErrorCode::HEADER, "read_only".parse().unwrap());
        assert!(matches!(
            classify_error(StatusCode::FORBIDDEN, &duplicate, session),
            HttpError::Server { .. }
        ));
        // #1525: the 401 message must not blame a token env var.
        let rendered = HttpError::Unauthorized.to_string();
        assert!(!rendered.contains("AOE_DAEMON_TOKEN") && rendered.contains("401"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn session_list_logs_in_renews_once_and_fails_clearly() {
        use super::passphrase_session::test_daemon::{TestDaemon, PASSPHRASE};
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);

        let daemon = TestDaemon::start(PASSPHRASE).await;
        let client = HttpClient::new(daemon.endpoint.clone()).unwrap();

        let info = client.session_view_info("s-1").await.unwrap();
        assert_eq!(info.title, "one");
        assert_eq!(daemon.logins(), 1);
        let requests = daemon.list_requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0]
            .0
            .as_deref()
            .is_some_and(|c| c.starts_with("aoe_session=")));
        assert!(requests[0].1.is_some());

        // Cached session is reused without another login.
        client.list_sessions(None).await.unwrap();
        assert_eq!(daemon.logins(), 1);

        // Expired session: one re-login, one retry.
        daemon.expire_session();
        client.list_sessions(None).await.unwrap();
        assert_eq!(daemon.logins(), 2);

        // Wrong passphrase: a single login attempt and a clear 401.
        let wrong = TestDaemon::start("other").await;
        let client = HttpClient::new(wrong.endpoint.clone()).unwrap();
        let error = client.list_sessions(None).await.unwrap_err();
        assert!(matches!(error, HttpError::Unauthorized), "{error}");
        assert_eq!(wrong.logins(), 1);
        assert!(!error.to_string().contains(PASSPHRASE));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn set_config_option_posts_the_pick_with_passphrase_credentials() {
        use super::passphrase_session::test_daemon::{TestDaemon, PASSPHRASE};
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);

        let daemon = TestDaemon::start(PASSPHRASE).await;
        let client = HttpClient::new(daemon.endpoint.clone()).unwrap();
        client
            .set_config_option("s-1", "reasoning_effort", "high")
            .await
            .unwrap();

        let requests = daemon.config_option_requests();
        assert_eq!(requests.len(), 1);
        let (id, cookie, binding, body) = &requests[0];
        assert_eq!(id, "s-1");
        assert!(cookie
            .as_deref()
            .is_some_and(|c| c.starts_with("aoe_session=")));
        assert!(binding.is_some());
        assert_eq!(
            body,
            &serde_json::json!({"config_id": "reasoning_effort", "value": "high"})
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn credentials_are_refused_before_any_send_to_plaintext_remote() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let client = HttpClient::new(DaemonEndpoint::new(
            "http://203.0.113.9:8080".into(),
            Some("tok".into()),
            Source::Env,
        ))
        .unwrap();
        let refused = |error: HttpError| {
            matches!(
                error,
                HttpError::Daemon(crate::daemon::DaemonClientError::InsecureCredentialTransport)
            )
        };
        assert!(refused(client.health_check().await.unwrap_err()));
        assert!(refused(client.replay("s-1", 0).await.unwrap_err()));
        assert!(refused(
            client
                .resolve_approval("s-1", "n", ApprovalDecisionWire::Cancelled, None)
                .await
                .unwrap_err()
        ));
        assert!(refused(client.list_sessions(None).await.unwrap_err()));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn authenticated_requests_do_not_follow_redirects() {
        use futures_util::FutureExt;
        use tokio::io::AsyncWriteExt;
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", origin.local_addr().unwrap());
        let location = format!("http://{}/api/sessions", target.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let response =
                format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client =
            HttpClient::new(DaemonEndpoint::new(base, Some("tok".into()), Source::Env)).unwrap();
        let error = client.health_check().await.unwrap_err();
        server.await.unwrap();
        assert!(
            matches!(error, HttpError::Server { status, .. } if status == StatusCode::FOUND),
            "{error}"
        );
        assert!(
            target.accept().now_or_never().is_none(),
            "the redirect target was contacted"
        );
    }

    #[test]
    fn debug_and_transport_errors_carry_no_credential_or_base_path() {
        let endpoint = DaemonEndpoint::new(
            "http://127.0.0.1:1/base-secret".into(),
            Some("secret-token".into()),
            Source::Env,
        );
        let client = HttpClient::new(endpoint.clone()).unwrap();
        for rendered in [format!("{client:?}"), format!("{endpoint:?}")] {
            assert!(!rendered.contains("secret-token"), "{rendered}");
            assert!(!rendered.contains("base-secret"), "{rendered}");
        }
        for url in [
            "http://user:pw@127.0.0.1:1",
            "http://127.0.0.1:1?token=x",
            "http://127.0.0.1:1#frag",
        ] {
            let endpoint = DaemonEndpoint::new(url.into(), None, Source::Env);
            assert!(HttpClient::new(endpoint).is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn transport_failure_message_omits_the_request_url() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/base-secret", listener.local_addr().unwrap());
        drop(listener);
        let client =
            HttpClient::new(DaemonEndpoint::new(base, Some("tok".into()), Source::Env)).unwrap();
        let error = client.health_check().await.unwrap_err();
        assert!(matches!(error, HttpError::Transport(_)), "{error}");
        assert!(!format!("{error:?} {error}").contains("base-secret"));
    }

    /// A daemon that requires the passphrase factor on top of the bearer token rejects the
    /// bearer alone; the client logs in, retries once, and then prefers the session.
    #[tokio::test]
    #[serial_test::serial]
    async fn bearer_refused_for_a_second_factor_falls_back_to_a_passphrase_login() {
        use super::passphrase_session::test_daemon::TestDaemon;
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let daemon = TestDaemon::start(super::passphrase_session::test_daemon::PASSPHRASE).await;
        let client = HttpClient::new(daemon.endpoint_with_token("tok")).unwrap();

        client.list_sessions(None).await.unwrap();
        assert_eq!(daemon.logins(), 1);
        let requests = daemon.list_requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].0.is_none(), "first attempt is bearer only");
        assert!(requests[1]
            .0
            .as_deref()
            .is_some_and(|c| c.starts_with("aoe_session=")));

        client.list_sessions(None).await.unwrap();
        assert_eq!(daemon.logins(), 1);
        assert_eq!(daemon.list_requests().len(), 3);
    }

    /// Against the real router behind a proxy, a bearer alone is refused on a
    /// token-plus-passphrase daemon, and the fallback login must itself carry the bearer.
    #[tokio::test]
    #[serial_test::serial]
    async fn log_level_falls_back_to_a_passphrase_login_on_a_real_router() {
        use crate::server::test_support;
        use std::sync::Arc;
        let mut _env = test_support::RuntimeEnvGuard::read_lock();
        let dir = tempfile::tempdir().unwrap();
        _env.bind(dir.path());
        let phrase = "log level second factor";
        let token = "b".repeat(64);
        let _phrase =
            crate::session::test_support::EnvGuard::set(&[("AOE_DAEMON_PASSPHRASE", phrase)]);
        let mut state = test_support::build_test_app_state_with_policy(
            Vec::new(),
            vec!["127.0.0.1".into()],
            Vec::new(),
            Some(token.clone()),
        );
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.login_manager = Arc::new(crate::server::login::LoginManager::new(Some(phrase)));
        mutable.behind_tunnel = true;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = test_support::build_router_for_test(state.clone());
        let shutdown = state.shutdown.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .unwrap();
        });
        let client = HttpClient::new(DaemonEndpoint::new(base, Some(token), Source::Env)).unwrap();
        let body = client.log_level(None).await.unwrap();
        assert_eq!(body.reloadable, Some(false), "{body:?}");
        assert_eq!(state.login_manager.device_snapshot(None).await.len(), 1);
        state.shutdown.cancel();
        server.await.unwrap();
    }

    /// Authenticated session listing classifies from the status and exactly one
    /// status-consistent `AoE-Error-Code`, never the body, and degrades to the generic
    /// error for a missing, repeated or inconsistent header.
    #[tokio::test]
    #[serial_test::serial]
    async fn session_list_errors_classify_from_the_safe_header_without_the_body() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let deadline = Duration::from_secs(10);
        for (status, codes, expect) in [
            ("403 Forbidden", &["read_only"][..], "read_only"),
            ("403 Forbidden", &["access_policy_denied"], "access_policy"),
            ("403 Forbidden", &["cityhall_mode"], "cityhall"),
            ("403 Forbidden", &["read_only", "cityhall_mode"], "generic"),
            ("403 Forbidden", &["bogus"], "generic"),
            ("404 Not Found", &["read_only"], "generic"),
            ("403 Forbidden", &[], "generic"),
            ("500 Internal Server Error", &[], "generic"),
        ] {
            let headers: String = codes
                .iter()
                .map(|code| format!("AoE-Error-Code: {code}\r\n"))
                .collect();
            let head: &'static str = Box::leak(
                format!("HTTP/1.1 {status}\r\n{headers}Content-Length: 1000000\r\n\r\n")
                    .into_boxed_str(),
            );
            let (base, server) = stalled_body_server(head).await;
            let client =
                HttpClient::new(DaemonEndpoint::new(base, Some("tok".into()), Source::Env))
                    .unwrap();
            let error = tokio::time::timeout(deadline, client.list_sessions(None))
                .await
                .expect("listing waited on the error body")
                .unwrap_err();
            let matched = matches!(
                (&error, expect),
                (HttpError::ReadOnly, "read_only")
                    | (
                        HttpError::Refused(AoeErrorCode::AccessPolicyDenied),
                        "access_policy"
                    )
                    | (HttpError::Refused(AoeErrorCode::CityhallMode), "cityhall")
                    | (
                        HttpError::Daemon(crate::daemon::DaemonClientError::Status {
                            code: None,
                            ..
                        }),
                        "generic"
                    )
            );
            assert!(matched, "{status} {codes:?}: {error:?}");
            server.abort();
        }
    }

    /// A failed step-up must not replace the daemon's own 403 with a misleading 401.
    #[tokio::test]
    #[serial_test::serial]
    async fn failed_step_up_keeps_the_original_forbidden() {
        let _env =
            crate::session::test_support::EnvGuard::set(&[("AOE_DAEMON_PASSPHRASE", "hunter2")]);
        let (base, server) =
            stalled_body_server("HTTP/1.1 403 Forbidden\r\nContent-Length: 1000000\r\n\r\n").await;
        let client =
            HttpClient::new(DaemonEndpoint::new(base, Some("tok".into()), Source::Env)).unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            client.set_plugin_enabled("p", true),
        )
        .await
        .expect("step-up waited on the error body")
        .unwrap_err();
        assert!(
            matches!(error, HttpError::Server { status } if status == StatusCode::FORBIDDEN),
            "{error}"
        );
        server.abort();
    }

    /// Serves every connection the status line and headers, then never the promised body.
    async fn stalled_body_server(head: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    stream.write_all(head.as_bytes()).await.unwrap();
                    std::future::pending::<()>().await;
                });
            }
        });
        (base, server)
    }

    /// Classification comes from status and `AoE-Error-Code` alone: a server that promises
    /// a body and never sends it cannot delay it, and an old server without the header
    /// degrades to the generic status.
    #[tokio::test]
    #[serial_test::serial]
    async fn error_classification_does_not_wait_for_the_body() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let head = |status: &str, code: Option<&str>| -> &'static str {
            let code = code
                .map(|code| format!("AoE-Error-Code: {code}\r\n"))
                .unwrap_or_default();
            Box::leak(
                format!("HTTP/1.1 {status}\r\n{code}Content-Length: 1000000\r\n\r\n")
                    .into_boxed_str(),
            )
        };
        let deadline = Duration::from_secs(10);
        for (status, code, expect) in [
            ("404 Not Found", Some("pending_target_gone"), "gone"),
            ("404 Not Found", None, "unconfirmed"),
            ("403 Forbidden", Some("read_only"), "read_only"),
            ("500 Internal Server Error", None, "server"),
        ] {
            let (base, server) = stalled_body_server(head(status, code)).await;
            let client =
                HttpClient::new(DaemonEndpoint::new(base, Some("tok".into()), Source::Env))
                    .unwrap();
            let error = tokio::time::timeout(
                deadline,
                client.resolve_approval("s-1", "n-1", ApprovalDecisionWire::Allow, None),
            )
            .await
            .expect("resolve waited on the error body")
            .unwrap_err();
            let matched = matches!(
                (&error, expect),
                (HttpError::ApprovalGone, "gone")
                    | (HttpError::PendingUnconfirmed, "unconfirmed")
                    | (HttpError::ReadOnly, "read_only")
                    | (HttpError::Server { .. }, "server")
            );
            assert!(matched, "{status} {code:?}: {error}");
            server.abort();
        }

        let (base, server) =
            stalled_body_server(head("426 Upgrade Required", Some("tls_required"))).await;
        let client =
            HttpClient::new(DaemonEndpoint::new(base, Some("tok".into()), Source::Env)).unwrap();
        let error = tokio::time::timeout(deadline, client.health_check())
            .await
            .expect("health check waited on the error body")
            .unwrap_err();
        assert!(
            matches!(error, HttpError::Refused(AoeErrorCode::TlsRequired)),
            "{error}"
        );
        server.abort();
    }
}
