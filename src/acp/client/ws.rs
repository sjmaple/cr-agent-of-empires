//! WebSocket client for the structured view broadcast stream.
//!
//! Subscribes to `/sessions/{id}/acp/ws?since=N` and yields decoded events.
//! `parse_text` documents the frame shapes the daemon pushes.
//!
//! The bearer token rides an `Authorization` header, never the URL. The daemon's
//! auth middleware still accepts a `?token=` query for browsers, which cannot set
//! headers on a WebSocket.
//!
//! A `--auth=passphrase` daemon never mints a bearer token, so when only a
//! passphrase resolves the upgrade request instead carries `Cookie:
//! aoe_session=...` and `Sec-WebSocket-Protocol: aoe-auth,
//! aoe-device.<secret>` headers, the same passphrase-login session
//! `HttpClient` uses (see `passphrase_session`). `aoe-auth` must be offered
//! alongside the device-binding value: the daemon (`acp_ws.rs`) only echoes
//! a `Sec-WebSocket-Protocol` response header, at all, when the client
//! offered that literal string, and tungstenite fails the handshake outright
//! if the response omits it while the request carried one (RFC 6455). The
//! web client already offers it the same way (`useAcpSession.ts`).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::{debug, warn};

use super::discovery::DaemonEndpoint;
use super::http::HttpError;
use super::passphrase_session::{self, PassphraseSessionCache};
use crate::acp::protocol::AcpBroadcastFrame;
use crate::acp::state::AcpState;
use crate::acp::transcript::{TranscriptDelta, TranscriptRow};

#[derive(Debug, Error)]
pub enum WsError {
    #[error("websocket transport error: {0}")]
    Transport(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("invalid websocket URL: {0}")]
    InvalidUrl(String),
    #[error("websocket closed unexpectedly (code {0:?})")]
    UnexpectedClose(Option<CloseCode>),
    /// Surfaced so a toast carries the real reason, not a fabricated
    /// transport error.
    #[error("failed to parse websocket frame: {0}")]
    Parse(String),
    /// The passphrase-login handshake (see `passphrase_session::login`)
    /// failed before the WS upgrade was even attempted.
    #[error("passphrase login failed: {0}")]
    Auth(#[from] HttpError),
}

/// One message off the structured view WebSocket.
#[derive(Debug, Clone)]
pub enum WsMessage {
    /// A raw event frame, consumed by `aoe acp tail`. The structured view
    /// reads the two folded projections below instead.
    Frame(Arc<AcpBroadcastFrame>),
    /// Server-folded control state (turn flags, approvals, elicitations,
    /// usage, modes, commands, plan), sent on connect and after every event.
    /// Boxed because `AcpState` dwarfs the other variants.
    ///
    /// `unchanged` names the cold fields the server omitted because this
    /// connection already holds them (`COLD_STATE_FIELDS` in
    /// `src/server/acp_ws.rs`). They deserialize to empty defaults, so a
    /// consumer must keep what it has rather than adopt the blank.
    ReducedState {
        seq: u64,
        state: Box<AcpState>,
        unchanged: Vec<String>,
    },
    /// The daemon's ring evicted events this client missed. The consumer must
    /// drop its reducer state and `HttpClient::replay(since=last_seq)`.
    Lagged,
    /// Connect snapshot of the folded transcript rows, reconciled by id so an
    /// overlap with a `?view=rows` replay is idempotent.
    TranscriptSnapshot(Vec<TranscriptRow>),
    /// One folded row change. Boxed: a `Patch` carries a whole
    /// `TranscriptRow`, which would bloat every `WsMessage`.
    TranscriptDelta(Box<TranscriptDelta>),
}

/// Handle to a running WebSocket reader task. Drop or call
/// [`Self::shutdown`] to close the connection.
pub struct WsHandle {
    rx: mpsc::Receiver<Result<WsMessage, WsError>>,
    task: JoinHandle<()>,
    shutdown: tokio_util::sync::CancellationToken,
    /// Cancels the same token, so dropping the handle without an explicit
    /// `shutdown().await` still closes the socket instead of leaving
    /// `reader_loop` parked on `stream.next()`. Cancellation is idempotent.
    _drop_guard: tokio_util::sync::DropGuard,
}

/// Long enough for a healthy loopback close round-trip, short enough that a
/// stuck reader task cannot block our caller's teardown.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(200);

impl WsHandle {
    pub async fn recv(&mut self) -> Option<Result<WsMessage, WsError>> {
        self.rx.recv().await
    }

    /// Close cleanly, falling back to `abort()` past `SHUTDOWN_GRACE`.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let mut task = self.task;
        if tokio::time::timeout(SHUTDOWN_GRACE, &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
    }
}

/// Stream `session_id`'s events after `since` (`0` for a full replay).
pub async fn connect(
    endpoint: &DaemonEndpoint,
    session_id: &str,
    since: u64,
) -> Result<WsHandle, WsError> {
    connect_with(endpoint, session_id, since, true).await
}

/// [`connect`], but a consumer that renders only the folded projections passes
/// `forward_frames: false` so a long session's history is not shipped on every
/// open. The server still folds it to build the connect snapshots.
pub async fn connect_with(
    endpoint: &DaemonEndpoint,
    session_id: &str,
    since: u64,
    forward_frames: bool,
) -> Result<WsHandle, WsError> {
    let url = ws_url(endpoint, session_id, since, forward_frames);
    debug!(
        target: "acp.client.ws",
        session = %session_id,
        since,
        "connecting to structured view ws"
    );
    let cache = PassphraseSessionCache::default();
    let stream = connect_authed(endpoint, &url, &cache).await?;
    let (frame_tx, frame_rx) = mpsc::channel(64);
    let shutdown = tokio_util::sync::CancellationToken::new();
    let _drop_guard = shutdown.clone().drop_guard();
    let task = tokio::spawn(reader_loop(stream, frame_tx, shutdown.clone()));
    Ok(WsHandle {
        rx: frame_rx,
        task,
        shutdown,
        _drop_guard,
    })
}

/// Connect the WS upgrade, retrying once after a fresh passphrase login if a *cached*
/// session was rejected (rotated passphrase, expired or evicted session), or if a bearer
/// token alone was refused and a passphrase resolves (a daemon that also requires the
/// second factor). A first-ever login failure is not retried: the credential itself is
/// wrong.
async fn connect_authed(
    endpoint: &DaemonEndpoint,
    url: &str,
    cache: &PassphraseSessionCache,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, WsError> {
    let (request, credential) = build_authed_request(endpoint, url, cache, false).await?;
    match connect_pinned(request).await {
        Err(err) if is_unauthorized(&err) => match credential {
            Credential::Session { cached: true } => cache.invalidate(endpoint),
            Credential::Bearer if endpoint.resolved_passphrase().is_some() => {}
            _ => return Err(err.into()),
        },
        result => return Ok(result?),
    }
    let (request, _) = build_authed_request(endpoint, url, cache, true).await?;
    Ok(connect_pinned(request).await?)
}

/// A handshake rejection keeps its status and headers but not a body, which a server
/// could use to reflect credentials into an error message.
fn without_response_body(
    error: tokio_tungstenite::tungstenite::Error,
) -> tokio_tungstenite::tungstenite::Error {
    use tokio_tungstenite::tungstenite::Error;
    match error {
        Error::Http(response) => Error::Http(Box::new(response.map(|_| None))),
        error => error,
    }
}

async fn connect_pinned(
    request: tokio_tungstenite::tungstenite::http::Request<()>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, tokio_tungstenite::tungstenite::Error> {
    connect_loopback_pinned(request)
        .await
        .map_err(without_response_body)
}

/// `localhost` connects to loopback addresses only, never whatever the resolver returns.
/// Redirects are not followed and no proxy is used.
async fn connect_loopback_pinned(
    request: tokio_tungstenite::tungstenite::http::Request<()>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, tokio_tungstenite::tungstenite::Error> {
    use tokio_tungstenite::tungstenite::Error;
    let uri = request.uri().clone();
    if uri.host() != Some("localhost") {
        return Ok(connect_async(request).await?.0);
    }
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("wss") {
            443
        } else {
            80
        });
    let loopback = [
        std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
    ];
    let stream = TcpStream::connect(&loopback[..]).await.map_err(Error::Io)?;
    Ok(
        tokio_tungstenite::client_async_tls_with_config(request, stream, None, None)
            .await?
            .0,
    )
}

/// Which credential the upgrade request carries.
enum Credential {
    None,
    Bearer,
    /// `cached` is false when this call performed the login.
    Session {
        cached: bool,
    },
}

/// Build the WS upgrade request. A cached passphrase-login session wins over a bearer
/// token; otherwise a resolved token rides an `Authorization` header, else a passphrase
/// attaches the login session's `aoe_session` cookie and device-binding secret, logging in
/// on first use. `force_session` skips the bearer. Refuses before any connection when the
/// transport would expose the credential.
async fn build_authed_request(
    endpoint: &DaemonEndpoint,
    url: &str,
    cache: &PassphraseSessionCache,
    force_session: bool,
) -> Result<
    (
        tokio_tungstenite::tungstenite::http::Request<()>,
        Credential,
    ),
    WsError,
> {
    let mut request = url
        .into_client_request()
        .map_err(|e| WsError::InvalidUrl(e.to_string()))?;
    let token = endpoint.resolved_token();
    let has_passphrase = endpoint.resolved_passphrase().is_some();
    let cached = has_passphrase && cache.get(endpoint).is_some();
    if token.is_none() && !has_passphrase {
        return Ok((request, Credential::None));
    }
    let base = crate::daemon::parse_base_url(&endpoint.base_url).map_err(HttpError::from)?;
    crate::daemon::require_secure_credential_transport(&base).map_err(HttpError::from)?;
    if let Some(token) = token.filter(|_| !(has_passphrase && (force_session || cached))) {
        let mut value: tokio_tungstenite::tungstenite::http::HeaderValue =
            format!("Bearer {token}")
                .parse()
                .map_err(|_| WsError::InvalidUrl("invalid bearer token".to_string()))?;
        value.set_sensitive(true);
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
            value,
        );
        return Ok((request, Credential::Bearer));
    }
    let session = match cache.get(endpoint) {
        Some(session) => session,
        None => passphrase_session::login(endpoint, cache).await?,
    };
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::COOKIE,
        session
            .cookie
            .parse()
            .map_err(|_| WsError::InvalidUrl("invalid session cookie".to_string()))?,
    );
    // `aoe-auth` must be offered too: the daemon only echoes a
    // `Sec-WebSocket-Protocol` response header when the client offered
    // that exact literal, and tungstenite hard-fails the handshake
    // (`NoSubProtocol`) if the response omits it while the request
    // carried one. See the module doc comment.
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
        format!("aoe-auth, aoe-device.{}", session.binding_secret)
            .parse()
            .map_err(|_| WsError::InvalidUrl("invalid device binding secret".to_string()))?,
    );
    Ok((request, Credential::Session { cached }))
}

fn is_unauthorized(err: &tokio_tungstenite::tungstenite::Error) -> bool {
    matches!(
        err,
        tokio_tungstenite::tungstenite::Error::Http(response) if response.status().as_u16() == 401
    )
}

async fn reader_loop(
    mut stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    tx: mpsc::Sender<Result<WsMessage, WsError>>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                let _ = stream
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Normal,
                        reason: "client shutdown".into(),
                    })))
                    .await;
                return;
            }
            next = stream.next() => {
                match next {
                    Some(Ok(Message::Text(text))) => {
                        // `Ok(None)` is a keepalive: nothing to wake the consumer for.
                        let delivery = match parse_text(&text) {
                            Ok(None) => None,
                            Ok(Some(msg)) => Some(Ok(msg)),
                            Err(e) => Some(Err(e)),
                        };
                        if let Some(delivery) = delivery {
                            if tx.send(delivery).await.is_err() {
                                return; // consumer dropped
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = stream.send(Message::Pong(payload)).await;
                    }
                    // The daemon never sends binary; ignore defensively.
                    Some(Ok(
                        Message::Binary(_) | Message::Pong(_) | Message::Frame(_),
                    )) => {}
                    Some(Ok(Message::Close(frame))) => {
                        let code = frame.as_ref().map(|f| f.code);
                        let _ = tx.send(Err(WsError::UnexpectedClose(code))).await;
                        return;
                    }
                    Some(Err(e)) => {
                        let _ = tx.send(Err(WsError::Transport(e))).await;
                        return;
                    }
                    None => {
                        let _ = tx.send(Err(WsError::UnexpectedClose(None))).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Decode one text frame: either an `AcpBroadcastFrame` event or a
/// `{"kind": ...}` control frame. `Ok(None)` is a frame with nothing for the
/// consumer to act on, distinct from `Err`, which consumers escalate to a
/// socket teardown and reconnect.
fn parse_text(raw: &str) -> Result<Option<WsMessage>, WsError> {
    // An event frame serializes only session_id/seq/event, so the presence of
    // `kind` alone marks a control frame. `Option<Option<_>>` tells an absent
    // `kind` apart from a present-but-null one.
    #[derive(serde::Deserialize)]
    struct KindProbe {
        #[serde(default, deserialize_with = "present")]
        kind: Option<Option<serde_json::Value>>,
    }
    fn present<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Option<serde_json::Value>>, D::Error> {
        Option::<serde_json::Value>::deserialize(d).map(Some)
    }
    #[derive(serde::Deserialize)]
    struct TranscriptSnapshotFrame {
        rows: Vec<TranscriptRow>,
    }
    #[derive(serde::Deserialize)]
    struct TranscriptDeltaFrame {
        delta: TranscriptDelta,
    }
    #[derive(serde::Deserialize)]
    struct ReducedStateFrame {
        seq: u64,
        state: AcpState,
        #[serde(default)]
        unchanged: Vec<String>,
    }
    if let Ok(KindProbe { kind: Some(kind) }) = serde_json::from_str::<KindProbe>(raw) {
        let kind = kind.unwrap_or(serde_json::Value::Null);
        match kind.as_str() {
            Some("lagged") => return Ok(Some(WsMessage::Lagged)),
            // App-level keepalive (#2287).
            Some("heartbeat") => return Ok(None),
            Some("transcript_snapshot") => {
                let frame: TranscriptSnapshotFrame =
                    serde_json::from_str(raw).map_err(|e| WsError::Parse(e.to_string()))?;
                return Ok(Some(WsMessage::TranscriptSnapshot(frame.rows)));
            }
            Some("transcript_delta") => {
                let frame: TranscriptDeltaFrame =
                    serde_json::from_str(raw).map_err(|e| WsError::Parse(e.to_string()))?;
                return Ok(Some(WsMessage::TranscriptDelta(Box::new(frame.delta))));
            }
            Some("reduced_state") => {
                let frame: ReducedStateFrame =
                    serde_json::from_str(raw).map_err(|e| WsError::Parse(e.to_string()))?;
                return Ok(Some(WsMessage::ReducedState {
                    seq: frame.seq,
                    state: Box::new(frame.state),
                    unchanged: frame.unchanged,
                }));
            }
            // A sentinel a newer daemon grew. Dropping it is safe: every
            // projection above is re-sent on connect and on each event (#3560).
            _ => {
                debug!(
                    target: "acp.client.ws",
                    kind = %kind,
                    "ignoring unrecognized ws control frame"
                );
                return Ok(None);
            }
        }
    }
    // No `kind` key, or not a JSON object: an event frame. A malformed one
    // surfaces as `WsError::Parse`, which the consumer treats as a dead socket.
    let frame: AcpBroadcastFrame = serde_json::from_str(raw).map_err(|e| {
        warn!(target: "acp.client.ws", error = %e, "ws frame parse failed");
        WsError::Parse(e.to_string())
    })?;
    Ok(Some(WsMessage::Frame(Arc::new(frame))))
}

fn ws_url(endpoint: &DaemonEndpoint, session_id: &str, since: u64, forward_frames: bool) -> String {
    let base = endpoint.ws_base_url();
    let path = format!("/sessions/{session_id}/acp/ws");
    let mut params: Vec<String> = Vec::new();
    if since > 0 {
        params.push(format!("since={since}"));
    }
    if !forward_frames {
        params.push("frames=0".to_string());
    }
    if params.is_empty() {
        format!("{base}{path}")
    } else {
        format!("{base}{path}?{}", params.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::client::discovery::Source;

    fn endpoint(base: &str, token: Option<&str>) -> DaemonEndpoint {
        DaemonEndpoint::new(base.to_string(), token.map(str::to_string), Source::Env)
    }

    /// `since=0` is omitted, `frames=0` marks a projections-only consumer, an https
    /// endpoint upgrades to `wss`, and the URL never carries the token.
    #[test]
    fn ws_url_query_shape() {
        let e = endpoint("http://127.0.0.1:8080", Some("abc"));
        for (since, frames, want) in [
            (42, true, "ws://127.0.0.1:8080/sessions/s-1/acp/ws?since=42"),
            (
                42,
                false,
                "ws://127.0.0.1:8080/sessions/s-1/acp/ws?since=42&frames=0",
            ),
            (0, true, "ws://127.0.0.1:8080/sessions/s-1/acp/ws"),
        ] {
            assert_eq!(ws_url(&e, "s-1", since, frames), want);
        }
        assert!(
            ws_url(&endpoint("https://remote.test", Some("t")), "s-1", 0, true)
                .starts_with("wss://")
        );
    }

    /// Any present `kind` marks a control frame, whatever its JSON type, and
    /// one this build does not know must be dropped rather than fall through
    /// to the event parse. That fall-through failed on a missing `event`
    /// field and drove a reconnect loop against the heartbeat (#3171) and
    /// against the connect snapshot of a `frames=0` client (#3560).
    #[derive(Debug)]
    enum Expect {
        Lagged,
        Ignored,
        ParseError,
    }

    #[test]
    fn parse_text_classifies_kind_sentinels() {
        for (raw, expect) in [
            (r#"{"kind":"lagged"}"#, Expect::Lagged),
            (r#"{"kind":"heartbeat"}"#, Expect::Ignored),
            (r#"{"kind":"something_new"}"#, Expect::Ignored),
            (
                r#"{"kind":"something_new","session_id":"s-1","seq":9}"#,
                Expect::Ignored,
            ),
            (r#"{"kind":null}"#, Expect::Ignored),
            (r#"{"kind":42}"#, Expect::Ignored),
            // No `kind` and no event shape: genuinely malformed.
            (r#"{"session_id":"s-1","seq":9}"#, Expect::ParseError),
        ] {
            let got = parse_text(raw);
            match expect {
                Expect::Lagged => assert!(
                    matches!(got, Ok(Some(WsMessage::Lagged))),
                    "{raw}: expected Lagged, got {got:?}"
                ),
                Expect::Ignored => assert!(
                    matches!(got, Ok(None)),
                    "{raw}: expected to be ignored, got {got:?}"
                ),
                Expect::ParseError => {
                    assert!(got.is_err(), "{raw}: expected a parse error, got {got:?}")
                }
            }
        }
    }

    #[test]
    fn parse_text_reads_the_reduced_state_frame() {
        // An omitted field must default: a parse error reads as a dead socket.
        let raw = serde_json::json!({
            "kind": "reduced_state",
            "session_id": "s-1",
            "seq": 7,
            "state": {
                "session_id": "s-1",
                "agent": "claude",
                "model": null,
                "mode": "Default",
                "current_plan": null,
                "todos": [],
                "in_flight_tool": null,
                "pending_approvals": [],
                "thinking": null,
                "rate_limit": null,
                "turn_active": true,
                "last_seq": 7,
                "updated_at": "2026-08-16T00:00:00Z",
            },
        })
        .to_string();
        match parse_text(&raw) {
            Ok(Some(WsMessage::ReducedState { seq, state, .. })) => {
                assert_eq!(seq, 7);
                assert!(state.turn_active);
                assert!(state.available_modes.is_empty(), "absent field defaults");
                // `recent_diffs` is one of the server's cold fields (omitted
                // from the wire when unchanged, see `COLD_STATE_FIELDS` in
                // `src/server/acp_ws.rs`), so it must default the same way.
                assert!(state.recent_diffs.is_empty(), "absent field defaults");
            }
            other => panic!("expected reduced state, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn build_authed_request_sends_the_bearer_token_as_a_sensitive_header() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let e = endpoint("http://127.0.0.1:8080", Some("tok"));
        let cache = PassphraseSessionCache::default();
        let request =
            build_authed_request(&e, "ws://127.0.0.1:8080/sessions/s-1/acp/ws", &cache, false)
                .await
                .unwrap()
                .0;
        let authorization = request
            .headers()
            .get(tokio_tungstenite::tungstenite::http::header::AUTHORIZATION)
            .unwrap();
        assert_eq!(authorization, "Bearer tok");
        assert!(authorization.is_sensitive());
        assert!(request.uri().query().is_none());
        assert!(request
            .headers()
            .get(tokio_tungstenite::tungstenite::http::header::COOKIE)
            .is_none());
    }

    /// #3003: a local daemon's rotated token file wins over the discovered one.
    #[tokio::test]
    #[serial_test::serial]
    async fn build_authed_request_uses_the_rotated_local_token() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("serve.token");
        let rotated = "b".repeat(64);
        std::fs::write(&token_path, &rotated).unwrap();
        let e = DaemonEndpoint::new(
            "http://127.0.0.1:8080".into(),
            Some("a".repeat(64)),
            Source::LocalDaemon,
        )
        .with_local_token_path(token_path);
        let request = build_authed_request(
            &e,
            "ws://127.0.0.1:8080/sessions/s-1/acp/ws",
            &PassphraseSessionCache::default(),
            false,
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            request
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::AUTHORIZATION)
                .unwrap(),
            format!("Bearer {rotated}").as_str()
        );
    }

    /// A credential never reaches a plaintext remote endpoint: the request is refused
    /// before any connection is attempted.
    #[tokio::test]
    #[serial_test::serial]
    async fn build_authed_request_refuses_plaintext_remote_credentials() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let e = endpoint("http://203.0.113.9:8080", Some("tok"));
        let result = build_authed_request(
            &e,
            "ws://203.0.113.9:8080/sessions/s-1/acp/ws",
            &PassphraseSessionCache::default(),
            false,
        )
        .await;
        assert!(matches!(
            result,
            Err(WsError::Auth(HttpError::Daemon(
                crate::daemon::DaemonClientError::InsecureCredentialTransport
            )))
        ));
        assert!(build_authed_request(
            &endpoint("https://203.0.113.9", Some("tok")),
            "wss://203.0.113.9/sessions/s-1/acp/ws",
            &PassphraseSessionCache::default(),
            false,
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn build_authed_request_adds_no_headers_without_token_or_passphrase() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let e = endpoint("http://127.0.0.1:8080", None);
        let cache = PassphraseSessionCache::default();
        let request =
            build_authed_request(&e, "ws://127.0.0.1:8080/sessions/s-1/acp/ws", &cache, false)
                .await
                .unwrap()
                .0;
        assert!(request
            .headers()
            .get(tokio_tungstenite::tungstenite::http::header::COOKIE)
            .is_none());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn build_authed_request_sends_cached_passphrase_session_as_headers() {
        let _env = crate::session::test_support::EnvGuard::unset(&["AOE_DAEMON_PASSPHRASE"]);
        let dir = tempfile::tempdir().unwrap();
        let passphrase_path = dir.path().join("serve.passphrase");
        std::fs::write(&passphrase_path, "hunter2").unwrap();
        let e = DaemonEndpoint::new("http://127.0.0.1:8080".into(), None, Source::LocalDaemon)
            .with_local_passphrase_path(passphrase_path);
        let cache = PassphraseSessionCache::default();
        cache.set_for_test(passphrase_session::PassphraseSession {
            cookie: "aoe_session=abc123".to_string(),
            binding_secret: "the-binding-secret".to_string(),
        });

        let request =
            build_authed_request(&e, "ws://127.0.0.1:8080/sessions/s-1/acp/ws", &cache, false)
                .await
                .unwrap()
                .0;
        assert_eq!(
            request
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::COOKIE)
                .unwrap(),
            "aoe_session=abc123"
        );
        // Must include the `aoe-auth` literal alongside the device-binding
        // value, or the daemon never echoes a Sec-WebSocket-Protocol
        // response header and tungstenite fails the handshake outright.
        assert_eq!(
            request
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL)
                .unwrap(),
            "aoe-auth, aoe-device.the-binding-secret"
        );
    }

    #[test]
    fn is_unauthorized_matches_only_http_401() {
        use tokio_tungstenite::tungstenite::http::{Response, StatusCode};
        use tokio_tungstenite::tungstenite::Error as TError;

        let unauthorized = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(None)
            .unwrap();
        assert!(is_unauthorized(&TError::Http(Box::new(unauthorized))));

        let forbidden = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(None)
            .unwrap();
        assert!(!is_unauthorized(&TError::Http(Box::new(forbidden))));
        assert!(!is_unauthorized(&TError::ConnectionClosed));
    }
}
