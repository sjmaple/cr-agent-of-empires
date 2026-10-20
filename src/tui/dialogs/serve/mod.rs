//! Remote access view: a controller for the `aoe serve --daemon` lifecycle, which outlives the TUI.

mod daemon;
mod render;
mod words;

use std::cell::RefCell;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;

use crate::cli::serve::{read_serve_urls, ServeUrl};
use crate::tui::components::hover::HoverState;
use crate::tui::dialogs::{contains, hit, target_rects};
use crate::tui::styles::Theme;
use crate::tui::worker::Worker;
pub(crate) use daemon::start_local_daemon_and_wait;
use daemon::*;

const TUNNEL_STARTUP_TIMEOUT_SECS: u64 = 60;
const FLASH_TTL: Duration = Duration::from_millis(1500);
const CONFIRM_TTL: Duration = Duration::from_secs(3);

pub enum ServeAction {
    Continue,
    Close,
}

/// Persisted to `serve.mode` and `serve.last_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServeMode {
    Local,
    Tunnel,
}

impl ServeMode {
    fn file_token(self) -> &'static str {
        match self {
            ServeMode::Local => "local",
            ServeMode::Tunnel => "tunnel",
        }
    }

    fn from_file_token(s: &str) -> Option<Self> {
        match s.trim() {
            "local" => Some(ServeMode::Local),
            "tunnel" => Some(ServeMode::Tunnel),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelTransport {
    Tailscale,
    Cloudflare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportStatus {
    Ready,
    NotInstalled,
    /// Tailscale is logged in but the ACL doesn't grant Funnel.
    FunnelNotEnabled,
}

/// Process work the dialog hands to its worker thread.
enum Job {
    /// Whether a daemon is running.
    Probe,
    /// Admission check plus launch; a restart stops the old daemon first.
    Launch {
        restart: bool,
        mode: ServeMode,
        transport: Option<TunnelTransport>,
        passphrase: Option<String>,
    },
}

enum JobDone {
    Probe(bool),
    Launched(Result<(), String>),
}

/// Transient message shown after a rejected keypress.
type Flash = Option<(String, Instant)>;

fn expire_flash(flash: &mut Flash) -> bool {
    let expired = flash.as_ref().is_some_and(|(_, t)| t.elapsed() > FLASH_TTL);
    if expired {
        *flash = None;
    }
    expired
}

enum ServeViewState {
    /// Waiting on the probe that decides between reattaching and the mode picker.
    Checking { attempt: u64 },
    ModePicker {
        selected: ServeMode,
        tunnel_available: bool,
        local_available: bool,
        flash: Flash,
    },
    /// Tunnel only: risk explanation plus the transport picker.
    Confirm {
        selected: TunnelTransport,
        tailscale: TransportStatus,
        cloudflare: TransportStatus,
        flash: Flash,
    },
    /// Waiting on the launch job; closing is blocked so the daemon never appears unseen.
    Spawning {
        attempt: u64,
        restart: bool,
        mode: ServeMode,
        transport: Option<TunnelTransport>,
        passphrase: Option<String>,
        log_offset: u64,
    },
    /// Polling `serve.url`; `transport` is None for Local and reattached daemons.
    /// `probe` is the attempt of the in-flight liveness check.
    Starting {
        mode: ServeMode,
        transport: Option<TunnelTransport>,
        passphrase: Option<String>,
        started_at: Instant,
        log_offset: u64,
        probe: Option<u64>,
    },
    Active {
        mode: ServeMode,
        transport: Option<TunnelTransport>,
        urls: Vec<ServeUrl>,
        url_index: usize,
        /// Known only when this TUI started the daemon or the server wrote it to disk.
        passphrase: Option<String>,
        opened_at: Instant,
        log_offset: u64,
    },
    /// What failed, kept so a Tunnel failure can offer the other provider.
    Error {
        message: String,
        mode: ServeMode,
        transport: Option<TunnelTransport>,
    },
}

impl ServeViewState {
    fn mode_picker() -> Self {
        let tunnel_available = crate::server::tunnel::tailscale_available_sync()
            || crate::server::tunnel::check_cloudflared().is_ok();
        let local_available = !crate::server::discover_tagged_ips().is_empty();
        // Prefer the last launched mode, falling back to whichever one is available.
        let last = read_last_mode().unwrap_or(ServeMode::Local);
        let selected = match (last, local_available, tunnel_available) {
            (ServeMode::Local, false, true) | (ServeMode::Tunnel, _, true) => ServeMode::Tunnel,
            _ => ServeMode::Local,
        };
        ServeViewState::ModePicker {
            selected,
            tunnel_available,
            local_available,
            flash: None,
        }
    }

    /// The provider screen after a Tunnel failure: the provider that did not just fail is
    /// preselected when it is ready.
    fn provider_retry(
        failed: Option<TunnelTransport>,
        tailscale: TransportStatus,
        cloudflare: TransportStatus,
    ) -> Self {
        let other = match failed {
            Some(TunnelTransport::Tailscale) => Some((TunnelTransport::Cloudflare, cloudflare)),
            Some(TunnelTransport::Cloudflare) => Some((TunnelTransport::Tailscale, tailscale)),
            None => None,
        };
        let selected = match other {
            Some((transport, TransportStatus::Ready)) => transport,
            _ => default_transport(tailscale, cloudflare),
        };
        ServeViewState::Confirm {
            selected,
            tailscale,
            cloudflare,
            flash: None,
        }
    }

    /// Active once the daemon has published its URLs, Starting until then.
    fn running(
        mode: ServeMode,
        transport: Option<TunnelTransport>,
        passphrase: Option<String>,
        log_offset: u64,
    ) -> Self {
        let urls = read_serve_urls();
        if urls.is_empty() {
            return ServeViewState::Starting {
                mode,
                transport,
                passphrase,
                started_at: Instant::now(),
                log_offset,
                probe: None,
            };
        }
        ServeViewState::Active {
            mode,
            transport,
            urls,
            url_index: 0,
            passphrase,
            opened_at: Instant::now(),
            log_offset,
        }
    }
}

/// What the last frame drew under the mouse, recorded through a `RefCell`
/// since rendering borrows the view immutably.
#[derive(Default)]
struct ServeMouse {
    /// Hints and cards, each standing for a key.
    keys: Vec<(KeyEvent, Rect)>,
    /// Values a click copies, keyed by `(label, value)`.
    copies: Vec<((&'static str, String), Rect)>,
    hover: HoverState,
}

impl ServeMouse {
    fn rects(&self) -> Vec<Rect> {
        let mut rects = target_rects(&self.keys);
        rects.extend(target_rects(&self.copies));
        rects
    }
}

/// The error for a daemon that vanished before publishing its URL.
fn exited_before_ready(mode: ServeMode, transport: Option<TunnelTransport>) -> ServeViewState {
    let tail = initial_log_tail();
    let prefix = match mode {
        ServeMode::Tunnel => "`aoe serve --remote --daemon` exited before the tunnel came up.",
        ServeMode::Local => "`aoe serve --daemon` exited before the server started.",
    };
    let hint = diagnose_daemon_exit(&tail.join("\n"), mode);
    ServeViewState::Error {
        message: format!("{prefix}{hint}{}", last_log_lines(&tail)),
        mode,
        transport,
    }
}

fn stop_failed(e: &str) -> String {
    format!("Stop failed: {e}. Daemon may still be running; retry or use `aoe serve --stop` from a shell.")
}

/// `tailscale funnel reset` only helps a Tunnel that went through Funnel; a reattached
/// daemon's transport is unknown, so its message decides.
fn funnel_reset_applies(
    message: &str,
    mode: ServeMode,
    transport: Option<TunnelTransport>,
) -> bool {
    mode == ServeMode::Tunnel
        && transport.map_or_else(
            || error_mentions_tailscale(message),
            |t| t == TunnelTransport::Tailscale,
        )
}

/// A destructive action awaiting a second press of its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingConfirm {
    NewPassphrase,
    Restart,
}

pub struct ServeView {
    state: ServeViewState,
    /// Passphrase for the next Tunnel spawn; persisted so it survives stop/start.
    pending_passphrase: String,
    pending_confirm: Option<(PendingConfirm, Instant)>,
    show_help: bool,
    mouse: RefCell<ServeMouse>,
    /// The label of the value a click last copied, shown for `FLASH_TTL`.
    copied: Option<(&'static str, Instant)>,
    worker: Worker<(u64, Job), (u64, JobDone)>,
    last_attempt: u64,
}

impl Default for ServeView {
    fn default() -> Self {
        Self::new()
    }
}

impl ServeView {
    /// Reattaches to a running daemon, otherwise opens the mode picker.
    pub fn new() -> Self {
        Self::with_handler(run_job)
    }

    fn with_handler(mut handler: impl FnMut(Job) -> JobDone + Send + 'static) -> Self {
        let worker = Worker::spawn("aoe-serve-dialog", move |(attempt, job)| {
            (attempt, handler(job))
        });
        let mut view = Self::from_state(
            ServeViewState::Checking { attempt: 0 },
            load_or_generate_passphrase(),
            worker,
        );
        let attempt = view.request(Job::Probe);
        view.state = ServeViewState::Checking { attempt };
        view
    }

    fn from_state(
        state: ServeViewState,
        pending_passphrase: String,
        worker: Worker<(u64, Job), (u64, JobDone)>,
    ) -> Self {
        Self {
            state,
            pending_passphrase,
            pending_confirm: None,
            show_help: false,
            mouse: RefCell::default(),
            copied: None,
            worker,
            last_attempt: 0,
        }
    }

    #[cfg(test)]
    fn with_state(state: ServeViewState) -> Self {
        Self::from_state(
            state,
            String::new(),
            Worker::spawn("aoe-serve-dialog-test", |_| unreachable!()),
        )
    }

    /// Queues `job` and returns its attempt, which its result must still match.
    fn request(&mut self, job: Job) -> u64 {
        self.last_attempt += 1;
        self.worker.request((self.last_attempt, job));
        self.last_attempt
    }

    /// Hints and cards return their key; the URL, token and passphrase copy
    /// on click. Any click closes help, like any key.
    pub fn handle_click(&mut self, col: u16, row: u16) -> Option<KeyEvent> {
        if self.show_help {
            return Some(KeyEvent::from(KeyCode::Esc));
        }
        let mouse = self.mouse.get_mut();
        let copy = mouse
            .copies
            .iter()
            .find(|(_, rect)| contains(*rect, col, row))
            .map(|(copy, _)| copy.clone());
        if let Some((label, value)) = copy {
            crate::tui::clipboard::copy_to_clipboard(&value);
            self.copied = Some((label, Instant::now()));
            return None;
        }
        hit(&mouse.keys, col, row)
    }

    pub fn handle_hover(&mut self, col: u16, row: u16) -> bool {
        let mouse = self.mouse.get_mut();
        let rects = mouse.rects();
        mouse.hover.update(col, row, &rects)
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> ServeAction {
        match self.state {
            ServeViewState::Checking { .. } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => ServeAction::Close,
                _ => ServeAction::Continue,
            },
            ServeViewState::Spawning { .. } => ServeAction::Continue,
            ServeViewState::ModePicker { .. } => self.mode_picker_key(key.code),
            ServeViewState::Confirm { .. } => self.confirm_key(key.code),
            ServeViewState::Starting { .. } => match key.code {
                // Closing leaves the daemon coming up; `s` aborts it.
                KeyCode::Esc | KeyCode::Char('q') => ServeAction::Close,
                KeyCode::Char('s' | 'S') => {
                    let _ = stop_daemon();
                    ServeAction::Close
                }
                _ => ServeAction::Continue,
            },
            ServeViewState::Active { .. } => self.active_key(key.code),
            ServeViewState::Error { .. } => self.error_key(key.code),
        }
    }

    fn mode_picker_key(&mut self, code: KeyCode) -> ServeAction {
        let ServeViewState::ModePicker {
            selected,
            tunnel_available,
            local_available,
            flash,
        } = &mut self.state
        else {
            return ServeAction::Continue;
        };
        expire_flash(flash);
        match code {
            KeyCode::Left | KeyCode::Char('h') => *selected = ServeMode::Local,
            KeyCode::Right | KeyCode::Char('l') if *tunnel_available => {
                *selected = ServeMode::Tunnel
            }
            KeyCode::Tab => {
                *selected = match *selected {
                    ServeMode::Local if *tunnel_available => ServeMode::Tunnel,
                    ServeMode::Tunnel if *local_available => ServeMode::Local,
                    other => other,
                }
            }
            KeyCode::Char('t' | 'T') => {
                *selected = ServeMode::Tunnel;
                return self.commit_mode();
            }
            // Lowercase `l` moves right, so capital `L` is the Local shortcut.
            KeyCode::Char('L') => {
                *selected = ServeMode::Local;
                return self.commit_mode();
            }
            KeyCode::Enter => return self.commit_mode(),
            KeyCode::Esc | KeyCode::Char('q') => return ServeAction::Close,
            _ => {}
        }
        ServeAction::Continue
    }

    fn commit_mode(&mut self) -> ServeAction {
        let ServeViewState::ModePicker {
            selected,
            tunnel_available,
            local_available,
            flash,
        } = &mut self.state
        else {
            return ServeAction::Continue;
        };
        let rejection = match *selected {
            ServeMode::Tunnel if !*tunnel_available => {
                "Install tailscale or cloudflared to enable Tunnel mode."
            }
            ServeMode::Local if !*local_available => "No non-loopback network interface available.",
            ServeMode::Tunnel => {
                let (tailscale, cloudflare) = assess_transports();
                self.state = ServeViewState::Confirm {
                    selected: default_transport(tailscale, cloudflare),
                    tailscale,
                    cloudflare,
                    flash: None,
                };
                return ServeAction::Continue;
            }
            ServeMode::Local => {
                self.spawn(ServeMode::Local, None);
                return ServeAction::Continue;
            }
        };
        *flash = Some((rejection.to_string(), Instant::now()));
        ServeAction::Continue
    }

    fn confirm_key(&mut self, code: KeyCode) -> ServeAction {
        let ServeViewState::Confirm {
            selected,
            tailscale,
            cloudflare,
            flash,
        } = &mut self.state
        else {
            return ServeAction::Continue;
        };
        expire_flash(flash);
        match code {
            KeyCode::Left | KeyCode::Char('h') => *selected = TunnelTransport::Tailscale,
            KeyCode::Right | KeyCode::Char('l') => *selected = TunnelTransport::Cloudflare,
            KeyCode::Tab => {
                *selected = match *selected {
                    TunnelTransport::Tailscale => TunnelTransport::Cloudflare,
                    TunnelTransport::Cloudflare => TunnelTransport::Tailscale,
                }
            }
            KeyCode::Char('t' | 'T') => {
                *selected = TunnelTransport::Tailscale;
                return self.commit_transport();
            }
            KeyCode::Char('c' | 'C') => {
                *selected = TunnelTransport::Cloudflare;
                return self.commit_transport();
            }
            KeyCode::Enter => return self.commit_transport(),
            KeyCode::Char('r' | 'R') => {
                (*tailscale, *cloudflare) = assess_transports();
                *flash = Some(("Refreshed.".to_string(), Instant::now()));
            }
            KeyCode::Esc | KeyCode::Char('q') => return ServeAction::Close,
            _ => {}
        }
        ServeAction::Continue
    }

    fn commit_transport(&mut self) -> ServeAction {
        let ServeViewState::Confirm {
            selected,
            tailscale,
            cloudflare,
            flash,
        } = &mut self.state
        else {
            return ServeAction::Continue;
        };
        let pick = *selected;
        let rejection = match (pick, *tailscale, *cloudflare) {
            (TunnelTransport::Tailscale, TransportStatus::Ready, _)
            | (TunnelTransport::Cloudflare, _, TransportStatus::Ready) => {
                self.spawn(ServeMode::Tunnel, Some(pick));
                return ServeAction::Continue;
            }
            (TunnelTransport::Tailscale, TransportStatus::FunnelNotEnabled, _) => {
                "Tailscale Funnel isn't enabled for this node; pick Cloudflare or update your ACL."
            }
            (TunnelTransport::Tailscale, ..) => "Tailscale isn't installed; pick Cloudflare.",
            (TunnelTransport::Cloudflare, ..) => "cloudflared isn't installed; pick Tailscale.",
        };
        *flash = Some((rejection.to_string(), Instant::now()));
        ServeAction::Continue
    }

    fn spawn(&mut self, mode: ServeMode, transport: Option<TunnelTransport>) {
        let passphrase = (mode == ServeMode::Tunnel).then(|| self.pending_passphrase.clone());
        self.launch(false, mode, transport, passphrase);
    }

    fn launch(
        &mut self,
        restart: bool,
        mode: ServeMode,
        transport: Option<TunnelTransport>,
        passphrase: Option<String>,
    ) {
        // Taken before launching so only the new daemon's output counts as progress.
        let log_offset = log_file_size();
        let attempt = self.request(Job::Launch {
            restart,
            mode,
            transport,
            passphrase: passphrase.clone(),
        });
        self.state = ServeViewState::Spawning {
            attempt,
            restart,
            mode,
            transport,
            passphrase,
            log_offset,
        };
    }

    fn active_key(&mut self, code: KeyCode) -> ServeAction {
        if std::mem::take(&mut self.show_help) {
            return ServeAction::Continue;
        }
        let confirmed = self.pending_confirm.take().and_then(|(action, when)| {
            let repeated = match action {
                PendingConfirm::NewPassphrase => matches!(code, KeyCode::Char('g' | 'G')),
                PendingConfirm::Restart => matches!(code, KeyCode::Char('r' | 'R')),
            };
            (repeated && when.elapsed() <= CONFIRM_TTL).then_some(action)
        });
        let ServeViewState::Active {
            mode,
            transport,
            urls,
            url_index,
            passphrase,
            ..
        } = &mut self.state
        else {
            return ServeAction::Continue;
        };
        let (mode, transport) = (*mode, *transport);
        match code {
            KeyCode::Char('s' | 'S') => match stop_daemon() {
                Ok(()) => self.state = ServeViewState::mode_picker(),
                Err(e) => {
                    self.state = ServeViewState::Error {
                        message: stop_failed(&e),
                        mode,
                        transport,
                    }
                }
            },
            KeyCode::Char('g' | 'G') if mode == ServeMode::Tunnel => {
                if confirmed == Some(PendingConfirm::NewPassphrase) {
                    let new_pp = generate_passphrase();
                    save_passphrase_to_disk(&new_pp);
                    self.pending_passphrase = new_pp.clone();
                    self.restart(mode, transport, Some(new_pp));
                } else {
                    self.pending_confirm = Some((PendingConfirm::NewPassphrase, Instant::now()));
                }
            }
            // Tunnel restarts clear all login sessions; Local rebinds the port.
            KeyCode::Char('r' | 'R') => {
                if confirmed == Some(PendingConfirm::Restart) {
                    let pp = (mode == ServeMode::Tunnel).then(|| {
                        passphrase
                            .clone()
                            .unwrap_or_else(|| self.pending_passphrase.clone())
                    });
                    self.restart(mode, transport, pp);
                } else {
                    self.pending_confirm = Some((PendingConfirm::Restart, Instant::now()));
                }
            }
            KeyCode::Tab if urls.len() > 1 => *url_index = (*url_index + 1) % urls.len(),
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Esc | KeyCode::Char('q') => return ServeAction::Close,
            _ => {}
        }
        ServeAction::Continue
    }

    fn error_key(&mut self, code: KeyCode) -> ServeAction {
        let ServeViewState::Error {
            message,
            mode,
            transport,
        } = &self.state
        else {
            return ServeAction::Continue;
        };
        let (mode, transport) = (*mode, *transport);
        match code {
            // Best effort: no daemon left running is the goal either way.
            KeyCode::Char('s' | 'S') => {
                let _ = stop_daemon();
                ServeAction::Close
            }
            KeyCode::Char('p' | 'P') if mode == ServeMode::Tunnel => {
                // Like S: a daemon left running must not outlive the retry.
                if crate::cli::serve::daemon_pid().is_some() {
                    if let Err(e) = stop_daemon() {
                        self.state = ServeViewState::Error {
                            message: stop_failed(&e),
                            mode,
                            transport,
                        };
                        return ServeAction::Continue;
                    }
                }
                let (tailscale, cloudflare) = assess_transports();
                self.state = ServeViewState::provider_retry(transport, tailscale, cloudflare);
                ServeAction::Continue
            }
            // Clears a stale funnel config blocking port 443; safe when none exists.
            KeyCode::Char('r' | 'R') if funnel_reset_applies(message, mode, transport) => {
                let message = match run_tailscale_funnel_reset() {
                    Ok(()) => "Ran `tailscale funnel reset`. The existing funnel \
                         config (if any) has been cleared.\n\n\
                         Press P to pick a provider and start again."
                        .to_string(),
                    Err(e) => format!(
                        "`tailscale funnel reset` failed: {e}\n\n\
                         Try running it manually from a shell, then press P to start again."
                    ),
                };
                self.state = ServeViewState::Error {
                    message,
                    mode,
                    transport,
                };
                ServeAction::Continue
            }
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char(' ' | 'q') => ServeAction::Close,
            _ => ServeAction::Continue,
        }
    }

    fn restart(
        &mut self,
        mode: ServeMode,
        transport: Option<TunnelTransport>,
        passphrase: Option<String>,
    ) {
        self.launch(true, mode, transport, passphrase);
    }

    /// Apply finished jobs, poll the daemon's files and advance the state. Returns true when a
    /// redraw is needed.
    pub fn tick(&mut self) -> bool {
        let mut changed = self.apply_jobs();
        changed |= self.poll_files();
        if matches!(self.state, ServeViewState::Starting { probe: None, .. }) {
            let attempt = self.request(Job::Probe);
            if let ServeViewState::Starting { probe, .. } = &mut self.state {
                *probe = Some(attempt);
            }
        }
        changed
    }

    fn apply_jobs(&mut self) -> bool {
        use std::sync::mpsc::TryRecvError;
        let mut changed = false;
        loop {
            let (attempt, done) = match self.worker.try_recv() {
                Ok(reply) => reply,
                Err(TryRecvError::Empty) => return changed,
                Err(TryRecvError::Disconnected) => {
                    return changed | self.fail_pending("the background worker stopped")
                }
            };
            changed |= self.apply_job(attempt, done);
        }
    }

    /// Only the job the current state is waiting on may change it.
    fn apply_job(&mut self, attempt: u64, done: JobDone) -> bool {
        match (&mut self.state, done) {
            (ServeViewState::Checking { attempt: want }, JobDone::Probe(running))
                if *want == attempt =>
            {
                self.state = if running {
                    // Daemons that predate `serve.mode` could only be Tunnel.
                    let mode = read_serve_mode().unwrap_or(ServeMode::Tunnel);
                    let passphrase = (mode == ServeMode::Tunnel)
                        .then(recall_passphrase)
                        .flatten();
                    ServeViewState::running(mode, None, passphrase, log_file_size())
                } else {
                    ServeViewState::mode_picker()
                };
                true
            }
            (
                ServeViewState::Starting {
                    mode,
                    transport,
                    probe,
                    ..
                },
                JobDone::Probe(running),
            ) if *probe == Some(attempt) => {
                *probe = None;
                // A published URL outranks a probe that saw the daemon exit.
                if running || !read_serve_urls().is_empty() {
                    return false;
                }
                self.state = exited_before_ready(*mode, *transport);
                true
            }
            (
                ServeViewState::Spawning {
                    attempt: want,
                    restart,
                    mode,
                    transport,
                    passphrase,
                    log_offset,
                },
                JobDone::Launched(result),
            ) if *want == attempt => {
                let (restart, mode, transport) = (*restart, *mode, *transport);
                let passphrase = passphrase.take();
                self.state = match result {
                    Ok(()) if restart => {
                        if let Some(pp) = &passphrase {
                            remember_passphrase(pp);
                        }
                        ServeViewState::running(mode, transport, passphrase, *log_offset)
                    }
                    Ok(()) => {
                        remember_last_mode(mode);
                        ServeViewState::Starting {
                            mode,
                            transport,
                            passphrase,
                            started_at: Instant::now(),
                            log_offset: *log_offset,
                            probe: None,
                        }
                    }
                    Err(e) => ServeViewState::Error {
                        message: if restart {
                            format!("Restart failed: {e}")
                        } else {
                            e
                        },
                        mode,
                        transport,
                    },
                };
                true
            }
            _ => false,
        }
    }

    /// Turns a state waiting on a dead worker into an error so it cannot hang.
    fn fail_pending(&mut self, message: &str) -> bool {
        let (mode, transport) = match &self.state {
            ServeViewState::Checking { .. } => (ServeMode::Local, None),
            ServeViewState::Spawning {
                mode, transport, ..
            }
            | ServeViewState::Starting {
                mode,
                transport,
                probe: Some(_),
                ..
            } => (*mode, *transport),
            _ => return false,
        };
        self.state = ServeViewState::Error {
            message: message.to_string(),
            mode,
            transport,
        };
        true
    }

    fn poll_files(&mut self) -> bool {
        match &mut self.state {
            ServeViewState::ModePicker { flash, .. } => expire_flash(flash),
            ServeViewState::Starting {
                mode,
                transport,
                passphrase,
                started_at,
                log_offset,
                ..
            } => {
                let log_grew = log_grew(log_offset);
                let mode = *mode;
                let urls = read_serve_urls();
                if !urls.is_empty() {
                    // A reattached daemon writes serve.passphrase only once startup finishes.
                    let passphrase = passphrase.take().or_else(|| {
                        (mode == ServeMode::Tunnel)
                            .then(recall_passphrase)
                            .flatten()
                    });
                    self.state = ServeViewState::Active {
                        mode,
                        transport: *transport,
                        urls,
                        url_index: 0,
                        passphrase,
                        opened_at: Instant::now(),
                        log_offset: log_file_size(),
                    };
                    return true;
                }
                if mode == ServeMode::Tunnel
                    && started_at.elapsed() > Duration::from_secs(TUNNEL_STARTUP_TIMEOUT_SECS)
                {
                    // Stop it so a tunnel that never came up doesn't linger in the status bar.
                    let stop_note = match stop_daemon() {
                        Ok(()) => "Stuck daemon stopped.".to_string(),
                        Err(e) => format!(
                            "Daemon may still be running \
                             (tried to stop: {}). Stop manually with `aoe serve --stop`.",
                            e
                        ),
                    };
                    let message = format!(
                        "HTTPS tunnel did not announce a URL within {}s. \
                         {}\n\n\
                         Most likely cause: Tailscale Funnel needs HTTPS certs \
                         or ACL approval, OR cloudflared is rate-limited / \
                         offline. Re-run with AGENT_OF_EMPIRES_DEBUG=1 and \
                         check debug.log for details.{}",
                        TUNNEL_STARTUP_TIMEOUT_SECS,
                        stop_note,
                        last_log_lines(&initial_log_tail())
                    );
                    self.state = ServeViewState::Error {
                        message,
                        mode,
                        transport: *transport,
                    };
                    return true;
                }
                log_grew
            }
            ServeViewState::Active { log_offset, .. } => {
                let log_grew = log_grew(log_offset);
                if self
                    .pending_confirm
                    .is_some_and(|(_, t)| t.elapsed() > CONFIRM_TTL)
                {
                    self.pending_confirm = None;
                    return true;
                }
                log_grew
            }
            ServeViewState::Checking { .. }
            | ServeViewState::Spawning { .. }
            | ServeViewState::Confirm { .. }
            | ServeViewState::Error { .. } => false,
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        render::render(self, frame, area, theme);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn serve_mode_file_token_parses_server_output() {
        for mode in [ServeMode::Local, ServeMode::Tunnel] {
            let written = format!("{}\n", mode.file_token());
            assert_eq!(ServeMode::from_file_token(&written), Some(mode));
        }
        assert_eq!(ServeMode::from_file_token("garbage"), None);
        assert_eq!(ServeMode::from_file_token(""), None);
    }

    #[test]
    fn a_tunnel_retry_preselects_the_provider_that_did_not_fail() {
        use TransportStatus::{FunnelNotEnabled, NotInstalled, Ready};
        use TunnelTransport::{Cloudflare, Tailscale};
        // (failed provider, tailscale, cloudflare, preselected)
        let cases = [
            (Some(Tailscale), Ready, Ready, Cloudflare),
            // The other provider isn't ready, so the usual default applies.
            (Some(Tailscale), Ready, NotInstalled, Tailscale),
            (Some(Cloudflare), Ready, Ready, Tailscale),
            (Some(Cloudflare), FunnelNotEnabled, Ready, Cloudflare),
            // A reattached daemon's transport is unknown.
            (None, Ready, Ready, Tailscale),
            (None, NotInstalled, Ready, Cloudflare),
        ];
        for (failed, ts, cf, want) in cases {
            let ServeViewState::Confirm {
                selected,
                tailscale,
                cloudflare,
                flash,
            } = ServeViewState::provider_retry(failed, ts, cf)
            else {
                panic!("{failed:?} {ts:?} {cf:?}: not the provider screen");
            };
            assert_eq!(
                (selected, tailscale, cloudflare, flash.is_none()),
                (want, ts, cf, true),
                "{failed:?} {ts:?} {cf:?}"
            );
        }
    }

    #[test]
    fn a_local_error_offers_no_provider_retry_or_funnel_reset() {
        let message = "`aoe serve --daemon` exited: tailscale status failed".to_string();
        let mut view = ServeView::with_state(ServeViewState::Error {
            message: message.clone(),
            mode: ServeMode::Local,
            transport: None,
        });
        for key in ['p', 'P', 'r', 'R'] {
            let action = view.handle_key(KeyEvent::from(KeyCode::Char(key)));
            assert!(matches!(action, ServeAction::Continue), "{key}");
            assert!(
                matches!(&view.state, ServeViewState::Error { message: m, mode: ServeMode::Local, .. } if *m == message),
                "{key}"
            );
        }
    }

    /// A handler that reports each job it starts, then holds it until released.
    struct Gate {
        entered: std::sync::mpsc::Receiver<()>,
        release: std::sync::mpsc::Sender<JobDone>,
    }

    impl Gate {
        fn wait_entered(&self) {
            self.entered
                .recv_timeout(Duration::from_secs(10))
                .expect("job never reached the worker");
        }
    }

    fn gated_view() -> (ServeView, Gate) {
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let view = ServeView::with_handler(move |_| {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap()
        });
        (view, Gate { entered, release })
    }

    fn tick_until(view: &mut ServeView, done: impl Fn(&ServeViewState) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(&view.state) {
            view.tick();
            assert!(Instant::now() < deadline, "result never applied");
            std::thread::yield_now();
        }
    }

    fn isolated() -> (tempfile::TempDir, crate::session::test_support::AppDirGuard) {
        let temp = tempfile::TempDir::new().unwrap();
        let guard = crate::session::test_support::isolate_app_dir_at(temp.path());
        (temp, guard)
    }

    #[test]
    #[serial]
    fn a_held_probe_at_construction_leaves_the_dialog_responsive() {
        let (_temp, _guard) = isolated();
        let (mut view, gate) = gated_view();
        gate.wait_entered();

        assert!(!view.tick());
        assert!(matches!(
            view.handle_key(KeyEvent::from(KeyCode::Char('x'))),
            ServeAction::Continue
        ));
        assert!(matches!(view.state, ServeViewState::Checking { .. }));
        assert!(matches!(
            view.handle_key(KeyEvent::from(KeyCode::Esc)),
            ServeAction::Close
        ));

        gate.release.send(JobDone::Probe(true)).unwrap();
        tick_until(&mut view, |s| !matches!(s, ServeViewState::Checking { .. }));
    }

    #[test]
    #[serial]
    fn a_starting_dialog_keeps_one_probe_in_flight_and_ignores_a_stale_result() {
        let (_temp, _guard) = isolated();
        let (mut view, gate) = gated_view();
        gate.wait_entered();
        gate.release.send(JobDone::Probe(true)).unwrap();
        // The construction probe is stale once the state is replaced.
        view.state = ServeViewState::Starting {
            mode: ServeMode::Local,
            transport: None,
            passphrase: None,
            started_at: Instant::now(),
            log_offset: 0,
            probe: None,
        };
        view.tick();
        gate.wait_entered();
        let ServeViewState::Starting { probe, .. } = &view.state else {
            panic!("not starting");
        };
        let current = probe.expect("a probe is in flight");
        // The blocked FIFO worker hides queued requests, so count enqueues instead.
        let enqueued = view.last_attempt;
        for _ in 0..5 {
            view.tick();
        }
        assert_eq!(view.last_attempt, enqueued, "a second probe was queued");
        assert!(matches!(
            view.state,
            ServeViewState::Starting { probe: Some(p), .. } if p == current
        ));

        // A result for an attempt the state no longer awaits must not change it.
        assert!(!view.apply_job(current - 1, JobDone::Probe(false)));
        assert!(matches!(
            view.state,
            ServeViewState::Starting { probe: Some(p), .. } if p == current
        ));
        gate.release.send(JobDone::Probe(true)).unwrap();
    }

    #[test]
    #[serial]
    fn a_held_launch_leaves_the_dialog_responsive_and_only_the_current_attempt_applies() {
        let (_temp, _guard) = isolated();
        let (mut view, gate) = gated_view();
        gate.wait_entered();
        gate.release.send(JobDone::Probe(true)).unwrap();
        view.spawn(ServeMode::Local, None);
        gate.wait_entered();

        assert!(!view.tick());
        assert!(matches!(
            view.handle_key(KeyEvent::from(KeyCode::Esc)),
            ServeAction::Continue
        ));
        assert!(matches!(view.state, ServeViewState::Spawning { .. }));

        gate.release
            .send(JobDone::Launched(Err("port in use".into())))
            .unwrap();
        tick_until(&mut view, |s| matches!(s, ServeViewState::Error { .. }));
        let ServeViewState::Error { message, .. } = &view.state else {
            unreachable!()
        };
        assert_eq!(message, "port in use");
    }
}
