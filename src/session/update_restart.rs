//! Detects a running agent whose binary was replaced on disk after it launched.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};

use crate::acp::agent_registry::AgentRegistry;
use crate::process::worker_registry::WorkerRecord;
use crate::session::{Instance, Status};

const MTIME_TTL: Duration = Duration::from_secs(30);

/// Bounded by the number of distinct agent binaries.
static MTIME_CACHE: Mutex<Option<HashMap<String, (Instant, Option<SystemTime>)>>> =
    Mutex::new(None);

/// The terminal binary whose replacement makes this session stale, or `None` when it cannot be
/// named safely (custom agents, command overrides that carry arguments).
fn agent_binary(inst: &Instance) -> Option<&str> {
    if inst.command.is_empty() {
        crate::agents::get_agent(&inst.tool).map(|a| a.binary)
    } else if !inst.command.contains(char::is_whitespace) {
        Some(&inst.command)
    } else {
        None
    }
}

/// What a structured worker actually runs: the registered ACP command, which for adapter-backed
/// agents is the adapter (it bundles its own CLI), not the CLI on `PATH`.
fn adapter_command(inst: &Instance, record: &WorkerRecord) -> Option<String> {
    if !inst.command.is_empty() {
        return None;
    }
    AgentRegistry::with_defaults()
        .get(&record.agent_key)
        .map(|spec| spec.command.clone())
}

/// `acp` resolves the command as the daemon does when it spawns the adapter, so a pinned bundled
/// copy is watched when it is the one in use.
fn binary_mtime(binary: &str, acp: bool) -> Option<SystemTime> {
    let key = if acp {
        format!("acp:{binary}")
    } else {
        binary.to_string()
    };
    let mut guard = MTIME_CACHE.lock().ok()?;
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some((at, mtime)) = cache.get(&key) {
        if at.elapsed() < MTIME_TTL {
            return *mtime;
        }
    }
    let path = if acp {
        let app_dir = crate::session::get_app_dir().ok();
        crate::acp::acp_client::resolve_agent_command(binary, app_dir.as_deref()).map(|r| r.path)
    } else {
        which::which(binary).ok()
    };
    let mtime = path.and_then(|path| {
        // A package manager may keep a fixed mtime on the target but recreate the bin symlink.
        let target = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        let link = std::fs::symlink_metadata(&path)
            .and_then(|m| m.modified())
            .ok();
        target.max(link)
    });
    cache.insert(key, (Instant::now(), mtime));
    mtime
}

type LaunchPathKey = (String, String);

/// Bounded by the number of distinct profile and project pairs.
static LAUNCH_PATH_CACHE: Mutex<Option<HashMap<LaunchPathKey, (Instant, bool)>>> = Mutex::new(None);

fn environment_sets_path(entries: &[String]) -> bool {
    entries.iter().any(|entry| entry.starts_with("PATH="))
}

/// Whether the session's launch environment may resolve the agent through a PATH other than
/// AoE's: a `PATH=` entry or any `before_session` hook. Fails closed when the config cannot be
/// read.
fn launch_path_overridden(inst: &Instance) -> bool {
    let key = (inst.effective_profile(), inst.project_path.clone());
    let Ok(mut guard) = LAUNCH_PATH_CACHE.lock() else {
        return true;
    };
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some((at, overridden)) = cache.get(&key) {
        if at.elapsed() < MTIME_TTL {
            return *overridden;
        }
    }
    let overridden = crate::session::config::repo_config::resolve_config_with_repo(
        &key.0,
        std::path::Path::new(&key.1),
    )
    .map_or(true, |config| {
        // A hook's exports are transient, so any hook may have chosen the executable.
        environment_sets_path(&config.environment) || !config.host_hooks.before_session.is_empty()
    });
    cache.insert(key, (Instant::now(), overridden));
    overridden
}

/// Whole seconds, so a binary written in the launch second is not flagged.
fn modified_after(mtime: SystemTime, started_at: DateTime<Utc>) -> bool {
    let modified = mtime.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    modified as i64 > started_at.timestamp()
}

/// An idle row whose agent binary was replaced after launch. Reads only the row and the
/// filesystem, so it is safe to call while painting.
pub fn binary_updated(inst: &Instance) -> bool {
    // A sandboxed agent runs the container's copy, which host files say nothing about.
    if inst.status != Status::Idle || inst.is_archived() || inst.is_trashed() || inst.is_sandboxed()
    {
        return false;
    }
    let stale = if inst.is_structured() {
        crate::process::worker_registry::load(&inst.id)
            .ok()
            .flatten()
            .and_then(|record| {
                let started_at =
                    DateTime::from_timestamp(i64::try_from(record.started_at).ok()?, 0)?;
                let command = adapter_command(inst, &record)?;
                Some(modified_after(binary_mtime(&command, true)?, started_at))
            })
    } else {
        agent_binary(inst)
            .zip(inst.started_at)
            .and_then(|(binary, started_at)| {
                Some(modified_after(binary_mtime(binary, false)?, started_at))
            })
    };
    stale.unwrap_or(false)
}

/// Whether to offer "restart to apply update". `resume_available` is the row's
/// `ContextResumeAvailability::Available`; `structured_ready` is a running worker with no pending
/// approvals. The restart must keep the conversation, so every gate fails closed.
pub fn offer_pending(inst: &Instance, resume_available: bool, structured_ready: bool) -> bool {
    inst.queued_prompts.is_empty()
        && resume_available
        && (!inst.is_structured() || structured_ready)
        && binary_updated(inst)
        // Terminal launches resolve the agent through the session's own environment, which the
        // host lookup in `binary_updated` cannot see. Reads config, so never call it from paint.
        && (inst.is_structured() || !launch_path_overridden(inst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtime_is_compared_in_whole_seconds() {
        let started = DateTime::from_timestamp(1_000, 500_000_000).unwrap();
        let at = |secs| UNIX_EPOCH + Duration::from_secs(secs);
        assert!(!modified_after(at(999), started));
        assert!(!modified_after(at(1_000), started));
        assert!(modified_after(at(1_001), started));
    }

    #[test]
    fn only_a_nameable_binary_is_watched() {
        let mut inst = Instance::new("t", "/tmp");
        inst.tool = "claude".into();
        assert_eq!(agent_binary(&inst), Some("claude"));
        inst.command = "/opt/bin/claude".into();
        assert_eq!(agent_binary(&inst), Some("/opt/bin/claude"));
        inst.command = "env FOO=1 claude".into();
        assert_eq!(agent_binary(&inst), None);
        inst.command.clear();
        inst.tool = "not-an-agent".into();
        assert_eq!(agent_binary(&inst), None);
    }

    #[test]
    fn a_structured_worker_watches_its_adapter_not_the_cli() {
        let record = |agent_key: &str| {
            WorkerRecord::new(
                "t".into(),
                1,
                "/tmp/s".into(),
                agent_key.into(),
                agent_key.into(),
                "/tmp".into(),
                None,
                vec![],
                vec![],
                None,
                None,
            )
        };
        let mut inst = Instance::new("t", "/tmp");
        assert_eq!(
            adapter_command(&inst, &record("claude")).as_deref(),
            Some("claude-agent-acp")
        );
        assert_eq!(adapter_command(&inst, &record("my-custom")), None);
        inst.command = "wrapper".into();
        assert_eq!(adapter_command(&inst, &record("claude")), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_sandboxed_row_is_never_flagged_by_host_binaries() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("agent");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut inst = Instance::new("t", "/tmp");
        inst.status = Status::Idle;
        inst.command = bin.to_str().unwrap().into();
        inst.started_at = DateTime::from_timestamp(1_000, 0);
        assert!(binary_updated(&inst));

        inst.sandbox_info = Some(crate::session::SandboxInfo {
            provider: None,
            enabled: true,
            container_id: None,
            image: "alpine".to_string(),
            container_name: "sandbox".to_string(),
            extra_env: None,
            custom_instruction: None,
            before_start_env: Vec::new(),
            container_workdir: None,
        });
        assert!(!binary_updated(&inst));
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn a_before_session_hook_means_the_host_binary_cannot_be_attested() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let _home = crate::session::test_support::isolate_app_dir_at(temp.path());
        let bin = temp.path().join("agent");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let eligible = |project: &str| {
            let mut inst = Instance::new("t", project);
            inst.status = Status::Idle;
            inst.command = bin.to_str().unwrap().into();
            inst.started_at = DateTime::from_timestamp(1_000, 0);
            inst
        };
        assert!(offer_pending(&eligible("/tmp/no-hook"), true, false));

        crate::session::config::update_config(|global| {
            global.host_hooks.before_session = vec!["export PATH=/opt/agent-a/bin:$PATH".into()];
        })
        .unwrap();
        // A distinct project path avoids the cached answer from before the hook existed.
        assert!(!offer_pending(&eligible("/tmp/with-hook"), true, false));
    }

    #[test]
    fn only_a_path_assignment_overrides_the_host_path() {
        let entries = |list: &[&str]| list.iter().map(|e| e.to_string()).collect::<Vec<_>>();
        assert!(environment_sets_path(&entries(&[
            "FOO=1",
            "PATH=/opt/a:$PATH"
        ])));
        assert!(!environment_sets_path(&entries(&[
            "FOO=1", "PATHS=x", "PATH"
        ])));
    }

    #[test]
    fn busy_or_unresumable_rows_are_never_offered() {
        let mut inst = Instance::new("t", "/tmp");
        inst.status = Status::Running;
        assert!(!offer_pending(&inst, true, true));
        inst.status = Status::Idle;
        assert!(!offer_pending(&inst, false, true));
        // No `started_at`: the row predates v041 and has never launched since.
        assert!(!offer_pending(&inst, true, true));
    }
}
