//! Detects a running agent whose binary was replaced on disk after it launched.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};

use crate::session::{Instance, Status};

const MTIME_TTL: Duration = Duration::from_secs(30);

/// Bounded by the number of distinct agent binaries.
static MTIME_CACHE: Mutex<Option<HashMap<String, (Instant, Option<SystemTime>)>>> =
    Mutex::new(None);

/// The binary whose replacement makes this session stale, or `None` when it cannot be named
/// safely (custom agents, command overrides that carry arguments).
fn agent_binary(inst: &Instance) -> Option<&str> {
    if inst.command.is_empty() {
        crate::agents::get_agent(&inst.tool).map(|a| a.binary)
    } else if !inst.is_structured() && !inst.command.contains(char::is_whitespace) {
        Some(&inst.command)
    } else {
        None
    }
}

fn binary_mtime(binary: &str) -> Option<SystemTime> {
    let mut guard = MTIME_CACHE.lock().ok()?;
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some((at, mtime)) = cache.get(binary) {
        if at.elapsed() < MTIME_TTL {
            return *mtime;
        }
    }
    let mtime = which::which(binary)
        .and_then(|path| std::fs::metadata(path).map_err(|_| which::Error::CannotFindBinaryPath))
        .ok()
        .and_then(|m| m.modified().ok());
    cache.insert(binary.to_string(), (Instant::now(), mtime));
    mtime
}

/// Whole seconds, so a binary written in the launch second is not flagged.
fn modified_after(mtime: SystemTime, started_at: DateTime<Utc>) -> bool {
    let modified = mtime.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    modified as i64 > started_at.timestamp()
}

/// When the process this row is running was launched.
fn process_started_at(inst: &Instance) -> Option<DateTime<Utc>> {
    if inst.is_structured() {
        let record = crate::process::worker_registry::load(&inst.id)
            .ok()
            .flatten()?;
        DateTime::from_timestamp(i64::try_from(record.started_at).ok()?, 0)
    } else {
        inst.started_at
    }
}

/// An idle row whose agent binary was replaced after launch. Reads only the row and the
/// filesystem, so it is safe to call while painting.
pub fn binary_updated(inst: &Instance) -> bool {
    if inst.status != Status::Idle || inst.is_archived() || inst.is_trashed() {
        return false;
    }
    let Some(binary) = agent_binary(inst) else {
        return false;
    };
    match (process_started_at(inst), binary_mtime(binary)) {
        (Some(started_at), Some(mtime)) => modified_after(mtime, started_at),
        _ => false,
    }
}

/// Whether to offer "restart to apply update". `resume_available` is the row's
/// `ContextResumeAvailability::Available`; `structured_ready` is a running worker with no pending
/// approvals. The restart must keep the conversation, so every gate fails closed.
pub fn offer_pending(inst: &Instance, resume_available: bool, structured_ready: bool) -> bool {
    inst.queued_prompts.is_empty()
        && resume_available
        && (!inst.is_structured() || structured_ready)
        && binary_updated(inst)
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
