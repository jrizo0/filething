//! `metrics` — minimal sync observability persisted per Space (`TODO.md` Fase B).
//!
//! [`SyncMetrics`] is a tiny counter set the [`run`](crate::SpaceContext::run)
//! loop maintains and snapshots to `<root>/.filething/metrics.json` after each
//! meaningful event, so a *separate* process (`filething metrics`) can read a
//! running daemon's activity without any IPC. It lives under the control dir
//! (which `scan` ignores) so it is never itself synced.
//!
//! It deliberately holds only cheap, human-paced counters — commits, pulls that
//! changed the tree, conflict copies, change-feed parse errors, staleness alerts
//! — plus a few timestamps. It is telemetry, never load-bearing for sync
//! correctness: a lost or corrupt file resets to zero and the daemon runs on.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::scan::CONTROL_DIR;

/// The metrics snapshot filename under the control dir.
const METRICS_FILE: &str = "metrics.json";

/// Per-Space sync counters + timestamps (unix seconds). Serialized to
/// `<root>/.filething/metrics.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMetrics {
    /// Revisions this daemon committed (real commits, not no-ops).
    pub commits: u64,
    /// Pulls that actually changed the local tree (fast-forward or reconcile).
    pub pulls_applied: u64,
    /// Conflict copies written across all reconciles.
    pub conflicts: u64,
    /// Change-feed errors observed: a pushed head value that failed to parse, or
    /// a feed-triggered pull that failed (a transient fault, e.g. mid
    /// auth-refresh/reconnect — issue #12). The `run` loop logs a `cause` field
    /// alongside each increment so the journal explains why the counter moved.
    pub feed_errors: u64,
    /// Times the head went unseen past the staleness threshold.
    pub stale_alerts: u64,
    /// When the current daemon run started (unix seconds).
    pub started_at: Option<u64>,
    /// Last time the head was confirmed (feed update or successful pull).
    pub last_head_seen: Option<u64>,
    /// Last successful commit (unix seconds).
    pub last_commit: Option<u64>,
    /// How many times this Space entered quarantine (a mount/run attempt failed
    /// and the daemon backed off before retrying, `docs/adr` "Space quarantine").
    /// `#[serde(default)]` so a metrics.json written before this field existed
    /// still loads (preserving the older counters) instead of resetting to zero.
    #[serde(default)]
    pub quarantines: u64,
    /// Whether the Space is CURRENTLY quarantined (its last attempt failed and it
    /// has not yet run healthily long enough to be considered recovered).
    #[serde(default)]
    pub quarantined: bool,
    /// When the Space most recently entered quarantine (unix seconds).
    #[serde(default)]
    pub last_quarantine: Option<u64>,
    /// The error that caused the most recent quarantine, for `filething metrics`.
    #[serde(default)]
    pub last_quarantine_error: Option<String>,
}

/// Current unix time in whole seconds (0 before the epoch, which never happens).
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl SyncMetrics {
    /// The metrics file path for the Space rooted at `root`.
    pub fn path(root: &Path) -> PathBuf {
        root.join(CONTROL_DIR).join(METRICS_FILE)
    }

    /// Loads the snapshot for `root`, or [`SyncMetrics::default`] if it is absent
    /// or unreadable (telemetry must never block a real operation).
    pub fn load(root: &Path) -> Self {
        match std::fs::read(Self::path(root)) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Best-effort persist of the snapshot next to the index. Errors are ignored:
    /// a failed metrics write must not surface as a sync error.
    pub fn save(&self, root: &Path) {
        let path = Self::path(root);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(path, bytes);
        }
    }

    /// Records the start of a daemon run (stamps `started_at`).
    pub fn mark_started(&mut self) {
        self.started_at = Some(now_secs());
    }

    /// Records a real commit.
    pub fn record_commit(&mut self) {
        self.commits += 1;
        self.last_commit = Some(now_secs());
    }

    /// Records that the head was confirmed (feed update or successful pull).
    pub fn record_head_seen(&mut self) {
        self.last_head_seen = Some(now_secs());
    }

    /// Records an applied pull and any conflict copies it produced.
    pub fn record_pull_applied(&mut self, conflicts: usize) {
        self.pulls_applied += 1;
        self.conflicts += conflicts as u64;
    }

    /// Records a change-feed error (a parse failure or a feed-triggered pull
    /// failure); the caller logs the specific `cause`.
    pub fn record_feed_error(&mut self) {
        self.feed_errors += 1;
    }

    /// Records a staleness alert (head unseen past the threshold).
    pub fn record_stale(&mut self) {
        self.stale_alerts += 1;
    }

    /// Records that the Space entered quarantine: a mount/run attempt failed and
    /// the daemon is backing off before retrying. Bumps the counter, flags the
    /// Space quarantined, and stamps the time + error for `filething metrics`.
    pub fn record_quarantine(&mut self, error: &str) {
        self.quarantines += 1;
        self.quarantined = true;
        self.last_quarantine = Some(now_secs());
        self.last_quarantine_error = Some(error.to_string());
    }

    /// Records that the Space left quarantine: a retry attempt ran healthily for
    /// long enough that the supervisor considers it recovered. Clears the
    /// `quarantined` flag; the historical `quarantines` count is left intact.
    pub fn record_quarantine_cleared(&mut self) {
        self.quarantined = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A metrics.json written before the quarantine fields existed must still
    /// load — preserving the older counters — instead of failing to deserialize
    /// (which `load` would swallow as `default()`, silently zeroing everything).
    /// The `#[serde(default)]` on the new fields is what makes this hold.
    #[test]
    fn old_format_metrics_json_loads_and_preserves_counters() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // An on-disk snapshot from before the quarantine fields were added.
        let legacy = r#"{
            "commits": 7,
            "pulls_applied": 3,
            "conflicts": 1,
            "feed_errors": 2,
            "stale_alerts": 0,
            "started_at": 1700000000,
            "last_head_seen": 1700000100,
            "last_commit": 1700000050
        }"#;
        std::fs::create_dir_all(SyncMetrics::path(root).parent().unwrap()).unwrap();
        std::fs::write(SyncMetrics::path(root), legacy).unwrap();

        let m = SyncMetrics::load(root);
        // Old counters survive (not reset to zero via unwrap_or_default).
        assert_eq!(m.commits, 7);
        assert_eq!(m.pulls_applied, 3);
        assert_eq!(m.conflicts, 1);
        assert_eq!(m.feed_errors, 2);
        assert_eq!(m.started_at, Some(1_700_000_000));
        assert_eq!(m.last_commit, Some(1_700_000_050));
        // New fields default cleanly.
        assert_eq!(m.quarantines, 0);
        assert!(!m.quarantined);
        assert_eq!(m.last_quarantine, None);
        assert_eq!(m.last_quarantine_error, None);
    }

    #[test]
    fn record_quarantine_sets_flag_count_and_error() {
        let mut m = SyncMetrics::default();
        m.record_quarantine("boom");
        assert_eq!(m.quarantines, 1);
        assert!(m.quarantined);
        assert_eq!(m.last_quarantine_error.as_deref(), Some("boom"));
        assert!(m.last_quarantine.is_some());
        m.record_quarantine("boom again");
        assert_eq!(m.quarantines, 2);
        m.record_quarantine_cleared();
        assert!(!m.quarantined);
        // History is retained after clearing.
        assert_eq!(m.quarantines, 2);
    }
}
