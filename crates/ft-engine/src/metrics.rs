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
}
