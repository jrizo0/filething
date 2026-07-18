//! `run` — the continuous bidirectional sync loop (`docs/format.md §8`, `§9`).
//!
//! [`SpaceContext::run`] is what makes the demo bidirectional (criteria a/b). It:
//!
//! - starts a [`Watcher`](ft_watcher::Watcher) over `local_root` and shares its
//!   [`AppliedState`] with this context (so [`pull`](SpaceContext::pull) marks
//!   every file it writes, `§9`);
//! - subscribes to the Space head (the change feed, `§8`);
//! - runs a [`startup_sync`](SpaceContext::startup_sync): an initial `pull` AND
//!   an initial `commit_and_reconcile`, so a Device that was edited (or had files
//!   deleted) while the daemon was down pushes those changes at mount, without
//!   waiting for the next FS event to arm the commit debounce (`§7`/`§9`);
//! - `select!`s between:
//!   - a watcher event → canonicalize, read the real `(mtime, pcid)`, and
//!     [`is_echo`](ft_watcher::is_echo). A NON-echo (a real user edit) arms a short
//!     debounce; when it fires, [`commit_and_reconcile`](SpaceContext::commit_and_reconcile)
//!     pushes the change (coalescing a burst into one commit);
//!   - a head update from the feed → [`pull`](SpaceContext::pull);
//!   - a periodic tick ([`FALLBACK_PULL_INTERVAL`]) → a backstop `pull` that
//!     recovers a feed gone silent on a flaky link;
//!   - `shutdown` resolving → a clean exit.
//!
//! The echo loop is broken structurally: applying from the feed marks the write,
//! so the watcher event it triggers is suppressed and never re-committed (`§9`).

use std::future::Future;
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};

use ft_watcher::{is_echo, ChangeEvent, ChangeKind, Watcher};
use futures::StreamExt;
use tokio::sync::mpsc as tokio_mpsc;

use crate::context::{join_canonical, SpaceContext};
use crate::error::{EngineError, Result};
use crate::metrics::SyncMetrics;
use crate::{CommitOutcome, PullOutcome};

/// How long to wait for the filesystem to go quiet before committing a burst of
/// edits as one Revision. Short enough to feel live, long enough to fold an
/// editor's save (write + rename + chmod) into a single commit.
const COMMIT_DEBOUNCE: Duration = Duration::from_millis(300);

/// How far out to re-arm the commit debounce after a commit FAILED, so the edit
/// is retried rather than dropped (issue #8: a transient commit error must not
/// tear the loop down). Longer than [`COMMIT_DEBOUNCE`] so a persistent fault
/// retries at a human pace instead of hot-looping.
const COMMIT_RETRY_BACKOFF: Duration = Duration::from_secs(10);

/// A safety-net interval for pulling the head even when the change feed is quiet.
///
/// The `head_stream` branch of the `select!` is normally the ONLY way remote
/// changes reach this Device after startup: the convex client reconnects and
/// re-subscribes on its own. But on a flaky link (unstable SSH tunnel / VPN) we
/// observed a daemon that kept committing yet went deaf to the feed
/// indefinitely — no error, just silence. A periodic pull is the backstop: it is
/// cheap when nothing moved (`read_head` sees the same root and `apply_head`
/// returns [`PullOutcome::UpToDate`](crate::PullOutcome) early, `pull.rs:143-150`),
/// and it recovers a stuck feed without a restart.
const FALLBACK_PULL_INTERVAL: Duration = Duration::from_secs(30);

/// How long the head may go unconfirmed — no feed update AND no successful
/// backstop pull — before the daemon logs a staleness alert (`TODO.md` Fase B,
/// "alerta si un daemon queda >N min sin ver el head"). ~10× the backstop
/// interval: a healthy Device confirms the head at least every 30s.
const STALE_HEAD_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// How often the watchdog checks head-staleness and emits a metrics heartbeat.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(60);

impl SpaceContext {
    /// Runs the continuous sync loop until `shutdown` resolves (`§8`/`§9`).
    ///
    /// Requires a Coordinator (it subscribes to the head and commits). Runs
    /// [`startup_sync`](SpaceContext::startup_sync) once — an initial pull AND an
    /// initial commit, so offline edits/deletes are pushed at mount without
    /// waiting for the next FS event — then loops watcher-events ↔ feed-updates ↔
    /// a [`FALLBACK_PULL_INTERVAL`] backstop pull ↔ shutdown. See the module docs.
    pub async fn run(&mut self, shutdown: impl Future<Output = ()>) -> Result<()> {
        // Start the watcher; share its echo-suppression marks with this context so
        // pull() can mark every file it writes (§9).
        let (fs_tx, fs_rx) = std_mpsc::channel::<ChangeEvent>();
        let watcher = Watcher::new(self.local_root.clone(), fs_tx)?;
        self.attach_applied_state(watcher.applied_state());

        // Bridge the watcher's std mpsc into a tokio channel via a blocking task,
        // so the select! below can await events. The task ends when the watcher
        // (and thus fs_tx) is dropped.
        let (ev_tx, mut ev_rx) = tokio_mpsc::unbounded_channel::<ChangeEvent>();
        let bridge = tokio::task::spawn_blocking(move || {
            while let Ok(ev) = fs_rx.recv() {
                if ev_tx.send(ev).is_err() {
                    break;
                }
            }
        });

        // Subscribe to the head on a CLONE of the coordinator (it multiplexes one
        // WebSocket), leaving self.coordinator free for commits/pulls. The clone
        // and the stream it produces both live on this stack frame for the whole
        // loop: `subscribe_head` returns a stream that borrows the coordinator, so
        // `head_coord` must outlive `head_stream` (and is never touched again).
        let space_id = self.space_id.clone();
        let mut head_coord = self.coordinator.clone().ok_or_else(|| {
            crate::error::EngineError::SpaceState("run requires a Coordinator".to_string())
        })?;
        let head_stream = head_coord.subscribe_head(&space_id).await?;
        tokio::pin!(head_stream);

        // Observability (Fase B): a per-Space counter set persisted under the
        // control dir so `filething metrics` can read this daemon's activity. It
        // is telemetry only — a failed write never disturbs sync.
        let mut metrics = SyncMetrics::load(&self.local_root);
        metrics.mark_started();
        metrics.save(&self.local_root);
        // Head-staleness watchdog state: when the head was last confirmed (feed
        // update OR a successful pull), and whether we have already alerted for
        // the current stale episode (so we warn once, not every tick).
        let mut last_head_seen = Instant::now();
        let mut stale_alerted = false;
        // The last metrics snapshot the heartbeat logged at `info`. The periodic
        // "sync metrics" line only rises to `info` when a counter changed since
        // then; an idle Space demotes it to `debug` so a healthy daemon stops
        // writing one line per Space per minute forever (GitHub #22).
        let mut last_logged_metrics: Option<(u64, u64, u64, u64, u64)> = None;

        // Initial catch-up so a freshly mounted Device is current before watching:
        // pull the head AND commit any local edits/deletes made while the daemon
        // was down (§7/§9).
        let (startup_pull, startup_retry_conflicts) = self.startup_sync().await?;
        // The startup pull is a pull like any other: FastForwarded/Reconciled
        // count as pulls_applied (+ conflicts); the commit-retry conflict copies
        // count as conflicts only.
        record_pull_outcome(startup_pull, &mut metrics);
        metrics.record_conflicts(startup_retry_conflicts.len());
        metrics.record_head_seen();
        metrics.save(&self.local_root);

        tokio::pin!(shutdown);
        let mut dirty = false;
        // A debounce timer that is only polled while `dirty`.
        let debounce = tokio::time::sleep(COMMIT_DEBOUNCE);
        tokio::pin!(debounce);

        // The backstop pull timer. `interval_at` with a first tick one PERIOD out
        // (not the immediate default) so the loop's first fallback pull waits a
        // full interval — the startup_sync above already brought us current. Delay
        // (not Burst) skipped ticks: a slow pull must not queue a thundering herd.
        let mut fallback = tokio::time::interval_at(
            tokio::time::Instant::now() + FALLBACK_PULL_INTERVAL,
            FALLBACK_PULL_INTERVAL,
        );
        fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // The watchdog + heartbeat timer.
        let mut watchdog = tokio::time::interval_at(
            tokio::time::Instant::now() + WATCHDOG_INTERVAL,
            WATCHDOG_INTERVAL,
        );
        watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // (c) shutdown -> clean exit.
                _ = &mut shutdown => break,

                // (a) a filesystem event from the watcher.
                Some(event) = ev_rx.recv() => {
                    if self.is_user_change(&event) {
                        dirty = true;
                        // (Re)arm the debounce window.
                        debounce
                            .as_mut()
                            .reset(tokio::time::Instant::now() + COMMIT_DEBOUNCE);
                    }
                }

                // (b) the Space head moved -> pull (diff + apply, with echo marks).
                Some(update) = head_stream.next() => {
                    // A parse error on one pushed value is logged, not fatal.
                    match update {
                        Ok(_) => {
                            // The feed-triggered pull is NOT fatal on error, for
                            // the same reason as the backstop below: a transient
                            // fault (e.g. a Coordinator round-trip that lands mid
                            // auth-refresh/reconnect, issue #12) must not kill the
                            // daemon. Log with the cause, count it, and let the
                            // next feed item or backstop tick retry. (A structural
                            // failure at loop STARTUP — watcher, subscribe, initial
                            // sync — still propagates: the daemon's supervisor
                            // quarantines that Space and retries with backoff,
                            // issue #8.)
                            //
                            // The head is only confirmed AFTER a successful pull:
                            // a pull that fails permanently (Space deleted, auth
                            // revoked) must keep the staleness watchdog armed —
                            // a live feed alone must not mask it forever.
                            match self.pull().await {
                                Ok(outcome) => {
                                    last_head_seen = Instant::now();
                                    stale_alerted = false;
                                    metrics.record_head_seen();
                                    record_pull_outcome(outcome, &mut metrics);
                                }
                                Err(e) => {
                                    log_pull_error(&e, "feed_pull");
                                    metrics.record_feed_error();
                                }
                            }
                            metrics.save(&self.local_root);
                        }
                        Err(e) => {
                            tracing::warn!(
                                cause = "head_feed_parse",
                                error = %e,
                                "feed error: a pushed head value did not parse"
                            );
                            metrics.record_feed_error();
                            metrics.save(&self.local_root);
                        }
                    }
                }

                // Backstop: pull on a timer in case the feed died silently on a
                // flaky link (FALLBACK_PULL_INTERVAL). Cheap when the head has not
                // moved (apply_head short-circuits to UpToDate). Unlike the feed
                // branch (which only runs while connected), this timer also fires
                // mid-outage — so a transient failure here is EXPECTED and must not
                // kill the daemon; warn and let the next tick retry. A persistent
                // fault stays visible as a warning every interval.
                _ = fallback.tick() => {
                    match self.pull().await {
                        Ok(outcome) => {
                            // A successful backstop pull confirms the head is
                            // reachable even when the feed is silent.
                            last_head_seen = Instant::now();
                            stale_alerted = false;
                            metrics.record_head_seen();
                            record_pull_outcome(outcome, &mut metrics);
                            metrics.save(&self.local_root);
                        }
                        Err(e) => {
                            log_pull_error(&e, "backstop_pull");
                        }
                    }
                }

                // Debounce fired: if there were real edits, commit them as one.
                _ = &mut debounce, if dirty => {
                    dirty = false;
                    // A commit can fail transiently (a mid-flight Vault/Coordinator
                    // hiccup, an exhausted CAS retry). Don't tear the loop down
                    // (issue #8): warn, mark the tree dirty again, and re-arm the
                    // debounce further out so the edit is retried, not dropped.
                    match self.commit_and_reconcile().await {
                        Ok((outcome, conflicts)) => {
                            if let CommitOutcome::Committed { .. } = outcome {
                                metrics.record_commit();
                            }
                            // A concurrent edit surfaces here as a CAS conflict
                            // whose retry pull reconciles and writes conflict copies
                            // (issue #9): count them even when this branch (not the
                            // feed) drove the reconcile.
                            metrics.record_conflicts(conflicts.len());
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "commit failed; retrying shortly");
                            dirty = true;
                            debounce
                                .as_mut()
                                .reset(tokio::time::Instant::now() + COMMIT_RETRY_BACKOFF);
                        }
                    }
                    metrics.save(&self.local_root);
                }

                // Watchdog + heartbeat: alert once if the head has gone unseen past
                // the threshold, and log a periodic metrics line either way.
                _ = watchdog.tick() => {
                    if last_head_seen.elapsed() > STALE_HEAD_THRESHOLD && !stale_alerted {
                        tracing::warn!(
                            cause = "head_unseen",
                            space = %self.space_id,
                            unseen_secs = last_head_seen.elapsed().as_secs(),
                            "stale alert: head not confirmed past staleness threshold — no feed \
                             update and no successful backstop pull (feed silent, or the \
                             connection is down / re-authenticating)"
                        );
                        metrics.record_stale();
                        stale_alerted = true;
                    }
                    // Log at `info` only when something moved since the last
                    // heartbeat; otherwise demote to `debug` so RUST_LOG=debug
                    // still sees it but a steady-state daemon does not spam the
                    // log with an unchanging line every interval.
                    let snapshot = (
                        metrics.commits,
                        metrics.pulls_applied,
                        metrics.conflicts,
                        metrics.feed_errors,
                        metrics.stale_alerts,
                    );
                    if last_logged_metrics != Some(snapshot) {
                        tracing::info!(
                            space = %self.space_id,
                            commits = metrics.commits,
                            pulls = metrics.pulls_applied,
                            conflicts = metrics.conflicts,
                            feed_errors = metrics.feed_errors,
                            stale_alerts = metrics.stale_alerts,
                            "sync metrics"
                        );
                        last_logged_metrics = Some(snapshot);
                    } else {
                        tracing::debug!(
                            space = %self.space_id,
                            commits = metrics.commits,
                            pulls = metrics.pulls_applied,
                            conflicts = metrics.conflicts,
                            feed_errors = metrics.feed_errors,
                            stale_alerts = metrics.stale_alerts,
                            "sync metrics"
                        );
                    }
                    metrics.save(&self.local_root);
                }
            }
        }

        // Persist a final snapshot on clean shutdown.
        metrics.save(&self.local_root);
        drop(bridge);
        Ok(())
    }

    /// The startup catch-up the [`run`](SpaceContext::run) loop performs once
    /// before watching: pull the head, THEN commit any local changes (`§7`/`§9`).
    ///
    /// The initial pull alone (the old behavior) left a gap: edits or deletes made
    /// on disk while the daemon was DOWN were never pushed until some later FS
    /// event happened to arm the commit debounce — a file deleted offline could
    /// sit uncommitted indefinitely. Committing here closes that gap.
    ///
    /// The commit is cheap when there is nothing to push: with no local change the
    /// scanned `manifestRoot` equals `last_synced.root`, so `commit` returns
    /// [`CommitOutcome::NoChange`](crate::CommitOutcome) after only a scan + a pure
    /// `ft_manifest::build`, touching neither the Vault nor the Coordinator
    /// (`commit.rs:94-96`: `if self.last_synced.seq >= 0 && root ==
    /// self.last_synced.root { return Ok(CommitOutcome::NoChange); }`).
    ///
    /// Split out of `run` so the arrival-time behavior is testable offline (the
    /// full loop needs a live head subscription; this needs only a Coordinator for
    /// the commit path). Order matters: pull first so the commit's `expected_base`
    /// reflects the current head and a first commit reconciles instead of looping.
    ///
    /// Returns the initial catch-up pull's [`PullOutcome`] — so the caller can
    /// fold it into [`SyncMetrics`](crate::SyncMetrics) with the SAME semantics as
    /// any other pull (a startup fast-forward or reconcile counts as
    /// `pulls_applied`, and a reconcile's conflict copies count as `conflicts`,
    /// issue #9) — plus the conflict-copy paths written by the reconciling retries
    /// inside [`commit_and_reconcile`](SpaceContext::commit_and_reconcile), which
    /// are counted as conflicts only (their enclosing commit is the accounted
    /// event; see [`SyncMetrics::record_conflicts`](crate::SyncMetrics::record_conflicts)).
    pub async fn startup_sync(&mut self) -> Result<(PullOutcome, Vec<String>)> {
        let outcome = self.pull().await?;
        let (_committed, retry_conflicts) = self.commit_and_reconcile().await?;
        Ok((outcome, retry_conflicts))
    }

    /// Decides whether a watcher [`ChangeEvent`] is a genuine user change (vs our
    /// own write echoing back, `§9`). For a created/modified file it canonicalizes
    /// the path, reads the real `(mtime, pcid)` and consults
    /// [`is_echo`](ft_watcher::is_echo); a removal (no `pcid`) is always treated as
    /// a real change (a later commit reconciles it to the head, never looping).
    /// Paths outside the Space, the control dir, or non-canonicalizable paths are
    /// ignored.
    fn is_user_change(&self, event: &ChangeEvent) -> bool {
        // Canonicalize the absolute path against the Space root; ignore anything
        // that escapes the root or the control directory.
        let canonical = match ft_fsmap::canonicalize(&self.local_root, &event.path) {
            Ok(c) => c,
            Err(_) => return false,
        };
        if canonical.as_str().is_empty()
            || canonical.as_str() == crate::scan::CONTROL_DIR
            || canonical
                .as_str()
                .starts_with(&format!("{}/", crate::scan::CONTROL_DIR))
        {
            return false;
        }

        match event.kind {
            ChangeKind::Removed => true, // no pcid to match; commit reconciles it.
            ChangeKind::Created | ChangeKind::Modified => {
                let Some(applied) = &self.applied else {
                    return true; // no echo state: treat every event as a change.
                };
                let abs = join_canonical(&self.local_root, &canonical);
                let Ok(meta) = std::fs::symlink_metadata(&abs) else {
                    return true; // vanished mid-flight: let the commit sort it out.
                };
                if meta.is_dir() {
                    // Directories are first-class entries now (ADR 0019), so a
                    // freshly CREATED directory — which may be empty and thus have
                    // no child file events to arm a commit — must arm one itself. A
                    // MODIFIED dir event is only a mtime bump from child activity
                    // that already fires its own events, so it is ignored to avoid
                    // redundant scans. There is no content pcid to echo-check; a
                    // commit armed by our own just-pulled dir simply finds NoChange.
                    return matches!(event.kind, ChangeKind::Created);
                }
                let mtime = self
                    .fs
                    .real_mtime(&abs)
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let pcid = match std::fs::read(&abs) {
                    Ok(bytes) => ft_hash::pcid_of(&bytes),
                    Err(_) => return true,
                };
                // is_echo consumes a matching mark and returns true; a real edit
                // returns false and is committed.
                !is_echo(applied, &canonical, mtime, &pcid)
            }
        }
    }
}

/// True when a pull failure is permanent — the Coordinator answered with a
/// typed "this will never work" code (issue #11): the Space is gone, this
/// Account does not own it, or the Device's auth is no good. Retrying cannot
/// fix these; everything else (transport, Vault hiccups, unknown codes) is
/// treated as transient and retried by the next feed item / backstop tick.
fn is_permanent_pull_error(e: &EngineError) -> bool {
    matches!(
        e,
        EngineError::Coordinator(
            ft_coordinator::CoordinatorError::SpaceNotFound { .. }
                | ft_coordinator::CoordinatorError::NotAuthorized { .. }
                | ft_coordinator::CoordinatorError::NotAuthenticated { .. }
        )
    )
}

/// Logs a non-fatal pull failure with a machine-stable `cause` so a bump of
/// `feed_errors` in the metrics line is correlatable with WHY (issue #12).
/// Permanent faults escalate to ERROR with a `<cause>_permanent` cause; they
/// will re-fire every feed item / backstop tick until an operator acts.
fn log_pull_error(e: &EngineError, cause: &'static str) {
    if is_permanent_pull_error(e) {
        tracing::error!(
            cause = format!("{cause}_permanent").as_str(),
            error = %e,
            "pull failed with a permanent fault (Space deleted, access revoked, or \
             session invalid); retries cannot fix this — re-check the Space and \
             `filething login`"
        );
    } else {
        tracing::warn!(
            cause = cause,
            error = %e,
            "pull failed (transient); retrying on the next feed item or backstop tick"
        );
    }
}

/// Folds a [`PullOutcome`] into the [`SyncMetrics`] counters: an applied
/// fast-forward or reconcile bumps `pulls_applied` (and adds any conflict
/// copies); an up-to-date pull is not counted.
fn record_pull_outcome(outcome: PullOutcome, metrics: &mut SyncMetrics) {
    match outcome {
        PullOutcome::UpToDate => {}
        PullOutcome::FastForwarded { applied } if applied > 0 => metrics.record_pull_applied(0),
        PullOutcome::FastForwarded { .. } => {}
        PullOutcome::Reconciled { conflicts } => metrics.record_pull_applied(conflicts.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The metrics-folding contract behind issue #9. The end-to-end
    /// commit→CAS-conflict→reconcile→retry path needs a live Coordinator (no
    /// offline double exists), so it is exercised by the `#[ignore]`d multi-device
    /// test `commit_retry_reconcile_conflicts_are_counted` in `tests/two_devices.rs`.
    /// This locks the layer that regressed: a reconcile's conflict copies must
    /// reach `SyncMetrics.conflicts` no matter which branch drove the reconcile.

    #[test]
    fn feed_branch_reconcile_counts_pull_and_conflicts() {
        let mut m = SyncMetrics::default();
        record_pull_outcome(
            PullOutcome::Reconciled {
                conflicts: vec!["a (conflicto devX, seq 0).txt".to_string()],
            },
            &mut m,
        );
        assert_eq!(m.pulls_applied, 1, "a reconcile is an applied pull");
        assert_eq!(m.conflicts, 1, "its conflict copy is counted");
    }

    #[test]
    fn commit_retry_conflicts_are_counted_without_a_pull() {
        // The exact shape of the bug: the debounce/startup path records the commit
        // but the reconcile happened inside commit_and_reconcile's retry. Recording
        // the commit alone must leave `conflicts` at 0; folding the returned
        // conflict copies is what fixes it — and it must NOT inflate pulls_applied.
        let mut m = SyncMetrics::default();
        m.record_commit();
        assert_eq!(m.conflicts, 0, "a commit by itself records no conflict");

        // Two conflict copies came back from the retry pulls.
        m.record_conflicts(2);
        assert_eq!(m.conflicts, 2, "retry-pull conflicts must be counted");
        assert_eq!(
            m.pulls_applied, 0,
            "commit-retry pulls do not count as pulls_applied"
        );
    }

    #[test]
    fn up_to_date_and_ff_without_changes_count_nothing() {
        let mut m = SyncMetrics::default();
        record_pull_outcome(PullOutcome::UpToDate, &mut m);
        record_pull_outcome(PullOutcome::FastForwarded { applied: 0 }, &mut m);
        assert_eq!(m, SyncMetrics::default());
    }

    #[test]
    fn permanent_pull_errors_are_the_typed_never_recoverable_codes() {
        for e in [
            ft_coordinator::CoordinatorError::SpaceNotFound {
                message: "gone".into(),
            },
            ft_coordinator::CoordinatorError::NotAuthorized {
                message: "not yours".into(),
            },
            ft_coordinator::CoordinatorError::NotAuthenticated {
                message: "expired".into(),
            },
        ] {
            assert!(is_permanent_pull_error(&EngineError::Coordinator(e)));
        }
    }

    #[test]
    fn transient_pull_errors_stay_transient() {
        // Transport blips, Vault hiccups and unknown codes must keep the
        // warn-and-retry path (issue #12: an auth refresh mid-flight looks
        // like transport, and MUST not be treated as fatal or permanent).
        for e in [
            ft_coordinator::CoordinatorError::Transport("ws closed".into()),
            ft_coordinator::CoordinatorError::VaultUnavailable {
                message: "sign failed".into(),
            },
            ft_coordinator::CoordinatorError::Function("Server Error".into()),
        ] {
            assert!(!is_permanent_pull_error(&EngineError::Coordinator(e)));
        }
    }
}
