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
//!   - a watcher event → canonicalize and decide whether it is a real user edit
//!     ([`is_user_change`](SpaceContext::is_user_change), which consults
//!     [`is_echo`](ft_watcher::is_echo)). A NON-echo (a real user edit) arms a short
//!     debounce; when it fires, [`commit_and_reconcile`](SpaceContext::commit_and_reconcile)
//!     pushes the change (coalescing a burst into one commit);
//!   - a head update from the feed → [`pull`](SpaceContext::pull);
//!   - a periodic tick ([`FALLBACK_PULL_INTERVAL`]) → a backstop `pull` that
//!     recovers a feed gone silent on a flaky link;
//!   - a watchdog tick ([`WATCHDOG_INTERVAL`]) → head-staleness alert, watch
//!     liveness ([`watch_tick`]) and a metrics heartbeat;
//!   - `shutdown` resolving → a clean exit.
//!
//! The echo loop is broken structurally: applying from the feed marks the write,
//! so the watcher event it triggers is suppressed and never re-committed (`§9`).
//!
//! ## Failing loudly vs. retrying forever
//!
//! A transient fault must not tear the loop down (issue #8), but a PERMANENT one
//! must not be retried forever either: a Space deleted remotely, an invalid session
//! or a safety guard that refuses this tree fails identically on every attempt,
//! burning API quota and drowning the log. Those propagate out of `run` so the
//! Daemon's supervisor quarantines *that* Space — capped exponential backoff, plus a
//! reason the user can read in `filething metrics` (`ft-daemon`, issue #8).
//! Everything else is retried in place, with the commit path backing off up to
//! [`COMMIT_RETRY_MAX_BACKOFF`].

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

/// Ceiling for the commit-retry backoff, which DOUBLES on each consecutive failure.
///
/// A fault that is not provably permanent can still be long-lived (a Vault
/// answering 500 for an hour, a link that is down). Retrying such a commit every
/// [`COMMIT_RETRY_BACKOFF`] forever burns API quota and writes one identical
/// warning per interval into the journal; doubling up to this cap keeps a wedged
/// Space retrying at a human pace while a genuine blip still recovers on the first
/// retry. Matches `ft-daemon`'s own quarantine ceiling so a wedged Space retries at
/// the same rate whichever layer noticed.
const COMMIT_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);

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
        // `mut` because the watchdog RE-ARMS the watch when it dies (see the
        // WATCHDOG_INTERVAL branch): `Watcher::rewatch` takes `&mut self`.
        let (fs_tx, fs_rx) = std_mpsc::channel::<ChangeEvent>();
        let mut watcher = Watcher::new(self.local_root.clone(), fs_tx)?;
        self.attach_applied_state(watcher.applied_state());
        // Watch liveness, shared with the watcher's notify callback: backend errors
        // are RECORDED there, and this is the only place they can be observed
        // (`ft_watcher::WatchHealth`).
        let watch_health = watcher.health();

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
        // Watch-liveness watchdog state: whether we are inside an episode of "the
        // watch is dead and could not be re-armed" (so the incident is recorded
        // ONCE, not once per tick), and how many backend errors we have already
        // reported.
        let mut watch_degraded = false;
        let mut watch_errors_reported = watch_health.errors();
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
        // How far out the NEXT failed commit re-arms the debounce: doubles per
        // consecutive failure, capped at COMMIT_RETRY_MAX_BACKOFF, reset by a
        // commit that succeeds.
        let mut commit_backoff = COMMIT_RETRY_BACKOFF;
        // Set when the loop must end because the fault will repeat identically:
        // returned to the Daemon's supervisor, which quarantines this Space (see
        // the module docs). Held rather than returned on the spot so the exit path
        // still persists the final metrics snapshot the supervisor reads.
        let mut fatal: Option<EngineError> = None;

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
                    if self.is_user_change(&event).await {
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
                                    // A permanent fault (Space deleted, access
                                    // revoked, session invalid) answers every feed
                                    // item and every backstop tick with the SAME
                                    // error, forever. Hand it to the supervisor
                                    // instead: quarantine is where a broken Space
                                    // belongs (capped backoff + a reason in
                                    // `filething metrics`), and its retry re-mounts
                                    // from scratch, which is the only thing that can
                                    // pick up a fresh `filething login`.
                                    if is_permanent_pull_error(&e) {
                                        fatal = Some(e);
                                        metrics.save(&self.local_root);
                                        break;
                                    }
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
                            // Same reasoning as the feed branch: a permanent fault
                            // re-fires every interval until an operator acts, so it
                            // belongs in quarantine, not in this loop.
                            if is_permanent_pull_error(&e) {
                                fatal = Some(e);
                                break;
                            }
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
                            commit_backoff = COMMIT_RETRY_BACKOFF;
                        }
                        // A commit that cannot succeed on ANY retry — the Space is
                        // gone, the session is invalid, or a safety guard refused
                        // this tree (and will refuse the identical tree next time).
                        // Re-arming the debounce would repeat it every backoff
                        // window forever, so quarantine it: that is what surfaces
                        // the reason in `filething metrics` instead of burying it in
                        // a warning nobody greps.
                        Err(e) if is_permanent_commit_error(&e) => {
                            fatal = Some(e);
                            metrics.save(&self.local_root);
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                retry_in_secs = commit_backoff.as_secs(),
                                "commit failed; retrying with backoff"
                            );
                            dirty = true;
                            debounce
                                .as_mut()
                                .reset(tokio::time::Instant::now() + commit_backoff);
                            // Escalate for the NEXT failure: a fault that outlives
                            // one retry is not a blip.
                            commit_backoff = escalated(commit_backoff);
                        }
                    }
                    metrics.save(&self.local_root);
                }

                // Watchdog + heartbeat: alert once if the head has gone unseen past
                // the threshold, re-arm a dead filesystem watch, and log a periodic
                // metrics line either way.
                _ = watchdog.tick() => {
                    // Watch liveness (`§9`). The commit debounce is armed ONLY by
                    // watcher events, so a watch that stopped delivering means local
                    // edits never leave this Device again — silently, while `status`
                    // and `metrics` still look green. One re-arm attempt per tick is
                    // the rate limit: a root that is simply not there (an unmounted
                    // volume) must not spin.
                    let healthy = watcher.is_healthy();
                    match watch_tick(healthy, || watcher.rewatch()) {
                        WatchTick::Healthy => {}
                        WatchTick::Rearmed => {
                            tracing::warn!(
                                cause = "watch_rearmed",
                                space = %self.space_id,
                                "the filesystem watch had stopped covering the Space root (deleted, \
                                 moved, or replaced) and was re-armed; committing a full scan"
                            );
                            // LOAD-BEARING: everything edited during the blind window
                            // produced no event, so a plain re-arm alone still loses
                            // those edits. Arming the debounce runs
                            // commit_and_reconcile, whose scan sees the whole tree.
                            dirty = true;
                            debounce
                                .as_mut()
                                .reset(tokio::time::Instant::now() + COMMIT_DEBOUNCE);
                            if watch_degraded {
                                watch_degraded = false;
                                metrics.record_quarantine_cleared();
                                tracing::info!(
                                    space = %self.space_id,
                                    "filesystem watch recovered; local edits are being committed again"
                                );
                            }
                        }
                        WatchTick::RearmFailed(e) => {
                            tracing::warn!(
                                cause = "watch_lost",
                                space = %self.space_id,
                                error = %e,
                                "watch re-arm failed; retrying next tick"
                            );
                            // Never silently green: while there is no watch, nothing
                            // the user edits here is committed. `SyncMetrics` has no
                            // watch-health field of its own yet, so the degradation
                            // is reported through the one channel `filething metrics`
                            // already renders — once per episode, so the counter
                            // stays a count of incidents rather than of ticks.
                            if !watch_degraded {
                                watch_degraded = true;
                                metrics.record_quarantine(&format!(
                                    "filesystem watch lost for {} and re-arming failed ({e}); \
                                     local edits are NOT being committed until the Space root is \
                                     back",
                                    self.local_root.display()
                                ));
                            }
                        }
                    }
                    // Backend errors are a WEAKER signal than a lost root: notify
                    // reports them per subtree (`MaxFilesWatch` = the inotify budget
                    // is exhausted), so they do not justify re-arming the whole
                    // recursive watch — but they must not stay buried in the callback
                    // either, because part of the tree may have stopped being watched.
                    let watch_errors = watch_health.errors();
                    if watch_errors > watch_errors_reported {
                        tracing::warn!(
                            cause = "watch_backend_error",
                            space = %self.space_id,
                            errors = watch_errors,
                            error = %watch_health.last_error().unwrap_or_default(),
                            "the filesystem watch reported backend errors; part of the tree may no \
                             longer be watched (inotify limits?)"
                        );
                        watch_errors_reported = watch_errors;
                    }

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
        match fatal {
            // The Daemon's supervisor turns this into a quarantine: logged with the
            // cause, recorded in `SyncMetrics`, retried with capped backoff, and
            // never fatal to the sibling Spaces (`ft-daemon`, issue #8).
            Some(e) => Err(e),
            None => Ok(()),
        }
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
    /// the path and consults [`is_echo`](ft_watcher::is_echo) — but only after the
    /// cheap checks below have failed to answer, because the hash `is_echo` needs
    /// costs a full read of the file. A removal (no `pcid`) is always treated as a
    /// real change (a later commit reconciles it to the head, never looping). Paths
    /// outside the Space, the control dir, an apply's scratch files, or
    /// non-canonicalizable paths are ignored.
    ///
    /// COST, not just correctness: this runs inside the `select!` of the ONE task
    /// that drives every Space, and a single large copy fans out one forwarded
    /// `Modified` event per few MiB. Reading + hashing the whole file on each of them
    /// turned a 2 GiB copy into ~200 full-file reads while every other Space waited
    /// (the head-staleness watchdog could trip). So the answer is short-circuited in
    /// order of cost: no marks at all ⇒ no echo is possible; a `(size, mtime)` that
    /// no longer matches the index row ⇒ the file changed; only then the hash, and
    /// that runs off this task.
    async fn is_user_change(&self, event: &ChangeEvent) -> bool {
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
        // An apply's own scratch file is never a user change: `ft_diff::materialize`
        // writes `.<file>.ft-tmp` and renames it away (`§8.4`), and the echo mark
        // belongs to the PUBLISHED path — so these events sail past echo suppression
        // and make every pull arm a pointless commit round.
        if is_apply_tmp(&canonical) {
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
                // `is_echo` returns false whenever the path carries no mark, and only
                // `pull` records marks — so with NOTHING marked the answer is already
                // known and the read is pure waste. This is the overwhelmingly common
                // case on a Device the user is actively writing to. Deliberately
                // AFTER the dir rule above, which must keep applying: a `Modified`
                // dir event is just a child's mtime bump and arming a commit for it
                // would undo a deliberate saving.
                if applied.is_empty() {
                    return true;
                }
                let mtime = self
                    .fs
                    .real_mtime(&abs)
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                // A file whose `(size, mtime)` no longer match its index row HAS
                // changed: `pull` writes the row and the mark from the same stat, and
                // `is_echo` demands the mark's exact `(mtime, pcid)`, so a mismatch
                // cannot be an echo whatever the bytes hash to. This is what keeps a
                // multi-GiB copy from being re-read once per forwarded event while an
                // unrelated pull's marks are still outstanding — Dir/Symlink marks are
                // never consumed and live for the whole `MARK_TTL`.
                if !self.stat_matches_index(&canonical, meta.len(), mtime) {
                    return true;
                }
                // Only here — a mark outstanding AND the file still looking exactly
                // like what we last wrote — is the hash worth its cost.
                let Some(pcid) = pcid_off_task(abs).await else {
                    return true; // unreadable mid-flight: let the commit sort it out.
                };
                // is_echo consumes a matching mark and returns true; a real edit
                // returns false and is committed.
                !is_echo(applied, &canonical, mtime, &pcid)
            }
        }
    }

    /// Whether the local index still describes the file on disk at `path`: same
    /// size, same whole-second mtime.
    ///
    /// Used ONLY as a negative filter for echo suppression: a mismatch proves the
    /// file changed. A match is never taken as proof that the content is unchanged —
    /// `local_entry.mtime` is whole seconds (`§9`), so a same-size edit inside that
    /// second matches too, which is why the hash stays the authority (the same
    /// residual window `scan.rs`'s `reuse_unchanged` documents). Erring towards "it
    /// changed" costs one commit whose scan finds `NoChange`; erring the other way
    /// would drop a user edit.
    fn stat_matches_index(&self, path: &ft_core::CanonicalPath, size: u64, mtime: i64) -> bool {
        match self.index.get_entry(self.space_id.as_str(), path) {
            Ok(Some(row)) => row.size == size && row.mtime == mtime,
            // No row (a path we never recorded) or an index we could not read:
            // nothing here says this event is our own write.
            _ => false,
        }
    }
}

/// Whether `path`'s last component is a scratch file written by an apply, i.e.
/// `.<file_name><TMP_SUFFIX>` (`ft_diff::materialize`, `§8.4`).
///
/// Matched on the exact shape ft-diff mints — leading dot AND the suffix — via the
/// public const, so the two can never drift apart.
fn is_apply_tmp(path: &ft_core::CanonicalPath) -> bool {
    let name = path.as_str().rsplit('/').next().unwrap_or_default();
    name.starts_with('.') && name.ends_with(ft_diff::TMP_SUFFIX)
}

/// Hashes the file at `abs` into its whole-file `pcid` on the blocking pool.
///
/// Off-task because the daemon drives EVERY Space of the Device on ONE task (the
/// `run` future is `!Send`, so `ft-daemon` multiplexes the Spaces with `join_all`
/// rather than `tokio::spawn`): hashing inline blocks every sibling Space's change
/// feed and watchdog for the duration of a whole-file read.
///
/// `None` when the file could not be read (it vanished mid-flight) or the blocking
/// task could not run; the caller then treats the event as a real change, which is
/// the safe direction (`§9`).
async fn pcid_off_task(abs: std::path::PathBuf) -> Option<ft_core::Pcid> {
    tokio::task::spawn_blocking(move || std::fs::read(&abs).ok().map(|b| ft_hash::pcid_of(&b)))
        .await
        .ok()
        .flatten()
}

/// What one watchdog tick decided about the filesystem watch (`§9`).
#[derive(Debug, PartialEq, Eq)]
enum WatchTick {
    /// The watch still covers the Space root; nothing to do.
    Healthy,
    /// The watch had died and was re-armed. The caller MUST arm a full scan/commit:
    /// nothing that happened during the blind window produced an event, so
    /// re-arming alone still leaves those edits uncommitted.
    Rearmed,
    /// The watch is dead and could not be re-armed — the root is still missing (a
    /// volume that has not remounted, a directory nobody recreated). Carries the
    /// reason for the log and for the user-visible degradation.
    RearmFailed(String),
}

/// The watch-liveness policy of one watchdog tick, split out of the `select!` so it
/// is testable without a live loop or a real filesystem (`docs/BUILD-PLAN.md §3` —
/// the same split `ft-watcher` makes for its own callback policy).
///
/// `rearm` is invoked ONLY when the watch is not healthy, which makes "at most one
/// attempt per tick, never on a healthy watch" a property of this function rather
/// than of the loop that calls it. Generic over the failure type because all this
/// needs of it is a message for the log and for the user-visible degradation, which
/// also lets a test drive it without a real `notify` backend.
fn watch_tick<E: std::fmt::Display>(
    healthy: bool,
    rearm: impl FnOnce() -> std::result::Result<(), E>,
) -> WatchTick {
    if healthy {
        return WatchTick::Healthy;
    }
    match rearm() {
        Ok(()) => WatchTick::Rearmed,
        Err(e) => WatchTick::RearmFailed(e.to_string()),
    }
}

/// True when a pull failure is permanent — no retry can clear it, so the Space is
/// quarantined with an actionable reason instead of failing identically every
/// backstop tick (issue #11):
///
/// - a typed "this will never work" Coordinator code: the Space is gone, this
///   Account does not own it, or the Device's auth is no good;
/// - [`EngineError::Refused`]. A safety guard refuses a STATE, not an attempt: the
///   pull path's own refusals are the directory the head replaces with a file but
///   that still holds unsynced local content (`pull.rs`), and a Manifest this build
///   cannot read or one carrying two entries under one casefold key (`context.rs`).
///   Every one of them re-fires unchanged until a human moves a file, renames a
///   path or updates the binary — which is exactly what the quarantine message
///   tells them to do, and which the retry loop was silently swallowing.
///
/// Everything else (transport, Vault hiccups, unknown codes) is treated as
/// transient and retried by the next feed item / backstop tick. `SpaceLocked` in
/// particular is deliberately NOT permanent: the other holder can exit.
fn is_permanent_pull_error(e: &EngineError) -> bool {
    matches!(
        e,
        EngineError::Refused(_)
            | EngineError::Coordinator(
                ft_coordinator::CoordinatorError::SpaceNotFound { .. }
                    | ft_coordinator::CoordinatorError::NotAuthorized { .. }
                    | ft_coordinator::CoordinatorError::NotAuthenticated { .. }
            )
    )
}

/// The backoff to use after the NEXT consecutive commit failure: double, capped at
/// [`COMMIT_RETRY_MAX_BACKOFF`]. A commit that succeeds resets it to
/// [`COMMIT_RETRY_BACKOFF`].
fn escalated(backoff: Duration) -> Duration {
    (backoff * 2).min(COMMIT_RETRY_MAX_BACKOFF)
}

/// True when a COMMIT failure will fail identically on every retry, so re-arming
/// the debounce would repeat it until an operator acts (issue #11).
///
/// Exactly the permanent PULL faults, for exactly the same reason: a safety guard
/// that refused this tree refuses the same tree on the next scan too (e.g. the §7
/// mass-delete guard on a root that is not there), and only the user can resolve it
/// — so the message belongs where the user looks (`filething metrics`), not in one
/// warning per backoff window. Kept as its own name because the two paths quarantine
/// separately and may yet diverge; `SpaceLocked` is permanent for neither.
fn is_permanent_commit_error(e: &EngineError) -> bool {
    is_permanent_pull_error(e)
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
    use std::path::Path;
    use std::sync::Arc;

    use ft_core::{CanonicalPath, FileType};
    use ft_index::{Index, LocalEntry, SpaceState};
    use ft_watcher::AppliedState;

    use super::*;

    /// Mounts a Coordinator-less context over `root` with a fresh (empty)
    /// [`AppliedState`] attached, the shape the `run` loop hands
    /// [`SpaceContext::is_user_change`]. The returned `Arc` is the same map the
    /// context sees, so a test can plant marks and observe which ones were consumed.
    fn ctx_with_applied(root: &Path) -> (SpaceContext, Arc<AppliedState>) {
        let index = Index::open_in_memory().unwrap();
        index
            .upsert_space_state(&SpaceState {
                space_id: "space-run".to_string(),
                last_synced_seq: 0,
                last_synced_root: ft_manifest::build(Vec::new()).root,
                last_synced_revision_id: None,
                chunk_secret: [7u8; 32].to_vec(),
                dedup_secret: None,
                local_root_path: root.to_string_lossy().into_owned(),
            })
            .unwrap();
        // Under the control dir so the vault's own files could never be mistaken for
        // Space content (nothing here scans, but keep the tree honest).
        let vault = ft_vault::FsVault::new(root.join(crate::scan::CONTROL_DIR).join("vault"));
        let mut ctx = SpaceContext::mount(
            index,
            Box::new(vault),
            Box::new(ft_fsmap::LinuxFs),
            crate::AccountId::new("acct"),
            crate::DeviceId::new("devA"),
            crate::SpaceId::new("space-run"),
        )
        .unwrap();
        let applied = Arc::new(AppliedState::new());
        ctx.attach_applied_state(Arc::clone(&applied));
        (ctx, applied)
    }

    fn mtime_secs(abs: &Path) -> i64 {
        std::fs::metadata(abs)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Seeds the local-index row the `(size, mtime)` fast path consults.
    fn seed_row(ctx: &SpaceContext, path: &CanonicalPath, size: u64, mtime: i64) {
        ctx.index
            .upsert_entry(
                ctx.space_id.as_str(),
                &LocalEntry {
                    path: path.clone(),
                    casefold_key: ft_fsmap::casefold_key(path),
                    file_type: FileType::File,
                    exec: false,
                    size,
                    mtime,
                    pcid: Some(ft_core::Pcid::new([0u8; 32])),
                    base_seq: 0,
                    blocks: Vec::new(),
                    local_only: false,
                },
            )
            .unwrap();
    }

    fn ev(kind: ChangeKind, path: &Path) -> ChangeEvent {
        ChangeEvent {
            kind,
            path: path.to_path_buf(),
        }
    }

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

    /// A guard's refusal is as permanent on the PULL path as on the commit path —
    /// which is what its own message promises. `pull`'s dir→file refusal (a
    /// directory the head replaces with a file that still holds unsynced local
    /// content) documents "a Refused is never transient — no retry clears it", yet
    /// it used to be retried on every backstop tick forever instead of quarantining
    /// the Space with the message that says which paths to move.
    #[test]
    fn a_refused_pull_is_permanent_so_the_space_is_quarantined_with_the_actionable_message() {
        assert!(is_permanent_pull_error(&EngineError::Refused(
            "the Space head replaces docs with a file, but it still holds local files".to_string()
        )));
        // A held Space lock is NOT permanent on either path: the other holder can
        // exit, and the very next tick then succeeds.
        assert!(!is_permanent_pull_error(&EngineError::SpaceLocked {
            root: "/space".to_string(),
            holder: "pid 1".to_string(),
        }));
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

    /// A safety guard's refusal is PERMANENT for the commit path: the next scan of
    /// the same tree refuses identically, so re-arming the debounce would repeat it
    /// every backoff window until an operator acts. It must reach the supervisor
    /// (quarantine + a reason in `filething metrics`) instead.
    #[test]
    fn a_refused_commit_is_permanent_while_a_transient_fault_is_not() {
        assert!(is_permanent_commit_error(&EngineError::Refused(
            "would delete everything".to_string()
        )));
        assert!(is_permanent_commit_error(&EngineError::Coordinator(
            ft_coordinator::CoordinatorError::SpaceNotFound {
                message: "gone".into(),
            }
        )));
        // Transport blips keep retrying in place, and so does a Space another
        // process happens to hold: that holder can exit.
        assert!(!is_permanent_commit_error(&EngineError::Coordinator(
            ft_coordinator::CoordinatorError::Transport("ws closed".into())
        )));
        assert!(!is_permanent_commit_error(&EngineError::SpaceLocked {
            root: "/space".to_string(),
            holder: "pid 1".to_string(),
        }));
    }

    // ---- watch liveness (§9) --------------------------------------------

    /// A healthy watch must not be re-armed: re-arming a recursive watch is
    /// expensive, and doing it every watchdog tick would be a permanent tax.
    #[test]
    fn a_healthy_watch_is_never_re_armed() {
        let mut attempts = 0;
        let tick = watch_tick(true, || {
            attempts += 1;
            Err::<(), String>("must not be called".to_string())
        });
        assert_eq!(tick, WatchTick::Healthy);
        assert_eq!(attempts, 0, "a healthy watch must not be re-armed");
    }

    /// A dead watch is re-armed, and the caller is told so it can force the full
    /// scan the blind window's lost events would otherwise never trigger.
    #[test]
    fn a_dead_watch_is_re_armed_once_and_reported_so_a_full_scan_follows() {
        let mut attempts = 0;
        let tick = watch_tick(false, || {
            attempts += 1;
            Ok::<(), String>(())
        });
        assert_eq!(tick, WatchTick::Rearmed);
        assert_eq!(
            attempts, 1,
            "exactly one attempt per tick — a missing root must not spin"
        );
    }

    /// A root that is still missing (an unmounted volume) fails to re-arm: the
    /// reason is carried out so the loop can log it AND make the Space visibly
    /// degraded, then retry on the next tick — never spin.
    #[test]
    fn a_failed_re_arm_carries_its_reason_for_the_user_visible_degradation() {
        let tick = watch_tick(false, || {
            Err::<(), String>("no such file or directory".to_string())
        });
        match tick {
            WatchTick::RearmFailed(reason) => assert!(reason.contains("no such file")),
            other => panic!("expected RearmFailed, got {other:?}"),
        }
    }

    // ---- is_user_change: cost and correctness (§9) ----------------------

    /// THE cost bug: the echo check used to slurp and BLAKE3 the whole file on every
    /// forwarded event, so copying a 2 GiB file into a Space (~200 forwarded
    /// `Modified` events) meant ~200 full-file reads on the ONE task that drives
    /// every Space. A file whose `(size, mtime)` no longer match its index row has
    /// provably changed, so the answer needs no hash at all.
    ///
    /// The mark planted here MATCHES the bytes on disk, so the old code would have
    /// hashed the file, recognized its own write, CONSUMED the mark and returned
    /// false. Asserting the mark survives is what proves `is_echo` — and therefore
    /// the read — was never reached.
    #[tokio::test]
    async fn a_file_whose_size_no_longer_matches_the_index_is_a_user_change_without_hashing() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, applied) = ctx_with_applied(dir.path());
        let abs = dir.path().join("big.bin");
        let bytes = b"the bytes that are on disk right now";
        std::fs::write(&abs, bytes).unwrap();
        let path = CanonicalPath("big.bin".to_string());
        let mtime = mtime_secs(&abs);

        applied.mark_applied(path.clone(), mtime, ft_hash::pcid_of(bytes));
        // The row records the size the last apply/scan saw — a copy still in flight
        // grows past it on every one of those forwarded events.
        seed_row(&ctx, &path, bytes.len() as u64 + 4_096, mtime);

        assert!(
            ctx.is_user_change(&ev(ChangeKind::Modified, &abs)).await,
            "a file that does not match its recorded (size, mtime) has changed"
        );
        assert_eq!(
            applied.len(),
            1,
            "the mark must be untouched: is_echo (and its hash) were never needed"
        );
    }

    /// The cost fixes must not weaken `§9`: an event for a file that still looks
    /// EXACTLY like what the last apply wrote is our own echo, is suppressed, and
    /// consumes its mark.
    #[tokio::test]
    async fn an_echo_of_a_freshly_applied_file_is_still_suppressed() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, applied) = ctx_with_applied(dir.path());
        let abs = dir.path().join("notes.txt");
        let bytes = b"pulled from the feed";
        std::fs::write(&abs, bytes).unwrap();
        let path = CanonicalPath("notes.txt".to_string());
        let mtime = mtime_secs(&abs);

        // What `pull` records: the row and the mark from the same stat.
        seed_row(&ctx, &path, bytes.len() as u64, mtime);
        applied.mark_applied(path.clone(), mtime, ft_hash::pcid_of(bytes));

        assert!(
            !ctx.is_user_change(&ev(ChangeKind::Modified, &abs)).await,
            "our own applied write must not be re-committed"
        );
        assert!(
            applied.is_empty(),
            "a matched mark is consumed so the next real edit is not suppressed"
        );
    }

    /// A real edit of a file we applied earlier — same size, same whole-second
    /// mtime, different content — is exactly the case the hash still has to decide.
    #[tokio::test]
    async fn a_same_size_edit_inside_the_same_second_is_still_caught_by_the_hash() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, applied) = ctx_with_applied(dir.path());
        let abs = dir.path().join("notes.txt");
        std::fs::write(&abs, b"AAAA").unwrap();
        let path = CanonicalPath("notes.txt".to_string());
        let mtime = mtime_secs(&abs);
        seed_row(&ctx, &path, 4, mtime);
        // The mark is for the content we APPLIED; the user has since written other
        // bytes of the same length, and the row/mark (size, mtime) still match.
        applied.mark_applied(path.clone(), mtime, ft_hash::pcid_of(b"AAAA"));
        std::fs::write(&abs, b"BBBB").unwrap();

        assert!(
            ctx.is_user_change(&ev(ChangeKind::Modified, &abs)).await,
            "a same-size edit is only distinguishable by content, so the hash must run"
        );
    }

    /// Ordering guard: the "no marks outstanding" short-circuit must not jump the
    /// dir rule (ADR 0019). A `Modified` dir event is a child's mtime bump, whose own
    /// event already arms the commit; arming another one per parent directory would
    /// undo a deliberate saving.
    #[tokio::test]
    async fn a_modified_directory_event_is_still_ignored_with_no_marks_outstanding() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, applied) = ctx_with_applied(dir.path());
        let sub = dir.path().join("d");
        std::fs::create_dir(&sub).unwrap();
        assert!(applied.is_empty());

        assert!(!ctx.is_user_change(&ev(ChangeKind::Modified, &sub)).await);
        assert!(
            ctx.is_user_change(&ev(ChangeKind::Created, &sub)).await,
            "a created dir may be empty forever, so it must arm its own commit"
        );
    }

    /// An apply's scratch file (`.<file>.ft-tmp`) must never arm a commit: it is
    /// created and renamed away by `ft_diff::materialize`, and the echo mark belongs
    /// to the published path — so before this every pull was followed by a needless
    /// commit round.
    #[tokio::test]
    async fn an_apply_scratch_file_never_arms_a_commit() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, _applied) = ctx_with_applied(dir.path());
        let tmp = dir.path().join(format!(".doc.txt{}", ft_diff::TMP_SUFFIX));
        std::fs::write(&tmp, b"in flight").unwrap();
        let published = dir.path().join("doc.txt");
        std::fs::write(&published, b"published").unwrap();

        assert!(!ctx.is_user_change(&ev(ChangeKind::Created, &tmp)).await);
        assert!(!ctx.is_user_change(&ev(ChangeKind::Removed, &tmp)).await);
        assert!(
            ctx.is_user_change(&ev(ChangeKind::Created, &published))
                .await,
            "the file the rename publishes is a genuine change"
        );
    }

    /// The tmp matcher keys off the EXACT shape ft-diff mints, so an ordinary file
    /// whose name merely ends in the suffix keeps syncing.
    #[test]
    fn only_the_exact_apply_tmp_shape_is_recognized() {
        let cp = |s: &str| CanonicalPath(s.to_string());
        assert!(is_apply_tmp(&cp(&format!(
            ".doc.txt{}",
            ft_diff::TMP_SUFFIX
        ))));
        assert!(is_apply_tmp(&cp(&format!(
            "a/b/.doc.txt{}",
            ft_diff::TMP_SUFFIX
        ))));
        assert!(!is_apply_tmp(&cp("doc.txt")));
        // No leading dot: a user's own file, not ours.
        assert!(!is_apply_tmp(&cp(&format!(
            "doc.txt{}",
            ft_diff::TMP_SUFFIX
        ))));
        assert!(!is_apply_tmp(&cp(".hidden")));
    }

    /// The commit-retry backoff must ESCALATE and then stop growing, so a long-lived
    /// fault stops re-trying every 10s forever (burning quota, one warning per
    /// window) while a real blip still retries promptly.
    #[test]
    fn the_commit_retry_backoff_doubles_up_to_a_cap() {
        let mut backoff = COMMIT_RETRY_BACKOFF;
        let mut seen = Vec::new();
        for _ in 0..12 {
            seen.push(backoff);
            backoff = escalated(backoff);
        }
        assert_eq!(seen[0], COMMIT_RETRY_BACKOFF);
        assert_eq!(seen[1], COMMIT_RETRY_BACKOFF * 2);
        assert!(seen[1] < seen[2], "the backoff must grow");
        assert_eq!(
            *seen.last().unwrap(),
            COMMIT_RETRY_MAX_BACKOFF,
            "and must stop growing at the cap"
        );
    }
}
