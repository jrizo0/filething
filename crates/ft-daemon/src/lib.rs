//! ft-daemon — the foreground multi-Space Daemon (`CONTEXT.md` "Daemon",
//! `docs/BUILD-PLAN.md §3`).
//!
//! The Daemon is the always-on background process on a Device: it runs the
//! engine's continuous bidirectional sync loop ([`SpaceContext::run`]) for every
//! Space the Device syncs, all in one foreground process (one Seat per Device in
//! the MVP). It owns no sync logic of its own — it supervises the engine.
//!
//! [`serve`] takes one [`SpaceSlot`] per Space (a *factory* that mounts and runs
//! the Space, so every attempt is a fresh connection + context) and a single
//! `shutdown` future. It supervises each slot independently and fans the one
//! shutdown signal out to all of them over a [`watch`](tokio::sync::watch)
//! channel. It returns only when `shutdown` resolves.
//!
//! ## Per-Space quarantine (issue #8: "un Space roto brickea el daemon entero")
//!
//! A single Space must never take the whole Daemon down. Before, a per-Space
//! failure — at mount time (e.g. `space_key` recovery hitting a deleted Space) or
//! at runtime — propagated out of `serve`, and the OS service supervisor
//! relaunched the process into an infinite crash-loop where NO Space synced.
//!
//! Now each slot is supervised: a failed attempt puts *that* Space into
//! QUARANTINE — the failure is logged, the Space is retried with exponential
//! backoff ([`QUARANTINE_INITIAL_BACKOFF`] → ×[`QUARANTINE_BACKOFF_FACTOR`],
//! capped at [`QUARANTINE_MAX_BACKOFF`]), and a retry that stays healthy for
//! [`HEALTHY_RUN_THRESHOLD`] resets the backoff. Healthy Spaces run untouched.
//! Quarantine is surfaced through [`SyncMetrics`] (`filething metrics`). The
//! process exits only on `shutdown`.
//!
//! ## Status / control socket
//!
//! A local Unix control socket (CLI ↔ Daemon) is intentionally NOT implemented in
//! this MVP: the `filething status` command reads the on-disk local index of each
//! Space directly (the index is the source of truth for `last_synced`), so it does
//! not need a running Daemon to answer. Wiring a socket here is reserved for a
//! later build; omitting it keeps the foreground Daemon a thin supervisor.

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use ft_engine::SyncMetrics;
use futures::future::{join_all, LocalBoxFuture};
use tokio::sync::watch;

/// Backoff before the first retry of a quarantined Space.
const QUARANTINE_INITIAL_BACKOFF: Duration = Duration::from_secs(5);
/// Multiplier applied to the backoff after each consecutive failed attempt.
const QUARANTINE_BACKOFF_FACTOR: u32 = 2;
/// Ceiling for the retry backoff — a wedged Space still retries every 5 min.
const QUARANTINE_MAX_BACKOFF: Duration = Duration::from_secs(300);
/// How long an attempt must run before it counts as "healthy": a slot that
/// survived this long before failing has its backoff reset to the initial value
/// (a transient blip should not inherit a long backoff). The `quarantined`
/// metrics flag itself is cleared by the slot's task on a successful mount, not
/// by this timer (see `commands::daemon` in the CLI).
const HEALTHY_RUN_THRESHOLD: Duration = Duration::from_secs(60);

/// One supervised Space: a factory the Daemon calls to (re)mount and run a Space.
///
/// The `task` is a *factory*, not a single future: the supervisor calls it once
/// per attempt so every retry starts from scratch (fresh Coordinator connection,
/// fresh `SpaceContext`, fresh `space_key` recovery). It is handed a `stop`
/// future — resolved when the Daemon is shutting down — and returns a future that
/// runs the Space's sync loop until either `stop` resolves (→ `Ok(())`) or the
/// Space fails (→ `Err`, which quarantines the Space rather than the Daemon).
pub struct SpaceSlot {
    /// Human label for logs and metrics (the Space root path, typically).
    pub label: String,
    /// The Space root on disk, where per-Space quarantine telemetry is persisted
    /// via [`SyncMetrics`] (`<root>/.filething/metrics.json`).
    pub root: PathBuf,
    /// Mounts the Space and runs its sync loop until `stop` resolves. Each call is
    /// a fresh attempt. The returned future is `!Send` on purpose: the engine's
    /// [`SpaceContext::run`] future is `!Send`, so all slots are driven
    /// concurrently on one task (never across a [`tokio::spawn`] boundary).
    ///
    /// [`SpaceContext::run`]: ft_engine::SpaceContext::run
    #[allow(clippy::type_complexity)]
    pub task:
        Box<dyn FnMut(LocalBoxFuture<'static, ()>) -> LocalBoxFuture<'static, anyhow::Result<()>>>,
}

/// Supervises every `slot` until `shutdown` resolves, then waits for each to exit
/// (`docs/BUILD-PLAN.md §3`, issue #8).
///
/// The single `shutdown` future is fanned out to all slots over a
/// [`watch`](tokio::sync::watch) channel so one Ctrl-C stops every Space. Each
/// slot is supervised independently ([`supervise`]): a failing Space is
/// quarantined and retried with backoff, never taking the Daemon (or its
/// siblings) down. The call returns `Ok(())` once `shutdown` has resolved and
/// every slot's supervisor has exited.
///
/// An empty `slots` list returns `Ok(())` as soon as `shutdown` resolves (the
/// Daemon has nothing to supervise but still honors the signal).
///
/// The per-Space futures run concurrently on this one task (via
/// [`join_all`](futures::future::join_all)) rather than on spawned tasks: the
/// engine's [`SpaceContext::run`](ft_engine::SpaceContext::run) future is `!Send`
/// (the watcher and diff hold `!Send` state across awaits), so it cannot cross a
/// [`tokio::spawn`] boundary. Concurrency on a single multiplexed task is exactly
/// what the foreground MVP Daemon needs.
pub async fn serve(
    slots: Vec<SpaceSlot>,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    // The fan-out: a watch channel every supervisor observes. Flipping it to
    // `true` (when the outer shutdown resolves) ends every supervision loop.
    let (stop_tx, stop_rx) = watch::channel(false);

    // An empty Daemon has nothing to supervise but still honors the signal
    // (documented contract): wait for shutdown, then return.
    if slots.is_empty() {
        shutdown.await;
        return Ok(());
    }

    // One supervisor future per slot, each with its own shutdown receiver. (`!Send`
    // is fine; these stay on the current task via join_all.)
    let supervisors = slots
        .into_iter()
        .map(|slot| supervise(slot, stop_rx.clone()));

    // Drive all supervisors while fanning the external shutdown out through the
    // watch. With supervision, a supervisor only ends after the watch flips, so
    // the join only completes once shutdown has fired.
    let all = join_all(supervisors);
    let supervisor = async {
        shutdown.await;
        // Signal every supervisor to stop. The send only fails if every receiver
        // has already dropped, which is fine.
        let _ = stop_tx.send(true);
    };
    tokio::pin!(all);
    tokio::pin!(supervisor);
    tokio::select! {
        // Every supervisor ended on its own. With the quarantine design this only
        // happens after the watch flipped, but keep the branch so a degenerate
        // set of slots can never leave us hanging (the old "daemon zombi" guard).
        _ = &mut all => {}
        // Shutdown fired: the watch is flipped; now await the supervisors' exit.
        () = &mut supervisor => {
            all.await;
        }
    }
    Ok(())
}

/// Supervises a single [`SpaceSlot`] until shutdown: run it, and on failure
/// quarantine it (log + backoff + retry) instead of propagating the error.
///
/// Returns only when the `stop_rx` watch flips to `true` (shutdown). A failure is
/// recorded to the Space's [`SyncMetrics`] and retried with exponential backoff;
/// an attempt that ran healthily for [`HEALTHY_RUN_THRESHOLD`] resets the backoff
/// and clears the quarantine flag.
async fn supervise(mut slot: SpaceSlot, stop_rx: watch::Receiver<bool>) {
    let mut backoff = QUARANTINE_INITIAL_BACKOFF;
    loop {
        // Already shutting down (e.g. before the first attempt): stop.
        if *stop_rx.borrow() {
            break;
        }

        // A fresh stop future for this attempt (owned clone → `'static`).
        let stop: LocalBoxFuture<'static, ()> = {
            let mut rx = stop_rx.clone();
            Box::pin(async move {
                let _ = rx.wait_for(|stopped| *stopped).await;
            })
        };

        let started = tokio::time::Instant::now();
        let outcome = (slot.task)(stop).await;

        match outcome {
            // The attempt's own loop observed shutdown and exited cleanly.
            Ok(()) => break,
            Err(e) => {
                // The failure raced with shutdown: don't quarantine on the way out.
                if *stop_rx.borrow() {
                    break;
                }

                // An attempt that ran healthily for a while before failing is a
                // NEW incident, not the same one escalating: restart the backoff
                // from the initial value. Note this keys off elapsed time alone —
                // a failure whose surfacing itself takes >= the threshold (e.g. a
                // slow connect timeout) never escalates its backoff, which is
                // acceptable: the slow failure already paces the retries.
                // (The `quarantined` flag itself is cleared by the slot's task on
                // a successful mount — see `commands::daemon` — so a recovered
                // Space stops showing as quarantined without waiting for its
                // attempt to end.)
                if started.elapsed() >= HEALTHY_RUN_THRESHOLD {
                    backoff = QUARANTINE_INITIAL_BACKOFF;
                }

                // Quarantine: record telemetry, log, then back off before retrying.
                let mut metrics = SyncMetrics::load(&slot.root);
                metrics.record_quarantine(&format!("{e:#}"));
                metrics.save(&slot.root);
                tracing::error!(
                    space = %slot.label,
                    error = %e,
                    retry_in_secs = backoff.as_secs(),
                    "space quarantined; retrying with backoff"
                );

                // Sleep the backoff, but wake immediately on shutdown.
                let mut rx = stop_rx.clone();
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = rx.wait_for(|stopped| *stopped) => break,
                }
                tracing::info!(space = %slot.label, "space leaving quarantine; retrying");
                backoff = (backoff * QUARANTINE_BACKOFF_FACTOR).min(QUARANTINE_MAX_BACKOFF);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Builds a [`SpaceSlot`] from a label, root, and task factory.
    fn slot(
        label: &str,
        root: PathBuf,
        task: impl FnMut(LocalBoxFuture<'static, ()>) -> LocalBoxFuture<'static, anyhow::Result<()>>
            + 'static,
    ) -> SpaceSlot {
        SpaceSlot {
            label: label.to_string(),
            root,
            task: Box::new(task),
        }
    }

    /// A `shutdown` future that resolves after `secs` of (virtual) time.
    async fn shutdown_after(secs: u64) {
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }

    /// An empty Daemon honors shutdown and returns Ok with no Spaces to supervise.
    #[tokio::test]
    async fn serve_with_no_slots_returns_on_shutdown() {
        let r = serve(Vec::new(), async {}).await;
        assert!(r.is_ok(), "empty serve must return Ok, got {r:?}");
    }

    /// An already-resolved shutdown returns promptly even with no Spaces (the
    /// common Ctrl-C-before-anything case).
    #[tokio::test]
    async fn serve_returns_when_shutdown_already_resolved() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        drop(tx); // resolved (closed) immediately.
        let shutdown = async move {
            let _ = rx.await;
        };
        let r = serve(Vec::new(), shutdown).await;
        assert!(r.is_ok());
    }

    /// A healthy slot runs until shutdown, observes the stop signal, and serve
    /// returns Ok — the base case the supervisor must not disturb.
    #[tokio::test(start_paused = true)]
    async fn serve_runs_healthy_slot_until_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let stopped = Arc::new(AtomicUsize::new(0));
        let s = stopped.clone();
        let task = move |stop: LocalBoxFuture<'static, ()>| {
            let s = s.clone();
            Box::pin(async move {
                stop.await;
                s.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }) as LocalBoxFuture<'static, anyhow::Result<()>>
        };
        let r = serve(
            vec![slot("healthy", dir.path().to_path_buf(), task)],
            shutdown_after(1),
        )
        .await;
        assert!(r.is_ok());
        assert_eq!(
            stopped.load(Ordering::SeqCst),
            1,
            "the healthy slot must observe shutdown exactly once"
        );
    }

    /// ISSUE #8: a slot whose attempt always errors immediately must NOT take the
    /// Daemon down. serve keeps running (does not return) until shutdown; the
    /// Space is quarantined and retried, so its metrics.json shows repeated
    /// quarantines with the last error recorded.
    #[tokio::test(start_paused = true)]
    async fn always_failing_slot_is_quarantined_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let task = move |_stop: LocalBoxFuture<'static, ()>| {
            Box::pin(async move { anyhow::bail!("mount failed: space deleted") })
                as LocalBoxFuture<'static, anyhow::Result<()>>
        };
        // Backoffs: 5s, 10s, 20s, … Shutdown at 20s virtual time sees >= 2 retries.
        let r = tokio::time::timeout(
            Duration::from_secs(120),
            serve(
                vec![slot("broken", dir.path().to_path_buf(), task)],
                shutdown_after(20),
            ),
        )
        .await
        .expect("serve must return on shutdown, not hang");
        assert!(r.is_ok(), "a broken Space must never fail serve, got {r:?}");

        let m = SyncMetrics::load(dir.path());
        assert!(
            m.quarantines >= 2,
            "expected >= 2 quarantines, got {}",
            m.quarantines
        );
        assert_eq!(
            m.last_quarantine_error.as_deref(),
            Some("mount failed: space deleted")
        );
        assert!(m.quarantined, "a never-recovering Space stays quarantined");
    }

    /// ISSUE #8: a failing slot must not stop a healthy sibling. The healthy slot
    /// runs until shutdown and returns Ok; the failing slot quarantines in the
    /// background. Both complete and serve returns Ok.
    #[tokio::test(start_paused = true)]
    async fn failing_slot_does_not_stop_healthy_slot() {
        let good_dir = tempfile::tempdir().unwrap();
        let bad_dir = tempfile::tempdir().unwrap();

        let healthy_stopped = Arc::new(AtomicUsize::new(0));
        let hs = healthy_stopped.clone();
        let healthy = move |stop: LocalBoxFuture<'static, ()>| {
            let hs = hs.clone();
            Box::pin(async move {
                stop.await;
                hs.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }) as LocalBoxFuture<'static, anyhow::Result<()>>
        };

        let bad_attempts = Arc::new(AtomicUsize::new(0));
        let ba = bad_attempts.clone();
        let failing = move |_stop: LocalBoxFuture<'static, ()>| {
            ba.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { anyhow::bail!("always down") })
                as LocalBoxFuture<'static, anyhow::Result<()>>
        };

        let r = tokio::time::timeout(
            Duration::from_secs(120),
            serve(
                vec![
                    slot("healthy", good_dir.path().to_path_buf(), healthy),
                    slot("broken", bad_dir.path().to_path_buf(), failing),
                ],
                shutdown_after(20),
            ),
        )
        .await
        .expect("serve must return on shutdown, not hang");
        assert!(r.is_ok());
        assert_eq!(
            healthy_stopped.load(Ordering::SeqCst),
            1,
            "the healthy slot must have run to a clean shutdown"
        );
        assert!(
            bad_attempts.load(Ordering::SeqCst) >= 2,
            "the failing slot must have retried under quarantine while the sibling ran"
        );
    }

    /// ISSUE #8: the retry backoff grows between consecutive failed attempts.
    /// Record the (virtual) time of each attempt and assert the gaps increase.
    #[tokio::test(start_paused = true)]
    async fn quarantine_backoff_grows_between_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let base = tokio::time::Instant::now();
        let times: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        let t = times.clone();
        let task = move |_stop: LocalBoxFuture<'static, ()>| {
            t.lock().unwrap().push(base.elapsed());
            Box::pin(async move { anyhow::bail!("down") })
                as LocalBoxFuture<'static, anyhow::Result<()>>
        };
        // Attempts at t=0, 5, 15, 35, … (gaps 5, 10, 20). Shutdown at 40s captures
        // at least four attempts.
        let r = tokio::time::timeout(
            Duration::from_secs(300),
            serve(
                vec![slot("broken", dir.path().to_path_buf(), task)],
                shutdown_after(40),
            ),
        )
        .await
        .expect("serve must return on shutdown, not hang");
        assert!(r.is_ok());

        let times = times.lock().unwrap();
        assert!(
            times.len() >= 3,
            "expected >= 3 attempts to compare gaps, got {}",
            times.len()
        );
        let gap1 = times[1] - times[0];
        let gap2 = times[2] - times[1];
        assert!(
            gap2 > gap1,
            "backoff must grow: gap1={gap1:?} gap2={gap2:?}"
        );
    }
}
