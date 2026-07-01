//! ft-daemon — the foreground multi-Space Daemon (`CONTEXT.md` "Daemon",
//! `docs/BUILD-PLAN.md §3`).
//!
//! The Daemon is the always-on background process on a Device: it runs the
//! engine's continuous bidirectional sync loop ([`SpaceContext::run`]) for every
//! Space the Device syncs, all in one foreground process (one Seat per Device in
//! the MVP). It owns no sync logic of its own — it supervises the engine.
//!
//! [`serve`] takes a set of already-mounted [`SpaceContext`]s and a single
//! `shutdown` future, spawns one Tokio task per Space, fans the one shutdown
//! signal out to all of them (via a [`watch`](tokio::sync::watch) channel), and
//! waits for every loop to exit cleanly. The first Space whose loop errors aborts
//! the others and surfaces that error.
//!
//! ## Status / control socket
//!
//! A local Unix control socket (CLI ↔ Daemon) is intentionally NOT implemented in
//! this MVP: the `filething status` command reads the on-disk local index of each
//! Space directly (the index is the source of truth for `last_synced`), so it does
//! not need a running Daemon to answer. Wiring a socket here is reserved for a
//! later build; omitting it keeps the foreground Daemon a thin supervisor.

use std::future::Future;

use ft_engine::SpaceContext;
use futures::future::join_all;
use thiserror::Error;
use tokio::sync::watch;

/// Anything that can go wrong supervising the Daemon's Space loops.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// One Space's [`SpaceContext::run`] loop failed (the underlying engine
    /// error). The Daemon stops the remaining loops and surfaces this.
    #[error("space loop: {0}")]
    Engine(#[from] ft_engine::EngineError),

    /// A raw filesystem IO error (e.g. preparing the Daemon's runtime dir).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Crate-wide `Result` alias over [`DaemonError`].
pub type Result<T> = std::result::Result<T, DaemonError>;

/// Runs the continuous sync loop of every `space` concurrently until `shutdown`
/// resolves, then waits for each loop to exit cleanly (`docs/BUILD-PLAN.md §3`).
///
/// Each [`SpaceContext`] is moved onto its own Tokio task running
/// [`SpaceContext::run`]; the single `shutdown` future is fanned out to all of
/// them over a [`watch`](tokio::sync::watch) channel so one Ctrl-C stops every
/// Space. The call returns:
///
/// - `Ok(())` once every loop has exited (all observed `shutdown`), or
/// - the first `Err` a loop produced — after signalling the rest to stop and
///   awaiting them (best-effort), so no task is left orphaned.
///
/// An empty `spaces` list returns `Ok(())` as soon as `shutdown` resolves (the
/// Daemon has nothing to supervise but still honors the signal).
///
/// The per-Space loops run concurrently on this one task (via
/// [`join_all`](futures::future::join_all)) rather than on spawned tasks: the
/// engine's [`SpaceContext::run`] future is `!Send` (the watcher and diff hold
/// `!Send` state across awaits), so it cannot cross a [`tokio::spawn`] boundary.
/// Concurrency on a single multiplexed task is exactly what the foreground MVP
/// Daemon needs.
pub async fn serve(spaces: Vec<SpaceContext>, shutdown: impl Future<Output = ()>) -> Result<()> {
    // The fan-out: a watch channel each per-Space loop observes. Flipping it to
    // `true` (when the outer shutdown resolves, or when one loop errors) ends
    // every loop.
    let (stop_tx, stop_rx) = watch::channel(false);

    // An empty Daemon has nothing to supervise but still honors the signal
    // (documented contract; `run_loops` would otherwise return immediately).
    if spaces.is_empty() {
        shutdown.await;
        return Ok(());
    }

    // One supervised loop future per Space, each with its own shutdown receiver
    // and a stop sender so a loop that fails tears the others down too. (`!Send`
    // is fine; these stay on the current task.)
    let loops = spaces.into_iter().map(|mut space| {
        let mut rx = stop_rx.clone();
        let stop_tx = stop_tx.clone();
        async move {
            // The per-Space shutdown: resolve when the watch flips to true (or the
            // sender drops — both mean "stop"). `wait_for` returns immediately if
            // the value already satisfies the predicate.
            let stop = async move {
                let _ = rx.wait_for(|stopped| *stopped).await;
            };
            let space_id = space.space_id.to_string();
            tracing::info!(space = %space_id, "space loop started");
            let outcome = space.run(stop).await;
            match &outcome {
                Ok(()) => tracing::info!(space = %space_id, "space loop stopped"),
                Err(e) => {
                    tracing::error!(space = %space_id, error = %e, "space loop failed");
                    // A failure stops the whole Daemon: flip the signal so the
                    // sibling loops exit too.
                    let _ = stop_tx.send(true);
                }
            }
            outcome
        }
    });

    // Drive all loops to completion while fanning the external shutdown out
    // through the watch. Surface the first real error.
    let results = run_loops(join_all(loops), shutdown, &stop_tx).await;
    for outcome in results {
        outcome?;
    }
    Ok(())
}

/// Drives `all` (the joined Space loops) to completion, flipping `stop_tx` when
/// `shutdown` resolves so every loop exits.
///
/// Must return AS SOON AS every loop has ended — even when `shutdown` never
/// resolves. A plain `join(all, shutdown)` also waits for the shutdown: a Daemon
/// whose every loop had died (e.g. a poisoned pull) sat alive-but-deaf until
/// Ctrl-C, its error invisible until then (the "daemon zombi" bug).
async fn run_loops<F: Future>(
    all: futures::future::JoinAll<F>,
    shutdown: impl Future<Output = ()>,
    stop_tx: &watch::Sender<bool>,
) -> Vec<F::Output> {
    let supervisor = async {
        shutdown.await;
        // Signal every loop to stop. The send only fails if every receiver has
        // already dropped (all loops exited), which is fine.
        let _ = stop_tx.send(true);
    };
    tokio::pin!(all);
    tokio::pin!(supervisor);
    tokio::select! {
        // All loops ended on their own (an error tears the siblings down via
        // the watch): return now, do not wait for the shutdown.
        results = &mut all => results,
        // Shutdown fired: the watch is flipped; now await the loops' exit.
        () = &mut supervisor => all.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty Daemon honors shutdown and returns Ok with no Spaces to supervise.
    #[tokio::test]
    async fn serve_with_no_spaces_returns_on_shutdown() {
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

    /// REGRESSION ("daemon zombi", diario 2026-07-01): once every loop has
    /// ended (e.g. errored), the supervision must return WITHOUT waiting for a
    /// shutdown that never fires. With `join` semantics this hangs: process
    /// alive, no loops running, the error invisible until Ctrl-C.
    #[tokio::test]
    async fn run_loops_returns_when_all_loops_end_without_shutdown() {
        let (tx, _rx) = watch::channel(false);
        let all = join_all(vec![async { Err::<(), &str>("boom") }]);
        let results = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_loops(all, std::future::pending::<()>(), &tx),
        )
        .await
        .expect("must return once all loops ended; hanging here = zombie daemon");
        assert_eq!(results, vec![Err("boom")]);
    }

    /// The shutdown path still works: the signal flips the watch, a loop
    /// observing it exits, and its result is collected.
    #[tokio::test]
    async fn run_loops_shutdown_flips_watch_and_collects_results() {
        let (tx, mut rx) = watch::channel(false);
        let waiter = async move {
            let _ = rx.wait_for(|stopped| *stopped).await;
            7usize
        };
        let all = join_all(vec![waiter]);
        let results = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_loops(all, async {}, &tx),
        )
        .await
        .expect("shutdown must end the loops promptly");
        assert_eq!(results, vec![7]);
    }
}
