//! ft-watcher — file watcher + echo suppression (`docs/format.md §9`).
//!
//! Three cooperating pieces:
//!
//! 1. A recursive [`Watcher`] over a Space's local root. It uses the `notify`
//!    crate with a short debounce/coalescing window ([`CoalesceBuffer`]) and
//!    emits coalesced [`ChangeEvent`]s ([`ChangeKind::Created`] /
//!    [`ChangeKind::Modified`] / [`ChangeKind::Removed`]) on a channel the
//!    engine drains.
//!
//! 2. Echo suppression (`§9`). After the engine writes a file it pulled from the
//!    change feed, it calls [`Watcher::mark_applied`] to record the REAL `mtime`
//!    the filesystem assigned plus the file's `pcid`. When the corresponding FS
//!    event later surfaces, the engine recomputes `(mtime, pcid)` and calls the
//!    pure policy [`is_echo`]: if `(path, mtime, pcid)` matches a recorded
//!    application, the event is recognized as our own (the mark is consumed) and
//!    NOT propagated as a user change; otherwise it is a real edit and flows on.
//!
//! 3. Watch liveness ([`WatchHealth`]). A watch can die without a word: on Linux
//!    inotify binds to the root's INODE, so a Space root that is deleted, moved
//!    or replaced (restore from backup, `rm -rf` + recreate, a volume that
//!    unmounts) leaves a descriptor over an inode nobody writes to and no event
//!    ever arrives again. Since the engine's commit debounce is armed ONLY by
//!    watcher events, local edits then stop being committed while `status` and
//!    `metrics` still report a healthy Space. So the watcher records what it
//!    learns — backend errors and the loss of the root — [`Watcher::is_healthy`]
//!    answers "does this watch still cover the root?" (comparing the root's inode
//!    identity, not just its path), and [`Watcher::rewatch`] re-arms it. Re-arming
//!    is the supervisor's call: after a successful one it MUST force a full
//!    scan/commit, because nothing that happened during the blind window produced
//!    an event.
//!
//! ## Why the policy is split out
//!
//! `notify` reports a path and a kind — never a `pcid`, and not always a usable
//! `mtime`. So this crate does NOT try to suppress inside the OS callback. It
//! emits the raw, coalesced FS events; the engine, which can `stat`+re-hash the
//! file, owns the `(mtime, pcid)` and calls [`is_echo`] against the
//! [`AppliedState`] this `Watcher` exposes. That keeps the suppression POLICY a
//! pure, deterministic function testable without touching the filesystem
//! (`docs/BUILD-PLAN.md §3`, `format.md §9`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ft_core::{CanonicalPath, Pcid};
use notify::event::ModifyKind;
use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher,
};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised while constructing or driving a [`Watcher`].
#[derive(Debug, Error)]
pub enum Error {
    /// The underlying `notify` backend failed to start or to watch the root.
    #[error("notify backend error: {0}")]
    Notify(#[from] notify::Error),
}

/// Crate `Result` alias over the watcher [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Change events
// ---------------------------------------------------------------------------

/// The kind of filesystem change observed, coalesced from raw `notify` events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeKind {
    /// A path appeared.
    Created,
    /// A path's contents or metadata changed.
    Modified,
    /// A path was removed.
    Removed,
}

/// A coalesced filesystem change emitted by the [`Watcher`].
///
/// `path` is the absolute path reported by `notify`. Canonicalization to a
/// Space-relative [`CanonicalPath`] is the engine's job (it owns the root and
/// the `ft-fsmap` rules); this crate stays free of path policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEvent {
    /// What happened.
    pub kind: ChangeKind,
    /// The absolute path the event concerns.
    pub path: PathBuf,
}

// ---------------------------------------------------------------------------
// Applied state + echo-suppression policy (§9)
// ---------------------------------------------------------------------------

/// How long an echo-suppression mark stays valid.
///
/// Most marks are CONSUMED by the very event they predict ([`is_echo`]), but some
/// are never claimed: the engine also marks Dirs and Symlinks, with the
/// contentless zero `pcid` (ADR 0019, `ft-engine/src/pull.rs`) that no `pcid`
/// recomputed from an event can ever equal — and any event can be coalesced away
/// or lost with the watch. Without an expiry those marks pile up for the daemon's
/// whole lifetime.
///
/// Deliberately generous — minutes, not milliseconds. Expiring a mark too early
/// costs at most one redundant commit (the scan compares against the local index
/// and finds nothing to do), while keeping one forever risks suppressing a REAL
/// user edit that happens to match it, which is data loss. A long pull only drains
/// the FS events it caused once it returns, so a mark must comfortably outlive the
/// pull that recorded it.
const MARK_TTL: Duration = Duration::from_secs(5 * 60);

/// How often [`AppliedState`] sweeps expired marks. Periodic rather than on every
/// insert because a pull marks every entry it applies, and an O(n) scan per insert
/// would make a large pull O(n²).
const MARK_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// One echo-suppression mark: the `(mtime, pcid)` the engine wrote, plus WHEN it
/// was recorded so the mark can expire ([`MARK_TTL`]).
#[derive(Debug, Clone, Copy)]
struct Mark {
    mtime: i64,
    pcid: Pcid,
    recorded: Instant,
}

/// The marks themselves plus the bookkeeping for their periodic sweep.
#[derive(Debug, Default)]
struct Marks {
    by_path: HashMap<CanonicalPath, Mark>,
    /// When the last sweep ran; `None` until the first insert.
    last_swept: Option<Instant>,
}

impl Marks {
    /// Drops every mark older than [`MARK_TTL`], at most once per
    /// [`MARK_SWEEP_INTERVAL`].
    fn maybe_sweep(&mut self, now: Instant) {
        if let Some(swept) = self.last_swept {
            if now.duration_since(swept) < MARK_SWEEP_INTERVAL {
                return;
            }
        }
        self.last_swept = Some(now);
        self.by_path
            .retain(|_, mark| now.duration_since(mark.recorded) < MARK_TTL);
    }
}

/// What the engine just WROTE while applying a change pulled from the feed:
/// the REAL `mtime` the filesystem assigned and the file's `pcid`, keyed by its
/// canonical path. Used purely for echo suppression (`§9`).
///
/// Holds a single mark per path: applying a path again overwrites the previous
/// mark, matching the "latest write wins" reality of the apply loop. Interior
/// mutability (`Mutex<HashMap>`) lets [`is_echo`] CONSUME a matched mark behind a
/// shared `&` reference, so the watcher can hand the same `AppliedState` to the
/// engine without ceremony. Marks that no event ever consumes expire after
/// [`MARK_TTL`], so the map stays bounded by recent activity.
#[derive(Debug, Default)]
pub struct AppliedState {
    marks: Mutex<Marks>,
}

impl AppliedState {
    /// A fresh, empty applied-state map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that the engine wrote `path` with real `mtime` and `pcid`.
    /// Overwrites any prior mark for the same path.
    pub fn mark_applied(&self, path: CanonicalPath, mtime: i64, pcid: Pcid) {
        self.mark_applied_at(path, mtime, pcid, Instant::now());
    }

    /// [`Self::mark_applied`] against an injected clock, so the expiry policy is
    /// testable without sleeping.
    fn mark_applied_at(&self, path: CanonicalPath, mtime: i64, pcid: Pcid, now: Instant) {
        let mut marks = self.marks.lock().expect("AppliedState mutex poisoned");
        marks.maybe_sweep(now);
        marks.by_path.insert(
            path,
            Mark {
                mtime,
                pcid,
                recorded: now,
            },
        );
    }

    /// Number of outstanding marks (test/diagnostic helper).
    pub fn len(&self) -> usize {
        self.marks
            .lock()
            .expect("AppliedState mutex poisoned")
            .by_path
            .len()
    }

    /// Whether there are no outstanding marks.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Echo-suppression policy (`§9`) — PURE and filesystem-free.
///
/// Given the `state` of what the engine just applied and the `(path, mtime,
/// pcid)` recomputed from an incoming FS event, returns `true` when the event is
/// our OWN write echoing back — i.e. there is a recorded mark for `path` whose
/// `(mtime, pcid)` matches exactly. A matched mark is CONSUMED (removed) so the
/// next event on that path is treated as a genuine user change.
///
/// Returns `false` when there is no mark for `path`, the mark's `mtime`/`pcid`
/// differs, or the mark is older than [`MARK_TTL`] — that is a real edit by the
/// user and must be emitted. The match is on `pcid` (content identity), never on
/// `mtime` alone, per the causal rule of `§9`/`§10`; `mtime` is part of the key
/// only to tighten the recognition of our own write, not to decide "changed".
pub fn is_echo(state: &AppliedState, path: &CanonicalPath, mtime: i64, pcid: &Pcid) -> bool {
    is_echo_at(state, path, mtime, pcid, Instant::now())
}

/// [`is_echo`] against an injected clock, so the expiry policy is testable
/// without sleeping.
fn is_echo_at(
    state: &AppliedState,
    path: &CanonicalPath,
    mtime: i64,
    pcid: &Pcid,
    now: Instant,
) -> bool {
    let mut marks = state.marks.lock().expect("AppliedState mutex poisoned");
    match marks.by_path.get(path) {
        Some(mark) if now.duration_since(mark.recorded) >= MARK_TTL => {
            // Too old to plausibly be the echo of our own write: drop it and let
            // the event through as a user change. Erring this way costs a
            // redundant commit; erring the other way loses a real edit.
            marks.by_path.remove(path);
            false
        }
        Some(mark) if mark.mtime == mtime && mark.pcid == *pcid => {
            // Recognized as our own application: consume the mark so a later
            // real edit on this path is no longer suppressed.
            marks.by_path.remove(path);
            true
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Watch liveness
// ---------------------------------------------------------------------------

/// What the watcher has learned about its own watch, shared with whoever owns the
/// [`Watcher`] so a dead watch is OBSERVABLE instead of silent.
///
/// `notify` volunteers almost nothing when a watch stops working: the backend
/// error callback is the only channel, and the case that matters most — the root
/// itself going away — is not even an error there (notify 6 `inotify.rs` turns
/// `IN_DELETE_SELF` into an ordinary remove event and then drops the watch
/// descriptor). So this type collects both signals: backend errors, and the loss
/// of the root. Poll it via [`Watcher::health`], or ask
/// [`Watcher::is_healthy`], which also re-checks the root's inode identity.
#[derive(Debug, Default)]
pub struct WatchHealth {
    /// Backend errors seen since this watcher started (cumulative; a successful
    /// [`Watcher::rewatch`] does not reset it, so it stays usable as a metric).
    errors: AtomicU64,
    /// Set when the watch is known to no longer cover the root.
    lost: AtomicBool,
    /// The most recent backend error, for the log/status line.
    last_error: Mutex<Option<String>>,
}

impl WatchHealth {
    /// Fresh, healthy state.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many backend errors this watcher has seen, ever.
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// The most recent backend error, if any.
    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .expect("WatchHealth mutex poisoned")
            .clone()
    }

    /// Whether the watch is known to have stopped covering the root, i.e. the
    /// caller should [`Watcher::rewatch`].
    pub fn is_lost(&self) -> bool {
        self.lost.load(Ordering::Relaxed)
    }

    /// Records a backend error, marking the watch lost only for the kinds that
    /// mean the watch/path itself is gone. A transient failure on one subtree
    /// (`Generic`, `Io`, `MaxFilesWatch`) is counted but NOT treated as loss:
    /// re-arming a recursive watch is expensive and `MaxFilesWatch` in particular
    /// would just fail again, so the caller decides what to do with the counter.
    fn record_error(&self, err: &notify::Error) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().expect("WatchHealth mutex poisoned") = Some(err.to_string());
        if matches!(
            err.kind,
            notify::ErrorKind::WatchNotFound | notify::ErrorKind::PathNotFound
        ) {
            self.mark_lost();
        }
    }

    /// Marks the watch as no longer covering the root.
    fn mark_lost(&self) {
        self.lost.store(true, Ordering::Relaxed);
    }

    /// Clears the lost flag after a successful (re)arm. The error counter is
    /// deliberately left alone.
    fn clear_lost(&self) {
        self.lost.store(false, Ordering::Relaxed);
    }
}

/// Whether a raw `notify` event says the watch lost its own root: the root was
/// deleted, moved away, or replaced.
///
/// inotify reports `IN_DELETE_SELF` / `IN_MOVE_SELF` on the root as a plain
/// remove / rename event carrying the ROOT path, and then quietly drops the watch
/// descriptor (notify 6 `inotify.rs`) — after which no event ever arrives again.
/// Recognizing it here is what turns a silent sync death into a signal the
/// supervisor can act on, without waiting for the next liveness poll. Pure so it
/// is testable without a filesystem (`docs/BUILD-PLAN.md §3`).
fn is_root_lost(kind: &EventKind, paths: &[PathBuf], roots: &[PathBuf]) -> bool {
    let fatal = matches!(
        kind,
        EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
    );
    fatal && paths.iter().any(|p| roots.contains(p))
}

/// The paths a backend may report for the root ITSELF: the one we registered plus
/// its symlink-resolved form, because FSEvents reports resolved paths
/// (`/private/var/...` for `/var/...`) while inotify echoes back what we
/// registered.
fn root_aliases(root: &Path) -> Vec<PathBuf> {
    let mut aliases = vec![root.to_path_buf()];
    if let Ok(resolved) = std::fs::canonicalize(root) {
        if resolved != *root {
            aliases.push(resolved);
        }
    }
    aliases
}

/// Identity of the watched root: `(dev, ino)` on unix, where the watch is bound to
/// the INODE and not to the path. `None` when the root cannot be stat'ed, or on
/// platforms where no inode is available (there, existence is all
/// [`Watcher::root_is_intact`] can check).
#[cfg(unix)]
fn root_identity(root: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    // Follow symlinks: that is the directory the backend actually watches.
    std::fs::metadata(root).ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn root_identity(_root: &Path) -> Option<(u64, u64)> {
    None
}

// ---------------------------------------------------------------------------
// Watcher
// ---------------------------------------------------------------------------

/// Debounce/coalescing window for raw `notify` events. Short so the feedback
/// loop stays snappy; long enough to fold an editor's write burst into one
/// event per path.
///
/// SAFETY REQUIREMENT: this MUST stay `<=` ft-engine's `COMMIT_DEBOUNCE` (300ms,
/// `crates/ft-engine/src/run.rs`). The engine scans the disk 300ms after the
/// last *forwarded* event; any write whose own event was suppressed inside this
/// window must already be on disk by the time that scan runs, i.e. it must have
/// happened at least `DEBOUNCE` before the forwarded event that triggers the
/// scan's timer. At 50ms we have wide margin under the 300ms scan delay.
const DEBOUNCE: Duration = Duration::from_millis(50);

/// Coalescing decision for raw `notify` events, extracted from the `notify`
/// callback so it is testable without a real filesystem (`docs/BUILD-PLAN.md
/// §3`).
///
/// Tracks, per `(kind, path)`, the [`Instant`] the event was last FORWARDED
/// (not merely seen). [`Self::should_forward`] answers "should this occurrence
/// be forwarded now?" and, if so, records `now` as the new last-forwarded time.
///
/// This is a debounce, not a one-shot filter: unlike a plain
/// `HashSet<(kind, path)>` that would remember a key forever and suppress
/// every later occurrence for the life of the process, a forwarded key's timer
/// resets, so a change that keeps recurring after the window elapses keeps
/// being forwarded (at most once per [`DEBOUNCE`] window per key).
///
/// Suppressed occurrences do NOT update the recorded time — otherwise a
/// continuous burst (writes closer together than `DEBOUNCE`) would keep
/// pushing the window forward and starve the callback indefinitely.
#[derive(Debug, Default)]
struct CoalesceBuffer {
    last_forwarded: HashMap<(ChangeKind, PathBuf), Instant>,
}

impl CoalesceBuffer {
    fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if a `(kind, path)` occurrence at `now` should be
    /// forwarded: either it is the first time this key is seen, or at least
    /// [`DEBOUNCE`] has elapsed since the last time it was forwarded. When
    /// `true`, records `now` as the key's new last-forwarded time.
    ///
    /// Also opportunistically purges entries older than [`DEBOUNCE`] so the
    /// map does not grow unbounded over a long-lived watch (`§3`). The map
    /// only ever holds keys touched recently, so this scan is cheap.
    fn should_forward(&mut self, kind: ChangeKind, path: &Path, now: Instant) -> bool {
        let forward = match self.last_forwarded.get(&(kind, path.to_path_buf())) {
            Some(last) => now.duration_since(*last) >= DEBOUNCE,
            None => true,
        };
        if forward {
            self.last_forwarded.insert((kind, path.to_path_buf()), now);
        }
        self.last_forwarded
            .retain(|_, last| now.duration_since(*last) < DEBOUNCE);
        forward
    }

    /// Number of tracked keys (test helper).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.last_forwarded.len()
    }
}

/// A recursive filesystem watcher over a Space's local root.
///
/// Construct with [`Watcher::new`], passing the root and a [`Sender`] the engine
/// drains for [`ChangeEvent`]s. The watcher keeps the underlying `notify` backend
/// alive for its lifetime (dropping the `Watcher` stops watching) and owns the
/// [`AppliedState`] used by [`is_echo`]; mark applied writes through
/// [`Watcher::mark_applied`].
///
/// A watch does not necessarily stay alive as long as the `Watcher` does, so the
/// owner is expected to poll [`Watcher::is_healthy`] and [`Watcher::rewatch`] when
/// it turns false (see the module docs).
pub struct Watcher {
    /// The `notify` backend. Kept alive to keep watching, and re-armed by
    /// [`Watcher::rewatch`].
    inner: RecommendedWatcher,
    /// The root handed to `notify`, kept verbatim so the watch can be re-armed
    /// over the same path.
    root: PathBuf,
    /// Identity of the root when the watch was last armed, so
    /// [`Watcher::root_is_intact`] can tell "the same directory" from "a new
    /// directory at the same path".
    root_id: Option<(u64, u64)>,
    /// Echo-suppression marks, shared with the engine via [`Watcher::applied_state`].
    applied: Arc<AppliedState>,
    /// Watch liveness, shared with the caller via [`Watcher::health`].
    health: Arc<WatchHealth>,
}

impl Watcher {
    /// Starts a recursive watcher over `root`, emitting coalesced
    /// [`ChangeEvent`]s on `sender`.
    ///
    /// Raw `notify` events are debounced/coalesced via [`CoalesceBuffer`]: at
    /// most one [`ChangeEvent`] per `(kind, path)` per [`DEBOUNCE`] window is
    /// sent, but — unlike a one-shot dedup — a `(kind, path)` that keeps
    /// recurring keeps being forwarded, once per window, for as long as the
    /// watcher runs. Suppression of our own writes is NOT done here (notify has
    /// no `pcid`); the engine applies [`is_echo`] against
    /// [`Watcher::applied_state`].
    pub fn new(root: PathBuf, sender: Sender<ChangeEvent>) -> Result<Self> {
        let applied = Arc::new(AppliedState::new());
        let health = Arc::new(WatchHealth::new());

        // Coalescing buffer: collapse a burst of raw events into at most one
        // event per (kind, path) per DEBOUNCE window. Cheap and deterministic;
        // the engine re-stats anyway.
        let coalesce: Arc<Mutex<CoalesceBuffer>> = Arc::new(Mutex::new(CoalesceBuffer::new()));

        let cb_sender = sender.clone();
        let cb_health = Arc::clone(&health);
        let cb_roots = root_aliases(&root);
        let mut inner = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                let event = match res {
                    Ok(ev) => ev,
                    Err(err) => {
                        // Record before logging: a log line nobody greps is how a
                        // dead watch became invisible in the first place.
                        cb_health.record_error(&err);
                        tracing::warn!(?err, "notify watch error");
                        return;
                    }
                };
                if is_root_lost(&event.kind, &event.paths, &cb_roots) {
                    cb_health.mark_lost();
                    tracing::warn!(
                        root = ?cb_roots.first(),
                        "watch root removed or moved; the watch must be re-armed"
                    );
                    // Fall through: the event itself is still forwarded unchanged.
                }
                let kind = match map_kind(&event.kind) {
                    Some(k) => k,
                    None => return, // access/other: not a content change we report
                };
                let now = Instant::now();
                let mut buf = coalesce.lock().expect("coalesce mutex poisoned");
                for path in event.paths {
                    if buf.should_forward(kind, &path, now) {
                        let _ = cb_sender.send(ChangeEvent { kind, path });
                    }
                }
            },
            Config::default().with_poll_interval(DEBOUNCE),
        )?;

        inner.watch(&root, RecursiveMode::Recursive)?;
        let root_id = root_identity(&root);

        Ok(Self {
            inner,
            root,
            root_id,
            applied,
            health,
        })
    }

    /// Re-arms the recursive watch over the root, for a caller that observed the
    /// watch is no longer healthy.
    ///
    /// Idempotent: it unwatches first — ignoring "not watched", which is exactly
    /// the state a dead watch is in, and which on FSEvents also avoids registering
    /// the same path twice — then watches again, so the new watch binds to whatever
    /// directory now lives at the root path. On success the root identity is
    /// re-recorded and the lost flag cleared; on failure the flag is SET so the
    /// caller keeps retrying (the root may still be missing, e.g. a volume that has
    /// not remounted yet).
    ///
    /// The caller must treat a successful rewatch as "the tree may have changed
    /// without us being told" and force a full scan/commit: nothing that happened
    /// during the blind window produced an event.
    pub fn rewatch(&mut self) -> Result<()> {
        let _ = self.inner.unwatch(&self.root);
        if let Err(err) = self.inner.watch(&self.root, RecursiveMode::Recursive) {
            self.health.record_error(&err);
            self.health.mark_lost();
            return Err(err.into());
        }
        self.root_id = root_identity(&self.root);
        self.health.clear_lost();
        Ok(())
    }

    /// Whether the root is still the very directory the watch was armed over.
    ///
    /// Compares the root's `(dev, ino)` against the one recorded when the watch was
    /// armed: on Linux the watch follows the INODE, so a root that was deleted,
    /// moved or replaced keeps its path but gets a new inode and the old watch never
    /// reports again. A root that no longer stats is never intact (`rm -rf`, a
    /// volume that unmounted). Where no inode is available, falls back to existence.
    pub fn root_is_intact(&self) -> bool {
        match (self.root_id, root_identity(&self.root)) {
            (Some(armed), Some(current)) => armed == current,
            (None, _) | (_, None) => self.root.exists(),
        }
    }

    /// Whether this watch is still believed to deliver events for the Space root:
    /// nothing marked it lost AND the root is still the same directory it was armed
    /// over. The supervisor polls this and calls [`Watcher::rewatch`] when it turns
    /// false (see the module docs).
    pub fn is_healthy(&self) -> bool {
        !self.health.is_lost() && self.root_is_intact()
    }

    /// The shared [`WatchHealth`] this watcher records into, so errors and watch
    /// loss can be polled (metrics, `filething status`) without holding the
    /// `Watcher` itself.
    pub fn health(&self) -> Arc<WatchHealth> {
        Arc::clone(&self.health)
    }

    /// Records that the engine just wrote `path` with real `mtime` and `pcid`,
    /// so the resulting FS event is recognized as an echo and suppressed (`§9`).
    /// Delegates to [`AppliedState::mark_applied`].
    pub fn mark_applied(&self, path: CanonicalPath, mtime: i64, pcid: Pcid) {
        self.applied.mark_applied(path, mtime, pcid);
    }

    /// The shared [`AppliedState`] this watcher records into. The engine holds a
    /// clone of this `Arc` and passes it to [`is_echo`] for each incoming event.
    pub fn applied_state(&self) -> Arc<AppliedState> {
        Arc::clone(&self.applied)
    }
}

/// Maps a raw `notify` [`EventKind`] to our coalesced [`ChangeKind`], or `None`
/// for kinds we do not surface (access events, "any/other" noise).
fn map_kind(kind: &EventKind) -> Option<ChangeKind> {
    match kind {
        EventKind::Create(_) => Some(ChangeKind::Created),
        EventKind::Modify(_) => Some(ChangeKind::Modified),
        EventKind::Remove(_) => Some(ChangeKind::Removed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    fn cp(s: &str) -> CanonicalPath {
        CanonicalPath(s.to_string())
    }

    // (1) is_echo true when (path, mtime, pcid) matches what was applied, and
    //     the mark is consumed.
    #[test]
    fn is_echo_true_on_match_and_consumes_mark() {
        let state = AppliedState::new();
        let path = cp("src/main.rs");
        let pcid = Pcid::new([7u8; 32]);
        state.mark_applied(path.clone(), 1_700_000_000, pcid);
        assert_eq!(state.len(), 1);

        // Exact match -> recognized as our own echo.
        assert!(is_echo(&state, &path, 1_700_000_000, &pcid));
        // Mark consumed: a second identical event is NOT suppressed.
        assert!(state.is_empty());
        assert!(!is_echo(&state, &path, 1_700_000_000, &pcid));
    }

    // (2) is_echo false for a change with a different pcid (a real user edit),
    //     and the mark is NOT consumed.
    #[test]
    fn is_echo_false_on_different_pcid() {
        let state = AppliedState::new();
        let path = cp("notes.txt");
        let applied = Pcid::new([1u8; 32]);
        let edited = Pcid::new([2u8; 32]);
        state.mark_applied(path.clone(), 42, applied);

        // Same path + mtime but different content -> real edit, not an echo.
        assert!(!is_echo(&state, &path, 42, &edited));
        // The mark for the applied content survives (only a true match consumes).
        assert_eq!(state.len(), 1);
        assert!(is_echo(&state, &path, 42, &applied));
    }

    // Extra coverage: a different mtime (same pcid) is also not an echo, and an
    // unmarked path is never an echo.
    #[test]
    fn is_echo_false_on_different_mtime_or_unknown_path() {
        let state = AppliedState::new();
        let path = cp("a/b.bin");
        let pcid = Pcid::new([9u8; 32]);
        state.mark_applied(path.clone(), 100, pcid);

        assert!(!is_echo(&state, &path, 101, &pcid)); // mtime differs
        assert_eq!(state.len(), 1); // not consumed
        assert!(!is_echo(&state, &cp("other"), 100, &pcid)); // unmarked path
    }

    // A Dir/Symlink mark is recorded with the contentless zero pcid (ADR 0019), so
    // no recomputed event pcid can ever match it and nothing consumes it. It must
    // be evicted once its TTL elapsed instead of living for the daemon's lifetime.
    #[test]
    fn a_mark_no_event_ever_consumes_is_swept_once_its_ttl_elapsed() {
        let state = AppliedState::new();
        let dir = cp("some/dir");
        let zero = Pcid::new([0u8; 32]);
        let t0 = Instant::now();
        state.mark_applied_at(dir.clone(), 10, zero, t0);
        assert_eq!(state.len(), 1);

        // A later apply, past the TTL, sweeps the stale mark instead of adding to it.
        let t1 = t0 + MARK_TTL + Duration::from_secs(1);
        state.mark_applied_at(cp("other"), 11, Pcid::new([1u8; 32]), t1);
        assert_eq!(state.len(), 1, "the unconsumable mark should be swept");
        assert!(!is_echo_at(&state, &dir, 10, &zero, t1));
    }

    // An expired mark must not suppress anything even if no sweep has run yet:
    // a mark that old cannot be the echo of a write still in flight.
    #[test]
    fn an_expired_mark_is_not_an_echo_and_is_dropped_on_lookup() {
        let state = AppliedState::new();
        let path = cp("notes.txt");
        let pcid = Pcid::new([3u8; 32]);
        let t0 = Instant::now();
        state.mark_applied_at(path.clone(), 7, pcid, t0);

        let t1 = t0 + MARK_TTL;
        assert!(!is_echo_at(&state, &path, 7, &pcid, t1));
        assert!(state.is_empty(), "the expired mark should not linger");
    }

    // The eviction must not weaken suppression: a mark still inside its TTL
    // survives sweeps and is still recognized as our own write.
    #[test]
    fn marks_inside_their_ttl_survive_sweeps_and_still_suppress() {
        let state = AppliedState::new();
        let path = cp("still/fresh.txt");
        let pcid = Pcid::new([4u8; 32]);
        let t0 = Instant::now();
        state.mark_applied_at(path.clone(), 5, pcid, t0);

        // Later applies (each one a sweep opportunity) must leave it alone.
        let mut t = t0;
        for i in 0..5 {
            t += MARK_SWEEP_INTERVAL;
            state.mark_applied_at(cp(&format!("noise/{i}")), 1, Pcid::new([9u8; 32]), t);
        }
        assert!(t - t0 < MARK_TTL, "test must stay inside the TTL");
        assert!(is_echo_at(&state, &path, 5, &pcid, t));
    }

    // mark_applied overwrites a prior mark for the same path.
    #[test]
    fn mark_applied_overwrites_same_path() {
        let state = AppliedState::new();
        let path = cp("x");
        state.mark_applied(path.clone(), 1, Pcid::new([1u8; 32]));
        state.mark_applied(path.clone(), 2, Pcid::new([2u8; 32]));
        assert_eq!(state.len(), 1);
        // Old mark gone, new mark recognized.
        assert!(!is_echo(&state, &path, 1, &Pcid::new([1u8; 32])));
        assert!(is_echo(&state, &path, 2, &Pcid::new([2u8; 32])));
    }

    // ---- CoalesceBuffer (coalescing debounce, not one-shot dedup) --------

    // THE bug test: the same (kind, path) occurring twice, separated by more
    // than DEBOUNCE, must be forwarded BOTH times. A plain "first occurrence
    // wins forever" dedup fails this because it never forgets the key.
    #[test]
    fn same_key_forwarded_again_after_debounce_elapses() {
        let mut buf = CoalesceBuffer::new();
        let path = PathBuf::from("/space/file.txt");
        let t0 = Instant::now();

        assert!(buf.should_forward(ChangeKind::Modified, &path, t0));
        // Well past the window.
        let t1 = t0 + DEBOUNCE + Duration::from_millis(1);
        assert!(buf.should_forward(ChangeKind::Modified, &path, t1));
    }

    // Same (kind, path) twice within the window: only the first is forwarded.
    #[test]
    fn same_key_suppressed_within_window() {
        let mut buf = CoalesceBuffer::new();
        let path = PathBuf::from("/space/file.txt");
        let t0 = Instant::now();

        assert!(buf.should_forward(ChangeKind::Modified, &path, t0));
        let t1 = t0 + DEBOUNCE / 2;
        assert!(!buf.should_forward(ChangeKind::Modified, &path, t1));
    }

    // A continuous burst every 10ms for 200ms must still be forwarded roughly
    // every DEBOUNCE (~50ms), not just once at the very start. Suppressed
    // occurrences must not push the window forward indefinitely.
    #[test]
    fn continuous_burst_forwards_periodically_not_just_once() {
        let mut buf = CoalesceBuffer::new();
        let path = PathBuf::from("/space/file.txt");
        let t0 = Instant::now();
        let step = Duration::from_millis(10);

        let mut forwarded = 0;
        let mut t = t0;
        while t < t0 + Duration::from_millis(200) {
            if buf.should_forward(ChangeKind::Modified, &path, t) {
                forwarded += 1;
            }
            t += step;
        }

        // ~200ms / 50ms window => ~4 forwards; assert loosely to avoid
        // over-fitting to exact boundary rounding.
        assert!(
            forwarded >= 3,
            "expected at least 3 forwards over a 200ms burst, got {forwarded}"
        );
    }

    // Different kind, same path: independent keys, neither suppresses the
    // other.
    #[test]
    fn different_kind_same_path_not_suppressed() {
        let mut buf = CoalesceBuffer::new();
        let path = PathBuf::from("/space/file.txt");
        let t0 = Instant::now();

        assert!(buf.should_forward(ChangeKind::Created, &path, t0));
        assert!(buf.should_forward(ChangeKind::Modified, &path, t0));
    }

    // Same kind, different path: independent keys, neither suppresses the
    // other.
    #[test]
    fn same_kind_different_path_not_suppressed() {
        let mut buf = CoalesceBuffer::new();
        let t0 = Instant::now();

        assert!(buf.should_forward(ChangeKind::Modified, Path::new("/a"), t0));
        assert!(buf.should_forward(ChangeKind::Modified, Path::new("/b"), t0));
    }

    // Opportunistic purge: once "now" moves past the window, stale entries
    // must not linger in the map forever.
    #[test]
    fn stale_entries_are_purged() {
        let mut buf = CoalesceBuffer::new();
        let t0 = Instant::now();

        assert!(buf.should_forward(ChangeKind::Modified, Path::new("/a"), t0));
        assert!(buf.should_forward(ChangeKind::Created, Path::new("/b"), t0));
        assert_eq!(buf.len(), 2);

        // Advance well past the window and touch an unrelated key: the purge
        // is opportunistic (runs on each call), so this should sweep the old
        // entries instead of letting the map grow unbounded.
        let t1 = t0 + DEBOUNCE * 10;
        assert!(buf.should_forward(ChangeKind::Modified, Path::new("/c"), t1));
        assert_eq!(buf.len(), 1, "stale entries should have been purged");
    }

    // Drains `rx` until an event for a file named `name` shows up, or a short
    // budget elapses. notify's backends are asynchronous, so polling is the only
    // way to observe one.
    fn saw_event_for(rx: &std::sync::mpsc::Receiver<ChangeEvent>, name: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(ev) => {
                    if ev.path.file_name().and_then(|n| n.to_str()) == Some(name) {
                        return true;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        false
    }

    // (3) Optional, with tempfile: a real filesystem change fires an event.
    #[test]
    fn real_change_fires_an_event() {
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let (tx, rx) = channel();
        let _watcher = Watcher::new(dir.path().to_path_buf(), tx).expect("watcher");

        // Create a file under the watched root.
        let file = dir.path().join("hello.txt");
        fs::write(&file, b"hello").expect("write");

        assert!(
            saw_event_for(&rx, "hello.txt"),
            "expected a change event for the created file"
        );
    }

    // ---- Watch liveness -------------------------------------------------

    // A backend error must land on the shared health, not only in a log line:
    // that is the ONLY thing notify tells the process when a watch misbehaves.
    #[test]
    fn a_backend_error_is_recorded_on_the_shared_health() {
        let health = WatchHealth::new();
        assert_eq!(health.errors(), 0);
        assert!(!health.is_lost());

        health.record_error(&notify::Error::generic("backend hiccup"));
        assert_eq!(health.errors(), 1);
        assert!(health.last_error().unwrap().contains("backend hiccup"));
        // A generic error says nothing about the ROOT, so re-arming is not implied.
        assert!(!health.is_lost());
    }

    // WatchNotFound / PathNotFound mean the watch itself is gone: that is a lost
    // watch and the caller must re-arm it.
    #[test]
    fn a_missing_watch_or_path_error_marks_the_watch_lost() {
        let health = WatchHealth::new();
        health.record_error(&notify::Error::watch_not_found());
        assert!(health.is_lost());

        let health = WatchHealth::new();
        health.record_error(&notify::Error::path_not_found());
        assert!(health.is_lost());
    }

    // inotify reports the root's own deletion as an ordinary remove event carrying
    // the root path, then drops the watch descriptor without an error: recognizing
    // that event is what keeps the death from being silent.
    #[test]
    fn a_remove_event_for_the_root_itself_is_watch_loss() {
        let root = PathBuf::from("/space");
        let roots = vec![root.clone()];
        let kind = EventKind::Remove(notify::event::RemoveKind::Folder);
        assert!(is_root_lost(&kind, &[root], &roots));
    }

    // MOVE_SELF on the root surfaces as a rename event on the root path; the
    // descriptor survives but no longer covers the path we sync.
    #[test]
    fn a_rename_event_for_the_root_itself_is_watch_loss() {
        let root = PathBuf::from("/space");
        let roots = vec![root.clone()];
        let kind = EventKind::Modify(ModifyKind::Name(notify::event::RenameMode::From));
        assert!(is_root_lost(&kind, &[root], &roots));
    }

    // Ordinary churn inside the Space must never look like watch loss, or the
    // supervisor would re-arm on every deleted file.
    #[test]
    fn removals_inside_the_root_are_not_watch_loss() {
        let root = PathBuf::from("/space");
        let roots = vec![root.clone()];
        let child = root.join("notes.txt");
        let removed = EventKind::Remove(notify::event::RemoveKind::File);
        assert!(!is_root_lost(
            &removed,
            std::slice::from_ref(&child),
            &roots
        ));
        let created = EventKind::Create(notify::event::CreateKind::File);
        assert!(!is_root_lost(&created, &[root], &roots));
    }

    // THE silent-death test: on Linux the watch is bound to the root's INODE, so a
    // restore-from-backup (`mv space space.old && cp -a backup space`) leaves the
    // watch over an inode nobody writes to and the daemon goes deaf forever while
    // still looking healthy. The watcher must report that, and rewatch() must
    // re-arm over whatever directory now lives at the root path.
    #[cfg(unix)]
    #[test]
    fn a_root_replaced_by_a_new_directory_is_unhealthy_until_rewatch_re_arms_it() {
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("space");
        fs::create_dir(&root).expect("create root");

        let (tx, rx) = channel();
        let mut watcher = Watcher::new(root.clone(), tx).expect("watcher");
        assert!(
            watcher.is_healthy(),
            "a fresh watch over an existing root is healthy"
        );

        // Same path, different directory. The old one stays alive under space.old,
        // so its inode number cannot be recycled by the new one.
        fs::rename(&root, dir.path().join("space.old")).expect("move the root aside");
        fs::create_dir(&root).expect("recreate the root");
        assert!(
            !watcher.is_healthy(),
            "the watch no longer covers the directory at the root path"
        );

        watcher.rewatch().expect("rewatch");
        assert!(
            watcher.is_healthy(),
            "rewatch re-arms the watch over the new directory"
        );
        assert!(!watcher.health().is_lost());

        // And the re-armed watch really does deliver events again.
        fs::write(root.join("after.txt"), b"x").expect("write");
        assert!(
            saw_event_for(&rx, "after.txt"),
            "expected an event from the re-armed watch"
        );
    }

    // A root that vanished (rm -rf, a volume that unmounted) must not look healthy,
    // and a rewatch that cannot succeed must leave it that way so the caller retries.
    #[test]
    fn a_vanished_root_is_unhealthy_and_a_failed_rewatch_keeps_it_that_way() {
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("space");
        fs::create_dir(&root).expect("create root");

        let (tx, _rx) = channel();
        let mut watcher = Watcher::new(root.clone(), tx).expect("watcher");
        assert!(watcher.is_healthy());

        fs::remove_dir_all(&root).expect("remove the root");
        assert!(!watcher.is_healthy(), "there is nothing left to watch");
        assert!(watcher.rewatch().is_err(), "cannot re-arm a missing root");
        assert!(!watcher.is_healthy());
        assert!(watcher.health().is_lost());
    }
}
