//! ft-watcher — file watcher + echo suppression (`docs/format.md §9`).
//!
//! Two cooperating pieces:
//!
//! 1. A recursive [`Watcher`] over a Space's local root. It uses the `notify`
//!    crate with a short debounce/coalescing window and emits coalesced
//!    [`ChangeEvent`]s ([`ChangeKind::Created`] / [`ChangeKind::Modified`] /
//!    [`ChangeKind::Removed`]) on a channel the engine drains.
//!
//! 2. Echo suppression (`§9`). After the engine writes a file it pulled from the
//!    change feed, it calls [`Watcher::mark_applied`] to record the REAL `mtime`
//!    the filesystem assigned plus the file's `pcid`. When the corresponding FS
//!    event later surfaces, the engine recomputes `(mtime, pcid)` and calls the
//!    pure policy [`is_echo`]: if `(path, mtime, pcid)` matches a recorded
//!    application, the event is recognized as our own (the mark is consumed) and
//!    NOT propagated as a user change; otherwise it is a real edit and flows on.
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
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ft_core::{CanonicalPath, Pcid};
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

/// What the engine just WROTE while applying a change pulled from the feed:
/// the REAL `mtime` the filesystem assigned and the file's `pcid`, keyed by its
/// canonical path. Used purely for echo suppression (`§9`).
///
/// Holds a single mark per path: applying a path again overwrites the previous
/// mark, matching the "latest write wins" reality of the apply loop. Interior
/// mutability (`Mutex<HashMap>`) lets [`is_echo`] CONSUME a matched mark behind a
/// shared `&` reference, so the watcher can hand the same `AppliedState` to the
/// engine without ceremony.
#[derive(Debug, Default)]
pub struct AppliedState {
    marks: Mutex<HashMap<CanonicalPath, (i64, Pcid)>>,
}

impl AppliedState {
    /// A fresh, empty applied-state map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that the engine wrote `path` with real `mtime` and `pcid`.
    /// Overwrites any prior mark for the same path.
    pub fn mark_applied(&self, path: CanonicalPath, mtime: i64, pcid: Pcid) {
        self.marks
            .lock()
            .expect("AppliedState mutex poisoned")
            .insert(path, (mtime, pcid));
    }

    /// Number of outstanding marks (test/diagnostic helper).
    pub fn len(&self) -> usize {
        self.marks
            .lock()
            .expect("AppliedState mutex poisoned")
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
/// Returns `false` when there is no mark for `path`, or the mark's `mtime`/`pcid`
/// differs — that is a real edit by the user and must be emitted. The match is on
/// `pcid` (content identity), never on `mtime` alone, per the causal rule of
/// `§9`/`§10`; `mtime` is part of the key only to tighten the recognition of our
/// own write, not to decide "changed".
pub fn is_echo(state: &AppliedState, path: &CanonicalPath, mtime: i64, pcid: &Pcid) -> bool {
    let mut marks = state.marks.lock().expect("AppliedState mutex poisoned");
    match marks.get(path) {
        Some((m, p)) if *m == mtime && p == pcid => {
            // Recognized as our own application: consume the mark so a later
            // real edit on this path is no longer suppressed.
            marks.remove(path);
            true
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Watcher
// ---------------------------------------------------------------------------

/// Debounce/coalescing window for raw `notify` events. Short so the feedback
/// loop stays snappy; long enough to fold an editor's write burst into one
/// event per path.
const DEBOUNCE: Duration = Duration::from_millis(50);

/// A recursive filesystem watcher over a Space's local root.
///
/// Construct with [`Watcher::new`], passing the root and a [`Sender`] the engine
/// drains for [`ChangeEvent`]s. The watcher keeps the underlying `notify` backend
/// alive for its lifetime (dropping the `Watcher` stops watching) and owns the
/// [`AppliedState`] used by [`is_echo`]; mark applied writes through
/// [`Watcher::mark_applied`].
pub struct Watcher {
    /// Kept alive to keep watching; field is otherwise unused after setup.
    _inner: RecommendedWatcher,
    /// Echo-suppression marks, shared with the engine via [`Watcher::applied_state`].
    applied: Arc<AppliedState>,
}

impl Watcher {
    /// Starts a recursive watcher over `root`, emitting coalesced
    /// [`ChangeEvent`]s on `sender`.
    ///
    /// Raw `notify` events are debounced/coalesced into at most one
    /// [`ChangeEvent`] per `(kind, path)` per [`DEBOUNCE`] window before being
    /// sent. Suppression of our own writes is NOT done here (notify has no
    /// `pcid`); the engine applies [`is_echo`] against [`Watcher::applied_state`].
    pub fn new(root: PathBuf, sender: Sender<ChangeEvent>) -> Result<Self> {
        let applied = Arc::new(AppliedState::new());

        // Coalescing buffer: collapse a burst of raw events into one event per
        // (kind, path). Cheap and deterministic; the engine re-stats anyway.
        let coalesce: Arc<Mutex<HashMap<(ChangeKind, PathBuf), ()>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let cb_sender = sender.clone();
        let mut inner = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                let event = match res {
                    Ok(ev) => ev,
                    Err(err) => {
                        tracing::warn!(?err, "notify watch error");
                        return;
                    }
                };
                let kind = match map_kind(&event.kind) {
                    Some(k) => k,
                    None => return, // access/other: not a content change we report
                };
                let mut buf = coalesce.lock().expect("coalesce mutex poisoned");
                for path in event.paths {
                    // Dedup within the window: only the first occurrence of a
                    // (kind, path) pair is forwarded.
                    if buf.insert((kind, path.clone()), ()).is_none() {
                        let _ = cb_sender.send(ChangeEvent { kind, path });
                    }
                }
            },
            Config::default().with_poll_interval(DEBOUNCE),
        )?;

        inner.watch(&root, RecursiveMode::Recursive)?;

        Ok(Self {
            _inner: inner,
            applied,
        })
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
    use std::time::Instant;

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

        // Drain events until we see one touching our file, or time out. notify's
        // backend is asynchronous, so poll the channel for a short budget.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut saw = false;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(ev) => {
                    if ev.path.file_name().and_then(|n| n.to_str()) == Some("hello.txt") {
                        saw = true;
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        assert!(saw, "expected a change event for the created file");
    }
}
