//! ft-conflict — three-way per-file conflict resolution (`docs/format.md §10`).
//!
//! Reconciliation happens PER PATH against the common base. For one path three
//! states are compared:
//!
//! - `base`   — the [`FileEntry`] from the common base Revision (or `None` if
//!   the path did not exist there),
//! - `local`  — the path's state on this Device's disk/index (or `None`),
//! - `remote` — the path's state in the incoming Revision (or `None`).
//!
//! "Changed against base" is decided CAUSALLY, by type-keyed content identity
//! (`pcid` + exec bit `x` for files, literal target `lt` for symlinks, type
//! alone for derived and dir) — NEVER by clock/`mtime` (a project decision;
//! `mtime` only speeds the re-scan). A type change (file <-> symlink <-> derived
//! <-> dir) is itself a change. The decision table (`§10`):
//!
//! | local | remote | outcome |
//! |-------|--------|---------|
//! | unchanged | unchanged | [`Resolution::NoChange`] |
//! | changed   | same change (same content identity) | [`Resolution::NoChange`] (converged) |
//! | unchanged | changed   | [`Resolution::FastForwardToRemote`] |
//! | changed   | unchanged | [`Resolution::FastForwardToLocal`] |
//! | deleted (local change) | unchanged | [`Resolution::KeepLocal`] |
//! | unchanged | deleted (remote change) | [`Resolution::TakeRemoteDeletion`] |
//! | changed   | changed (content identity differs) | [`Resolution::ConflictCopy`] (keep both; local loses) |
//! | one side deleted, the other edited | [`Resolution::DeleteVsEditKeepEdit`] |
//!
//! Encryption is OFF in the MVP (`alg=0`, `cid == pcid`); nothing here touches a
//! `Cid` directly. This crate is PURE: it inspects three [`FileEntry`] snapshots
//! and the `(label, seq)` pair and returns a [`Resolution`]; it performs no IO and
//! applies nothing. The caller (the engine) executes the verdict.

use ft_core::{CanonicalPath, CasefoldKey, FileEntry, FileType};

pub mod merge;
pub use merge::{merge3, Merge3};

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// The verdict for one path's three-way merge. Each variant carries the
/// [`FileEntry`] the caller needs to act on, so the engine never has to re-derive
/// which side won.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Nothing to do: neither side changed against base, or both made the
    /// identical change (same `pcid`) and have already converged.
    NoChange,

    /// Only the remote side changed against base. Fast-forward the local Device
    /// to this remote [`FileEntry`] (download/restore it).
    FastForwardToRemote(FileEntry),

    /// Only the local side changed against base. Keep this local [`FileEntry`];
    /// the engine pushes it on the next commit. Remote stayed at base.
    FastForwardToLocal(FileEntry),

    /// Remote deleted the path and local left it at base (local unchanged).
    /// Apply the deletion locally.
    TakeRemoteDeletion,

    /// Local deleted the path and remote left it at base (remote unchanged).
    /// Keep the local deletion; nothing is restored.
    KeepLocal,

    /// Both sides changed the path to DIFFERENT content (the `pcid`s of local
    /// and remote differ from each other and from base). Keep BOTH: `winner` (by
    /// convention the remote) stays at its real path; `loser` (the local) is
    /// renamed to a conflict-copy path so no edit is lost.
    ConflictCopy {
        /// The side kept at the original path (the remote, by convention).
        winner: FileEntry,
        /// The side moved aside under a conflict-copy name (the local), with its
        /// `p` already rewritten via [`conflict_copy_name`].
        loser: FileEntry,
    },

    /// One side deleted the path while the other EDITED it (changed its `pcid`
    /// against base). The edit wins: the edited [`FileEntry`] is kept/restored
    /// and the deletion is NOT applied.
    DeleteVsEditKeepEdit(FileEntry),
}

// ---------------------------------------------------------------------------
// resolve — the three-way decision (docs/format.md §10)
// ---------------------------------------------------------------------------

/// Two [`FileEntry`]s represent the "same content" iff they are causally
/// equivalent for their TYPE. Identity is defined PER `FileType` (`§5.1`) so a
/// change the wire actually records cannot be dropped silently:
///
/// - [`FileType::File`] — `pcid` (whole-file plaintext id) AND `x` (the exec
///   bit): a `chmod +x` with identical bytes is still a real change.
/// - [`FileType::Symlink`] — `lt` (the literal target): a retarget with the same
///   (contentless) `pcid` is still a real change.
/// - [`FileType::Derived`] — nothing beyond the type: derived paths carry no
///   content, so two derived entries are always equivalent.
/// - [`FileType::Dir`] — nothing beyond the type: a directory entry carries no
///   content (ADR 0019), so two dir entries at one path are always equivalent.
///
/// A change of TYPE itself (file <-> symlink <-> derived <-> dir) is never "same
/// content". This is causal, never the clock (`mtime` is never consulted, `§10`).
#[inline]
fn same_content(a: &FileEntry, b: &FileEntry) -> bool {
    a.t == b.t
        && match a.t {
            FileType::File => a.pcid == b.pcid && a.x == b.x,
            FileType::Symlink => a.lt == b.lt,
            FileType::Derived | FileType::Dir => true,
        }
}

/// Did `side` change relative to `base`? Presence/absence is itself a change; for
/// two present entries the comparison is [`same_content`] (type-keyed identity:
/// `pcid`+`x` for files, `lt` for symlinks, type alone for derived).
#[inline]
fn changed(base: Option<&FileEntry>, side: Option<&FileEntry>) -> bool {
    match (base, side) {
        (None, None) => false,
        (Some(b), Some(s)) => !same_content(b, s),
        // appeared (None -> Some) or disappeared (Some -> None) is a change.
        _ => true,
    }
}

/// Resolves one path's three-way merge against the common base.
///
/// `base`/`local`/`remote` are the path's [`FileEntry`] in the base Revision, on
/// local disk, and in the incoming Revision respectively; `None` means the path
/// is absent in that state. `label` and `seq` name the local Device (a
/// human-readable Device name, or its opaque id as a fallback) and the incoming
/// Revision sequence — they parameterize the conflict-copy name so two Devices
/// never collide on the rename. "Changed" is decided by `pcid` only
/// (`docs/format.md §10`); `mtime` is never consulted.
///
/// The result is a pure verdict; the caller applies it.
pub fn resolve(
    base: Option<&FileEntry>,
    local: Option<&FileEntry>,
    remote: Option<&FileEntry>,
    label: &str,
    seq: u64,
) -> Resolution {
    let local_changed = changed(base, local);
    let remote_changed = changed(base, remote);

    // Neither side moved against base -> nothing to do.
    if !local_changed && !remote_changed {
        return Resolution::NoChange;
    }

    // Only the local side moved -> keep local (edit) or honor its deletion.
    if local_changed && !remote_changed {
        return match local {
            Some(l) => Resolution::FastForwardToLocal(l.clone()),
            None => Resolution::KeepLocal,
        };
    }

    // Only the remote side moved -> pull it (edit) or apply its deletion.
    if remote_changed && !local_changed {
        return match remote {
            Some(r) => Resolution::FastForwardToRemote(r.clone()),
            None => Resolution::TakeRemoteDeletion,
        };
    }

    // Both sides moved against base. Sub-cases:
    match (local, remote) {
        // Both present: if they converged on identical content, no conflict;
        // otherwise genuine divergent edits -> keep both, local renamed aside.
        (Some(l), Some(r)) => {
            if same_content(l, r) {
                Resolution::NoChange
            } else {
                let loser = conflict_copy_entry(l, label, seq);
                Resolution::ConflictCopy {
                    winner: r.clone(),
                    loser,
                }
            }
        }
        // Delete-vs-edit: one side gone, the other edited -> the edit wins.
        (Some(l), None) => Resolution::DeleteVsEditKeepEdit(l.clone()),
        (None, Some(r)) => Resolution::DeleteVsEditKeepEdit(r.clone()),
        // Both deleted (Some(base) -> None on both sides) -> converged on
        // absence; nothing to do.
        (None, None) => Resolution::NoChange,
    }
}

/// Clones `entry` and rewrites its `p` to the conflict-copy path, leaving content
/// (`pcid`, `bk`, …) untouched — only the key moves aside.
fn conflict_copy_entry(entry: &FileEntry, label: &str, seq: u64) -> FileEntry {
    let mut loser = entry.clone();
    loser.p = conflict_copy_name(&entry.p, label, seq);
    loser
}

// ---------------------------------------------------------------------------
// conflict_copy_name — deterministic loser rename (docs/format.md §10)
// ---------------------------------------------------------------------------

/// Builds the DETERMINISTIC conflict-copy path for a loser: inserts
/// `" (conflicto <label>, seq <seq>)"` before the file extension (or at the end
/// when there is no extension), preserving the directory prefix.
///
/// `label` is the human-readable Device name (or its opaque id as a fallback) that
/// makes the copy legible instead of cryptic. It is SANITIZED first (`/`, `(`, `)`
/// each collapse to `_`) so the result stays a single valid [`CanonicalPath`]
/// component and cannot confuse [`is_conflict_copy_name`]; every other character —
/// including spaces — is kept verbatim.
///
/// Rules:
/// - The extension is the final `.` segment of the LAST path component, and only
///   when that dot is INTERIOR — strictly after the basename's leading-dot run
///   and not the final byte. A dotfile like `.gitignore` (or `..hidden`) has its
///   whole basename as the dotfile stem, so the suffix goes at the end; a
///   trailing dot is likewise not an extension.
/// - Directory components are never touched.
/// - Pure and deterministic: same inputs always yield the same path.
///
/// Examples (`label = "dev1"`, `seq = 7`):
/// - `notes.txt`         -> `notes (conflicto dev1, seq 7).txt`
/// - `README`            -> `README (conflicto dev1, seq 7)`
/// - `a/b/report.tar.gz` -> `a/b/report.tar (conflicto dev1, seq 7).gz`
/// - `.gitignore`        -> `.gitignore (conflicto dev1, seq 7)`
/// - `..hidden`          -> `..hidden (conflicto dev1, seq 7)`
/// - `a..b`              -> `a. (conflicto dev1, seq 7).b`
pub fn conflict_copy_name(path: &CanonicalPath, label: &str, seq: u64) -> CanonicalPath {
    let full = path.as_str();
    let label = sanitize_label(label);
    let suffix = format!(" (conflicto {label}, seq {seq})");

    // Split off the directory prefix (everything up to and including the last
    // '/'); the rename only rewrites the final component.
    let (dir, name) = match full.rfind('/') {
        Some(i) => full.split_at(i + 1), // dir keeps the trailing '/'
        None => ("", full),
    };

    // A dotfile basename keeps its ENTIRE leading-dot run as part of the stem:
    // `.gitignore` and `..hidden` are dotfiles with no extension. Measure that
    // leading run so the extension dot must come strictly after it.
    let leading_dots = name.bytes().take_while(|&b| b == b'.').count();

    // The extension dot is the last '.' in `name` that is INTERIOR: after the
    // leading-dot run (so a dotfile's own dots never count) and not the final
    // byte (a trailing dot has no extension chars).
    let ext_dot = name
        .rfind('.')
        .filter(|&i| i >= leading_dots && i + 1 < name.len());

    let renamed = match ext_dot {
        Some(i) => {
            let (stem, ext) = name.split_at(i); // ext includes the leading '.'
            format!("{stem}{suffix}{ext}")
        }
        None => format!("{name}{suffix}"),
    };

    CanonicalPath(format!("{dir}{renamed}"))
}

/// Sanitizes a conflict-copy `label` so it stays a single valid path component:
/// `/` (would spawn a directory), `(` and `)` (would confuse the parenthetical
/// [`is_conflict_copy_name`] scans for) each collapse to `_`. Everything else,
/// spaces included, is preserved so a Device name like `Julian's Mac` reads
/// naturally.
fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .map(|c| match c {
            '/' | '(' | ')' => '_',
            other => other,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// is_conflict_copy_name — recognize a conflict-copy path (both formats)
// ---------------------------------------------------------------------------

/// Reports whether `name` looks like a conflict-copy path produced by
/// [`conflict_copy_name`], recognizing BOTH the current format
/// (`… (conflicto <label>, seq <n>)…`) and the LEGACY one
/// (`… (conflicto <deviceId> <n>)…`) so copies already on disk from an older
/// build are still surfaced by `filething status`.
///
/// It scans for the literal `(conflicto ` marker and, for each occurrence, checks
/// that the parenthesized body ends in a sequence number — `", seq <digits>"` for
/// the current format or ` <digits>` (trailing space-delimited digits) for the
/// legacy one. Passing a full canonical path is fine: the marker only ever appears
/// in the renamed component, but callers that want to match on the basename alone
/// may split it off first.
pub fn is_conflict_copy_name(name: &str) -> bool {
    const MARKER: &str = "(conflicto ";
    let mut rest = name;
    while let Some(start) = rest.find(MARKER) {
        let after = &rest[start + MARKER.len()..];
        match after.find(')') {
            Some(end) => {
                if conflict_marker_body_is_valid(&after[..end]) {
                    return true;
                }
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    false
}

/// True iff `body` (the text between `(conflicto ` and the closing `)`) ends in a
/// sequence number for either format: the current `"<label>, seq <digits>"` or the
/// legacy `"<label> <digits>"`. `<digits>` must be a non-empty run of ASCII digits.
fn conflict_marker_body_is_valid(body: &str) -> bool {
    if let Some((_label, digits)) = body.rsplit_once(", seq ") {
        if is_seq_digits(digits) {
            return true;
        }
    }
    if let Some((_label, digits)) = body.rsplit_once(' ') {
        if is_seq_digits(digits) {
            return true;
        }
    }
    false
}

/// A non-empty run of ASCII digits (a conflict-copy sequence number).
fn is_seq_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// collision_is_conflict — casefold/NFC collision (docs/format.md §5.2, §10)
// ---------------------------------------------------------------------------

/// Reports whether two paths are a case-only / NFC collision, which `§5.2` and
/// `§10` treat as a CONFLICT (never silently overwrite one with the other).
///
/// True iff the two [`CasefoldKey`]s are equal (`casefold(NFC(p))` collapses
/// them) while the real [`CanonicalPath`] keys differ byte-for-byte — i.e. two
/// distinct on-disk names that fold to the same key (case-only on a
/// case-insensitive peer, or precomposed-vs-decomposed across macOS/Linux).
/// Identical paths are NOT a collision.
pub fn collision_is_conflict(
    a: &CasefoldKey,
    b: &CasefoldKey,
    ka: &CanonicalPath,
    kb: &CanonicalPath,
) -> bool {
    a == b && ka != kb
}

#[cfg(test)]
mod tests {
    use super::*;
    use ft_core::{Cid, FileType, Pcid};

    // ---- helpers -------------------------------------------------------

    /// A file entry at `path` whose whole-file plaintext id is `pcid_byte`
    /// repeated. Distinct `pcid_byte` => distinct content (the §10 signal).
    fn file(path: &str, pcid_byte: u8) -> FileEntry {
        FileEntry {
            p: CanonicalPath(path.to_string()),
            t: FileType::File,
            x: false,
            sz: 1,
            pcid: Pcid::new([pcid_byte; 32]),
            bk: vec![Cid::new([pcid_byte; 32])],
            bk_ref: None,
            lt: None,
            wu: None,
        }
    }

    /// A file entry whose executable bit is explicitly set to `x`. Content
    /// (`pcid`) is keyed on `pcid_byte` exactly like [`file`].
    fn file_x(path: &str, pcid_byte: u8, x: bool) -> FileEntry {
        let mut e = file(path, pcid_byte);
        e.x = x;
        e
    }

    /// A symlink entry at `path` pointing at `target`. Symlinks carry no real
    /// block content, so `pcid` is held constant (zeroed) to prove identity is
    /// decided by `lt`, not `pcid`.
    fn symlink(path: &str, target: &str) -> FileEntry {
        FileEntry {
            p: CanonicalPath(path.to_string()),
            t: FileType::Symlink,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: None,
            lt: Some(target.to_string()),
            wu: None,
        }
    }

    /// A derived entry at `path` (e.g. `target/`, `node_modules/`). Derived
    /// paths carry no content; identity is by type alone.
    fn derived(path: &str) -> FileEntry {
        FileEntry {
            p: CanonicalPath(path.to_string()),
            t: FileType::Derived,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: None,
            lt: None,
            wu: None,
        }
    }

    const DEV: &str = "dev1";
    const SEQ: u64 = 7;

    fn resolve3(
        base: Option<&FileEntry>,
        local: Option<&FileEntry>,
        remote: Option<&FileEntry>,
    ) -> Resolution {
        resolve(base, local, remote, DEV, SEQ)
    }

    // ---- decision table: no change / converge --------------------------

    #[test]
    fn no_change_when_all_three_present_and_equal() {
        let base = file("a.txt", 1);
        let local = file("a.txt", 1);
        let remote = file("a.txt", 1);
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::NoChange
        );
    }

    #[test]
    fn no_change_when_path_absent_everywhere() {
        assert_eq!(resolve3(None, None, None), Resolution::NoChange);
    }

    #[test]
    fn converge_when_both_sides_made_the_same_edit() {
        // base=1, both sides moved to the SAME new content (2) -> converged.
        let base = file("a.txt", 1);
        let local = file("a.txt", 2);
        let remote = file("a.txt", 2);
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::NoChange
        );
    }

    #[test]
    fn converge_when_both_sides_added_identical_new_file() {
        // No base; both sides created the same content -> converged.
        let local = file("new.txt", 5);
        let remote = file("new.txt", 5);
        assert_eq!(
            resolve3(None, Some(&local), Some(&remote)),
            Resolution::NoChange
        );
    }

    #[test]
    fn converge_when_both_sides_deleted() {
        let base = file("a.txt", 1);
        assert_eq!(resolve3(Some(&base), None, None), Resolution::NoChange);
    }

    // ---- decision table: one-sided change (fast-forward) ---------------

    #[test]
    fn fast_forward_to_remote_when_only_remote_edited() {
        let base = file("a.txt", 1);
        let local = file("a.txt", 1); // unchanged
        let remote = file("a.txt", 2); // edited
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::FastForwardToRemote(remote)
        );
    }

    #[test]
    fn fast_forward_to_remote_when_remote_added_new_file() {
        let remote = file("new.txt", 3);
        assert_eq!(
            resolve3(None, None, Some(&remote)),
            Resolution::FastForwardToRemote(remote)
        );
    }

    #[test]
    fn fast_forward_to_local_when_only_local_edited() {
        let base = file("a.txt", 1);
        let local = file("a.txt", 9); // edited
        let remote = file("a.txt", 1); // unchanged
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::FastForwardToLocal(local)
        );
    }

    #[test]
    fn fast_forward_to_local_when_local_added_new_file() {
        let local = file("new.txt", 4);
        assert_eq!(
            resolve3(None, Some(&local), None),
            Resolution::FastForwardToLocal(local)
        );
    }

    // ---- decision table: deletions where the other side is unchanged ---

    #[test]
    fn take_remote_deletion_when_local_unchanged() {
        let base = file("a.txt", 1);
        let local = file("a.txt", 1); // unchanged at base; remote deleted it
        assert_eq!(
            resolve3(Some(&base), Some(&local), None),
            Resolution::TakeRemoteDeletion
        );
    }

    #[test]
    fn keep_local_deletion_when_remote_unchanged() {
        let base = file("a.txt", 1);
        let remote = file("a.txt", 1); // unchanged at base; local deleted it
        assert_eq!(
            resolve3(Some(&base), None, Some(&remote)),
            Resolution::KeepLocal
        );
    }

    // ---- decision table: both changed -> conflict copy -----------------

    #[test]
    fn conflict_copy_when_both_sides_edited_differently() {
        let base = file("a.txt", 1);
        let local = file("a.txt", 2); // local edit
        let remote = file("a.txt", 3); // different remote edit
        match resolve3(Some(&base), Some(&local), Some(&remote)) {
            Resolution::ConflictCopy { winner, loser } => {
                // Remote wins the real path; local is moved aside.
                assert_eq!(winner, remote);
                assert_eq!(loser.p.as_str(), "a (conflicto dev1, seq 7).txt");
                // The loser keeps the LOCAL content (only the key moved).
                assert_eq!(loser.pcid, local.pcid);
                assert_eq!(loser.bk, local.bk);
            }
            other => panic!("expected ConflictCopy, got {other:?}"),
        }
    }

    #[test]
    fn conflict_copy_when_both_sides_added_different_content() {
        // No base; both created the path with different content -> conflict.
        let local = file("new.txt", 8);
        let remote = file("new.txt", 9);
        match resolve3(None, Some(&local), Some(&remote)) {
            Resolution::ConflictCopy { winner, loser } => {
                assert_eq!(winner, remote);
                assert_eq!(loser.p.as_str(), "new (conflicto dev1, seq 7).txt");
            }
            other => panic!("expected ConflictCopy, got {other:?}"),
        }
    }

    // ---- decision table: delete-vs-edit -> edit wins -------------------

    #[test]
    fn delete_vs_edit_local_deleted_remote_edited_keeps_remote_edit() {
        let base = file("a.txt", 1);
        let remote = file("a.txt", 2); // remote edited; local deleted -> edit wins
        assert_eq!(
            resolve3(Some(&base), None, Some(&remote)),
            Resolution::DeleteVsEditKeepEdit(remote)
        );
    }

    #[test]
    fn delete_vs_edit_remote_deleted_local_edited_keeps_local_edit() {
        let base = file("a.txt", 1);
        let local = file("a.txt", 5); // local edited; remote deleted -> edit wins
        assert_eq!(
            resolve3(Some(&base), Some(&local), None),
            Resolution::DeleteVsEditKeepEdit(local)
        );
    }

    // ---- content identity is keyed by TYPE (x / lt / derived) ----------

    #[test]
    fn chmod_only_change_is_detected_and_fast_forwarded() {
        // Same content (pcid=1) on every side, but local flipped the exec bit.
        // Remote stayed at base. The chmod is a real change -> keep local so the
        // engine propagates it; comparing pcid alone would drop it as NoChange.
        let base = file_x("script.sh", 1, false);
        let local = file_x("script.sh", 1, true); // chmod +x, same bytes
        let remote = file_x("script.sh", 1, false); // unchanged
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::FastForwardToLocal(local)
        );
    }

    #[test]
    fn chmod_plus_remote_edit_is_a_conflict_not_silent_loss() {
        // base: script x=false. local: chmod +x (same bytes). remote: edited the
        // bytes (no chmod). Both sides changed against base -> ConflictCopy, so
        // neither the +x nor the remote edit is silently lost.
        let base = file_x("script.sh", 1, false);
        let local = file_x("script.sh", 1, true); // chmod +x only
        let remote = file_x("script.sh", 2, false); // content edit only
        match resolve3(Some(&base), Some(&local), Some(&remote)) {
            Resolution::ConflictCopy { winner, loser } => {
                assert_eq!(winner, remote);
                assert_eq!(loser.p.as_str(), "script (conflicto dev1, seq 7).sh");
                assert!(loser.x, "loser must preserve the local exec bit");
            }
            other => panic!("expected ConflictCopy, got {other:?}"),
        }
    }

    #[test]
    fn identical_chmod_on_both_sides_converges() {
        // base x=false; BOTH sides chmod +x the same bytes -> identical change,
        // already converged -> NoChange.
        let base = file_x("script.sh", 1, false);
        let local = file_x("script.sh", 1, true);
        let remote = file_x("script.sh", 1, true);
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::NoChange
        );
    }

    #[test]
    fn symlink_retarget_only_on_one_side_fast_forwards() {
        // pcid is identical across all three (symlinks have no block content);
        // identity must come from `lt`. Remote retargeted, local stayed.
        let base = symlink("link", "a/old");
        let local = symlink("link", "a/old"); // unchanged
        let remote = symlink("link", "b/new"); // retargeted
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::FastForwardToRemote(remote)
        );
    }

    #[test]
    fn divergent_symlink_retarget_is_a_conflict_not_no_change() {
        // Same pcid everywhere; both sides retargeted to DIFFERENT targets.
        // Comparing pcid alone would wrongly say NoChange.
        let base = symlink("link", "a/old");
        let local = symlink("link", "b/local"); // local retarget
        let remote = symlink("link", "c/remote"); // different remote retarget
        match resolve3(Some(&base), Some(&local), Some(&remote)) {
            Resolution::ConflictCopy { winner, loser } => {
                assert_eq!(winner, remote);
                assert_eq!(loser.lt.as_deref(), Some("b/local"));
            }
            other => panic!("expected ConflictCopy, got {other:?}"),
        }
    }

    #[test]
    fn identical_symlink_retarget_on_both_sides_converges() {
        // Both sides retargeted to the SAME new target -> converged -> NoChange.
        let base = symlink("link", "a/old");
        let local = symlink("link", "b/new");
        let remote = symlink("link", "b/new");
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::NoChange
        );
    }

    #[test]
    fn type_change_file_to_symlink_is_a_change() {
        // base is a file; remote replaced it with a symlink (different type),
        // local unchanged. A type change is a real change -> fast-forward.
        let base = file("p", 1);
        let local = file("p", 1); // unchanged
        let remote = symlink("p", "elsewhere"); // file -> symlink
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::FastForwardToRemote(remote)
        );
    }

    #[test]
    fn derived_entries_with_same_type_never_change() {
        // Derived paths carry no content; same type on both sides -> NoChange
        // even though their (zeroed) pcid is equal — identity is type-only.
        let base = derived("target");
        let local = derived("target");
        let remote = derived("target");
        assert_eq!(
            resolve3(Some(&base), Some(&local), Some(&remote)),
            Resolution::NoChange
        );
    }

    // ---- conflict_copy_name: deterministic, ext / no-ext / subdirs -----

    #[test]
    fn conflict_copy_name_inserts_before_extension() {
        let p = CanonicalPath("notes.txt".to_string());
        assert_eq!(
            conflict_copy_name(&p, "dev1", 7).as_str(),
            "notes (conflicto dev1, seq 7).txt"
        );
    }

    #[test]
    fn conflict_copy_name_no_extension_appends_at_end() {
        let p = CanonicalPath("README".to_string());
        assert_eq!(
            conflict_copy_name(&p, "dev1", 7).as_str(),
            "README (conflicto dev1, seq 7)"
        );
    }

    #[test]
    fn conflict_copy_name_preserves_subdirectories() {
        let p = CanonicalPath("a/b/report.txt".to_string());
        assert_eq!(
            conflict_copy_name(&p, "deviceX", 42).as_str(),
            "a/b/report (conflicto deviceX, seq 42).txt"
        );
    }

    #[test]
    fn conflict_copy_name_uses_only_the_last_dot_as_extension() {
        let p = CanonicalPath("a/b/report.tar.gz".to_string());
        assert_eq!(
            conflict_copy_name(&p, "dev1", 7).as_str(),
            "a/b/report.tar (conflicto dev1, seq 7).gz"
        );
    }

    #[test]
    fn conflict_copy_name_leading_dot_is_dotfile_not_extension() {
        let p = CanonicalPath(".gitignore".to_string());
        assert_eq!(
            conflict_copy_name(&p, "dev1", 7).as_str(),
            ".gitignore (conflicto dev1, seq 7)"
        );
    }

    #[test]
    fn conflict_copy_name_trailing_dot_is_not_an_extension() {
        // "file." has a trailing dot with no ext chars -> suffix at the end.
        let p = CanonicalPath("file.".to_string());
        assert_eq!(
            conflict_copy_name(&p, "dev1", 7).as_str(),
            "file. (conflicto dev1, seq 7)"
        );
    }

    #[test]
    fn conflict_copy_name_double_leading_dot_has_no_extension() {
        // "..hidden": the only dots are leading (indices 0 and 1). There is no
        // INTERIOR dot, so the whole name is a dotfile stem with no extension;
        // the suffix goes at the end. The buggy "last dot" rule would treat
        // ".hidden" as the extension and split before it.
        let p = CanonicalPath("..hidden".to_string());
        assert_eq!(
            conflict_copy_name(&p, "dev1", 7).as_str(),
            "..hidden (conflicto dev1, seq 7)"
        );
    }

    #[test]
    fn conflict_copy_name_dotfile_with_interior_dot_splits_at_interior_dot() {
        // "..hidden.txt": leading dots at 0,1 are not extensions, but the dot
        // before "txt" IS interior -> that is the extension.
        let p = CanonicalPath("..hidden.txt".to_string());
        assert_eq!(
            conflict_copy_name(&p, "dev1", 7).as_str(),
            "..hidden (conflicto dev1, seq 7).txt"
        );
    }

    #[test]
    fn conflict_copy_name_interior_double_dot_splits_at_last_dot() {
        // "a..b": first dot (index 1) is interior, last dot (index 2) is also
        // interior. The extension is the LAST interior dot -> split before ".b".
        let p = CanonicalPath("a..b".to_string());
        assert_eq!(
            conflict_copy_name(&p, "dev1", 7).as_str(),
            "a. (conflicto dev1, seq 7).b"
        );
    }

    #[test]
    fn conflict_copy_name_uses_human_label_with_spaces() {
        // A real Device name (with a space) reads naturally and stays one
        // component; the extension split is unaffected by the label's spaces.
        let p = CanonicalPath("notes.txt".to_string());
        assert_eq!(
            conflict_copy_name(&p, "Julian's Mac", 5).as_str(),
            "notes (conflicto Julian's Mac, seq 5).txt"
        );
    }

    #[test]
    fn conflict_copy_name_sanitizes_slashes_and_parens_in_label() {
        // A label with `/` would spawn a directory and `(`/`)` would confuse the
        // recognizer; each collapses to `_`, keeping the copy one valid component.
        let p = CanonicalPath("notes.txt".to_string());
        let out = conflict_copy_name(&p, "a/b (x)", 7);
        assert_eq!(out.as_str(), "notes (conflicto a_b _x_, seq 7).txt");
        // Still a single component (no interior '/') and still recognized.
        assert!(!out.as_str()["notes ".len()..].contains('/'));
        assert!(is_conflict_copy_name(out.as_str()));
    }

    // ---- is_conflict_copy_name: recognizes both formats ----------------

    #[test]
    fn is_conflict_copy_name_recognizes_current_format() {
        assert!(is_conflict_copy_name("notes (conflicto dev1, seq 7).txt"));
        assert!(is_conflict_copy_name(
            "README (conflicto Julian's Mac, seq 42)"
        ));
        assert!(is_conflict_copy_name(
            "a/b/report (conflicto dev1, seq 0).gz"
        ));
        // Consistent with what the formatter emits.
        let made = conflict_copy_name(&CanonicalPath("x/y.md".to_string()), "dev1", 3);
        assert!(is_conflict_copy_name(made.as_str()));
    }

    #[test]
    fn is_conflict_copy_name_recognizes_legacy_format() {
        // Copies already on disk from the pre-`seq` build must still be surfaced.
        assert!(is_conflict_copy_name("notes (conflicto dev1 7).txt"));
        assert!(is_conflict_copy_name("README (conflicto k17abc 42)"));
    }

    #[test]
    fn is_conflict_copy_name_rejects_non_conflict_names() {
        assert!(!is_conflict_copy_name("notes.txt"));
        assert!(!is_conflict_copy_name("my (conflicto notes)")); // no seq number
        assert!(!is_conflict_copy_name("(conflicto dev1, seq abc)")); // seq not digits
        assert!(!is_conflict_copy_name("plain (draft 2).txt")); // not the marker
        assert!(!is_conflict_copy_name("")); // empty
    }

    #[test]
    fn conflict_copy_name_is_deterministic() {
        let p = CanonicalPath("a/b/c.rs".to_string());
        let first = conflict_copy_name(&p, "dev1", 7);
        let second = conflict_copy_name(&p, "dev1", 7);
        assert_eq!(first, second);
    }

    #[test]
    fn conflict_copy_name_varies_with_device_and_seq() {
        let p = CanonicalPath("c.rs".to_string());
        assert_ne!(
            conflict_copy_name(&p, "dev1", 7),
            conflict_copy_name(&p, "dev2", 7)
        );
        assert_ne!(
            conflict_copy_name(&p, "dev1", 7),
            conflict_copy_name(&p, "dev1", 8)
        );
    }

    // ---- collision_is_conflict: casefold / NFC collisions --------------

    #[test]
    fn case_only_collision_is_a_conflict() {
        // README.md vs readme.md: same casefold key, different real path.
        let key = CasefoldKey("readme.md".to_string());
        let a = CanonicalPath("README.md".to_string());
        let b = CanonicalPath("readme.md".to_string());
        assert!(collision_is_conflict(&key, &key, &a, &b));
    }

    #[test]
    fn nfc_collision_is_a_conflict() {
        // Precomposed "é" (U+00E9) vs decomposed "e\u{0301}": byte-distinct paths
        // that fold to the same NFC casefold key -> conflict (§5.2 decision).
        let precomposed = CanonicalPath("caf\u{00e9}.txt".to_string());
        let decomposed = CanonicalPath("cafe\u{0301}.txt".to_string());
        assert_ne!(precomposed, decomposed); // byte-distinct on disk
        let folded = CasefoldKey("caf\u{00e9}.txt".to_string()); // same NFC key
        assert!(collision_is_conflict(
            &folded,
            &folded,
            &precomposed,
            &decomposed
        ));
    }

    #[test]
    fn identical_paths_are_not_a_collision() {
        let key = CasefoldKey("readme.md".to_string());
        let p = CanonicalPath("README.md".to_string());
        // Same real path -> not a collision (it's just the same file).
        assert!(!collision_is_conflict(&key, &key, &p, &p));
    }

    #[test]
    fn different_keys_are_not_a_collision() {
        let ka = CasefoldKey("a.txt".to_string());
        let kb = CasefoldKey("b.txt".to_string());
        let pa = CanonicalPath("a.txt".to_string());
        let pb = CanonicalPath("b.txt".to_string());
        assert!(!collision_is_conflict(&ka, &kb, &pa, &pb));
    }
}
