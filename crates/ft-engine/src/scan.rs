//! `scan` — walk the Space's local root and produce the FileEntry set + the
//! Blocks to upload (`docs/format.md §3`, `§5.1`, `§5.2`, `§9`).
//!
//! `scan` is the first step of a commit (`§7` step 1) AND of a pull, so every sync
//! operation passes through it: it must never fail because of ONE bad path, and it
//! must never let a path it could not read look like a deletion. It walks
//! `local_root` with `walkdir`, skipping the `.filething/` control directory, the
//! built-in platform-junk file names ([`JUNK_NAMES`], ADR 0011), ft-diff's
//! in-flight scratch files (`ft_diff::TMP_SUFFIX`) and any path excluded by
//! `.filethingignore` (empty by default ⇒ nothing excluded, `§Ignore file`).
//! For every surviving entry it:
//!
//! - derives the canonical path ([`ft_fsmap::canonicalize`]) and its
//!   [`CasefoldKey`] ([`ft_fsmap::casefold_key`]);
//! - classifies it ([`ft_fsmap::classify`] + [`ft_fsmap::symlink_policy`]):
//!   - **File** (`t=0`): reads the bytes, chunks them with the Space
//!     [`Chunker`](ft_chunker::Chunker), computes each span's `pcid`/`cid`
//!     (equal in the MVP) and the whole-file `pcid`, builds the ordered `bk`,
//!     and collects each Block's encoded object for upload — UNLESS the `§9`
//!     fast path applies (see [`SpaceContext::reuse_unchanged`]), in which case
//!     the stored `pcid`/`bk` are reused and the file is not read at all;
//!   - **Symlink** (`t=1`): `Preserve(target)` ⇒ a `t=1` FileEntry with `lt` set
//!     and a deterministic `pcid = pcid_of(target_bytes)` (so a retarget changes
//!     the `manifestRoot`); `LocalOnly` ⇒ recorded `local_only` in the index and
//!     KEPT OUT of the Manifest;
//!   - **Derived** (`t=2`): a `t=2` FileEntry with empty `bk` and no uploaded
//!     bytes; the walk does NOT descend into a derived directory.
//!   - **Dir** (`t=3`): a plain directory as a first-class `t=3` FileEntry (empty
//!     `bk`, no bytes) so empty directories sync (ADR 0019); the walk DOES descend
//!     into it. The Space root itself is never an entry.
//!
//! It then upserts the local-index path rows (`upsert_entry`) and DELETES index
//! rows whose path vanished from disk (so they drop out of the next Manifest — a
//! delete is an absence, `§8`). It does NOT touch the `local_block` upload-dedup
//! cache; that is the commit's upload step's job (`§7` step 2). The returned
//! [`ScanResult`] is the `(key, entry)` set ready for [`ft_manifest::build`] plus
//! the de-duplicated Blocks to upload.
//!
//! # A skip is not a deletion
//!
//! Because "deleted" is inferred from ABSENCE (`§8`), anything that makes a path
//! invisible to one scan would otherwise publish a Revision that deletes it on
//! every other Device. So a path the scan declines — unreadable, an unsupported
//! file type, freshly excluded by `.filethingignore`, deferred by the upload
//! budget, or absent-but-derived — keeps its index row and has its Manifest entry
//! republished ([`SpaceContext::entry_from_row`]). On a scan whose result will be
//! PUBLISHED that entry comes from the BASE Revision, not from the index row: a row
//! can name Blocks that never reached the Vault, and a path the base does not carry
//! was never in any Revision, so omitting it deletes nothing anywhere (see
//! [`SpaceContext::scan_with_base`]). Every skip is reported at WARN and in
//! [`ScanResult::skipped`]. The two deliberate exceptions are platform junk
//! (ADR 0011 wants that auto-clean) and ft-diff scratch files (never user data).
//!
//! The one skip that is REPORTED but deliberately NOT retained is an unsyncable
//! NAME ([`SkipReason::UnsyncableName`]): a component holding a `\` or looking
//! like a Windows drive prefix. Such a file is legal here and used to be committed
//! verbatim — which then aborted every other Device's whole pull on that single
//! entry, forever (`ft_diff::apply` now skips it instead of failing). Retaining it
//! would keep the entry in the Manifest for good, so it converges by deletion like
//! junk; the local file is never touched, it just stops syncing.
//!
//! # One key per Manifest
//!
//! `§5.2`/`§5.3` forbid two entries with the same `casefold(NFC(p))` key. The walk
//! can see two such paths on a case-sensitive filesystem (`Notes.md` + `notes.md`,
//! or the NFC and NFD spellings of `café.txt`), so the collision is resolved HERE,
//! before [`ft_manifest::build`]: the lexicographically first path keeps the key
//! and the other is reported loudly (ADR 0006).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ft_block::{cid_for, encode};
use ft_core::{CanonicalPath, CasefoldKey, Cid, FileEntry, FileType, Pcid};
use ft_diff::TMP_SUFFIX;
use ft_fsmap::{canonicalize, casefold_key, classify, is_derived, symlink_policy, SymlinkDecision};
use ft_index::{BlockRef, LocalEntry};
use walkdir::WalkDir;

use crate::context::{join_canonical, SpaceContext};
use crate::error::Result;

/// The control directory name kept out of the Manifest (`§Ignore file` /
/// engine internals). Anything under `.filething/` is never synced.
pub const CONTROL_DIR: &str = ".filething";

/// The per-Space ignore-file name (`§Ignore file`). Empty by default.
pub const IGNORE_FILE: &str = ".filethingignore";

/// Files below this size keep the code-optimized 16/64/256 KiB FastCDC profile
/// regardless of extension. The wider binary profile only pays off when enough
/// Blocks exist to amortize a profile switch.
const LARGE_BINARY_THRESHOLD: usize = 1024 * 1024;

/// Extensions whose formats are already compressed, containerized, or commonly
/// rewritten as opaque binary assets. Matching is ASCII case-insensitive.
const LARGE_BINARY_EXTENSIONS: &[&str] = &[
    "7z", "avi", "bin", "bmp", "bz2", "db", "docx", "flac", "gif", "gz", "ico", "jpeg", "jpg",
    "mkv", "mov", "mp3", "mp4", "ogg", "parquet", "pdf", "png", "pptx", "rar", "sqlite", "sqlite3",
    "tar", "tiff", "wav", "webm", "webp", "xlsx", "xz", "zip", "zst",
];

/// Platform-junk file names ALWAYS excluded from the Manifest, independent of
/// the user's `.filethingignore` (ADR 0011). These are OS-generated sidecars
/// (macOS Finder / Windows Explorer) that carry no user data and must never
/// contaminate a Space — Dropbox/iCloud exclude them too.
///
/// The match is by EXACT entry name, case-sensitive as written (no glob, no
/// extension match): `.DS_Store.bak`, `Thumbs.db.old` or `mythumbs.db` still
/// sync. It applies only on the scanner (outbound) side: the walk never emits
/// these into the Manifest. The apply/diff side is untouched, so a Space that
/// already committed one converges by deletion (ADR 0011).
pub const JUNK_NAMES: [&str; 3] = [".DS_Store", "Thumbs.db", "desktop.ini"];

/// How many bytes of ENCODED Block objects a single scan may buffer for the
/// commit's upload step (`§7` step 2).
///
/// [`ScanResult::blocks_to_upload`] holds every new Block in memory until the
/// commit uploads it, so without a cap peak RSS scales with the total size of the
/// Space and a large Space cannot be scanned at all (the daemon then OOM-loops).
/// Past the cap a file is DEFERRED: it keeps the Manifest entry it already had
/// (never a deletion) and the next scan picks it up, so a big Space converges over
/// several Revisions instead of dying. The budget is checked BEFORE a file, never
/// mid-file, so a single file larger than the cap is still taken whole — bounding
/// THAT needs the streaming upload path, which changes `commit`'s contract.
#[cfg(not(test))]
const MAX_PENDING_UPLOAD_BYTES: usize = 256 * 1024 * 1024;
/// The unit tests cross the budget with kilobytes instead of hundreds of MiB.
#[cfg(test)]
const MAX_PENDING_UPLOAD_BYTES: usize = 1024 * 1024;

/// True if `name` is an exact platform-junk file name (see [`JUNK_NAMES`]).
fn is_junk_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|n| JUNK_NAMES.contains(&n))
}

/// True if `name` is one of ft-diff's in-flight scratch files: it writes a File to
/// a sibling `.<file_name><TMP_SUFFIX>` and renames it ([`ft_diff::TMP_SUFFIX`]).
///
/// A crash between the write and the rename, or a scan racing an apply, would
/// otherwise commit that scratch file and replicate it to every Device forever.
/// The name must carry at least one character of the real file name, so a
/// hand-made file called exactly `.ft-tmp` is still user data and still syncs.
fn is_tmp_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|n| {
        n.starts_with('.') && n.ends_with(TMP_SUFFIX) && n.len() > 1 + TMP_SUFFIX.len()
    })
}

/// Why [`SpaceContext::scan`] left a path out of this Revision.
///
/// Every variant is reported in [`ScanResult::skipped`] and at WARN, because a
/// path that silently stops syncing is indistinguishable from data loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The path could not be read, stat'ed or canonicalized. The message carries
    /// the offending PATH plus the cause: a bare `Permission denied` with no path
    /// is useless to the person who has to fix it.
    Unreadable(String),

    /// Not a regular file, directory or symlink — a FIFO, a unix socket (an
    /// editor's or Postgres's `.s.PGSQL.5432`) or a device node. `§5.1` has no
    /// type for them and `fs::read` on a FIFO blocks FOREVER, so they are never
    /// opened.
    UnsupportedFileType,

    /// Another path already holds this path's `casefold(NFC(p))` Manifest key
    /// (`§5.2`, ADR 0006). Rename one of the two.
    CasefoldCollision {
        /// The colliding path that KEPT the key (the lexicographically first one).
        winner: String,
    },

    /// Excluded by `.filethingignore`. Only reported when the path was ALREADY
    /// synced, i.e. when its Manifest entry got frozen instead of deleted.
    Ignored,

    /// This scan had already buffered [`MAX_PENDING_UPLOAD_BYTES`] of encoded
    /// Blocks; the file waits for the next scan.
    Deferred,

    /// The name cannot be carried across platforms
    /// ([`ft_core::CanonicalPath::unsyncable_reason`]): a component holding a `\`
    /// (a path separator on Windows) or looking like a drive prefix (`a:b.txt`).
    /// The message is that rule, verbatim.
    ///
    /// Such a name is perfectly legal here, which is exactly the problem: the walk
    /// used to canonicalize it byte-for-byte, commit it, and publish it — and then
    /// every other Device's `apply` aborted its WHOLE pull on that one entry,
    /// forever. `ft_diff::apply` now skips the entry instead of failing, and this
    /// is the outbound half of the same agreement: never publish one again. Like
    /// platform junk (ADR 0011) it is NOT retained — the Manifest entry a previous
    /// build published is dropped, so the Space converges by deletion and the peers
    /// stop having to skip it. The local file itself is never touched; it simply
    /// stops syncing, which is why (unlike junk) it IS reported.
    UnsyncableName(&'static str),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(cause) => write!(f, "could not be read: {cause}"),
            Self::UnsupportedFileType => write!(
                f,
                "not a regular file, directory or symlink (FIFO, socket or device node)"
            ),
            Self::CasefoldCollision { winner } => write!(
                f,
                "collides with `{winner}` under casefold(NFC(p)) (§5.2); rename one of them"
            ),
            Self::Ignored => write!(f, "excluded by {IGNORE_FILE}"),
            Self::Deferred => write!(
                f,
                "deferred to the next scan: this scan's upload buffer is full"
            ),
            Self::UnsyncableName(reason) => write!(
                f,
                "cannot be synced: a path component {reason} (§5.2); rename it to sync it"
            ),
        }
    }
}

/// One path this scan did not put in the Manifest, with its cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedPath {
    /// The Space-relative canonical path when one could be derived, else the
    /// absolute path as the OS displays it.
    pub path: String,
    /// Why the path was skipped.
    pub reason: SkipReason,
    /// `true` when the Manifest entry of the previous scan was REPUBLISHED, so this
    /// skip cannot be read as a deletion (`§8`). `false` when there was nothing to
    /// keep (never synced) or another path holds the Manifest key.
    pub retained: bool,
}

/// The full output of [`SpaceContext::scan`].
///
/// `entries` is the `(CasefoldKey, FileEntry)` set to feed straight into
/// [`ft_manifest::build`] (it excludes local-only symlinks, `§5.1`) and holds at
/// most ONE entry per key (`§5.2`).
/// `blocks_to_upload` is the de-duplicated `(cid, encoded_object)` list for the
/// commit's upload step (`§7` step 2) — within a single scan the same `cid`
/// appears once. `sidecars` is the PARALLEL de-duplicated `(cid, wrapped_data_key)`
/// list when encryption is ON (`alg=1`): each entry is the `keys/<space_id>/<cid>` sidecar
/// for the Block of the same `cid`, to be uploaded alongside it (`§4.5`). It is
/// EMPTY when encryption is off (`alg=0`), so the cleartext path is unchanged.
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    /// FileEntries to put in the Manifest, keyed by their casefold key.
    pub entries: Vec<(CasefoldKey, FileEntry)>,
    /// Unique encoded Block objects to upload: `(cid, encoded_object)` — the
    /// object is `ft_block::encode(span)` (`alg=0`) or the encrypted object from
    /// `ft_block::encode_encrypted` (`alg=1`).
    pub blocks_to_upload: Vec<(Cid, Vec<u8>)>,
    /// Unique `keys/<space_id>/<cid>` data-key sidecars for the `alg=1` Blocks above, keyed
    /// by the same `cid`. Empty when encryption is off.
    pub sidecars: Vec<(Cid, Vec<u8>)>,
    /// Paths this scan deliberately left out of `entries`, with their causes. A
    /// non-empty list is not a failure, but every element is something the user
    /// should see: it is a path that is NOT syncing.
    pub skipped: Vec<SkippedPath>,
    /// Index rows whose path vanished from disk that this scan deliberately did
    /// NOT delete, because deleting them would have destroyed the mass-delete
    /// guard's own baseline (see [`SpaceContext::scan_with_base`] and
    /// [`SpaceContext::guard_mass_delete`](crate::SpaceContext)). Their entries are
    /// NOT republished — the shrink is real and must be visible to the guard — so
    /// this is purely evidence the guard needs on EVERY later scan, not just the
    /// first. A commit whose Revision actually publishes the shrink purges them.
    pub held_deletions: Vec<CanonicalPath>,
    /// `.filethingignore` lines whose syntax this MVP does not interpret (already
    /// logged at WARN). Such a line is matched LITERALLY, so it may exclude
    /// nothing at all — which for a pattern like `secrets/**` is a confidentiality
    /// failure, not a cosmetic one.
    pub ignore_warnings: Vec<String>,
}

impl ScanResult {
    /// The whole-tree root [`Cid`] this scan would commit, i.e.
    /// `ft_manifest::build(self.entries).root`. Computed on demand (it is a pure
    /// function of `entries`) so a caller can compare it against
    /// `last_synced.root` to detect "no change" without rebuilding twice.
    pub fn manifest_root(&self) -> Cid {
        ft_manifest::build(self.entries.clone()).root
    }

    /// `true` when at least one file was held back by the upload budget
    /// ([`MAX_PENDING_UPLOAD_BYTES`]), so a further commit is needed before the
    /// Space is fully published.
    pub fn has_deferred_work(&self) -> bool {
        self.skipped
            .iter()
            .any(|s| s.reason == SkipReason::Deferred)
    }
}

/// A single classified on-disk entry the walk yields to the per-type handlers.
struct WalkItem {
    /// Absolute path on disk.
    abs: PathBuf,
    /// Canonical Space-relative path.
    canonical: CanonicalPath,
    /// `casefold(NFC(path))`.
    key: CasefoldKey,
    /// Non-following metadata (so a symlink reports as a symlink).
    meta: std::fs::Metadata,
}

/// Everything one pass over the tree learned.
#[derive(Default)]
struct Walk {
    /// The entries to classify and emit, sorted by canonical path.
    items: Vec<WalkItem>,
    /// Canonical paths the walk DECLINED. Each is reported and retained: it keeps
    /// its own index row and Manifest entry, and so does everything under it (a
    /// directory we could not open, or an excluded directory, hides its children).
    declined: Vec<(CanonicalPath, SkipReason)>,
    /// Failures with no canonical path at all (a non-UTF-8 file name). Reported
    /// only: `§5.2` requires UTF-8, so such a path can never have been synced and
    /// there is nothing to retain.
    unmappable: Vec<(String, SkipReason)>,
    /// Paths whose NAME cannot be synced ([`SkipReason::UnsyncableName`]). Reported
    /// but deliberately NOT retained and NOT marked present, so an entry an older
    /// build published leaves the Manifest and the Space converges by deletion —
    /// the same treatment as platform junk (ADR 0011), which is what stops the
    /// entry from making every peer's pull skip it forever.
    unsyncable: Vec<(CanonicalPath, SkipReason)>,
    /// Set when a failure could not be attributed to any path (the root itself
    /// failed): deletion inference is unsafe for the WHOLE tree this scan.
    retain_all: Option<String>,
}

/// The entries of the PUBLISHED base Revision, keyed by `casefold(NFC(p))` — the
/// view a PUBLISHING scan verifies its own index rows against
/// ([`SpaceContext::scan_with_base`]).
///
/// It is the only evidence a Device has that an object really is in the Vault AND
/// referenced by the live head: `local_block` only says "we uploaded it once",
/// which a CAS that never landed leaves true while the GC is free to sweep the
/// object (`gc.rs`).
pub(crate) type BaseEntries = HashMap<CasefoldKey, FileEntry>;

/// What to do with an index row whose path is ABSENT from disk this scan.
enum Retention {
    /// Genuinely gone: drop the row so the path leaves the next Manifest (`§8`).
    Delete,
    /// Keep the row and republish the entry without reporting it — the normal,
    /// expected state of a derived path on a Device that never built it.
    KeepSilently,
    /// Keep the row and republish the entry, reporting why.
    Keep(SkipReason),
}

impl SpaceContext {
    /// Walks `local_root` and produces the [`ScanResult`] for this Device's
    /// current on-disk state, updating the local index as a side effect.
    ///
    /// See the module docs for the per-type rules, for why a path this scan could
    /// not read is republished rather than deleted, and for the one-key-per-Manifest
    /// collision rule. The index is brought in line with disk: present paths are
    /// upserted, genuinely vanished paths are deleted.
    ///
    /// This is the LOCAL-VIEW scan: it answers "what is on disk right now" and is
    /// what `status`, the offline paths and [`pull`](SpaceContext::pull) use. It
    /// trusts the local index for the paths it could not look at itself. A scan
    /// whose result will be PUBLISHED must go through
    /// [`scan_with_base`](Self::scan_with_base) instead, which additionally proves
    /// every reused/republished entry against the base Revision.
    pub fn scan(&self) -> Result<ScanResult> {
        self.scan_with_base(None)
    }

    /// [`scan`](Self::scan) with the published base Manifest in hand.
    ///
    /// `base` is `Some` exactly on the paths that PUBLISH what they scan
    /// ([`commit`](SpaceContext::commit), [`stage_to_vault`](SpaceContext::stage_to_vault)),
    /// and it turns two local-trust decisions into base-proved ones:
    ///
    /// - the `§9` fast path ([`reuse_unchanged`](Self::reuse_unchanged)) may skip
    ///   re-reading a file only when the base Revision already publishes exactly
    ///   that content, because only a head-reachable Block is safe from the GC;
    /// - a republished entry ("a skip is not a deletion", see the module docs) is
    ///   taken from the BASE Manifest rather than from the index row. A row can
    ///   describe bytes that never reached the Vault (a scan writes the row even
    ///   when the commit that follows it fails), and publishing those cids makes
    ///   every other Device's pull fail with "object not found". A path the base
    ///   does not carry is simply left out: it was never published, so leaving it
    ///   out deletes nothing anywhere.
    ///
    /// With `base = None` both fall back to the local index, which is correct for a
    /// view nobody publishes.
    ///
    /// It also owns the DURABILITY of the mass-delete guard's baseline: when the
    /// rows that vanished from disk amount to a mass delete
    /// ([`crate::commit::is_mass_delete`]) they are NOT deleted from the index but
    /// collected into [`ScanResult::held_deletions`]. The guard runs in `commit`
    /// AFTER this scan, so a scan that erased those rows would leave the retry with
    /// nothing to compare against and the second commit would publish the wipe the
    /// first one refused.
    pub(crate) fn scan_with_base(&self, base: Option<&BaseEntries>) -> Result<ScanResult> {
        let space_id = self.space_id.as_str().to_string();
        let base_seq = self.last_synced.seq;
        let ignore = IgnoreList::load(&self.local_root, self.fs.as_ref());

        let mut result = ScanResult::default();
        for warning in &ignore.warnings {
            tracing::warn!("{warning}");
        }
        result.ignore_warnings = ignore.warnings.clone();

        let mut seen_blocks: HashSet<Cid> = HashSet::new();
        // Manifest keys published so far: `ft_manifest::build` must never receive
        // two entries for one key (§5.2/§5.3).
        let mut emitted: HashSet<CasefoldKey> = HashSet::new();
        // Canonical paths present on disk this scan, to compute deletions.
        let mut present: HashSet<CanonicalPath> = HashSet::new();
        // Encoded Block bytes buffered so far (see MAX_PENDING_UPLOAD_BYTES).
        let mut pending_bytes = 0usize;

        let mut walk = self.walk(&ignore);
        // §5.2: resolve casefold/NFC collisions BEFORE the handlers run, so no two
        // entries can carry the same key and the loser's subtree is retained rather
        // than published as absent.
        resolve_collisions(&mut walk);

        for item in &walk.items {
            present.insert(item.canonical.clone());

            let file_type = classify(&item.meta, &item.canonical_as_path());
            match file_type {
                FileType::File => {
                    self.handle_file(
                        item,
                        base_seq,
                        base,
                        &mut result,
                        &mut emitted,
                        &mut seen_blocks,
                        &mut pending_bytes,
                    )?;
                }
                FileType::Symlink => {
                    self.handle_symlink(item, base_seq, base, &mut result, &mut emitted)?;
                }
                FileType::Derived => {
                    self.handle_derived(item, base_seq, &mut result, &mut emitted)?;
                }
                FileType::Dir => {
                    self.handle_dir(item, base_seq, &mut result, &mut emitted)?;
                }
            }
        }

        // A path with no canonical form cannot be synced (§5.2) and cannot have an
        // index row, so it is purely a report.
        for (path, reason) in &walk.unmappable {
            report_skip(&mut result, path.clone(), reason.clone(), false);
        }

        // An unsyncable NAME is reported but left out of `present`, so any row a
        // previous build wrote for it falls through to the deletion pass below and
        // the entry leaves the Manifest (see [`SkipReason::UnsyncableName`]). The
        // file on disk is untouched — only its Manifest entry goes away.
        for (path, reason) in &walk.unsyncable {
            report_skip(
                &mut result,
                path.as_str().to_string(),
                reason.clone(),
                false,
            );
        }

        // The paths the walk declined ARE on disk, so their rows must survive; what
        // they must not do is disappear from the Manifest, which the diff would read
        // as a deletion (§8).
        for (path, reason) in &walk.declined {
            present.insert(path.clone());
            let retained = self.republish(&space_id, path, base, &mut result, &mut emitted)?;
            // An ignored path that was never synced is the overwhelmingly common
            // case (a whole excluded tree); reporting each one would bury the
            // interesting ones. Only the frozen (previously synced) ones matter.
            if *reason != SkipReason::Ignored || retained {
                report_skip(
                    &mut result,
                    path.as_str().to_string(),
                    reason.clone(),
                    retained,
                );
            }
        }

        // Anything in the index but no longer on disk is a delete: drop it so it
        // does not enter this scan's Manifest (a delete is an absence, §8) — unless
        // this scan could not establish the truth about that path.
        //
        // Decided over the WHOLE set first, because dropping the rows is what the
        // mass-delete guard is later asked to judge: `commit` counts the tracked
        // rows BEFORE this scan and compares them with the entries it is about to
        // publish, so a scan that deletes 5000 rows leaves the NEXT commit comparing
        // 0 against 0 — a silent second chance to publish the very wipe the first
        // commit refused. When the shrink is that big the rows therefore stay put
        // (they are still absent from `entries`, so the guard still sees the wipe)
        // until a Revision that really published it purges them (`commit`).
        let rows = self.index.list_entries(&space_id)?;
        let tracked_rows = rows.iter().filter(|row| tracked_in_manifest(row)).count();
        let mut absent: Vec<(LocalEntry, Retention)> = Vec::new();
        for row in rows {
            if present.contains(&row.path) {
                continue;
            }
            let retention = self.retention_for(&row, &walk);
            absent.push((row, retention));
        }
        let vanished = absent
            .iter()
            .filter(|(row, retention)| {
                matches!(retention, Retention::Delete) && tracked_in_manifest(row)
            })
            .count();
        let hold_deletions =
            crate::commit::is_mass_delete(tracked_rows, tracked_rows.saturating_sub(vanished));
        if hold_deletions {
            tracing::warn!(
                space = %space_id,
                tracked_rows,
                vanished,
                "most of the tracked tree vanished from disk; keeping the index rows so the \
                 mass-delete guard can still see it on every retry, not just this one"
            );
        }

        for (row, retention) in &absent {
            match retention {
                Retention::Delete if hold_deletions => {
                    result.held_deletions.push(row.path.clone());
                }
                Retention::Delete => {
                    self.index.delete_entry(&space_id, &row.path)?;
                }
                Retention::KeepSilently => {
                    self.republish_row(row, base, &mut result, &mut emitted);
                }
                Retention::Keep(reason) => {
                    let retained = self.republish_row(row, base, &mut result, &mut emitted);
                    report_skip(
                        &mut result,
                        row.path.as_str().to_string(),
                        reason.clone(),
                        retained,
                    );
                }
            }
        }

        Ok(result)
    }

    /// Walks the tree, skipping the control dir, ignored paths, platform junk,
    /// ft-diff scratch files, unsyncable names ([`SkipReason::UnsyncableName`]) and
    /// the contents of derived directories (a derived dir yields ONE entry, then is
    /// not descended).
    ///
    /// Never fails: a per-entry problem is collected into the returned [`Walk`]
    /// (and retained there) instead of aborting, because both `commit` and `pull`
    /// start here — one root-owned mode-000 file or one stale unix socket used to
    /// stop a Space from syncing in either direction until a human found it.
    fn walk(&self, ignore: &IgnoreList) -> Walk {
        let root = &self.local_root;
        let mut out = Walk::default();

        let mut walker = WalkDir::new(root).follow_links(false).into_iter();
        while let Some(next) = walker.next() {
            let dent = match next {
                Ok(d) => d,
                Err(e) => {
                    // An unreadable DIRECTORY hides its whole subtree, so scoping the
                    // retention to its path is what keeps those children out of the
                    // deletion set. When the failure names no path we can map (or
                    // names the root itself) we do not know which rows it covers, so
                    // nothing may be inferred deleted this scan.
                    let cause = e.to_string();
                    match e.path() {
                        Some(p) if p != root.as_path() => match canonicalize(root, p) {
                            Ok(canonical) => {
                                out.declined
                                    .push((canonical, SkipReason::Unreadable(cause)));
                            }
                            Err(_) => out.retain_all = Some(cause),
                        },
                        _ => out.retain_all = Some(cause),
                    }
                    continue;
                }
            };
            let abs = dent.path().to_path_buf();

            // The root itself is not an entry.
            if abs == *root {
                continue;
            }
            let is_dir = dent.file_type().is_dir();

            // Canonicalize relative to the root. A path that has no canonical form
            // (non-UTF-8 name, `§5.2`) can never be synced, so it is reported and
            // its subtree pruned — descending would only repeat the same failure.
            let canonical = match canonicalize(root, &abs) {
                Ok(c) => c,
                Err(e) => {
                    out.unmappable.push((
                        abs.display().to_string(),
                        SkipReason::Unreadable(e.to_string()),
                    ));
                    if is_dir {
                        walker.skip_current_dir();
                    }
                    continue;
                }
            };

            // Skip the control directory and everything under it.
            if is_under(&canonical, CONTROL_DIR) {
                if is_dir {
                    walker.skip_current_dir();
                }
                continue;
            }

            // Skip ignored paths (empty .filethingignore ⇒ never matches). Recorded
            // as declined, so adding a pattern STOPS syncing those paths instead of
            // publishing a deletion that destroys them on every other Device.
            if ignore.is_ignored(&canonical, is_dir) {
                if is_dir {
                    walker.skip_current_dir();
                }
                out.declined.push((canonical, SkipReason::Ignored));
                continue;
            }

            // Skip built-in platform junk (`.DS_Store`, `Thumbs.db`,
            // `desktop.ini`) in ANY directory, regardless of .filethingignore
            // (ADR 0011). Matched by exact entry name; scanner side only, so it
            // never enters the Manifest and a Space already carrying one
            // converges by deletion. NOT retained, for exactly that reason.
            if is_junk_name(dent.file_name()) {
                continue;
            }

            // Skip ft-diff's `.<file>.ft-tmp` scratch files the same way: they are
            // never user data, so a leftover one must converge by deletion too.
            if is_tmp_name(dent.file_name()) {
                continue;
            }

            // A name this Space cannot carry across platforms (a `\` component, or
            // one that looks like a Windows drive prefix). Legal here, fatal there:
            // publishing one used to abort every OTHER Device's whole pull on that
            // single entry, forever. Reported (unlike junk — this IS user data, and
            // it is not syncing) but NOT retained: like junk it must converge by
            // DELETION, so the entry a pre-upgrade build published leaves the
            // Manifest and the peers stop having to skip it. Nothing on disk is
            // touched. A directory with such a name hides its whole subtree — every
            // child path would carry the same unsyncable component anyway.
            if let Some(reason) = canonical.unsyncable_reason() {
                out.unsyncable
                    .push((canonical, SkipReason::UnsyncableName(reason)));
                if is_dir {
                    walker.skip_current_dir();
                }
                continue;
            }

            // Non-following metadata so a symlink reads as a symlink.
            let meta = match std::fs::symlink_metadata(&abs) {
                Ok(m) => m,
                Err(e) => {
                    out.declined.push((
                        canonical,
                        SkipReason::Unreadable(format!("{}: {e}", abs.display())),
                    ));
                    if is_dir {
                        walker.skip_current_dir();
                    }
                    continue;
                }
            };

            // `§5.1` has no type for a FIFO, socket or device node, and `fs::read`
            // on a FIFO BLOCKS FOREVER — which hangs the daemon task outright. Never
            // open one: decline it here, before any handler can touch it.
            let file_type = meta.file_type();
            if !(file_type.is_file() || file_type.is_dir() || file_type.is_symlink()) {
                out.declined
                    .push((canonical, SkipReason::UnsupportedFileType));
                continue;
            }

            let canonical_path = Path::new(canonical.as_str()).to_path_buf();

            // A derived path: emit ONE entry for the derived directory (or file)
            // and do not descend into a derived directory.
            if is_derived(&canonical_path) {
                // Only emit for the topmost derived component — i.e. when the
                // PARENT is not itself derived — so `node_modules` yields one
                // entry, never `node_modules/foo`.
                let parent_is_derived = canonical_path.parent().map(is_derived).unwrap_or(false);
                if !parent_is_derived {
                    let key = casefold_key(&canonical);
                    out.items.push(WalkItem {
                        abs,
                        canonical,
                        key,
                        meta,
                    });
                }
                if is_dir {
                    walker.skip_current_dir();
                }
                continue;
            }

            // A plain directory is a first-class entry (ADR 0019) so empty
            // directories sync: emit a WalkItem for it AND keep descending (unlike
            // a derived dir, which is not descended). The Space root is never an
            // entry (skipped above). `classify` maps it to `FileType::Dir`.
            let key = casefold_key(&canonical);
            out.items.push(WalkItem {
                abs,
                canonical,
                key,
                meta,
            });
        }

        // Sort by canonical path so everything downstream is deterministic: which
        // path wins a casefold collision, and which files the upload budget defers.
        // The OS enumeration order must not decide either.
        out.items.sort_by(|a, b| a.canonical.cmp(&b.canonical));
        out.declined.sort_by(|a, b| a.0.cmp(&b.0));
        out.unsyncable.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// File (`t=0`): chunk, hash, build the ordered `bk`, collect Blocks, and
    /// upsert the index row (`§5.1`, `§9`).
    ///
    /// `base` is the published base view of a publishing scan (see
    /// [`scan_with_base`](Self::scan_with_base)); it is threaded down to the two
    /// decisions that may reference Blocks this scan did not produce itself (the
    /// `§9` fast path and the republish of a skipped path). Hence the argument
    /// count: splitting it would only move the same context one call deeper.
    #[allow(clippy::too_many_arguments)]
    fn handle_file(
        &self,
        item: &WalkItem,
        base_seq: i64,
        base: Option<&BaseEntries>,
        result: &mut ScanResult,
        emitted: &mut HashSet<CasefoldKey>,
        seen_blocks: &mut HashSet<Cid>,
        pending_bytes: &mut usize,
    ) -> Result<()> {
        let space_id = self.space_id.as_str();

        // `§9` fast path: an unchanged file reuses its stored `pcid` + Block list
        // instead of being re-read, re-chunked, re-hashed and re-encrypted.
        if let Some(entry) = self.reuse_unchanged(item, base)? {
            push_entry(result, emitted, item.key.clone(), entry);
            return Ok(());
        }

        // Bounded memory (see MAX_PENDING_UPLOAD_BYTES): once this scan has
        // buffered its budget of encoded Blocks, stop taking on new files. The
        // deferred file keeps whatever it published before, so the wait costs
        // latency, never data.
        if *pending_bytes >= MAX_PENDING_UPLOAD_BYTES {
            let retained = self.republish(space_id, &item.canonical, base, result, emitted)?;
            report_skip(
                result,
                item.canonical.as_str().to_string(),
                SkipReason::Deferred,
                retained,
            );
            return Ok(());
        }

        // Stat the mtime BEFORE reading the bytes. If the file is written between
        // the two, the row then records an mtime OLDER than the content we hashed,
        // so the next scan sees a mismatch and re-reads; the reverse order would
        // store the NEW mtime next to the OLD content and the fast path above would
        // never notice that write (`§9`).
        let mtime = self.mtime_secs(&item.abs);
        let bytes = match self.fs.read_bytes(&item.abs) {
            Ok(bytes) => bytes,
            Err(e) => {
                // ONE unreadable file must not fail the scan: `commit` AND `pull`
                // both start here, so propagating this used to stop the Space from
                // syncing in either direction until a human found the file.
                let retained = self.republish(space_id, &item.canonical, base, result, emitted)?;
                report_skip(
                    result,
                    item.canonical.as_str().to_string(),
                    SkipReason::Unreadable(format!("{}: {e}", item.abs.display())),
                    retained,
                );
                return Ok(());
            }
        };
        let whole_pcid = ft_hash::pcid_of(&bytes);
        let exec = self.fs.exec_bit(&item.meta);

        let spans = if uses_large_binary_profile(&item.canonical, bytes.len()) {
            self.chunker.chunk_large_binary(&bytes)
        } else {
            self.chunker.chunk(&bytes)
        };
        let mut bk: Vec<Cid> = Vec::with_capacity(spans.len());
        let mut block_refs: Vec<BlockRef> = Vec::with_capacity(spans.len());

        for span in &spans {
            let slice = &bytes[span.offset..span.end()];
            // Encryption OFF (`alg=0`): cid == pcid (nonce excluded), the object
            // is the cleartext payload, no sidecar. Encryption ON (`alg=1`): the
            // cid is `BLAKE3(nonce || ciphertext)` and DIVERGES from the cleartext
            // pcid — `bk`/the Manifest address by `cid`, the local index/dedup key
            // by `pcid`; the wrapped data key becomes the `keys/<space_id>/<cid>` sidecar.
            let (cid, pcid, obj, sidecar): (Cid, Pcid, Vec<u8>, Option<Vec<u8>>) =
                match self.crypto.as_ref() {
                    None => {
                        let pcid = ft_hash::pcid_of(slice);
                        (cid_for(slice), pcid, encode(slice), None)
                    }
                    Some(crypto) => {
                        let (cid, pcid, obj, data_key) =
                            ft_block::encode_encrypted(slice, &crypto.dedup_secret)?;
                        let sidecar =
                            ft_block::sidecar::wrap_data_key(&data_key, &crypto.space_key);
                        (cid, pcid, obj, Some(sidecar))
                    }
                };
            bk.push(cid);
            block_refs.push(BlockRef { pcid, cid });
            // De-dup within this scan: collect each Block's object (and, under
            // encryption, its sidecar) once per cid. Same content ⇒ same pcid ⇒
            // same deterministic key/nonce ⇒ same ciphertext ⇒ same cid, so this
            // dedups identically whether encryption is on or off (`§4.4`).
            if seen_blocks.insert(cid) {
                *pending_bytes += obj.len();
                result.blocks_to_upload.push((cid, obj));
                if let Some(sidecar) = sidecar {
                    *pending_bytes += sidecar.len();
                    result.sidecars.push((cid, sidecar));
                }
            }
        }

        let entry = FileEntry {
            p: item.canonical.clone(),
            t: FileType::File,
            x: exec,
            sz: bytes.len() as u64,
            pcid: whole_pcid,
            bk,
            bk_ref: None, // ft_manifest::build externalizes if it ever overflows.
            lt: None,
            wu: None,
        };

        // Local index: the path row with its ordered Block list (§9). NOTE: we
        // do NOT mark these Blocks present in `local_block` here — that table is
        // the upload-dedup cache ("already in the Vault"), populated by the
        // commit's upload step after a PUT/HEAD confirms presence (§7 step 2). If
        // scan marked them present, the first commit would skip every upload —
        // which is also exactly why `reuse_unchanged` may only trust a row whose
        // Blocks that table already lists.
        self.index.upsert_entry(
            space_id,
            &LocalEntry {
                path: item.canonical.clone(),
                casefold_key: item.key.clone(),
                file_type: FileType::File,
                exec,
                size: bytes.len() as u64,
                mtime,
                pcid: Some(whole_pcid),
                base_seq,
                blocks: block_refs,
                local_only: false,
            },
        )?;

        push_entry(result, emitted, item.key.clone(), entry);
        Ok(())
    }

    /// The `§9` re-scan fast path: reuse a file's stored `pcid` and Block list when
    /// `(size, mtime)` still match its index row, instead of re-reading and
    /// re-hashing (and, under `alg=1`, re-encrypting) every byte of the Space on
    /// every commit, pull and `status`. `None` ⇒ the caller must do the full work.
    ///
    /// TRUST BOUNDARY, deliberately narrow. `local_entry.mtime` is whole SECONDS
    /// (`§9`), so `(size, mtime)` can also match a file that CHANGED. Four guards
    /// narrow that window as far as the stored columns allow:
    ///
    /// 1. the mtime must be strictly OLDER than the current second, so a file
    ///    written while this scan runs — the daemon's normal case, since the
    ///    watcher fires milliseconds after a save — is always read;
    /// 2. the size AND the exec bit must match, so any edit that changes either is
    ///    caught whatever the clock did;
    /// 3. every reused `cid` must already be recorded in `local_block`. This is
    ///    what makes the reuse SAFE rather than merely fast: `scan` writes the row
    ///    even when the commit that follows it fails, so without this check a scan
    ///    after a failed upload would republish `bk` cids whose bytes never reached
    ///    the Vault, and every other Device's pull would fail with "object not
    ///    found";
    /// 4. the row must be a tracked (not `local_only`) File carrying a `pcid`.
    ///
    /// PUBLISHING SCANS ADD A FIFTH (`base`, see
    /// [`scan_with_base`](Self::scan_with_base)): the entry must be the one the
    /// BASE Revision already publishes for this path. `local_block` says only "this
    /// Device uploaded these bytes once", which stays true for a commit whose CAS
    /// never landed — and an object no Revision references is precisely what the GC
    /// sweeps (`gc.rs`). Referencing such a cid without re-uploading it would leave
    /// the head pointing at an object the Vault no longer has, permanently and with
    /// no self-healing, because every later scan would take this same fast path.
    /// Base-reachable cids have no such window: the GC never sweeps what a Revision
    /// references. A row that fails only this check falls through to the full path,
    /// which re-reads the file and re-uploads it under the commit's normal
    /// HEAD-before-PUT — so the Space repairs itself instead of publishing a
    /// dangling reference.
    ///
    /// The base match compares `(t, x, sz, pcid)`, NOT the `bk` list: the whole-file
    /// `pcid` pins the content, and chunking (and, under `alg=1`, encryption) is
    /// deterministic for a Space, so identical content yields identical cids. That
    /// also keeps the check working when the base entry externalized its blocklist
    /// (`bk_ref`), whose cids are not in the page at all.
    ///
    /// RESIDUAL WINDOW (accepted; `§9` prescribes the `(size, mtime)` check): a
    /// write that lands in the same wall-clock SECOND as the previous scan's read
    /// AND keeps the byte size identical is not noticed until the file changes
    /// again. Closing it needs a finer stat in the index (nanosecond mtime, or
    /// ctime+inode), which `local_entry` does not carry today.
    fn reuse_unchanged(
        &self,
        item: &WalkItem,
        base: Option<&BaseEntries>,
    ) -> Result<Option<FileEntry>> {
        let space_id = self.space_id.as_str();
        let Some(row) = self.index.get_entry(space_id, &item.canonical)? else {
            return Ok(None);
        };
        if row.file_type != FileType::File || row.local_only {
            return Ok(None);
        }
        let Some(pcid) = row.pcid else {
            return Ok(None);
        };
        if row.size != item.meta.len() || row.exec != self.fs.exec_bit(&item.meta) {
            return Ok(None);
        }
        // `mtime_secs` reports 0 when the platform cannot say; such a row can never
        // be trusted, and neither can one stamped in the current second (guard 1).
        let mtime = self.mtime_secs(&item.abs);
        if mtime <= 0 || row.mtime != mtime || mtime >= now_secs() {
            return Ok(None);
        }
        for block in &row.blocks {
            if !self.index.has_block(space_id, &block.cid)? {
                return Ok(None);
            }
        }
        let entry = FileEntry {
            p: row.path.clone(),
            t: FileType::File,
            x: row.exec,
            sz: row.size,
            pcid,
            bk: row.blocks.iter().map(|b| b.cid).collect(),
            bk_ref: None,
            lt: None,
            wu: None,
        };
        // Guard 5 (publishing scans only): the cids may be referenced without a
        // HEAD exactly when the base Revision already references them.
        if let Some(base) = base {
            if !base
                .get(&item.key)
                .is_some_and(|published| publishes_same_content(published, &entry))
            {
                return Ok(None);
            }
        }
        Ok(Some(entry))
    }

    /// Symlink (`t=1`): apply the `§5.1` policy. A preserved link enters the
    /// Manifest with `lt` set and a deterministic `pcid`; a local-only link is
    /// recorded in the index and kept OUT of the Manifest.
    fn handle_symlink(
        &self,
        item: &WalkItem,
        base_seq: i64,
        base: Option<&BaseEntries>,
        result: &mut ScanResult,
        emitted: &mut HashSet<CasefoldKey>,
    ) -> Result<()> {
        let space_id = self.space_id.as_str();
        let target = match self.fs.read_symlink(&item.abs) {
            Ok(target) => target,
            Err(e) => {
                // Same rule as an unreadable file: report it, keep what the link
                // published last time, never fail the whole scan.
                let retained = self.republish(space_id, &item.canonical, base, result, emitted)?;
                report_skip(
                    result,
                    item.canonical.as_str().to_string(),
                    SkipReason::Unreadable(format!("{}: {e}", item.abs.display())),
                    retained,
                );
                return Ok(());
            }
        };
        let link_rel = Path::new(item.canonical.as_str());
        let decision = symlink_policy(&target, link_rel, &self.local_root);
        let mtime = self.mtime_secs(&item.abs);

        match decision {
            SymlinkDecision::Preserve(literal) => {
                // Deterministic pcid over the target bytes: a retarget changes
                // the pcid ⇒ the FileEntry ⇒ the manifestRoot (§5.1).
                let entry = symlink_entry(&item.canonical, &literal);
                let pcid = entry.pcid;
                self.index.upsert_entry(
                    space_id,
                    &LocalEntry {
                        path: item.canonical.clone(),
                        casefold_key: item.key.clone(),
                        file_type: FileType::Symlink,
                        exec: false,
                        size: 0,
                        mtime,
                        pcid: Some(pcid),
                        base_seq,
                        blocks: Vec::new(),
                        local_only: false,
                    },
                )?;
                push_entry(result, emitted, item.key.clone(), entry);
            }
            SymlinkDecision::LocalOnly => {
                // Recorded local-only; NOT added to the Manifest (§5.1).
                self.index.upsert_entry(
                    space_id,
                    &LocalEntry {
                        path: item.canonical.clone(),
                        casefold_key: item.key.clone(),
                        file_type: FileType::Symlink,
                        exec: false,
                        size: 0,
                        mtime,
                        pcid: None,
                        base_seq,
                        blocks: Vec::new(),
                        local_only: true,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// Derived (`t=2`): a regenerable path. One FileEntry with empty `bk`; no
    /// bytes travel (`§5.1`).
    fn handle_derived(
        &self,
        item: &WalkItem,
        base_seq: i64,
        result: &mut ScanResult,
        emitted: &mut HashSet<CasefoldKey>,
    ) -> Result<()> {
        let space_id = self.space_id.as_str();
        let entry = derived_entry(&item.canonical);
        let mtime = self.mtime_secs(&item.abs);
        self.index.upsert_entry(
            space_id,
            &LocalEntry {
                path: item.canonical.clone(),
                casefold_key: item.key.clone(),
                file_type: FileType::Derived,
                exec: false,
                size: 0,
                mtime,
                pcid: None,
                base_seq,
                blocks: Vec::new(),
                local_only: true, // derived bytes are not synced (§5.1, §9).
            },
        )?;
        push_entry(result, emitted, item.key.clone(), entry);
        Ok(())
    }

    /// Dir (`t=3`): a plain directory tracked as a first-class entry so empty
    /// directories sync (ADR 0019). Only `p`/`t` are meaningful; no bytes travel.
    /// Mirrors [`handle_derived`](Self::handle_derived) but the index row is NOT
    /// `local_only` (dirs DO enter the Manifest and sync) and carries no `pcid`.
    fn handle_dir(
        &self,
        item: &WalkItem,
        base_seq: i64,
        result: &mut ScanResult,
        emitted: &mut HashSet<CasefoldKey>,
    ) -> Result<()> {
        let space_id = self.space_id.as_str();
        let entry = dir_entry(&item.canonical);
        let mtime = self.mtime_secs(&item.abs);
        self.index.upsert_entry(
            space_id,
            &LocalEntry {
                path: item.canonical.clone(),
                casefold_key: item.key.clone(),
                file_type: FileType::Dir,
                exec: false,
                size: 0,
                mtime,
                pcid: None,
                base_seq,
                blocks: Vec::new(),
                local_only: false, // dirs DO sync (ADR 0019), unlike derived.
            },
        )?;
        push_entry(result, emitted, item.key.clone(), entry);
        Ok(())
    }

    /// Republishes the Manifest entry the LAST scan wrote for `path`, read back out
    /// of its `§9` index row. Returns whether an entry was published.
    ///
    /// This is what keeps a skip from becoming a deletion (`§8`): a transient EACCES
    /// or a new `.filethingignore` line must not tell every other Device to delete a
    /// file that still exists here.
    fn republish(
        &self,
        space_id: &str,
        path: &CanonicalPath,
        base: Option<&BaseEntries>,
        result: &mut ScanResult,
        emitted: &mut HashSet<CasefoldKey>,
    ) -> Result<bool> {
        let Some(row) = self.index.get_entry(space_id, path)? else {
            return Ok(false); // never synced: nothing to keep
        };
        Ok(self.republish_row(&row, base, result, emitted))
    }

    /// [`republish`](Self::republish) for an already-loaded row.
    fn republish_row(
        &self,
        row: &LocalEntry,
        base: Option<&BaseEntries>,
        result: &mut ScanResult,
        emitted: &mut HashSet<CasefoldKey>,
    ) -> bool {
        match self.entry_from_row(row, base) {
            Some(entry) => push_entry(result, emitted, row.casefold_key.clone(), entry),
            None => false,
        }
    }

    /// Rebuilds the Manifest [`FileEntry`] to republish for `row`.
    ///
    /// On a PUBLISHING scan (`base` is `Some`, see
    /// [`scan_with_base`](Self::scan_with_base)) a File row is NOT the source of
    /// truth: the base Revision is. The row is written by every scan, including the
    /// scan of a commit that then failed before or during its upload, so its cids
    /// can name Blocks the Vault never received — republishing those would publish a
    /// head whose objects do not exist, and every other Device's pull would fail on
    /// them. Two fail-safe cases, both of which cost nothing that was ever visible
    /// to another Device:
    ///
    /// - the base publishes this path ⇒ republish the BASE entry verbatim. Its
    ///   Blocks are head-reachable, so the Vault has them and the GC will not take
    ///   them. The skip then really is "nothing changed for this path", which is the
    ///   whole point of retaining it (`§8`);
    /// - the base does NOT publish it ⇒ publish nothing. The path was never in any
    ///   Revision, so leaving it out cannot delete anything on any Device; the file
    ///   stays on disk untouched and is picked up by the first scan that can read
    ///   and upload it.
    ///
    /// Only File rows carry Blocks, so the other types rebuild the same way in both
    /// modes. `None` when the row never belonged in the Manifest (a local-only
    /// symlink, `§5.1`) or cannot be rebuilt: `local_entry` has no `lt` column, so a
    /// PRESERVED symlink is only recoverable by re-reading the link itself.
    fn entry_from_row(&self, row: &LocalEntry, base: Option<&BaseEntries>) -> Option<FileEntry> {
        match row.file_type {
            FileType::File => {
                if row.local_only {
                    return None;
                }
                if let Some(base) = base {
                    return base.get(&row.casefold_key).cloned();
                }
                Some(FileEntry {
                    p: row.path.clone(),
                    t: FileType::File,
                    x: row.exec,
                    sz: row.size,
                    pcid: row.pcid?,
                    bk: row.blocks.iter().map(|b| b.cid).collect(),
                    bk_ref: None,
                    lt: None,
                    wu: None,
                })
            }
            FileType::Symlink => {
                if row.local_only {
                    return None; // never entered the Manifest (§5.1)
                }
                let abs = join_canonical(&self.local_root, &row.path);
                let literal = self.fs.read_symlink(&abs).ok()?;
                match symlink_policy(&literal, Path::new(row.path.as_str()), &self.local_root) {
                    SymlinkDecision::Preserve(literal) => Some(symlink_entry(&row.path, &literal)),
                    SymlinkDecision::LocalOnly => None,
                }
            }
            // Both are pure functions of the path, so they rebuild exactly.
            FileType::Derived => Some(derived_entry(&row.path)),
            FileType::Dir => Some(dir_entry(&row.path)),
        }
    }

    /// Decides what to do with an index row whose path is ABSENT from disk.
    ///
    /// A derived path is absent on every Device that did not build it — by design,
    /// since derived bytes never travel (`§5.1`, ADR 0001) and
    /// [`ft_diff::materialize`] creates nothing for `t=2`. Inferring a deletion
    /// from that absence is what made two Devices fight forever: the receiver
    /// published the derived path as deleted, and the origin's `remove_dir` then
    /// failed with ENOTEMPTY on every pull. So a derived row NEVER participates in
    /// deletion inference — which also protects a plain FILE named `target` or
    /// `venv`, whose bytes were never uploaded and whose deletion is therefore
    /// unrecoverable.
    fn retention_for(&self, row: &LocalEntry, walk: &Walk) -> Retention {
        if row.file_type == FileType::Derived {
            return Retention::KeepSilently;
        }
        if let Some(cause) = &walk.retain_all {
            return Retention::Keep(SkipReason::Unreadable(cause.clone()));
        }
        for (prefix, reason) in &walk.declined {
            if path_is_under(row.path.as_str(), prefix.as_str()) {
                return Retention::Keep(reason.clone());
            }
        }
        Retention::Delete
    }

    /// Reads the real FS mtime as whole seconds since the epoch for the index
    /// (`§9`, re-scan only — never used for conflict detection). Falls back to
    /// `0` if the platform cannot report it.
    fn mtime_secs(&self, abs: &Path) -> i64 {
        match self.fs.real_mtime(abs) {
            Ok(t) => t
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            Err(_) => 0,
        }
    }
}

/// Publishes `(key, entry)` unless `key` is already taken, keeping the
/// one-entry-per-key invariant `ft_manifest::build` relies on (`§5.2`/`§5.3`).
/// Returns whether it was published.
fn push_entry(
    result: &mut ScanResult,
    emitted: &mut HashSet<CasefoldKey>,
    key: CasefoldKey,
    entry: FileEntry,
) -> bool {
    if !emitted.insert(key.clone()) {
        return false;
    }
    result.entries.push((key, entry));
    true
}

/// True when `row` is a path that WOULD appear in a Manifest (`§5.1`, ADR 0019).
///
/// A local-only symlink is not one; a Derived path IS (it is `local_only` in the
/// index only because its bytes never travel). Shared with
/// [`SpaceContext::tracked_entry_count`](crate::SpaceContext) so the mass-delete
/// guard's baseline and the rows this scan may drop are counted by ONE rule — two
/// rules that drift make the guard fire on the wrong trees or not at all.
pub(crate) fn tracked_in_manifest(row: &LocalEntry) -> bool {
    !row.local_only || row.file_type == FileType::Derived
}

/// True when `published` and `candidate` describe the same bytes at the same path,
/// i.e. referencing `candidate`'s Blocks references only objects the base Revision
/// already keeps alive.
///
/// Compares `(t, x, sz, pcid)` and deliberately not `bk`: the whole-file `pcid` is
/// the content, chunking is deterministic per Space (`§3`) and so is `alg=1`
/// encryption (`§4.4`), so equal `pcid` ⇒ equal cids. Comparing `bk` would also
/// spuriously fail for a base entry whose blocklist was externalized (`bk_ref`),
/// where the page does not carry the cids at all.
fn publishes_same_content(published: &FileEntry, candidate: &FileEntry) -> bool {
    published.t == candidate.t
        && published.x == candidate.x
        && published.sz == candidate.sz
        && published.pcid == candidate.pcid
}

/// Records a skipped path in the result AND logs it at WARN: a file that stops
/// syncing must never be silent, or the daemon reports green metrics while a path
/// is quietly excluded.
fn report_skip(result: &mut ScanResult, path: String, reason: SkipReason, retained: bool) {
    tracing::warn!(path = %path, retained, "scan skipped a path: {reason}");
    result.skipped.push(SkippedPath {
        path,
        reason,
        retained,
    });
}

/// Wall-clock seconds since the epoch, or `i64::MIN` when the clock predates the
/// epoch — which makes every fast path refuse rather than trust an mtime it cannot
/// order against "now".
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MIN)
}

/// The `t=1` FileEntry for a preserved symlink: `lt` byte-exact and a
/// deterministic `pcid` over the target bytes, so a retarget changes the
/// `manifestRoot` (`§5.1`, ADR 0006).
fn symlink_entry(path: &CanonicalPath, literal: &str) -> FileEntry {
    FileEntry {
        p: path.clone(),
        t: FileType::Symlink,
        x: false,
        sz: 0,
        pcid: ft_hash::pcid_of(literal.as_bytes()),
        bk: Vec::new(),
        bk_ref: None,
        lt: Some(literal.to_string()),
        wu: None,
    }
}

/// The `t=2` FileEntry for a derived path — a pure function of the path, since no
/// bytes and no metadata travel (`§5.1`, ADR 0001).
fn derived_entry(path: &CanonicalPath) -> FileEntry {
    FileEntry {
        p: path.clone(),
        t: FileType::Derived,
        x: false,
        sz: 0,
        pcid: Pcid::new([0u8; 32]),
        bk: Vec::new(),
        bk_ref: None,
        lt: None,
        wu: None,
    }
}

/// The `t=3` FileEntry for a plain directory — also a pure function of the path
/// (no mode, no permissions, ADR 0019).
fn dir_entry(path: &CanonicalPath) -> FileEntry {
    FileEntry {
        p: path.clone(),
        t: FileType::Dir,
        x: false,
        sz: 0,
        pcid: Pcid::new([0u8; 32]),
        bk: Vec::new(),
        bk_ref: None,
        lt: None,
        wu: None,
    }
}

/// Keeps at most one walked item per `casefold(NFC(p))` key, moving the rest to
/// `declined` as [`SkipReason::CasefoldCollision`] (`§5.2`, ADR 0006).
///
/// `items` must already be sorted by canonical path (the walk sorts it), so the
/// FIRST item for a key is the lexicographically first path and every Device
/// resolves the collision the same way regardless of directory order. A colliding
/// DIRECTORY also takes its subtree out of this Manifest, so no entry is published
/// whose parent directory is not — the subtree is retained through the declined
/// prefix, never published as absent.
fn resolve_collisions(walk: &mut Walk) {
    let mut winner_of: HashMap<CasefoldKey, CanonicalPath> = HashMap::new();
    let mut losers: Vec<(CanonicalPath, SkipReason)> = Vec::new();

    walk.items.retain(|item| match winner_of.get(&item.key) {
        Some(winner) => {
            losers.push((
                item.canonical.clone(),
                SkipReason::CasefoldCollision {
                    winner: winner.as_str().to_string(),
                },
            ));
            false
        }
        None => {
            winner_of.insert(item.key.clone(), item.canonical.clone());
            true
        }
    });

    if losers.is_empty() {
        return;
    }
    walk.items.retain(|item| {
        !losers.iter().any(|(loser, _)| {
            item.canonical != *loser && path_is_under(item.canonical.as_str(), loser.as_str())
        })
    });
    walk.declined.extend(losers);
    walk.declined.sort_by(|a, b| a.0.cmp(&b.0));
}

/// Selects the large-binary FastCDC profile from stable properties shared by
/// every Device. Keeping the decision path+size-only makes re-scans deterministic
/// without adding a chunk-profile field to the Manifest.
fn uses_large_binary_profile(path: &CanonicalPath, size: usize) -> bool {
    if size < LARGE_BINARY_THRESHOLD {
        return false;
    }
    Path::new(path.as_str())
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            LARGE_BINARY_EXTENSIONS
                .iter()
                .any(|known| extension.eq_ignore_ascii_case(known))
        })
}

impl WalkItem {
    /// The canonical path as a `Path` (for `classify`, which keys off path
    /// components for the derived check).
    fn canonical_as_path(&self) -> PathBuf {
        Path::new(self.canonical.as_str()).to_path_buf()
    }
}

/// The parsed `.filethingignore` for a Space (`§Ignore file`).
///
/// Each non-empty, non-`#` line is one pattern. The SUPPORTED syntax is exactly:
///
/// - `*` matches any run of characters WITHIN one path segment (never `/`), so
///   `*.key` matches `id.key` and `secrets/*` matches `secrets/prod`;
/// - a pattern with NO `/` matches that segment at ANY depth, so `*.key` also
///   excludes `deep/nested/id.key` and `build/` excludes every `build` directory.
///   A pattern that DOES contain a `/` is anchored at the Space root; a leading
///   `/` says so explicitly (`/build` is the root one only);
/// - a trailing `/` matches only a DIRECTORY, so `build/` leaves a FILE named
///   `build` alone;
/// - a matched path excludes everything under it at a component boundary, so
///   `secrets` also excludes `secrets/api.key` (and `ab` is not under `a`).
///
/// Anything else — `**`, `[a-z]`, `?`, a leading `!` negation — is NOT interpreted:
/// the line is matched literally (with `*` still the one wildcard) and reported in
/// [`ScanResult::ignore_warnings`] and at WARN. An ignore pattern that silently
/// matches nothing is a confidentiality failure, not a cosmetic one, so it must be
/// impossible to write one and not be told.
///
/// An absent or empty file ignores nothing — filething never drops data the user
/// did not choose to exclude.
#[derive(Default)]
struct IgnoreList {
    patterns: Vec<IgnorePattern>,
    warnings: Vec<String>,
}

/// One parsed `.filethingignore` line.
struct IgnorePattern {
    /// One matcher per pattern segment (each may contain `*`).
    segments: Vec<String>,
    /// Single-segment and not root-anchored ⇒ matches that segment at any depth.
    any_depth: bool,
    /// Written with a trailing `/` ⇒ only a directory matches it exactly.
    dir_only: bool,
}

impl IgnoreList {
    /// Loads `<root>/.filethingignore` via the OS adapter; an absent/empty file
    /// yields an empty list (no exclusions).
    fn load(root: &Path, fs: &(dyn ft_fsmap::OsFs + Send + Sync)) -> Self {
        let path = root.join(IGNORE_FILE);
        let Ok(bytes) = fs.read_bytes(&path) else {
            return Self::default();
        };
        let mut out = Self::default();
        for line in String::from_utf8_lossy(&bytes).lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(unsupported) = unsupported_glob_syntax(line) {
                out.warnings.push(format!(
                    "{IGNORE_FILE}: pattern `{line}` uses {unsupported}, which filething does not \
                     support; it is matched literally and may exclude nothing"
                ));
            }
            if let Some(pattern) = IgnorePattern::parse(line) {
                out.patterns.push(pattern);
            }
        }
        out
    }

    /// True if `canonical` (a directory when `is_dir`) is excluded.
    fn is_ignored(&self, canonical: &CanonicalPath, is_dir: bool) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.matches(canonical.as_str(), is_dir))
    }
}

impl IgnorePattern {
    /// Parses one line; `None` for a line that carries no segment at all (`/`).
    fn parse(line: &str) -> Option<Self> {
        // Normalize to forward slashes so a Windows-style line still parses.
        let line = line.replace('\\', "/");
        let dir_only = line.ends_with('/');
        let anchored = line.starts_with('/');
        let segments: Vec<String> = line
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if segments.is_empty() {
            return None;
        }
        let any_depth = segments.len() == 1 && !anchored;
        Some(Self {
            segments,
            any_depth,
            dir_only,
        })
    }

    /// True if canonical `path` is excluded by this pattern.
    fn matches(&self, path: &str, is_dir: bool) -> bool {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if self.any_depth {
            let pattern = &self.segments[0];
            return segments.iter().enumerate().any(|(i, segment)| {
                if !glob_segment(pattern, segment) {
                    return false;
                }
                // A match on a NON-last segment means an ancestor matched, and an
                // ancestor is a directory by construction, so `dir_only` is met.
                i + 1 < segments.len() || !self.dir_only || is_dir
            });
        }
        if segments.len() < self.segments.len() {
            return false;
        }
        if !self
            .segments
            .iter()
            .zip(&segments)
            .all(|(pattern, segment)| glob_segment(pattern, segment))
        {
            return false;
        }
        // Deeper than the pattern ⇒ an ancestor matched (a directory); exactly the
        // pattern ⇒ honor `dir_only`.
        segments.len() > self.segments.len() || !self.dir_only || is_dir
    }
}

/// Matches one path segment against one pattern segment where `*` stands for any
/// run of characters (`§Ignore file`). No other character is special.
///
/// Byte-wise with the classic single-star backtrack: `*` may only ever consume a
/// whole run, and every literal byte still has to line up, so the accepted set is
/// the same as a char-wise match would give.
fn glob_segment(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut resume) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            resume = ti;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            // Give the star one more byte and retry from just after it.
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|b| *b == b'*')
}

/// Names the first glob construct in an ignore line that this MVP does not
/// interpret, so the caller can warn about it instead of silently matching a
/// pattern that excludes nothing.
fn unsupported_glob_syntax(line: &str) -> Option<&'static str> {
    if line.starts_with('!') {
        Some("a `!` negation")
    } else if line.contains("**") {
        Some("a `**` cross-directory wildcard")
    } else if line.contains('?') {
        Some("a `?` single-character wildcard")
    } else if line.contains('[') || line.contains(']') {
        Some("a `[…]` character class")
    } else {
        None
    }
}

/// True if canonical path `p` equals `prefix` or sits under it at a component
/// boundary (`a/b` is under `a`, but `ab` is not).
fn path_is_under(p: &str, prefix: &str) -> bool {
    p == prefix || (p.starts_with(prefix) && p.as_bytes().get(prefix.len()) == Some(&b'/'))
}

/// True if `canonical`'s first path component is `name` (used to skip the
/// control directory and everything under it).
fn is_under(canonical: &CanonicalPath, name: &str) -> bool {
    path_is_under(canonical.as_str(), name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ft_index::Index;
    use ft_vault::{FsVault, Vault};

    fn canonical(p: &str) -> CanonicalPath {
        CanonicalPath(p.to_string())
    }

    /// A [`WalkItem`] with a chosen canonical path, borrowing the metadata of a
    /// real file so collision resolution can be exercised without depending on
    /// what the host filesystem does with two case-colliding names.
    fn walk_item(canonical_path: &str, meta: &std::fs::Metadata) -> WalkItem {
        let canonical = canonical(canonical_path);
        WalkItem {
            abs: PathBuf::from(canonical_path),
            key: casefold_key(&canonical),
            canonical,
            meta: meta.clone(),
        }
    }

    fn mount(root: &Path, vault_dir: &Path, space_id: &str) -> SpaceContext {
        let index = Index::open_in_memory().unwrap();
        index
            .upsert_space_state(&ft_index::SpaceState {
                space_id: space_id.to_string(),
                last_synced_seq: -1,
                last_synced_root: ft_manifest::build(Vec::new()).root,
                last_synced_revision_id: None,
                chunk_secret: vec![0x5A; 32],
                dedup_secret: None,
                local_root_path: root.to_string_lossy().into_owned(),
            })
            .unwrap();
        let vault: Box<dyn Vault> = Box::new(FsVault::new(vault_dir));
        SpaceContext::mount(
            index,
            vault,
            Box::new(ft_fsmap::LinuxFs),
            crate::AccountId::new("acct-scan-unit"),
            crate::DeviceId::new("dev-scan-unit"),
            crate::SpaceId::new(space_id),
        )
        .unwrap()
    }

    #[test]
    fn glob_segment_treats_star_as_any_run_of_characters_and_nothing_else_as_special() {
        assert!(glob_segment("*.key", "id.key"));
        assert!(glob_segment("*.key", ".key"));
        assert!(!glob_segment("*.key", "key"));
        assert!(glob_segment("a*b*c", "azzbzzc"));
        assert!(!glob_segment("a*b*c", "azzbzz"));
        assert!(glob_segment("*", "anything"));
        assert!(glob_segment("exact", "exact"));
        assert!(!glob_segment("exact", "exactly"));
        // `?` is not a wildcard (the load path warns about it instead).
        assert!(!glob_segment("a?c", "abc"));
        assert!(glob_segment("a?c", "a?c"));
    }

    #[test]
    fn ignore_pattern_without_a_slash_matches_that_segment_at_any_depth() {
        let pattern = IgnorePattern::parse("*.key").unwrap();
        assert!(pattern.matches("id.key", false));
        assert!(pattern.matches("deep/nested/id.key", false));
        assert!(!pattern.matches("deep/keyring", false));
        // A matched directory takes its subtree with it.
        let dir = IgnorePattern::parse("secrets").unwrap();
        assert!(dir.matches("secrets", true));
        assert!(dir.matches("a/b/secrets/api.key", false));
        assert!(!dir.matches("secretsx", false));
    }

    #[test]
    fn ignore_pattern_with_a_slash_is_anchored_at_the_space_root() {
        let pattern = IgnorePattern::parse("secrets/*").unwrap();
        assert!(pattern.matches("secrets/prod", false));
        assert!(pattern.matches("secrets/prod/api.key", false));
        assert!(!pattern.matches("secrets", true));
        assert!(!pattern.matches("nested/secrets/prod", false));

        let anchored = IgnorePattern::parse("/build").unwrap();
        assert!(anchored.matches("build", true));
        assert!(anchored.matches("build/out.o", false));
        assert!(!anchored.matches("crate/build", true));
    }

    #[test]
    fn ignore_pattern_with_a_trailing_slash_matches_only_a_directory() {
        let pattern = IgnorePattern::parse("build/").unwrap();
        assert!(pattern.matches("build", true));
        assert!(
            !pattern.matches("build", false),
            "a FILE named build must keep syncing"
        );
        assert!(pattern.matches("build/out.o", false));
    }

    #[test]
    fn unsupported_ignore_syntax_is_named_so_the_scan_can_warn_about_it() {
        assert_eq!(
            unsupported_glob_syntax("secrets/**"),
            Some("a `**` cross-directory wildcard")
        );
        assert_eq!(unsupported_glob_syntax("!keep.me"), Some("a `!` negation"));
        assert_eq!(
            unsupported_glob_syntax("a?c"),
            Some("a `?` single-character wildcard")
        );
        assert_eq!(
            unsupported_glob_syntax("[abc].txt"),
            Some("a `[…]` character class")
        );
        assert_eq!(unsupported_glob_syntax("*.key"), None);
        assert_eq!(unsupported_glob_syntax("secrets/prod"), None);
    }

    #[test]
    fn resolve_collisions_keeps_the_lexicographically_first_of_two_colliding_paths() {
        let dir = tempfile::tempdir().unwrap();
        let probe = dir.path().join("probe");
        std::fs::write(&probe, b"probe").unwrap();
        let meta = std::fs::symlink_metadata(&probe).unwrap();

        // Sorted by canonical path, as `walk` hands them over: `Notes.md` < `notes.md`.
        let mut walk = Walk {
            items: vec![
                walk_item("Notes.md", &meta),
                walk_item("notes.md", &meta),
                walk_item("other.md", &meta),
            ],
            ..Walk::default()
        };
        resolve_collisions(&mut walk);

        let kept: Vec<&str> = walk.items.iter().map(|i| i.canonical.as_str()).collect();
        assert_eq!(
            kept,
            vec!["Notes.md", "other.md"],
            "only one path may hold a casefold key (§5.2)"
        );
        assert_eq!(walk.declined.len(), 1);
        assert_eq!(walk.declined[0].0.as_str(), "notes.md");
        assert_eq!(
            walk.declined[0].1,
            SkipReason::CasefoldCollision {
                winner: "Notes.md".to_string()
            }
        );
    }

    #[test]
    fn resolve_collisions_takes_the_subtree_of_a_colliding_directory_out_of_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let probe = dir.path().join("probe");
        std::fs::write(&probe, b"probe").unwrap();
        let meta = std::fs::symlink_metadata(&probe).unwrap();

        let mut walk = Walk {
            items: vec![
                walk_item("Src", &meta),
                walk_item("Src/main.rs", &meta),
                walk_item("src", &meta),
                walk_item("src/other.rs", &meta),
            ],
            ..Walk::default()
        };
        resolve_collisions(&mut walk);

        let kept: Vec<&str> = walk.items.iter().map(|i| i.canonical.as_str()).collect();
        assert_eq!(
            kept,
            vec!["Src", "Src/main.rs"],
            "no entry may be published whose parent directory is not"
        );
        let declined: Vec<&str> = walk.declined.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(declined, vec!["src"]);
    }

    #[test]
    fn scan_defers_files_past_the_upload_byte_budget_and_keeps_their_previous_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("space");
        std::fs::create_dir_all(&root).unwrap();
        let vault_dir = dir.path().join("vault");

        // Each file is a hair over half the (test) budget, so the third one cannot
        // start: distinct content, so nothing dedups them away.
        let chunk = MAX_PENDING_UPLOAD_BYTES / 2 + 1024;
        for (i, name) in ["a.bin", "b.bin", "c.bin"].iter().enumerate() {
            let mut bytes = vec![0u8; chunk];
            for (j, b) in bytes.iter_mut().enumerate() {
                *b = ((i * 7 + j * 31) % 251) as u8;
            }
            std::fs::write(root.join(name), &bytes).unwrap();
        }

        let ctx = mount(&root, &vault_dir, "space-budget");
        let scan = ctx.scan().unwrap();

        assert!(
            scan.has_deferred_work(),
            "a tree bigger than the budget must defer, not buffer it all: {:?}",
            scan.skipped
        );
        let deferred: Vec<&str> = scan
            .skipped
            .iter()
            .filter(|s| s.reason == SkipReason::Deferred)
            .map(|s| s.path.as_str())
            .collect();
        assert_eq!(
            deferred,
            vec!["c.bin"],
            "the budget is spent in sorted order, so the LAST file waits"
        );
        assert!(
            scan.blocks_to_upload
                .iter()
                .map(|(_, obj)| obj.len())
                .sum::<usize>()
                < MAX_PENDING_UPLOAD_BYTES * 2,
            "the buffered bytes must stay bounded by the budget plus one file"
        );
        // The deferred file was never synced, so there is nothing to republish; it
        // is simply absent from this Revision and picked up by the next scan.
        let paths: Vec<&str> = scan.entries.iter().map(|(_, e)| e.p.as_str()).collect();
        assert_eq!(paths, vec!["a.bin", "b.bin"]);
        assert!(
            ctx.index
                .get_entry("space-budget", &canonical("c.bin"))
                .unwrap()
                .is_none(),
            "a deferred file must not get an index row claiming it was hashed"
        );
    }
}
