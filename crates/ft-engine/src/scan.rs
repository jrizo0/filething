//! `scan` — walk the Space's local root and produce the FileEntry set + the
//! Blocks to upload (`docs/format.md §3`, `§5.1`, `§5.2`, `§9`).
//!
//! `scan` is the first step of a commit (`§7` step 1). It walks `local_root`
//! with `walkdir`, skipping the `.filething/` control directory, the built-in
//! platform-junk file names ([`JUNK_NAMES`], ADR 0011) and any path excluded by
//! `.filethingignore` (empty by default ⇒ nothing excluded, `§Ignore file`).
//! For every surviving entry it:
//!
//! - derives the canonical path ([`ft_fsmap::canonicalize`]) and its
//!   [`CasefoldKey`] ([`ft_fsmap::casefold_key`]);
//! - classifies it ([`ft_fsmap::classify`] + [`ft_fsmap::symlink_policy`]):
//!   - **File** (`t=0`): reads the bytes, chunks them with the Space
//!     [`Chunker`](ft_chunker::Chunker), computes each span's `pcid`/`cid`
//!     (equal in the MVP) and the whole-file `pcid`, builds the ordered `bk`,
//!     and collects each Block's encoded object for upload;
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

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ft_block::{cid_for, encode};
use ft_core::{CanonicalPath, CasefoldKey, Cid, FileEntry, FileType, Pcid};
use ft_fsmap::{canonicalize, casefold_key, classify, is_derived, symlink_policy, SymlinkDecision};
use ft_index::{BlockRef, LocalEntry};
use walkdir::WalkDir;

use crate::context::SpaceContext;
use crate::error::Result;

/// The control directory name kept out of the Manifest (`§Ignore file` /
/// engine internals). Anything under `.filething/` is never synced.
pub const CONTROL_DIR: &str = ".filething";

/// The per-Space ignore-file name (`§Ignore file`). Empty by default.
pub const IGNORE_FILE: &str = ".filethingignore";

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

/// True if `name` is an exact platform-junk file name (see [`JUNK_NAMES`]).
fn is_junk_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|n| JUNK_NAMES.contains(&n))
}

/// The full output of [`SpaceContext::scan`].
///
/// `entries` is the `(CasefoldKey, FileEntry)` set to feed straight into
/// [`ft_manifest::build`] (it excludes local-only symlinks, `§5.1`).
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
}

impl ScanResult {
    /// The whole-tree root [`Cid`] this scan would commit, i.e.
    /// `ft_manifest::build(self.entries).root`. Computed on demand (it is a pure
    /// function of `entries`) so a caller can compare it against
    /// `last_synced.root` to detect "no change" without rebuilding twice.
    pub fn manifest_root(&self) -> Cid {
        ft_manifest::build(self.entries.clone()).root
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

impl SpaceContext {
    /// Walks `local_root` and produces the [`ScanResult`] for this Device's
    /// current on-disk state, updating the local index as a side effect.
    ///
    /// See the module docs for the per-type rules. The index is brought in line
    /// with disk: present paths are upserted, vanished paths are deleted.
    pub fn scan(&self) -> Result<ScanResult> {
        let space_id = self.space_id.as_str().to_string();
        let base_seq = self.last_synced.seq;
        let ignore = IgnoreList::load(&self.local_root, self.fs.as_ref());

        let mut result = ScanResult::default();
        let mut seen_blocks: HashSet<Cid> = HashSet::new();
        // Canonical paths present on disk this scan, to compute deletions.
        let mut present: HashSet<CanonicalPath> = HashSet::new();

        for item in self.walk(&ignore)? {
            let item = item?;
            present.insert(item.canonical.clone());

            let file_type = classify(&item.meta, &item.canonical_as_path());
            match file_type {
                FileType::File => {
                    self.handle_file(&item, base_seq, &mut result, &mut seen_blocks)?;
                }
                FileType::Symlink => {
                    self.handle_symlink(&item, base_seq, &mut result)?;
                }
                FileType::Derived => {
                    self.handle_derived(&item, base_seq, &mut result)?;
                }
                FileType::Dir => {
                    self.handle_dir(&item, base_seq, &mut result)?;
                }
            }
        }

        // Anything in the index but no longer on disk is a delete: drop it so it
        // does not enter this scan's Manifest (a delete is an absence, §8).
        for entry in self.index.list_entries(&space_id)? {
            if !present.contains(&entry.path) {
                self.index.delete_entry(&space_id, &entry.path)?;
            }
        }

        Ok(result)
    }

    /// Walks the tree, skipping the control dir, ignored paths and the contents
    /// of derived directories (a derived dir yields ONE entry, then is not
    /// descended). Returns each surviving entry as a [`WalkItem`].
    fn walk(&self, ignore: &IgnoreList) -> Result<Vec<Result<WalkItem>>> {
        let root = &self.local_root;
        let mut out: Vec<Result<WalkItem>> = Vec::new();

        let mut walker = WalkDir::new(root).follow_links(false).into_iter();
        while let Some(next) = walker.next() {
            let dent = match next {
                Ok(d) => d,
                Err(e) => {
                    out.push(Err(walkdir_io(e)));
                    continue;
                }
            };
            let abs = dent.path().to_path_buf();

            // The root itself is not an entry.
            if abs == *root {
                continue;
            }

            // Canonicalize relative to the root. A path that somehow escapes is
            // surfaced as an error rather than silently dropped.
            let canonical = match canonicalize(root, &abs) {
                Ok(c) => c,
                Err(e) => {
                    out.push(Err(e.into()));
                    continue;
                }
            };

            // Skip the control directory and everything under it.
            if is_under(&canonical, CONTROL_DIR) {
                if dent.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                continue;
            }

            // Skip ignored paths (empty .filethingignore ⇒ never matches).
            if ignore.is_ignored(&canonical) {
                if dent.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                continue;
            }

            // Skip built-in platform junk (`.DS_Store`, `Thumbs.db`,
            // `desktop.ini`) in ANY directory, regardless of .filethingignore
            // (ADR 0011). Matched by exact entry name; scanner side only, so it
            // never enters the Manifest and a Space already carrying one
            // converges by deletion.
            if is_junk_name(dent.file_name()) {
                continue;
            }

            // Non-following metadata so a symlink reads as a symlink.
            let meta = match std::fs::symlink_metadata(&abs) {
                Ok(m) => m,
                Err(e) => {
                    out.push(Err(e.into()));
                    continue;
                }
            };

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
                    out.push(Ok(WalkItem {
                        abs,
                        canonical,
                        key,
                        meta,
                    }));
                }
                if dent.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                continue;
            }

            // A plain directory is a first-class entry (ADR 0019) so empty
            // directories sync: emit a WalkItem for it AND keep descending (unlike
            // a derived dir, which is not descended). The Space root is never an
            // entry (skipped above). `classify` maps it to `FileType::Dir`.
            let key = casefold_key(&canonical);
            out.push(Ok(WalkItem {
                abs,
                canonical,
                key,
                meta,
            }));
        }

        Ok(out)
    }

    /// File (`t=0`): chunk, hash, build the ordered `bk`, collect Blocks, and
    /// upsert the index row (`§5.1`, `§9`).
    fn handle_file(
        &self,
        item: &WalkItem,
        base_seq: i64,
        result: &mut ScanResult,
        seen_blocks: &mut HashSet<Cid>,
    ) -> Result<()> {
        let space_id = self.space_id.as_str();
        let bytes = self.fs.read_bytes(&item.abs)?;
        let whole_pcid = ft_hash::pcid_of(&bytes);
        let exec = self.fs.exec_bit(&item.meta);

        let spans = self.chunker.chunk(&bytes);
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
                result.blocks_to_upload.push((cid, obj));
                if let Some(sidecar) = sidecar {
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
        // scan marked them present, the first commit would skip every upload.
        let mtime = self.mtime_secs(&item.abs);
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

        result.entries.push((item.key.clone(), entry));
        Ok(())
    }

    /// Symlink (`t=1`): apply the `§5.1` policy. A preserved link enters the
    /// Manifest with `lt` set and a deterministic `pcid`; a local-only link is
    /// recorded in the index and kept OUT of the Manifest.
    fn handle_symlink(
        &self,
        item: &WalkItem,
        base_seq: i64,
        result: &mut ScanResult,
    ) -> Result<()> {
        let space_id = self.space_id.as_str();
        let target = self.fs.read_symlink(&item.abs)?;
        let link_rel = Path::new(item.canonical.as_str());
        let decision = symlink_policy(&target, link_rel, &self.local_root);
        let mtime = self.mtime_secs(&item.abs);

        match decision {
            SymlinkDecision::Preserve(literal) => {
                // Deterministic pcid over the target bytes: a retarget changes
                // the pcid ⇒ the FileEntry ⇒ the manifestRoot (§5.1).
                let pcid = ft_hash::pcid_of(literal.as_bytes());
                let entry = FileEntry {
                    p: item.canonical.clone(),
                    t: FileType::Symlink,
                    x: false,
                    sz: 0,
                    pcid,
                    bk: Vec::new(),
                    bk_ref: None,
                    lt: Some(literal.clone()),
                    wu: None,
                };
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
                result.entries.push((item.key.clone(), entry));
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
    ) -> Result<()> {
        let space_id = self.space_id.as_str();
        let entry = FileEntry {
            p: item.canonical.clone(),
            t: FileType::Derived,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: Vec::new(),
            bk_ref: None,
            lt: None,
            wu: None,
        };
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
        result.entries.push((item.key.clone(), entry));
        Ok(())
    }

    /// Dir (`t=3`): a plain directory tracked as a first-class entry so empty
    /// directories sync (ADR 0019). Only `p`/`t` are meaningful; no bytes travel.
    /// Mirrors [`handle_derived`](Self::handle_derived) but the index row is NOT
    /// `local_only` (dirs DO enter the Manifest and sync) and carries no `pcid`.
    fn handle_dir(&self, item: &WalkItem, base_seq: i64, result: &mut ScanResult) -> Result<()> {
        let space_id = self.space_id.as_str();
        let entry = FileEntry {
            p: item.canonical.clone(),
            t: FileType::Dir,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: Vec::new(),
            bk_ref: None,
            lt: None,
            wu: None,
        };
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
        result.entries.push((item.key.clone(), entry));
        Ok(())
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

impl WalkItem {
    /// The canonical path as a `Path` (for `classify`, which keys off path
    /// components for the derived check).
    fn canonical_as_path(&self) -> PathBuf {
        Path::new(self.canonical.as_str()).to_path_buf()
    }
}

/// The parsed `.filethingignore` for a Space (`§Ignore file`).
///
/// MVP semantics: each non-empty, non-`#` line is a canonical path prefix. A
/// canonical path is ignored if it equals a pattern or sits under it (component
/// boundary). Empty (or absent) file ⇒ nothing is ignored — filething never
/// drops data the user did not choose to exclude.
struct IgnoreList {
    prefixes: Vec<String>,
}

impl IgnoreList {
    /// Loads `<root>/.filethingignore` via the OS adapter; an absent/empty file
    /// yields an empty list (no exclusions).
    fn load(root: &Path, fs: &(dyn ft_fsmap::OsFs + Send + Sync)) -> Self {
        let path = root.join(IGNORE_FILE);
        let prefixes = match fs.read_bytes(&path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes)
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                // Normalize to forward-slash, no leading/trailing slash.
                .map(|l| l.trim_matches('/').replace('\\', "/"))
                .filter(|l| !l.is_empty())
                .collect(),
            Err(_) => Vec::new(),
        };
        Self { prefixes }
    }

    /// True if `canonical` equals an ignore prefix or lives under one.
    fn is_ignored(&self, canonical: &CanonicalPath) -> bool {
        let p = canonical.as_str();
        self.prefixes.iter().any(|prefix| path_is_under(p, prefix))
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

/// Maps a `walkdir::Error` to an [`EngineError`], preferring its inner IO error.
fn walkdir_io(e: walkdir::Error) -> crate::error::EngineError {
    match e.into_io_error() {
        Some(io) => io.into(),
        None => std::io::Error::other("walkdir traversal error").into(),
    }
}
