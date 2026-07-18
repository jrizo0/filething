//! ft-diff — tree diff by hash pruning + apply (`docs/format.md §8`).
//!
//! Diffs two content-addressed Manifest trees (`root_a` = base/local, `root_b` =
//! new/remote) by **hash pruning**: two pages that share a `page_cid` name a
//! byte-identical subtree, so the whole subtree is pruned without downloading it.
//! Only the pages that differ are fetched; in the leaves that differ a linear
//! merge-join over the entries' [`CasefoldKey`] yields the per-file changes
//! ([`Change::Added`] / [`Change::Modified`] / [`Change::Deleted`]). A commit that
//! touched a handful of files therefore downloads only `O(log n)` pages — the
//! `~99 %` of the tree whose `page_cid` is unchanged is pruned (`§8.3`).
//!
//! [`materialize`] reconstructs a single [`FileEntry`] onto disk: it resolves the
//! ordered Block list (inline `bk`, or the externalized `blocklist/<cid>` object
//! when `bk_ref` is set), then downloads the `blocks/<cid>` objects CONCURRENTLY
//! (a bounded fan-out, ADR 0017) rather than one strictly-sequential round-trip at
//! a time — so a large multi-block file is no longer latency-bound. Each fetch
//! VERIFIES wire integrity (`ft_block::verify`, `§4.3`), decodes, and for `alg=1`
//! unwraps its data-key sidecar and AEAD-decrypts; the payloads are concatenated
//! back IN ORDER (`buffered`, not `buffer_unordered`, yields results in input
//! order with no reordering logic). The bytes are then written through the
//! [`OsFs`] adapter (honoring the executable bit). Symlinks (`t=1`) are recreated
//! from their literal target `lt`; Derived entries (`t=2`) materialize no bytes.
//! [`apply`] drives a slice of [`Change`]s: Added/Modified materialize, Deleted
//! removes the file from the filesystem.

use std::path::{Path, PathBuf};

use ft_core::{CasefoldKey, Cid, FileEntry, SpaceCrypto};
use ft_fsmap::OsFs;
use ft_manifest::{decode_page, Page};
use ft_vault::Vault;
use thiserror::Error;

/// Vault key for a Block's data-key sidecar:
/// `"keys/<space_id>/<aa>/<cid_hex>"` — the same 2-char fan-out as
/// `blocks/<aa>/<cid>`, but under a per-Space subtree of the `keys/` prefix
/// (`§4.5`). The sidecar lives and dies with `blocks/<cid>` (ADR 0015): the
/// download path reads it to unwrap the data key, the commit path writes it, and
/// the GC treats it as an attachment of the Block.
///
/// Unlike the Block object, which is Account-scoped and deduped across Spaces,
/// the sidecar is wrapped with a specific Space's `space_key`. Two Spaces of one
/// Account that share a chunk therefore need one sidecar EACH — the `<space_id>`
/// component keeps them from colliding on a single object key (which would leave
/// the second Space unable to unwrap the first Space's sidecar).
pub fn keys_key(space_id: &str, cid: &Cid) -> String {
    let prefix = format!("keys/{space_id}");
    ft_hash::fanout_key(&prefix, &ft_hash::hex_lower(cid.as_bytes()))
}

/// Errors produced while diffing or applying Manifest trees.
#[derive(Debug, Error)]
pub enum Error {
    /// A Vault `head`/`get`/`put` failed.
    #[error("vault error: {0}")]
    Vault(#[from] ft_vault::VaultError),

    /// Decoding a Manifest page object failed.
    #[error("manifest error: {0}")]
    Manifest(#[from] ft_manifest::ManifestError),

    /// Decoding or verifying a Block object failed (bad header, length mismatch,
    /// or a `cid` mismatch = a corrupt/wrong object on the wire, `§4.3`).
    #[error("block error: {0}")]
    Block(#[from] ft_block::Error),

    /// A core type error surfaced (e.g. an invalid id length).
    #[error("core error: {0}")]
    Core(#[from] ft_core::Error),

    /// An externalized blocklist object (`blocklist/<cid>` = canonical CBOR of a
    /// `Vec<Cid>`, no 64-byte header) failed to decode.
    #[error("blocklist decode at {cid}: {message}")]
    Blocklist {
        /// The blocklist object id (the entry's `bk_ref`).
        cid: Cid,
        /// A human-readable rendering of the CBOR error.
        message: String,
    },

    /// An externalized blocklist object's bytes did not hash to the `bk_ref` the
    /// entry promised: the Vault returned a substituted/reordered list under the
    /// expected key. Since the order of the list IS the file's content, this is a
    /// content-integrity failure caught BEFORE decoding (`§4.3`/`§5.3`).
    #[error("blocklist cid mismatch at {expected}: object hashed to {computed}")]
    BlocklistCidMismatch {
        /// The id the entry's `bk_ref` named (and the Vault key used to fetch).
        expected: Cid,
        /// The id the fetched bytes actually hash to.
        computed: Cid,
    },

    /// A Block object on the wire was encrypted (`alg=1`) but no
    /// [`SpaceCrypto`] was supplied to `materialize`/`apply`, so its data key
    /// cannot be unwrapped and the cleartext cannot be recovered. A typed error
    /// (never a panic): the caller mounted the Space without its key material.
    #[error(
        "block {cid} is encrypted (alg=1) but no Space key material was provided to decrypt it"
    )]
    EncryptedBlockWithoutKey {
        /// The addressing id of the encrypted Block that could not be decrypted.
        cid: Cid,
    },

    /// Writing/removing a file or symlink through the [`OsFs`] adapter failed.
    #[error("filesystem error: {0}")]
    Fs(#[from] ft_fsmap::FsMapError),

    /// A delete/remove of a materialized path failed at the OS level.
    #[error("removing {path}: {source}")]
    Remove {
        /// The path that could not be removed.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },
}

/// Crate `Result` alias over [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// A single per-file difference between two Manifest trees (`§8.3`).
///
/// `a` is the base/local side, `b` is the new/remote side, so:
/// - [`Change::Added`] — present only in `b`.
/// - [`Change::Modified`] — present on both with different content (`pcid`).
/// - [`Change::Deleted`] — present only in `a` (inferred by ABSENCE in `b`;
///   `§8` has no explicit tombstone in the Manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A file/symlink/derived entry that appears only in the new tree.
    Added(FileEntry),
    /// An entry present in both trees whose content (`pcid`) changed.
    Modified {
        /// The base/local entry.
        old: FileEntry,
        /// The new/remote entry.
        new: FileEntry,
    },
    /// An entry present only in the base tree (deleted in the new tree).
    Deleted(FileEntry),
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

/// Counts the Manifest pages downloaded during a [`diff`], so a test can assert
/// that hash pruning kept the walk to `O(log n)` pages (`§8.3`).
///
/// Each `fetch_page` increments the counter; pruned subtrees (equal `page_cid`)
/// are never fetched and never counted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DiffStats {
    /// Number of page objects fetched from the Vault during the diff.
    pub pages_fetched: usize,
}

/// Diffs two Manifest trees and returns the per-file [`Change`]s (`§8.3`).
///
/// `root_a` is the base/local root, `root_b` is the new/remote root. Both roots
/// are fetched (via `manifest_key` + [`decode_page`]); thereafter any two pages —
/// at any level — that share a `page_cid` name a byte-identical subtree and are
/// PRUNED (not fetched). Leaves that differ are merge-joined linearly by
/// [`CasefoldKey`].
///
/// See [`diff_counted`] for the variant that also reports how many pages were
/// downloaded.
pub async fn diff(vault: &dyn Vault, root_a: &Cid, root_b: &Cid) -> Result<Vec<Change>> {
    Ok(diff_counted(vault, root_a, root_b).await?.0)
}

/// Like [`diff`] but also returns a [`DiffStats`] recording how many pages were
/// downloaded — the hook the pruning test asserts on (`§8.3`).
pub async fn diff_counted(
    vault: &dyn Vault,
    root_a: &Cid,
    root_b: &Cid,
) -> Result<(Vec<Change>, DiffStats)> {
    let mut stats = DiffStats::default();

    // The whole tree is pruned up front if the roots are identical (a 32-byte
    // comparison, `§8.3` step "si a == b").
    if root_a == root_b {
        return Ok((Vec::new(), stats));
    }

    // Collect the differing leaf entries from each side, then merge-join the two
    // ordered runs into Added/Modified/Deleted. Because pruning drops every
    // shared subtree, `a_entries`/`b_entries` hold ONLY the entries reachable
    // through pages that actually differ — already key-ordered (the Manifest is
    // ordered by casefold key end-to-end).
    let mut a_entries: Vec<FileEntry> = Vec::new();
    let mut b_entries: Vec<FileEntry> = Vec::new();
    collect_diff(
        vault,
        Some(*root_a),
        Some(*root_b),
        &mut a_entries,
        &mut b_entries,
        &mut stats,
    )
    .await?;

    let changes = merge_join(a_entries, b_entries);
    Ok((changes, stats))
}

/// Fetches and decodes a single Manifest page, bumping the download counter.
async fn fetch_page(vault: &dyn Vault, cid: &Cid, stats: &mut DiffStats) -> Result<Page> {
    let key = ft_hash::manifest_key(cid);
    let obj = vault.get(&key).await?;
    stats.pages_fetched += 1;
    Ok(decode_page(&obj)?)
}

/// Recursively collects, into `a_out`/`b_out`, the leaf entries that are
/// reachable only through pages that DIFFER between the two subtrees rooted at
/// `a`/`b`. Pages sharing a `page_cid` are pruned (not fetched, not collected).
///
/// `a`/`b` are `Option<Cid>` so one side can be absent (a child range that exists
/// on only one side): its entries are all collected as additions/deletions.
///
/// The recursion is written without `async fn` recursion sugar (which Rust does
/// not allow directly) by boxing the returned future.
fn collect_diff<'a>(
    vault: &'a dyn Vault,
    a: Option<Cid>,
    b: Option<Cid>,
    a_out: &'a mut Vec<FileEntry>,
    b_out: &'a mut Vec<FileEntry>,
    stats: &'a mut DiffStats,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        match (a, b) {
            // Identical subtree -> prune (32-byte compare, no fetch). `§8.3`.
            (Some(ca), Some(cb)) if ca == cb => Ok(()),

            // Both present and differ: fetch each and reconcile by structure.
            (Some(ca), Some(cb)) => {
                let pa = fetch_page(vault, &ca, stats).await?;
                let pb = fetch_page(vault, &cb, stats).await?;
                reconcile_pages(vault, pa, pb, a_out, b_out, stats).await
            }

            // Only the base side has this range: every entry under it is a
            // deletion candidate.
            (Some(ca), None) => collect_all(vault, ca, a_out, stats).await,

            // Only the new side has this range: every entry is an addition.
            (None, Some(cb)) => collect_all(vault, cb, b_out, stats).await,

            (None, None) => Ok(()),
        }
    })
}

/// Reconciles two ALREADY-FETCHED pages that differ. Leaf-vs-leaf appends the
/// (ordered) entries to each side's run; index-vs-index pairs children by their
/// `min` key and recurses (pruning equal `page_cid` children). A leaf-vs-index
/// mismatch (different tree heights for the same key range) is handled by
/// collecting both sides fully into their runs, which still merge-joins
/// correctly.
fn reconcile_pages<'a>(
    vault: &'a dyn Vault,
    pa: Page,
    pb: Page,
    a_out: &'a mut Vec<FileEntry>,
    b_out: &'a mut Vec<FileEntry>,
    stats: &'a mut DiffStats,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        match (pa, pb) {
            (Page::Leaf(la), Page::Leaf(lb)) => {
                a_out.extend(la.e);
                b_out.extend(lb.e);
                Ok(())
            }
            (Page::Index(ia), Page::Index(ib)) => {
                // Merge-join the two child lists by their `min` key. Children
                // with the same `min` and the same `cid` are pruned by
                // `collect_diff`; same `min` but different `cid` recurse; a `min`
                // present on only one side is a one-sided range.
                let mut i = 0usize;
                let mut j = 0usize;
                let ca = ia.children;
                let cb = ib.children;
                while i < ca.len() || j < cb.len() {
                    match (ca.get(i), cb.get(j)) {
                        (Some(left), Some(right)) => match left.min.cmp(&right.min) {
                            std::cmp::Ordering::Equal => {
                                collect_diff(
                                    vault,
                                    Some(left.cid),
                                    Some(right.cid),
                                    a_out,
                                    b_out,
                                    stats,
                                )
                                .await?;
                                i += 1;
                                j += 1;
                            }
                            std::cmp::Ordering::Less => {
                                // This child range exists only on the base side.
                                collect_diff(vault, Some(left.cid), None, a_out, b_out, stats)
                                    .await?;
                                i += 1;
                            }
                            std::cmp::Ordering::Greater => {
                                // This child range exists only on the new side.
                                collect_diff(vault, None, Some(right.cid), a_out, b_out, stats)
                                    .await?;
                                j += 1;
                            }
                        },
                        (Some(left), None) => {
                            collect_diff(vault, Some(left.cid), None, a_out, b_out, stats).await?;
                            i += 1;
                        }
                        (None, Some(right)) => {
                            collect_diff(vault, None, Some(right.cid), a_out, b_out, stats).await?;
                            j += 1;
                        }
                        (None, None) => break,
                    }
                }
                Ok(())
            }
            // Heights differ for the same key range: collect each side fully.
            (Page::Leaf(la), Page::Index(ib)) => {
                a_out.extend(la.e);
                for child in ib.children {
                    collect_all(vault, child.cid, b_out, stats).await?;
                }
                Ok(())
            }
            (Page::Index(ia), Page::Leaf(lb)) => {
                for child in ia.children {
                    collect_all(vault, child.cid, a_out, stats).await?;
                }
                b_out.extend(lb.e);
                Ok(())
            }
        }
    })
}

/// Collects EVERY [`FileEntry`] under the subtree rooted at `cid` into `out`
/// (used for a key range present on only one side — a whole-subtree add/delete).
fn collect_all<'a>(
    vault: &'a dyn Vault,
    cid: Cid,
    out: &'a mut Vec<FileEntry>,
    stats: &'a mut DiffStats,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        match fetch_page(vault, &cid, stats).await? {
            Page::Leaf(leaf) => {
                out.extend(leaf.e);
                Ok(())
            }
            Page::Index(index) => {
                for child in index.children {
                    collect_all(vault, child.cid, out, stats).await?;
                }
                Ok(())
            }
        }
    })
}

/// Linear merge-join of two key-ordered entry runs into [`Change`]s.
///
/// Both runs are ordered by `casefold(NFC(p))` (the Manifest key), so a single
/// pass with two cursors classifies every entry: present only in `b` -> Added;
/// in both with a different `pcid` -> Modified; present only in `a` -> Deleted.
/// An entry present in both with the SAME `pcid` is unchanged and emitted as no
/// change (it only appears here when it shared a leaf with a changed sibling).
fn merge_join(a: Vec<FileEntry>, b: Vec<FileEntry>) -> Vec<Change> {
    // The runs may have been gathered from several differing leaves; sort by key
    // defensively so the two-cursor walk is correct even across page boundaries.
    let mut a = a;
    let mut b = b;
    a.sort_by_key(key_of);
    b.sort_by_key(key_of);

    let mut out = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < a.len() || j < b.len() {
        match (a.get(i), b.get(j)) {
            (Some(ea), Some(eb)) => {
                let ka = key_of(ea);
                let kb = key_of(eb);
                match ka.cmp(&kb) {
                    std::cmp::Ordering::Equal => {
                        // Same path on both sides: a change iff their FULL
                        // type-aware identity differs — not pcid alone. A
                        // metadata-only edit (exec bit `x`, a retargeted symlink
                        // `lt`, or a type flip) is a real change that must reach
                        // disk, even when `pcid` is unchanged (`BUG 3`; same
                        // notion as ft-conflict). "Changed" is causal, never the
                        // clock (`mtime` is never consulted, `§10`).
                        if !same_identity(ea, eb) {
                            out.push(Change::Modified {
                                old: ea.clone(),
                                new: eb.clone(),
                            });
                        }
                        i += 1;
                        j += 1;
                    }
                    std::cmp::Ordering::Less => {
                        // Present only in base -> deleted in the new tree.
                        out.push(Change::Deleted(ea.clone()));
                        i += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        // Present only in the new tree -> added.
                        out.push(Change::Added(eb.clone()));
                        j += 1;
                    }
                }
            }
            (Some(ea), None) => {
                out.push(Change::Deleted(ea.clone()));
                i += 1;
            }
            (None, Some(eb)) => {
                out.push(Change::Added(eb.clone()));
                j += 1;
            }
            (None, None) => break,
        }
    }
    out
}

/// The Manifest ordering/collision key of an entry: `casefold(NFC(p))`
/// (`ft_fsmap::casefold_key`), the same key the tree is built on.
fn key_of(e: &FileEntry) -> CasefoldKey {
    ft_fsmap::casefold_key(&e.p)
}

/// Do two entries at the SAME key carry identical materialized identity?
///
/// Identity is decided by TYPE, mirroring ft-conflict's content notion so the
/// diff and the conflict resolver agree on what "changed" means (`BUG 3`):
/// - **File** — whole-file plaintext id `pcid` AND the executable bit `x`.
/// - **Symlink** — the literal target `lt` (its `pcid` is contentless).
/// - **Derived** — type alone (its bytes never travel, so two derived entries at
///   one path are equivalent).
///
/// A change of TYPE itself (file <-> symlink <-> derived) is never the same
/// identity. `mtime` is never consulted (`§10`).
fn same_identity(a: &FileEntry, b: &FileEntry) -> bool {
    a.t == b.t
        && match a.t {
            ft_core::FileType::File => a.pcid == b.pcid && a.x == b.x,
            ft_core::FileType::Symlink => a.lt == b.lt,
            ft_core::FileType::Derived => true,
        }
}

// ---------------------------------------------------------------------------
// materialize
// ---------------------------------------------------------------------------

/// Max `blocks/<cid>` GETs kept in flight while materializing ONE file's Block
/// list (`§8.4`). Matches the commit path's upload fan-out (ADR 0017). Because
/// [`apply`] itself already drives up to 8 changes concurrently, the worst-case
/// number of in-flight Block GETs across a whole `apply` is `8 * 16 = 128`.
const BLOCK_DOWNLOAD_CONCURRENCY: usize = 16;

/// Materializes a single [`FileEntry`] onto disk under `space_root` (`§8.4`).
///
/// - **File** (`t=0`): resolves the ordered Block list — the externalized
///   `blocklist/<cid>` object when `bk_ref` is set, otherwise the inline `bk` —
///   then downloads the `blocks/<cid>` objects CONCURRENTLY (a bounded fan-out of
///   [`BLOCK_DOWNLOAD_CONCURRENCY`], ADR 0017). Each fetch VERIFIES integrity with
///   [`ft_block::verify`] (`BLAKE3(payload)` vs `cid`, `§4.3`) and decodes the
///   payload (for `alg=1`, unwrapping the data-key sidecar and AEAD-decrypting);
///   the decoded chunks are concatenated back IN ORDER (`buffered` yields results
///   in input order despite out-of-order completion). The bytes are written via
///   [`OsFs::write_bytes`] with the entry's executable bit. A single corrupt
///   object in the Vault aborts with [`Error::Block`] (the fan-out stops at the
///   first error; nothing is written).
/// - **Symlink** (`t=1`): recreates the symlink at the entry's path pointing at
///   its literal target `lt` (no bytes downloaded).
/// - **Derived** (`t=2`): materializes nothing (its bytes never travel, `§5.1`).
///
/// The on-disk path is `space_root` joined with the entry's canonical path; any
/// missing parent directories are created first.
///
/// `crypto` carries the Space's key material when runtime encryption is ON:
/// `alg=1` Block objects are decrypted with it (unwrapping each data key from its
/// `keys/<space_id>/<cid>` sidecar, where the Space id also comes from `crypto`).
/// It is `None` in the cleartext (`alg=0`) case — the
/// default; an `alg=1` object then fails with [`Error::EncryptedBlockWithoutKey`]
/// rather than panicking. An `alg=0` object never consults `crypto`.
pub async fn materialize(
    vault: &dyn Vault,
    fs: &dyn OsFs,
    space_root: &Path,
    entry: &FileEntry,
    crypto: Option<&SpaceCrypto>,
) -> Result<()> {
    let dest = join_canonical(space_root, entry);

    match entry.t {
        ft_core::FileType::Symlink => {
            // A symlink carries no Blocks: recreate it from its literal target.
            // Idempotently clear whatever occupies `dest` first, so a File (or a
            // stale symlink) at the same path does not make `create_symlink` fail
            // EEXIST and abort the batch (`BUG 1a`). On Unix `remove_file` removes
            // a regular file AND a symlink (it never follows it).
            ensure_parent(fs, &dest)?;
            remove_path(&dest)?;
            let target = entry.lt.clone().unwrap_or_default();
            fs.create_symlink(&target, &dest)?;
            Ok(())
        }
        ft_core::FileType::Derived => {
            // Derived bytes never travel; nothing to materialize. `§5.1`.
            Ok(())
        }
        ft_core::FileType::File => {
            use futures::stream::{self, StreamExt};
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::time::Instant;

            let bk = resolve_blocklist(vault, entry).await?;

            // Download, verify and decode every Block CONCURRENTLY, then
            // concatenate the plaintext chunks IN ORDER. `buffered` (NOT
            // `buffer_unordered`) drives up to `BLOCK_DOWNLOAD_CONCURRENCY` futures
            // at once but yields their results in INPUT order, so the ordered
            // concatenation below needs no reordering logic — the order of the
            // Block list IS the file's content (`§4.3`/`§5.3`). The first error
            // aborts the stream (via `?` below), leaving nothing written.
            let total = bk.len();
            let started = Instant::now();
            let completed = AtomicUsize::new(0);

            let mut stream = stream::iter(bk.iter())
                .map(|cid| {
                    let completed = &completed;
                    async move {
                        let key = ft_hash::block_key(cid);
                        let obj = vault.get(&key).await?;
                        // Wire-integrity check: a corrupt object fails here
                        // (`§4.3`). It recomputes the addressing hash from the
                        // object's own bytes and works for BOTH algs with no key,
                        // so it also guarantees the header's `alg` is 0 or 1 before
                        // we branch on it below.
                        ft_block::verify(&obj, cid)?;
                        let (header, payload) = ft_block::decode(&obj)?;
                        let chunk = if header.alg == ft_core::ALG_CLEARTEXT {
                            // Cleartext (`alg=0`): the payload IS the content.
                            payload
                        } else {
                            // Encrypted (`alg=1`): unwrap this Block's data key
                            // from its `keys/<space_id>/<cid>` sidecar with the
                            // Space key, then AEAD-decrypt the object
                            // (`§4.4`/`§4.5`). No key material ⇒ typed error, never
                            // a panic.
                            let crypto =
                                crypto.ok_or(Error::EncryptedBlockWithoutKey { cid: *cid })?;
                            let sidecar = vault.get(&keys_key(&crypto.space_id, cid)).await?;
                            let data_key =
                                ft_block::sidecar::unwrap_data_key(&sidecar, &crypto.space_key)?;
                            ft_block::decode_encrypted(&obj, &data_key)?
                        };
                        let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                        if n.is_multiple_of(25) {
                            tracing::info!(completed = n, total, "downloading blocks");
                        }
                        Result::Ok(chunk)
                    }
                })
                .buffered(BLOCK_DOWNLOAD_CONCURRENCY);

            let mut contents: Vec<u8> = Vec::with_capacity(entry.sz as usize);
            while let Some(chunk) = stream.next().await {
                contents.extend_from_slice(&chunk?);
            }

            let elapsed_ms = started.elapsed().as_millis() as u64;
            let bytes = contents.len();
            // Use `info` for real files so the throughput is visible next to the
            // commit path's "blocks uploaded" line; keep tiny files at `debug` so a
            // sync of many small files does not spam the log.
            if total >= 25 {
                tracing::info!(total, bytes, elapsed_ms, "blocks downloaded");
            } else {
                tracing::debug!(total, bytes, elapsed_ms, "blocks downloaded");
            }

            ensure_parent(fs, &dest)?;
            // Write through a sibling tmp + atomic rename so a stale SYMLINK at
            // `dest` is never followed (a plain `fs::write` follows the link and
            // scribbles its target — a phantom file — leaving `dest` a symlink,
            // `BUG 1b`). The rename also guarantees the final TYPE of the path is
            // exactly this File, replacing any pre-existing file/symlink in one
            // step; remove first as a fallback for platforms where rename-onto a
            // symlink would not clobber it.
            remove_path(&dest)?;
            write_file_atomic(fs, &dest, &contents, entry.x)?;
            Ok(())
        }
    }
}

/// Writes `bytes` to `dest` via a sibling temporary file + atomic `rename`, so a
/// stale symlink at `dest` is never followed and the final path is unambiguously
/// a regular file (`BUG 1b`). The exec bit is set on the tmp before the rename so
/// the published file has the right mode the instant it appears.
fn write_file_atomic(fs: &dyn OsFs, dest: &Path, bytes: &[u8], exec: bool) -> Result<()> {
    let dir = dest.parent().unwrap_or_else(|| Path::new("."));
    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // A deterministic, collision-resistant sibling name; the materialize is the
    // sole writer of this path within a batch.
    let tmp = dir.join(format!(".{file_name}.ft-tmp"));
    // Best-effort clear of any leftover tmp, then write + rename.
    remove_path(&tmp)?;
    fs.write_bytes(&tmp, bytes, exec)?;
    match std::fs::rename(&tmp, dest) {
        Ok(()) => Ok(()),
        Err(source) => {
            // Don't leak the tmp if the rename failed.
            let _ = std::fs::remove_file(&tmp);
            Err(Error::Remove {
                path: dest.display().to_string(),
                source,
            })
        }
    }
}

/// Resolves the ordered list of Block ids for a file [`FileEntry`].
///
/// When `bk_ref` is set the list lives in an externalized `blocklist/<cid>`
/// object — bare canonical CBOR of a `Vec<Cid>`, NO 64-byte header — decoded
/// directly with `ciborium` (`§5.3`). Otherwise the inline `bk` is used as-is.
async fn resolve_blocklist(vault: &dyn Vault, entry: &FileEntry) -> Result<Vec<Cid>> {
    match entry.bk_ref {
        Some(ref_cid) => {
            let key = ft_hash::blocklist_key(&ref_cid);
            let obj = vault.get(&key).await?;
            // Verify the object's bytes hash to the bk_ref the entry promised
            // BEFORE decoding. The order of the list IS the file's content, so a
            // reordered/substituted list under the same key would otherwise pass
            // silently even though every individual block still cid-checks
            // (`BUG 2`, `§4.3`/`§5.3`).
            let computed = ft_hash::cid_of(&obj);
            if computed != ref_cid {
                return Err(Error::BlocklistCidMismatch {
                    expected: ref_cid,
                    computed,
                });
            }
            let list: Vec<Cid> =
                ciborium::de::from_reader(&obj[..]).map_err(|e| Error::Blocklist {
                    cid: ref_cid,
                    message: e.to_string(),
                })?;
            Ok(list)
        }
        None => Ok(entry.bk.clone()),
    }
}

/// Joins `space_root` with an entry's canonical (forward-slash) path.
fn join_canonical(space_root: &Path, entry: &FileEntry) -> PathBuf {
    let mut dest = space_root.to_path_buf();
    for part in entry.p.as_str().split('/').filter(|s| !s.is_empty()) {
        dest.push(part);
    }
    dest
}

/// Creates the parent directory of `dest` if it does not exist, mapping any IO
/// error into [`Error::Remove`]-shaped context via [`ft_fsmap::FsMapError`].
fn ensure_parent(_fs: &dyn OsFs, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|source| Error::Fs(ft_fsmap::FsMapError::Io(source)))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

/// Applies a slice of [`Change`]s to the filesystem under `space_root` (`§8.4`).
///
/// - [`Change::Added`] / [`Change::Modified`] -> [`materialize`] the new entry.
/// - [`Change::Deleted`] -> remove the file (or symlink) from disk.
///
/// Removing an already-absent path is a no-op (a delete is idempotent), so a
/// re-apply does not fail.
///
/// `crypto` is forwarded to [`materialize`] for every Added/Modified change so an
/// `alg=1` Block can be decrypted; `None` keeps the cleartext path (see
/// [`materialize`]).
///
/// The changes run CONCURRENTLY (`buffer_unordered`, bounded to 8 in flight):
/// `changes` comes from a single [`diff`] call, whose merge-join emits at most one
/// `Change` per [`CasefoldKey`](ft_core::CasefoldKey) — every change here targets
/// a DIFFERENT path, so materializing/removing them in parallel touches disjoint
/// files and is safe. Aborts on the first error (a later change may still be
/// in flight when that happens; `apply` is not resumable mid-batch either way).
pub async fn apply(
    vault: &dyn Vault,
    fs: &dyn OsFs,
    space_root: &Path,
    changes: &[Change],
    crypto: Option<&SpaceCrypto>,
) -> Result<()> {
    use futures::stream::{self, StreamExt, TryStreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    let total = changes.len();
    tracing::info!(total, "applying changes");
    let started = Instant::now();
    let completed = AtomicUsize::new(0);

    stream::iter(changes.iter())
        .map(|change| {
            let completed = &completed;
            async move {
                match change {
                    Change::Added(entry) | Change::Modified { new: entry, .. } => {
                        materialize(vault, fs, space_root, entry, crypto).await?;
                    }
                    Change::Deleted(entry) => {
                        let dest = join_canonical(space_root, entry);
                        remove_path(&dest)?;
                    }
                }
                let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_multiple_of(25) {
                    tracing::info!(completed = n, total, "applying changes");
                }
                Result::Ok(())
            }
        })
        .buffer_unordered(8)
        .try_collect::<Vec<()>>()
        .await?;

    tracing::info!(
        total,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "changes applied"
    );
    Ok(())
}

/// Removes a file or symlink at `dest`; an absent path is a no-op.
fn remove_path(dest: &Path) -> Result<()> {
    match std::fs::remove_file(dest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::Remove {
            path: dest.display().to_string(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ft_core::{CanonicalPath, FileType, Pcid};
    use ft_fsmap::LinuxFs;
    use ft_manifest::{build, ManifestBuild};
    use ft_vault::FsVault;
    use std::collections::BTreeSet;

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    /// Uploads every page + blocklist object of a `ManifestBuild` to the Vault.
    async fn upload_manifest(vault: &FsVault, b: &ManifestBuild) {
        for (cid, obj) in &b.pages {
            vault
                .put(&ft_hash::manifest_key(cid), obj.clone())
                .await
                .unwrap();
        }
        for (cid, obj) in &b.blocklists {
            vault
                .put(&ft_hash::blocklist_key(cid), obj.clone())
                .await
                .unwrap();
        }
    }

    /// A single-block file entry whose path is `name` and whose one Block id is
    /// seeded by `seed` — perturbing `seed` perturbs `pcid` and the block id.
    fn file_entry(name: &str, seed: u8) -> (CasefoldKey, FileEntry) {
        let entry = FileEntry {
            p: CanonicalPath(name.to_string()),
            t: FileType::File,
            x: false,
            sz: 10,
            pcid: Pcid::new([seed; 32]),
            bk: vec![Cid::new([seed; 32])],
            bk_ref: None,
            lt: None,
            wu: None,
        };
        (ft_fsmap::casefold_key(&entry.p), entry)
    }

    /// `n` file entries with zero-padded, sortable keys, deterministic seeds.
    fn many(n: usize) -> Vec<(CasefoldKey, FileEntry)> {
        (0..n)
            .map(|i| file_entry(&format!("file{i:05}.rs"), (i % 251) as u8))
            .collect()
    }

    fn changed_paths(changes: &[Change]) -> Vec<String> {
        let mut v: Vec<String> = changes
            .iter()
            .map(|c| match c {
                Change::Added(e) => format!("A:{}", e.p.as_str()),
                Change::Modified { new, .. } => format!("M:{}", new.p.as_str()),
                Change::Deleted(e) => format!("D:{}", e.p.as_str()),
            })
            .collect();
        v.sort();
        v
    }

    // -----------------------------------------------------------------------
    // (1) PRUNING: change 1 file among >256 entries -> O(log n) pages fetched
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pruning_downloads_only_log_n_pages() {
        // 600 entries -> 3 leaves + 1 index root = 4 pages. We seed BOTH trees
        // into one Vault (content-addressed: shared pages dedup to one object).
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        let base = many(600);
        let a = build(base.clone());

        // Perturb exactly ONE entry (in the first leaf): same key, new pcid+block.
        let mut mutated = base.clone();
        let (k, _) = mutated[10].clone();
        let mut e = file_entry(k.as_str(), 222).1;
        e.p = CanonicalPath(k.as_str().to_string());
        mutated[10] = (k, e);
        let b = build(mutated);

        upload_manifest(&vault, &a).await;
        upload_manifest(&vault, &b).await;

        let (changes, stats) = diff_counted(&vault, &a.root, &b.root).await.unwrap();

        // Exactly one Modified change (the touched entry), nothing else.
        assert_eq!(changes.len(), 1, "exactly one change expected");
        match &changes[0] {
            Change::Modified { old, new } => {
                assert_eq!(old.p.as_str(), "file00010.rs");
                assert_eq!(new.p.as_str(), "file00010.rs");
                assert_ne!(old.pcid, new.pcid);
            }
            other => panic!("expected Modified, got {other:?}"),
        }

        // Pruning math: 600 entries -> 3 leaves + 1 root index per tree (8 pages
        // total across both trees). The two roots differ, so both are fetched (2)
        // and their 3 child ranges are merge-joined: the ONE changed leaf is
        // fetched on each side (2), the other two leaves share `page_cid` and are
        // PRUNED. So exactly 4 pages are downloaded — half the full 8, and the
        // unchanged-leaf count never enters the walk regardless of tree width.
        assert_eq!(
            stats.pages_fetched, 4,
            "expected 4 pages (2 roots + the 1 changed leaf on each side), got {}",
            stats.pages_fetched
        );
        // It is strictly fewer than the 8 pages the two full trees hold: pruning
        // skipped the 2 unchanged leaves on each side that share a page_cid.
        assert!(stats.pages_fetched < a.pages.len() + b.pages.len());
    }

    #[tokio::test]
    async fn pruning_scales_logarithmically_on_a_big_tree() {
        // ~5000 entries -> ~20 leaves + index levels. One change must still fetch
        // only a logarithmic number of pages, NOT the whole tree.
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        let n = 5000;
        let base = many(n);
        let a = build(base.clone());

        let mut mutated = base.clone();
        let (k, _) = mutated[2500].clone();
        let mut e = file_entry(k.as_str(), 199).1;
        e.p = CanonicalPath(k.as_str().to_string());
        mutated[2500] = (k, e);
        let b = build(mutated);

        upload_manifest(&vault, &a).await;
        upload_manifest(&vault, &b).await;

        let (changes, stats) = diff_counted(&vault, &a.root, &b.root).await.unwrap();
        assert_eq!(changes.len(), 1);

        // The full pair of trees is ~ (20 leaves + index pages) * 2 ~ > 40 pages.
        // A logarithmic walk fetches a tiny fraction. Assert generously: under 12.
        assert!(
            stats.pages_fetched < 12,
            "expected O(log n) pages, got {}",
            stats.pages_fetched
        );
    }

    #[tokio::test]
    async fn diff_of_identical_roots_fetches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let a = build(many(600));
        upload_manifest(&vault, &a).await;

        let (changes, stats) = diff_counted(&vault, &a.root, &a.root).await.unwrap();
        assert!(changes.is_empty());
        assert_eq!(stats.pages_fetched, 0, "identical roots prune immediately");
    }

    // -----------------------------------------------------------------------
    // (2) Added / Modified / Deleted all detected
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn detects_added_modified_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        // Base: a, b, c.
        let a_tree = build(vec![
            file_entry("a.txt", 1),
            file_entry("b.txt", 2),
            file_entry("c.txt", 3),
        ]);
        // New: a (modified), b (deleted), c (unchanged), d (added).
        let mut b_mod = file_entry("a.txt", 99).1; // different pcid -> Modified
        b_mod.p = CanonicalPath("a.txt".to_string());
        let b_tree = build(vec![
            (CasefoldKey("a.txt".to_string()), b_mod),
            file_entry("c.txt", 3), // unchanged (same seed -> same pcid)
            file_entry("d.txt", 4), // added
        ]);

        upload_manifest(&vault, &a_tree).await;
        upload_manifest(&vault, &b_tree).await;

        let changes = diff(&vault, &a_tree.root, &b_tree.root).await.unwrap();
        assert_eq!(
            changed_paths(&changes),
            vec!["A:d.txt", "D:b.txt", "M:a.txt"]
        );

        // c.txt is unchanged -> it must NOT appear as any change.
        assert!(!changes.iter().any(|c| match c {
            Change::Added(e) | Change::Deleted(e) => e.p.as_str() == "c.txt",
            Change::Modified { new, .. } => new.p.as_str() == "c.txt",
        }));
    }

    // -----------------------------------------------------------------------
    // (3) Deleted inferred purely by absence (no tombstone, §8)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_inferred_by_absence() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        let a_tree = build(vec![file_entry("keep.txt", 1), file_entry("gone.txt", 2)]);
        // New tree simply omits gone.txt — no explicit tombstone.
        let b_tree = build(vec![file_entry("keep.txt", 1)]);

        upload_manifest(&vault, &a_tree).await;
        upload_manifest(&vault, &b_tree).await;

        let changes = diff(&vault, &a_tree.root, &b_tree.root).await.unwrap();
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::Deleted(e) => assert_eq!(e.p.as_str(), "gone.txt"),
            other => panic!("expected Deleted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn diff_against_empty_tree_is_all_additions() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        let empty = build(vec![]);
        let full = build(vec![
            file_entry("x.txt", 1),
            file_entry("y.txt", 2),
            file_entry("z.txt", 3),
        ]);
        upload_manifest(&vault, &empty).await;
        upload_manifest(&vault, &full).await;

        let changes = diff(&vault, &empty.root, &full.root).await.unwrap();
        assert_eq!(
            changed_paths(&changes),
            vec!["A:x.txt", "A:y.txt", "A:z.txt"]
        );
    }

    // -----------------------------------------------------------------------
    // (4) materialize a multi-block file byte-identical + integrity check
    // -----------------------------------------------------------------------

    /// Builds a file entry whose content is split into `chunks` Blocks, uploads
    /// the Blocks to `vault`, and returns (entry, full_content).
    async fn upload_multiblock_file(
        vault: &FsVault,
        name: &str,
        chunks: &[&[u8]],
    ) -> (FileEntry, Vec<u8>) {
        let mut bk = Vec::new();
        let mut content = Vec::new();
        for chunk in chunks {
            let obj = ft_block::encode(chunk);
            let cid = ft_block::cid_for(chunk);
            vault.put(&ft_hash::block_key(&cid), obj).await.unwrap();
            bk.push(cid);
            content.extend_from_slice(chunk);
        }
        let entry = FileEntry {
            p: CanonicalPath(name.to_string()),
            t: FileType::File,
            x: false,
            sz: content.len() as u64,
            pcid: ft_hash::pcid_of(&content),
            bk,
            bk_ref: None,
            lt: None,
            wu: None,
        };
        (entry, content)
    }

    #[tokio::test]
    async fn materialize_reconstructs_multiblock_file_byte_identical() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let chunks: Vec<&[u8]> = vec![
            b"first chunk of bytes-",
            b"second chunk here----",
            b"and the third and last",
        ];
        let (entry, content) = upload_multiblock_file(&vault, "dir/multi.bin", &chunks).await;

        materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap();

        let on_disk = std::fs::read(space_dir.path().join("dir").join("multi.bin")).unwrap();
        assert_eq!(
            on_disk, content,
            "reconstructed file must be byte-identical"
        );
    }

    #[tokio::test]
    async fn materialize_detects_a_corrupt_block_in_the_vault() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let payload = vec![7u8; 4096];
        let cid = ft_block::cid_for(&payload);
        // Upload a CORRUPT object: a valid header but a flipped payload byte, so
        // its key still says `cid` but its bytes hash to something else.
        let mut obj = ft_block::encode(&payload);
        let mid = ft_core::BLOCK_HEADER_LEN + payload.len() / 2;
        obj[mid] ^= 0x01;
        vault.put(&ft_hash::block_key(&cid), obj).await.unwrap();

        let entry = FileEntry {
            p: CanonicalPath("corrupt.bin".to_string()),
            t: FileType::File,
            x: false,
            sz: payload.len() as u64,
            pcid: Pcid::new(*cid.as_bytes()),
            bk: vec![cid],
            bk_ref: None,
            lt: None,
            wu: None,
        };

        let err = materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Block(ft_block::Error::CidMismatch { .. })),
            "corrupt block must fail wire-integrity, got {err:?}"
        );
        // And nothing was written.
        assert!(!space_dir.path().join("corrupt.bin").exists());
    }

    #[tokio::test]
    async fn materialize_resolves_externalized_blocklist() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        // Upload two real blocks, then put their ids into a blocklist object
        // (bare canonical CBOR of Vec<Cid>, NO header) and reference it via bk_ref.
        let c1: &[u8] = b"alpha-";
        let c2: &[u8] = b"omega!";
        let cid1 = ft_block::cid_for(c1);
        let cid2 = ft_block::cid_for(c2);
        vault
            .put(&ft_hash::block_key(&cid1), ft_block::encode(c1))
            .await
            .unwrap();
        vault
            .put(&ft_hash::block_key(&cid2), ft_block::encode(c2))
            .await
            .unwrap();

        let bk = vec![cid1, cid2];
        let mut bl_bytes = Vec::new();
        ciborium::ser::into_writer(&bk, &mut bl_bytes).unwrap();
        let bl_cid = ft_hash::cid_of(&bl_bytes);
        vault
            .put(&ft_hash::blocklist_key(&bl_cid), bl_bytes)
            .await
            .unwrap();

        let entry = FileEntry {
            p: CanonicalPath("ext.bin".to_string()),
            t: FileType::File,
            x: false,
            sz: (c1.len() + c2.len()) as u64,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: Some(bl_cid),
            lt: None,
            wu: None,
        };

        materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap();
        let on_disk = std::fs::read(space_dir.path().join("ext.bin")).unwrap();
        assert_eq!(on_disk, b"alpha-omega!");
    }

    #[tokio::test]
    async fn materialize_sets_executable_bit() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let (mut entry, _content) =
            upload_multiblock_file(&vault, "run.sh", &[b"#!/bin/sh\n" as &[u8]]).await;
        entry.x = true;

        materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap();
        let meta = std::fs::symlink_metadata(space_dir.path().join("run.sh")).unwrap();
        assert!(fs.exec_bit(&meta), "executable bit must be set");
    }

    #[tokio::test]
    async fn materialize_creates_symlink_from_literal_target() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let entry = FileEntry {
            p: CanonicalPath("link".to_string()),
            t: FileType::Symlink,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: None,
            lt: Some("../target/x.md".to_string()),
            wu: None,
        };
        materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap();
        let target = fs.read_symlink(&space_dir.path().join("link")).unwrap();
        assert_eq!(target, "../target/x.md");
    }

    #[tokio::test]
    async fn materialize_derived_writes_nothing() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let entry = FileEntry {
            p: CanonicalPath("node_modules/dep.js".to_string()),
            t: FileType::Derived,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: None,
            lt: None,
            wu: None,
        };
        materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap();
        assert!(!space_dir
            .path()
            .join("node_modules")
            .join("dep.js")
            .exists());
    }

    // -----------------------------------------------------------------------
    // (5) round-trip: build -> upload -> diff vs empty -> apply -> disk matches
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn round_trip_diff_and_apply_materializes_the_whole_set() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        // A small set of real multi-block files: build their entries (uploading
        // their Blocks), then build + upload the Manifest of those entries.
        let files: Vec<(&str, Vec<&[u8]>)> = vec![
            (
                "src/main.rs",
                vec![b"fn main() {" as &[u8], b" println!(); }"],
            ),
            ("README.md", vec![b"# title\n" as &[u8]]),
            ("data/blob.bin", vec![b"AAAA" as &[u8], b"BBBB", b"CCCC"]),
        ];

        let mut entries = Vec::new();
        let mut expected: Vec<(String, Vec<u8>)> = Vec::new();
        for (name, chunks) in &files {
            let (entry, content) = upload_multiblock_file(&vault, name, chunks).await;
            entries.push((ft_fsmap::casefold_key(&entry.p), entry));
            expected.push((name.to_string(), content));
        }

        let manifest = build(entries);
        upload_manifest(&vault, &manifest).await;

        // diff vs the empty tree -> every file is an addition.
        let empty = build(vec![]);
        upload_manifest(&vault, &empty).await;
        let changes = diff(&vault, &empty.root, &manifest.root).await.unwrap();
        assert_eq!(changes.len(), files.len());
        assert!(changes.iter().all(|c| matches!(c, Change::Added(_))));

        // apply -> the files land on disk byte-identical.
        apply(&vault, &fs, space_dir.path(), &changes, None)
            .await
            .unwrap();
        for (name, content) in &expected {
            let mut p = space_dir.path().to_path_buf();
            for part in name.split('/') {
                p.push(part);
            }
            let on_disk = std::fs::read(&p).unwrap_or_else(|e| panic!("read {name}: {e}"));
            assert_eq!(&on_disk, content, "{name} must be byte-identical");
        }
    }

    #[tokio::test]
    async fn apply_deletes_remove_files_from_disk() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        // Put a file on disk, then apply a Deleted change for it.
        let (entry, _content) =
            upload_multiblock_file(&vault, "victim.txt", &[b"bye" as &[u8]]).await;
        materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap();
        assert!(space_dir.path().join("victim.txt").exists());

        apply(
            &vault,
            &fs,
            space_dir.path(),
            &[Change::Deleted(entry.clone())],
            None,
        )
        .await
        .unwrap();
        assert!(!space_dir.path().join("victim.txt").exists());

        // Idempotent: deleting an already-absent path is a no-op.
        apply(
            &vault,
            &fs,
            space_dir.path(),
            &[Change::Deleted(entry)],
            None,
        )
        .await
        .unwrap();
    }

    // -----------------------------------------------------------------------
    // (BUG 1) materialize must REPLACE whatever exists at a path so the final
    // on-disk TYPE is exactly the FileEntry's type — even across File<->Symlink
    // transitions — without aborting the batch or writing through a stale link.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn apply_file_to_symlink_transition_leaves_a_symlink_not_eexist() {
        // A path that was a FILE in the base tree becomes a SYMLINK in the new
        // tree. Without an idempotent pre-remove, create_symlink fails EEXIST and
        // `apply` aborts the WHOLE batch.
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        // Materialize the path as a regular file first.
        let (file_entry, _content) =
            upload_multiblock_file(&vault, "shifter", &[b"i was a file" as &[u8]]).await;
        materialize(&vault, &fs, space_dir.path(), &file_entry, None)
            .await
            .unwrap();
        let dest = space_dir.path().join("shifter");
        assert!(dest.is_file());

        // Now the same path is a symlink in the new tree.
        let link_entry = FileEntry {
            p: CanonicalPath("shifter".to_string()),
            t: FileType::Symlink,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: None,
            lt: Some("../elsewhere".to_string()),
            wu: None,
        };
        // Plus a second, unrelated addition AFTER it: if the batch aborts on the
        // EEXIST, this file never lands — that's how we detect the abort.
        let (sentinel, sentinel_content) =
            upload_multiblock_file(&vault, "sentinel.txt", &[b"i must exist" as &[u8]]).await;

        apply(
            &vault,
            &fs,
            space_dir.path(),
            &[
                Change::Modified {
                    old: file_entry,
                    new: link_entry,
                },
                Change::Added(sentinel),
            ],
            None,
        )
        .await
        .unwrap();

        // The path is now a SYMLINK (not the old file) pointing at the new target.
        let meta = std::fs::symlink_metadata(&dest).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "path must be a symlink after File->Symlink, got {:?}",
            meta.file_type()
        );
        assert_eq!(fs.read_symlink(&dest).unwrap(), "../elsewhere");

        // The batch did NOT abort: the later addition landed.
        let on_disk = std::fs::read(space_dir.path().join("sentinel.txt")).unwrap();
        assert_eq!(on_disk, sentinel_content, "batch must not have aborted");
    }

    #[tokio::test]
    async fn apply_symlink_to_file_transition_writes_a_real_file_not_through_the_link() {
        // A path that was a SYMLINK becomes a FILE. fs::write FOLLOWS the stale
        // symlink and writes into its target (a phantom file), leaving the path a
        // symlink — silent corruption. The fix must leave the path as a real file
        // and must NOT touch the old link target.
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        // The old symlink points at a sibling "victim" path inside the space.
        let link_entry = FileEntry {
            p: CanonicalPath("shifter".to_string()),
            t: FileType::Symlink,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: None,
            lt: Some("victim".to_string()),
            wu: None,
        };
        materialize(&vault, &fs, space_dir.path(), &link_entry, None)
            .await
            .unwrap();
        let dest = space_dir.path().join("shifter");
        assert!(std::fs::symlink_metadata(&dest)
            .unwrap()
            .file_type()
            .is_symlink());

        // Same path is now a real FILE in the new tree.
        let (file_entry, content) =
            upload_multiblock_file(&vault, "shifter", &[b"now i am bytes" as &[u8]]).await;

        apply(
            &vault,
            &fs,
            space_dir.path(),
            &[Change::Modified {
                old: link_entry,
                new: file_entry,
            }],
            None,
        )
        .await
        .unwrap();

        // The path is now a REAL FILE (not a symlink) with the new bytes.
        let meta = std::fs::symlink_metadata(&dest).unwrap();
        assert!(
            meta.file_type().is_file(),
            "path must be a regular file after Symlink->File, got {:?}",
            meta.file_type()
        );
        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk, content);

        // No phantom file was created at the old link target (write must not have
        // followed the stale symlink).
        assert!(
            !space_dir.path().join("victim").exists(),
            "writing must not have followed the stale symlink to its target"
        );
    }

    // -----------------------------------------------------------------------
    // (BUG 2) An externalized blocklist object must be verified against bk_ref
    // (order IS the content): a substituted/reordered list under the same key
    // must be REJECTED before decoding.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn materialize_rejects_a_substituted_blocklist_object() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        // Two real blocks.
        let c1: &[u8] = b"alpha-";
        let c2: &[u8] = b"omega!";
        let cid1 = ft_block::cid_for(c1);
        let cid2 = ft_block::cid_for(c2);
        vault
            .put(&ft_hash::block_key(&cid1), ft_block::encode(c1))
            .await
            .unwrap();
        vault
            .put(&ft_hash::block_key(&cid2), ft_block::encode(c2))
            .await
            .unwrap();

        // The honest blocklist [cid1, cid2] gives the bk_ref cid we trust.
        let honest = vec![cid1, cid2];
        let mut honest_bytes = Vec::new();
        ciborium::ser::into_writer(&honest, &mut honest_bytes).unwrap();
        let bl_cid = ft_hash::cid_of(&honest_bytes);

        // A CORRUPT vault stores a REORDERED list [cid2, cid1] under the SAME key.
        // Each block still passes its own cid-check, but the list order (=content)
        // was tampered with. Nothing in the per-block check can catch this.
        let tampered = vec![cid2, cid1];
        let mut tampered_bytes = Vec::new();
        ciborium::ser::into_writer(&tampered, &mut tampered_bytes).unwrap();
        vault
            .put(&ft_hash::blocklist_key(&bl_cid), tampered_bytes)
            .await
            .unwrap();

        let entry = FileEntry {
            p: CanonicalPath("ext.bin".to_string()),
            t: FileType::File,
            x: false,
            sz: (c1.len() + c2.len()) as u64,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: Some(bl_cid),
            lt: None,
            wu: None,
        };

        let err = materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::BlocklistCidMismatch { .. }),
            "a substituted blocklist must be rejected by integrity, got {err:?}"
        );
        // And nothing was written to disk.
        assert!(!space_dir.path().join("ext.bin").exists());
    }

    // -----------------------------------------------------------------------
    // (BUG 3) A metadata-only change (same pcid, different exec bit) is Modified.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn detects_exec_bit_only_change_as_modified() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        // Same key, same pcid+blocks; the ONLY difference is the exec bit.
        let (k, mut a_entry) = file_entry("run.sh", 7);
        a_entry.x = false;
        let mut b_entry = a_entry.clone();
        b_entry.x = true;
        assert_eq!(a_entry.pcid, b_entry.pcid, "pcid is held constant");

        let a_tree = build(vec![(k.clone(), a_entry)]);
        let b_tree = build(vec![(k, b_entry)]);
        upload_manifest(&vault, &a_tree).await;
        upload_manifest(&vault, &b_tree).await;

        let changes = diff(&vault, &a_tree.root, &b_tree.root).await.unwrap();
        assert_eq!(changes.len(), 1, "exec-bit flip must surface a change");
        match &changes[0] {
            Change::Modified { old, new } => {
                assert!(!old.x);
                assert!(new.x);
                assert_eq!(old.pcid, new.pcid, "pcid unchanged; identity by exec bit");
            }
            other => panic!("expected Modified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn detects_symlink_target_only_change_as_modified() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        // A symlink whose literal target changes but whose (contentless) pcid is
        // held constant: identity for symlinks is `lt`, not pcid.
        let mk = |lt: &str| FileEntry {
            p: CanonicalPath("link".to_string()),
            t: FileType::Symlink,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: None,
            lt: Some(lt.to_string()),
            wu: None,
        };
        let key = ft_fsmap::casefold_key(&CanonicalPath("link".to_string()));
        let a_tree = build(vec![(key.clone(), mk("../old"))]);
        let b_tree = build(vec![(key, mk("../new"))]);
        upload_manifest(&vault, &a_tree).await;
        upload_manifest(&vault, &b_tree).await;

        let changes = diff(&vault, &a_tree.root, &b_tree.root).await.unwrap();
        assert_eq!(changes.len(), 1, "retargeted symlink must be Modified");
        match &changes[0] {
            Change::Modified { old, new } => {
                assert_eq!(old.lt.as_deref(), Some("../old"));
                assert_eq!(new.lt.as_deref(), Some("../new"));
            }
            other => panic!("expected Modified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn diff_classifies_against_unique_page_set() {
        // Document that the diff result is a function of the entry sets, not the
        // page count — a quick BTreeSet check that changed keys are unique.
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        let a = build(many(300));
        let mut mutated = many(300);
        // Change 3 entries spread across the tree.
        for idx in [0usize, 150, 299] {
            let (k, _) = mutated[idx].clone();
            let mut e = file_entry(k.as_str(), 250).1;
            e.p = CanonicalPath(k.as_str().to_string());
            mutated[idx] = (k, e);
        }
        let b = build(mutated);

        upload_manifest(&vault, &a).await;
        upload_manifest(&vault, &b).await;

        let changes = diff(&vault, &a.root, &b.root).await.unwrap();
        let keys: BTreeSet<String> = changes
            .iter()
            .map(|c| match c {
                Change::Modified { new, .. } => new.p.as_str().to_string(),
                Change::Added(e) | Change::Deleted(e) => e.p.as_str().to_string(),
            })
            .collect();
        // 3 entries changed (seed differs from their originals at these indices).
        assert!(keys.len() <= 3 && !keys.is_empty());
    }

    // -----------------------------------------------------------------------
    // Encryption (alg=1): materialize decrypts, mixes with alg=0, and refuses
    // without key material (§4.4/§4.5).
    // -----------------------------------------------------------------------

    const DEDUP_SECRET: [u8; 32] = [0x11u8; 32];
    const SPACE_KEY: [u8; 32] = [0xAAu8; 32];
    const SPACE_ID: &str = "space-under-test";

    fn crypto() -> SpaceCrypto {
        SpaceCrypto {
            dedup_secret: DEDUP_SECRET,
            space_key: SPACE_KEY,
            space_id: SPACE_ID.to_string(),
        }
    }

    /// Encrypts `chunks` into `alg=1` Block objects, uploads each Block AND its
    /// `keys/<space_id>/<cid>` sidecar to `vault`, and returns (entry, cleartext).
    async fn upload_encrypted_file(
        vault: &FsVault,
        name: &str,
        chunks: &[&[u8]],
    ) -> (FileEntry, Vec<u8>) {
        let mut bk = Vec::new();
        let mut content = Vec::new();
        for chunk in chunks {
            let (cid, _pcid, obj, data_key) =
                ft_block::encode_encrypted(chunk, &DEDUP_SECRET).unwrap();
            vault.put(&ft_hash::block_key(&cid), obj).await.unwrap();
            let sidecar = ft_block::sidecar::wrap_data_key(&data_key, &SPACE_KEY);
            vault.put(&keys_key(SPACE_ID, &cid), sidecar).await.unwrap();
            bk.push(cid);
            content.extend_from_slice(chunk);
        }
        let entry = FileEntry {
            p: CanonicalPath(name.to_string()),
            t: FileType::File,
            x: false,
            sz: content.len() as u64,
            pcid: ft_hash::pcid_of(&content),
            bk,
            bk_ref: None,
            lt: None,
            wu: None,
        };
        (entry, content)
    }

    #[tokio::test]
    async fn materialize_decrypts_alg1_and_vault_never_holds_the_cleartext() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let chunks: Vec<&[u8]> = vec![b"SECRET-alpha-", b"SECRET-omega-", b"SECRET-tail!!"];
        let (entry, content) = upload_encrypted_file(&vault, "secret.bin", &chunks).await;

        // Materialize WITH key material -> the cleartext is reconstructed exactly.
        let c = crypto();
        materialize(&vault, &fs, space_dir.path(), &entry, Some(&c))
            .await
            .unwrap();
        let on_disk = std::fs::read(space_dir.path().join("secret.bin")).unwrap();
        assert_eq!(on_disk, content, "alg=1 must round-trip to the cleartext");

        // The stored Block objects must NOT contain the cleartext bytes: what
        // lives in the Vault is ciphertext, the plaintext only exists after decrypt.
        for cid in &entry.bk {
            let obj = vault.get(&ft_hash::block_key(cid)).await.unwrap();
            assert!(
                !contains_subslice(&obj, b"SECRET-"),
                "the encrypted Vault object must not carry the cleartext"
            );
        }
    }

    #[tokio::test]
    async fn materialize_alg1_without_key_material_is_a_typed_error_not_a_panic() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let (entry, _content) =
            upload_encrypted_file(&vault, "secret.bin", &[b"needs a key"]).await;

        // No SpaceCrypto -> a clean EncryptedBlockWithoutKey, and nothing written.
        let err = materialize(&vault, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::EncryptedBlockWithoutKey { .. }),
            "alg=1 without key material must be a typed error, got {err:?}"
        );
        assert!(!space_dir.path().join("secret.bin").exists());
    }

    #[tokio::test]
    async fn materialize_resolves_a_space_mixing_alg0_and_alg1_blocks() {
        // A Space with a preexisting cleartext (alg=0) file plus a new encrypted
        // (alg=1) file: both must materialize when key material is present (§11,
        // mixed vault is allowed forever).
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let (plain_entry, plain) =
            upload_multiblock_file(&vault, "plain.txt", &[b"i am cleartext" as &[u8]]).await;
        let (enc_entry, enc) = upload_encrypted_file(&vault, "enc.bin", &[b"i am encrypted"]).await;

        let c = crypto();
        materialize(&vault, &fs, space_dir.path(), &plain_entry, Some(&c))
            .await
            .unwrap();
        materialize(&vault, &fs, space_dir.path(), &enc_entry, Some(&c))
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(space_dir.path().join("plain.txt")).unwrap(),
            plain
        );
        assert_eq!(
            std::fs::read(space_dir.path().join("enc.bin")).unwrap(),
            enc
        );
    }

    /// True if `haystack` contains `needle` as a contiguous subslice.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    // -----------------------------------------------------------------------
    // Concurrency: materialize downloads a file's Blocks CONCURRENTLY but
    // concatenates them IN ORDER (ADR 0017). A latency-injecting Vault wrapper
    // scrambles completion order and records the peak number of in-flight GETs,
    // so we can assert both (a) byte-identical output and (b) real concurrency.
    // -----------------------------------------------------------------------

    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A [`Vault`] that wraps [`FsVault`], sleeps a per-`get` delay before each
    /// fetch, and tracks how many `get`s are in flight at once (current + peak).
    ///
    /// The delay is `base_ms + (hash(key) % (jitter_ms + 1))`: deterministic per
    /// key but varied across keys, so blocks fetched together finish in a
    /// SCRAMBLED order — exactly the condition an order-preserving fan-out must
    /// survive. `jitter_ms == 0` gives a fixed delay (used by the benchmark).
    struct DelayVault {
        inner: FsVault,
        base_ms: u64,
        jitter_ms: u64,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        gets: AtomicUsize,
    }

    impl DelayVault {
        fn new(inner: FsVault, base_ms: u64, jitter_ms: u64) -> Self {
            Self {
                inner,
                base_ms,
                jitter_ms,
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                gets: AtomicUsize::new(0),
            }
        }

        /// Deterministic per-key jitter in `0..=span` (FNV-1a of the key).
        fn jitter_for(key: &str, span: u64) -> u64 {
            if span == 0 {
                return 0;
            }
            let mut h: u64 = 0xcbf29ce484222325;
            for b in key.bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h % (span + 1)
        }
    }

    #[async_trait]
    impl Vault for DelayVault {
        async fn head(&self, key: &str) -> ft_vault::VaultResult<bool> {
            self.inner.head(key).await
        }

        async fn get(&self, key: &str) -> ft_vault::VaultResult<Vec<u8>> {
            let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(cur, Ordering::SeqCst);
            self.gets.fetch_add(1, Ordering::SeqCst);
            let ms = self.base_ms + Self::jitter_for(key, self.jitter_ms);
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            let r = self.inner.get(key).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            r
        }

        async fn put(&self, key: &str, body: Vec<u8>) -> ft_vault::VaultResult<()> {
            self.inner.put(key, body).await
        }

        async fn list(&self, prefix: &str) -> ft_vault::VaultResult<Vec<ft_vault::VaultObject>> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> ft_vault::VaultResult<()> {
            self.inner.delete(key).await
        }
    }

    #[tokio::test]
    async fn materialize_multiblock_is_order_preserving_under_concurrency() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        // 40 blocks with DISTINCT content per block, so a reordering bug would
        // corrupt the bytes (identical chunks would dedup to one cid and hide it).
        let owned: Vec<Vec<u8>> = (0..40)
            .map(|i| format!("block-{i:04}-distinct-payload-for-ordering-check-{i}").into_bytes())
            .collect();
        let chunks: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let (entry, content) = upload_multiblock_file(&vault, "big/multi.bin", &chunks).await;

        // Fetch through the delay vault (5..=15ms per get -> scrambled completion).
        let delay = DelayVault::new(FsVault::new(vault_dir.path()), 5, 10);
        materialize(&delay, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap();

        let on_disk = std::fs::read(space_dir.path().join("big").join("multi.bin")).unwrap();
        assert_eq!(
            on_disk, content,
            "reconstructed file must be byte-identical despite out-of-order completion"
        );

        // The fan-out was actually concurrent: more than one GET was in flight.
        let peak = delay.max_in_flight.load(Ordering::SeqCst);
        assert!(
            peak > 1,
            "expected concurrent block GETs (peak in-flight > 1), got {peak}"
        );
        assert_eq!(delay.gets.load(Ordering::SeqCst), 40, "one GET per block");
    }

    #[tokio::test]
    async fn materialize_alg1_multiblock_is_order_preserving_under_concurrency() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        let owned: Vec<Vec<u8>> = (0..24)
            .map(|i| format!("SECRET-{i:04}-encrypted-chunk-content-{i}").into_bytes())
            .collect();
        let chunks: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let (entry, content) = upload_encrypted_file(&vault, "secret/multi.bin", &chunks).await;

        // Encrypted path adds a per-block sidecar GET inside the same future; the
        // delay still scrambles completion across the buffered fan-out.
        let delay = DelayVault::new(FsVault::new(vault_dir.path()), 5, 10);
        let c = crypto();
        materialize(&delay, &fs, space_dir.path(), &entry, Some(&c))
            .await
            .unwrap();

        let on_disk = std::fs::read(space_dir.path().join("secret").join("multi.bin")).unwrap();
        assert_eq!(
            on_disk, content,
            "alg=1 multi-block must round-trip byte-identical under concurrency"
        );
        let peak = delay.max_in_flight.load(Ordering::SeqCst);
        assert!(
            peak > 1,
            "expected concurrent GETs on the encrypted path, got peak {peak}"
        );
    }

    #[tokio::test]
    async fn corrupt_block_still_fails_cleanly_through_the_delay_vault() {
        // The concurrent path must keep the same integrity semantics: a corrupt
        // block aborts with Error::Block(CidMismatch) and writes nothing.
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        // Several honest blocks plus one corrupt one in the middle.
        let good: &[u8] = b"good-and-honest-block-payload";
        for i in 0..5u8 {
            let mut c = good.to_vec();
            c.push(i);
            let cid = ft_block::cid_for(&c);
            vault
                .put(&ft_hash::block_key(&cid), ft_block::encode(&c))
                .await
                .unwrap();
        }
        let payload = vec![7u8; 4096];
        let corrupt_cid = ft_block::cid_for(&payload);
        let mut obj = ft_block::encode(&payload);
        let mid = ft_core::BLOCK_HEADER_LEN + payload.len() / 2;
        obj[mid] ^= 0x01;
        vault
            .put(&ft_hash::block_key(&corrupt_cid), obj)
            .await
            .unwrap();

        let mut bk = Vec::new();
        for i in 0..5u8 {
            let mut c = good.to_vec();
            c.push(i);
            bk.push(ft_block::cid_for(&c));
        }
        bk.insert(2, corrupt_cid);

        let entry = FileEntry {
            p: CanonicalPath("corrupt.bin".to_string()),
            t: FileType::File,
            x: false,
            sz: 4096,
            pcid: Pcid::new([0u8; 32]),
            bk,
            bk_ref: None,
            lt: None,
            wu: None,
        };

        let delay = DelayVault::new(FsVault::new(vault_dir.path()), 3, 6);
        let err = materialize(&delay, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Block(ft_block::Error::CidMismatch { .. })),
            "corrupt block must fail wire-integrity, got {err:?}"
        );
        assert!(!space_dir.path().join("corrupt.bin").exists());
    }

    /// A latency-bound benchmark for the concurrent download path. Ignored by
    /// default (it sleeps for hundreds of ms). Run with:
    /// `cargo test -p ft-diff -- --ignored bench_materialize`.
    ///
    /// 320 blocks x 64 KiB = 20 MiB, each GET delayed a FIXED 25ms. A sequential
    /// download would take at least `320 * 25ms = 8s`; the `buffered(16)` fan-out
    /// should finish in ~0.5s. Asserting `< 2s` fails loudly on any regression to
    /// a strictly-sequential loop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn bench_materialize_20mb_with_latency() {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vault_dir.path());
        let space_dir = tempfile::tempdir().unwrap();
        let fs = LinuxFs;

        const N: usize = 320;
        const CHUNK: usize = 64 * 1024;
        let owned: Vec<Vec<u8>> = (0..N)
            .map(|i| {
                let mut c = vec![0u8; CHUNK];
                // Distinct first bytes per block so every cid differs (no dedup).
                c[0] = (i & 0xff) as u8;
                c[1] = ((i >> 8) & 0xff) as u8;
                c
            })
            .collect();
        let chunks: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let (entry, content) = upload_multiblock_file(&vault, "bench/big.bin", &chunks).await;
        assert_eq!(content.len(), N * CHUNK);

        let per_get_ms = 25u64;
        let delay = DelayVault::new(FsVault::new(vault_dir.path()), per_get_ms, 0);

        let started = std::time::Instant::now();
        materialize(&delay, &fs, space_dir.path(), &entry, None)
            .await
            .unwrap();
        let elapsed = started.elapsed();

        let mib = (N * CHUNK) as f64 / (1024.0 * 1024.0);
        let mb_per_s = mib / elapsed.as_secs_f64();
        let sequential_ms = N as u64 * per_get_ms;
        println!(
            "bench_materialize_20mb_with_latency: {N} blocks x {CHUNK} B = {mib:.1} MiB, \
             {per_get_ms}ms/get\n  concurrent elapsed = {:?} ({mb_per_s:.1} MiB/s), \
             peak in-flight = {}\n  theoretical sequential >= {sequential_ms} ms ({:.1} s)",
            elapsed,
            delay.max_in_flight.load(Ordering::SeqCst),
            sequential_ms as f64 / 1000.0,
        );

        let on_disk = std::fs::read(space_dir.path().join("bench").join("big.bin")).unwrap();
        assert_eq!(on_disk.len(), content.len(), "20 MiB round-trip");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "concurrent download must be far faster than the {sequential_ms}ms sequential \
             floor; got {elapsed:?} (regression to a sequential loop?)"
        );
    }
}
