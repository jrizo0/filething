//! `gc` — mark-and-sweep garbage collection of unreachable Vault objects,
//! guarded by a grace-period and the retention floor (`docs/format.md §6.3`,
//! `docs/adr/0007`).
//!
//! The **mark** phase computes every Vault key reachable from the RETAINED
//! Revisions (those with `seq >= retentionFloorSeq`, or all of them in
//! [`GcOptions::keep_all`] mode): every Manifest page, every externalized
//! blocklist (and the Blocks it lists), every inline Block, plus the Space meta
//! blob and the empty-Manifest root. The **sweep** phase lists the physical
//! objects and deletes those that are BOTH unreachable AND older than the
//! grace-period. Dry-run by default: nothing is deleted unless
//! [`GcOptions::apply`] is set.
//!
//! Two independent safety nets make an erroneous delete of live data
//! impossible in normal operation (`docs/adr/0007`):
//! - **Retention floor** = `min(baseSeqInUse)` over the Account's Devices: the
//!   GC never sweeps objects reachable from a Revision any Device still bases on
//!   (`baseSeqInUse` only advances and is published on advance, so the floor is a
//!   lower bound on every Device's real base — it can only over-retain).
//! - **Grace-period**: never sweep an object younger than the window, so a
//!   commit in flight (Vault-first, head-after, `§7`) whose objects are uploaded
//!   but not yet referenced by a committed Revision is protected.
//!
//! As a last resort it REFUSES to run if the retained set is empty while the
//! Space has a head (a backend anomaly), rather than sweeping everything.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use ft_core::{Cid, FileEntry};
use ft_manifest::{decode_page, Page};
use ft_vault::{Vault, VaultObject};

use crate::context::SpaceContext;
use crate::error::{EngineError, Result};

/// The Vault prefixes the GC enumerates and may sweep. `keys/` and `reach/` are
/// reserved (encryption off, `§4.5`/`§6.3`) and deliberately never touched.
const SWEEP_PREFIXES: [&str; 4] = ["blocks/", "manifest/", "blocklist/", "meta/"];

/// The default grace-period: 24h. An object younger than this is never swept.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// Knobs for a [`SpaceContext::gc`] run.
#[derive(Debug, Clone)]
pub struct GcOptions {
    /// Actually delete swept objects. `false` (the default) is a dry run: the
    /// report lists what WOULD be deleted and the Vault is untouched.
    pub apply: bool,
    /// Never sweep an object younger than this. Protects in-flight commits.
    pub grace: Duration,
    /// Retain objects reachable from EVERY Revision (ignore the retention floor).
    /// Only orphaned debris (e.g. from an aborted commit) is then swept — history
    /// is never pruned. The cautious default for a first run.
    pub keep_all: bool,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            apply: false,
            grace: DEFAULT_GRACE,
            keep_all: false,
        }
    }
}

/// What a [`SpaceContext::gc`] run found and (with `apply`) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    /// The retention floor used, or `None` in `keep_all` mode.
    pub retention_floor_seq: Option<u64>,
    /// The Space head seq at GC time, if any.
    pub head_seq: Option<u64>,
    /// Number of retained Revisions whose Manifest trees were walked.
    pub retained_revisions: usize,
    /// Distinct reachable Vault objects (the mark set).
    pub reachable_objects: usize,
    /// Physical objects listed across the swept prefixes.
    pub scanned_objects: usize,
    /// Unreachable objects held back ONLY by the grace-period (younger than it).
    pub kept_by_grace: usize,
    /// Keys eligible to sweep (unreachable AND older than the grace-period),
    /// sorted. In a dry run these are what WOULD be deleted; with `apply` they
    /// were deleted.
    pub sweepable: Vec<String>,
    /// Objects actually deleted (0 in a dry run).
    pub deleted: usize,
    /// Whether deletes were applied.
    pub applied: bool,
}

impl SpaceContext {
    /// Runs a mark-and-sweep GC over this Space's Vault objects. See the module
    /// docs for the safety model. Requires a Coordinator (a staging-only mount
    /// errors). Dry-run unless [`GcOptions::apply`].
    pub async fn gc(&mut self, opts: GcOptions) -> Result<GcReport> {
        if self.coordinator.is_none() {
            return Err(EngineError::SpaceState(
                "gc requires a Coordinator; this context was mounted for staging only".to_string(),
            ));
        }
        let space_id = self.space_id.clone();
        let device_id = self.device_id.clone();
        let base_seq = self.last_synced.seq;

        // Publish THIS Device's base so the recomputed floor reflects at least our
        // own base (never higher than it). Skipped for a never-synced Space.
        if base_seq >= 0 {
            self.coordinator
                .as_mut()
                .expect("coordinator present")
                .set_base_seq(&device_id, base_seq as u64)
                .await?;
        }

        // The Space doc: needed for the meta blob (a reachability root outside the
        // Manifest tree) and to know whether a head exists (the anomaly guard).
        let space = self
            .coordinator
            .as_mut()
            .expect("coordinator present")
            .get_space(&space_id)
            .await?;

        // Determine the retained window: all Revisions (keep_all) or seq >= floor.
        let (min_seq, floor_reported, head_seq) = if opts.keep_all {
            (0u64, None, None)
        } else {
            let rf = self
                .coordinator
                .as_mut()
                .expect("coordinator present")
                .refresh_retention_floor(&space_id)
                .await?;
            (
                rf.retention_floor_seq,
                Some(rf.retention_floor_seq),
                rf.head_seq,
            )
        };

        let roots = self
            .coordinator
            .as_mut()
            .expect("coordinator present")
            .list_revisions_from(&space_id, min_seq)
            .await?;

        // Safety: never sweep everything. A head with no retained roots is a
        // backend anomaly — refuse rather than treat every object as garbage.
        if roots.is_empty() && space.head_revision_id.is_some() {
            return Err(EngineError::SpaceState(format!(
                "gc refusing to run: Space {} has a head but listFromSeq({min_seq}) returned no \
                 retained roots",
                space_id.as_str()
            )));
        }

        // ----- mark: every reachable Vault key -----
        let root_cids: Vec<Cid> = roots.iter().map(|r| r.manifest_root_cid).collect();
        let reachable =
            mark_reachable(self.vault.as_ref(), &root_cids, &space.meta_blob_cid).await?;

        // ----- sweep: list physical objects, hold back reachable + young -----
        let now = SystemTime::now();
        let mut scanned = 0usize;
        let mut all_objects: Vec<VaultObject> = Vec::new();
        for prefix in SWEEP_PREFIXES {
            let listed = self.vault.list(prefix).await?;
            scanned += listed.len();
            all_objects.extend(listed);
        }
        let (sweepable, kept_by_grace) = partition_sweep(all_objects, &reachable, now, opts.grace);

        // ----- apply -----
        let mut deleted = 0usize;
        if opts.apply {
            for key in &sweepable {
                self.vault.delete(key).await?;
                deleted += 1;
            }
        }

        Ok(GcReport {
            retention_floor_seq: floor_reported,
            head_seq,
            retained_revisions: roots.len(),
            reachable_objects: reachable.len(),
            scanned_objects: scanned,
            kept_by_grace,
            sweepable,
            deleted,
            applied: opts.apply,
        })
    }
}

/// Computes the complete set of reachable Vault keys over `&dyn Vault`: the meta
/// blob (`meta/`), the empty-Manifest root, and everything reachable from each
/// Manifest `root` (pages, externalized blocklists + their Blocks, inline
/// Blocks). Coordinator-free so it is testable against an [`ft_vault::FsVault`].
/// Fails if a reachable object cannot be read — the mark must be COMPLETE before
/// any sweep, so a partial mark aborts the whole GC rather than risk deleting
/// live data.
pub(crate) async fn mark_reachable(
    vault: &dyn Vault,
    roots: &[Cid],
    meta_cid: &Cid,
) -> Result<HashSet<String>> {
    let mut reachable: HashSet<String> = HashSet::new();
    // The Space meta blob (`meta/<cid>`) is a reachability root independent of the
    // Manifest tree; its cid is not discoverable by walking. Never delete.
    reachable.insert(crate::secrets::meta_key(meta_cid));
    // The empty-Manifest root is the "no base yet" base a fresh Device reads.
    // Insert its key directly (do NOT walk/fetch: it may legitimately be absent
    // from the Vault, which must not fail the mark).
    let empty_root = ft_manifest::build(Vec::new()).root;
    reachable.insert(ft_hash::manifest_key(&empty_root));
    // Walk every retained Revision's tree. Shared pages/blocks dedupe by cid.
    for root in roots {
        mark_from_root(vault, root, &mut reachable).await?;
    }
    Ok(reachable)
}

/// Adds every Vault key reachable from a single Manifest `root` to `reachable`.
/// Iterative walk with an explicit stack; pages dedupe by cid.
async fn mark_from_root(
    vault: &dyn Vault,
    root: &Cid,
    reachable: &mut HashSet<String>,
) -> Result<()> {
    let mut stack = vec![*root];
    while let Some(cid) = stack.pop() {
        let manifest_key = ft_hash::manifest_key(&cid);
        // Already visited this page (content-addressed pages dedupe by cid)?
        if !reachable.insert(manifest_key.clone()) {
            continue;
        }
        let obj = vault.get(&manifest_key).await?;
        match decode_page(&obj)? {
            Page::Index(index) => {
                for child in index.children {
                    stack.push(child.cid);
                }
            }
            Page::Leaf(leaf) => {
                for entry in leaf.e {
                    mark_entry_blocks(vault, &entry, reachable).await?;
                }
            }
        }
    }
    Ok(())
}

/// Marks the Block objects a single [`FileEntry`] references — either the
/// externalized blocklist (and every Block it lists) via `bk_ref`, or the inline
/// `bk` list. Verifies an externalized blocklist hashes to its `bk_ref` and
/// refuses to proceed on a mismatch (never sweep on corruption).
async fn mark_entry_blocks(
    vault: &dyn Vault,
    entry: &FileEntry,
    reachable: &mut HashSet<String>,
) -> Result<()> {
    match entry.bk_ref {
        Some(bk_ref) => {
            let bl_key = ft_hash::blocklist_key(&bk_ref);
            reachable.insert(bl_key.clone());
            let obj = vault.get(&bl_key).await?;
            let computed = ft_hash::cid_of(&obj);
            if computed != bk_ref {
                return Err(EngineError::SpaceState(format!(
                    "gc: blocklist {} bytes hash to {}, not its bk_ref — refusing to sweep on \
                     corrupt data",
                    bl_key,
                    computed.to_hex()
                )));
            }
            let list: Vec<Cid> = ciborium::de::from_reader(&obj[..]).map_err(|e| {
                EngineError::SpaceState(format!("gc: decoding blocklist {bl_key}: {e}"))
            })?;
            for c in list {
                reachable.insert(ft_hash::block_key(&c));
            }
        }
        None => {
            for c in &entry.bk {
                reachable.insert(ft_hash::block_key(c));
            }
        }
    }
    Ok(())
}

/// Splits listed objects into (sweepable, kept_by_grace_count). An object is
/// sweepable iff it is unreachable AND provably older than `grace`. A missing or
/// future `last_modified` counts as "too young" — the GC never sweeps on
/// uncertainty. The returned sweep list is sorted for stable output.
fn partition_sweep(
    objects: Vec<VaultObject>,
    reachable: &HashSet<String>,
    now: SystemTime,
    grace: Duration,
) -> (Vec<String>, usize) {
    let mut sweepable = Vec::new();
    let mut kept_by_grace = 0usize;
    for obj in objects {
        if reachable.contains(&obj.key) {
            continue;
        }
        let old_enough = match obj.last_modified {
            Some(mtime) => now
                .duration_since(mtime)
                .map(|age| age >= grace)
                .unwrap_or(false),
            None => false,
        };
        if old_enough {
            sweepable.push(obj.key);
        } else {
            kept_by_grace += 1;
        }
    }
    sweepable.sort();
    (sweepable, kept_by_grace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ft_core::{CanonicalPath, CasefoldKey, FileType};
    use ft_vault::FsVault;
    use std::time::{Duration, UNIX_EPOCH};

    fn cid(n: u8) -> Cid {
        Cid::new([n; 32])
    }

    /// A minimal File [`FileEntry`] at `path` referencing inline blocks `bk`.
    fn file_entry(path: &str, bk: Vec<Cid>) -> (CasefoldKey, FileEntry) {
        let p = CanonicalPath(path.to_string());
        let key = ft_fsmap::casefold_key(&p);
        let entry = FileEntry {
            p,
            t: FileType::File,
            x: false,
            sz: 0,
            pcid: ft_core::Pcid::new([0u8; 32]),
            bk,
            bk_ref: None,
            lt: None,
            wu: None,
        };
        (key, entry)
    }

    /// Uploads every Manifest page of `entries` to the Vault; returns the root.
    async fn upload_manifest(vault: &FsVault, entries: Vec<(CasefoldKey, FileEntry)>) -> Cid {
        let m = ft_manifest::build(entries);
        for (page_cid, bytes) in &m.pages {
            vault
                .put(&ft_hash::manifest_key(page_cid), bytes.clone())
                .await
                .unwrap();
        }
        for (bl_cid, bytes) in &m.blocklists {
            vault
                .put(&ft_hash::blocklist_key(bl_cid), bytes.clone())
                .await
                .unwrap();
        }
        m.root
    }

    #[tokio::test]
    async fn mark_reaches_pages_and_inline_blocks_and_meta() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let meta = cid(200);
        let block_a = cid(1);
        let block_b = cid(2);

        let root = upload_manifest(
            &vault,
            vec![
                file_entry("a.txt", vec![block_a]),
                file_entry("b.txt", vec![block_b]),
            ],
        )
        .await;

        let reachable = mark_reachable(&vault, &[root], &meta).await.unwrap();

        assert!(reachable.contains(&ft_hash::manifest_key(&root)));
        assert!(reachable.contains(&ft_hash::block_key(&block_a)));
        assert!(reachable.contains(&ft_hash::block_key(&block_b)));
        assert!(reachable.contains(&crate::secrets::meta_key(&meta)));
        // The empty-Manifest root is always protected.
        let empty = ft_manifest::build(Vec::new()).root;
        assert!(reachable.contains(&ft_hash::manifest_key(&empty)));
    }

    #[tokio::test]
    async fn mark_follows_externalized_blocklist() {
        // The dangerous path: a FileEntry whose blocks live in a `blocklist/`
        // object via bk_ref. Missing it would let the GC delete live blocks.
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let meta = cid(200);
        let block_a = cid(10);
        let block_b = cid(11);

        // Build the blocklist object exactly as the reader expects: bare CBOR of
        // Vec<Cid>, addressed by cid_of(bytes).
        let mut bl_bytes = Vec::new();
        ciborium::ser::into_writer(&vec![block_a, block_b], &mut bl_bytes).unwrap();
        let bl_cid = ft_hash::cid_of(&bl_bytes);
        vault
            .put(&ft_hash::blocklist_key(&bl_cid), bl_bytes)
            .await
            .unwrap();

        // A FileEntry that references the blocklist (bk empty, bk_ref set).
        let p = CanonicalPath("big.bin".to_string());
        let entry = FileEntry {
            p: p.clone(),
            t: FileType::File,
            x: false,
            sz: 0,
            pcid: ft_core::Pcid::new([0u8; 32]),
            bk: Vec::new(),
            bk_ref: Some(bl_cid),
            lt: None,
            wu: None,
        };
        let root = upload_manifest(&vault, vec![(ft_fsmap::casefold_key(&p), entry)]).await;

        let reachable = mark_reachable(&vault, &[root], &meta).await.unwrap();

        assert!(reachable.contains(&ft_hash::blocklist_key(&bl_cid)));
        assert!(reachable.contains(&ft_hash::block_key(&block_a)));
        assert!(reachable.contains(&ft_hash::block_key(&block_b)));
    }

    #[tokio::test]
    async fn mark_aborts_on_corrupt_blocklist() {
        // A blocklist object whose bytes do NOT hash to its bk_ref must abort the
        // mark (never sweep on corruption).
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let wrong_ref = cid(99);
        // Store arbitrary bytes under the key the entry will point at.
        vault
            .put(
                &ft_hash::blocklist_key(&wrong_ref),
                b"not a valid blocklist".to_vec(),
            )
            .await
            .unwrap();
        let p = CanonicalPath("x".to_string());
        let entry = FileEntry {
            p: p.clone(),
            t: FileType::File,
            x: false,
            sz: 0,
            pcid: ft_core::Pcid::new([0u8; 32]),
            bk: Vec::new(),
            bk_ref: Some(wrong_ref),
            lt: None,
            wu: None,
        };
        let root = upload_manifest(&vault, vec![(ft_fsmap::casefold_key(&p), entry)]).await;

        let err = mark_reachable(&vault, &[root], &cid(200))
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::SpaceState(_)));
    }

    #[test]
    fn partition_sweep_holds_back_reachable_and_young() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let grace = Duration::from_secs(3600);
        let mut reachable = HashSet::new();
        reachable.insert("blocks/aa/live".to_string());

        let objects = vec![
            // Reachable, old → kept.
            VaultObject {
                key: "blocks/aa/live".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
            // Unreachable + old → SWEEP.
            VaultObject {
                key: "blocks/bb/orphan-old".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
            // Unreachable but YOUNG → kept by grace.
            VaultObject {
                key: "blocks/cc/orphan-young".to_string(),
                last_modified: Some(now - Duration::from_secs(60)),
            },
            // Unreachable, no mtime → kept (never sweep on uncertainty).
            VaultObject {
                key: "blocks/dd/orphan-nomtime".to_string(),
                last_modified: None,
            },
        ];

        let (sweepable, kept_by_grace) = partition_sweep(objects, &reachable, now, grace);
        assert_eq!(sweepable, vec!["blocks/bb/orphan-old".to_string()]);
        assert_eq!(kept_by_grace, 2); // orphan-young + orphan-nomtime
    }
}
