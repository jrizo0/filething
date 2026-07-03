//! `gc` — mark-and-sweep garbage collection of ORPHANED Vault objects
//! (`docs/format.md §6.3`, `docs/adr/0007`, `docs/adr/0012`).
//!
//! The **mark** phase computes every Vault key reachable from EVERY Revision of
//! EVERY Space of the account: every Manifest page, every externalized blocklist
//! (and the Blocks it lists), every inline Block, plus each Space's meta blob and
//! the empty-Manifest root. The **sweep** phase lists the physical objects and
//! deletes those that are BOTH unreachable (from any Revision) AND older than the
//! grace-period. Dry-run by default: nothing is deleted unless
//! [`GcOptions::apply`] is set.
//!
//! This is deliberately **orphan-sweep only** — it retains ALL history, so it
//! never removes an object any Revision references and thus never strands a
//! Device's sync base. It reclaims genuine garbage: objects a commit uploaded but
//! never referenced because the head never advanced (a crash/abort between the
//! Vault write and the CAS, `§7`). History-pruning via a retention floor
//! (reclaiming Blocks of deleted/superseded content below `min(baseSeqInUse)`) is
//! DEFERRED: a SOUND per-Space floor needs per-(Device,Space) base telemetry,
//! which the current per-Device `baseSeqInUse` scalar cannot provide — a per-Space
//! seq published into a per-Device scalar can raise one Space's floor above a
//! Device's real base there and strand its data. The `revisions:listFromSeq` /
//! `spaces:refreshRetentionFloor` machinery is kept (unused for now) for that
//! future work. See `docs/adr/0012`.
//!
//! Safety nets:
//! - **Grace-period**: never sweep an object younger than the window (24h
//!   default), so a commit in flight (Vault-first, head-after, `§7`) whose objects
//!   are uploaded but not yet referenced is protected. A missing/future mtime is
//!   treated as "too young" (never sweep on uncertainty).
//! - **Concurrency guard**: the reachability snapshot predates the object listing,
//!   so before deleting (with `apply`) the GC re-reads every Space head; if any
//!   advanced (a concurrent commit) it ABORTS without deleting.
//! - **Anomaly guard**: refuses to run if a Space has a head but zero Revisions
//!   are listed, rather than sweeping everything.
//! - It fails if a reachable object cannot be read (never sweeps on a partial mark).
//!
//! Even so, a Device must still not trust a stale local presence cache: the commit
//! path HEAD-verifies every Block before referencing it (`commit.rs`), so a Block
//! this GC (or another Device's) removed is simply re-uploaded on the next commit.
//!
//! ## Scope: ONE bucket == ONE account
//!
//! The Vault is a single bucket and dedup is account-wide, so the GC computes
//! reachability as the UNION over EVERY Space of the account (not the one Space
//! the CLI pointed at) — otherwise it would delete Blocks another Space of the
//! same account still needs. It follows that the GC also sweeps any object NOT
//! reachable from the account, i.e. it assumes the bucket belongs to exactly one
//! account (the shipped self-hosted / personal-use model: a deployment has one
//! account). A future MANAGED multi-tenant Vault sharing one bucket across
//! accounts would need account-prefixed keys or a server-side cross-account
//! sweep before this could run safely there.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use ft_coordinator::SpaceId;
use ft_core::{Cid, FileEntry};
use ft_manifest::{decode_page, Page};
use ft_vault::{Vault, VaultObject};

use crate::context::SpaceContext;
use crate::error::{EngineError, Result};

/// The Vault prefixes the GC enumerates and may sweep. `keys/<space_id>/<cid>`
/// data-key sidecars (`§4.5`, ADR 0015) are attachments of `blocks/<cid>`: a
/// sidecar is reachable iff its Block is reachable FROM ITS OWN SPACE (see
/// [`mark_entry_blocks`]), so an orphan sidecar — one whose Block is gone, or
/// which never had a live Block — is swept here just like any other orphan. The
/// `keys/` prefix covers every Space's per-Space subtree in one sweep. `reach/`
/// stays reserved and is never touched.
const SWEEP_PREFIXES: [&str; 5] = ["blocks/", "manifest/", "blocklist/", "meta/", "keys/"];

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
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            apply: false,
            grace: DEFAULT_GRACE,
        }
    }
}

/// What a [`SpaceContext::gc`] run found and (with `apply`) did. GC is
/// **account-scoped**: the Vault (one bucket) holds Blocks for EVERY Space of the
/// account and dedup is account-wide, so reachability is the UNION over all of
/// them and these figures span the account, not one Space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    /// Number of the account's Spaces whose reachability was unioned.
    pub spaces: usize,
    /// Total Revisions (across all Spaces) whose trees were walked (all of them —
    /// orphan-sweep retains full history).
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
    /// Runs an orphan-sweep GC over the **account-wide** Vault. The Vault is
    /// shared across ALL of the account's Spaces (one bucket, account-scoped
    /// dedup), so reachability is the UNION over every Space's Revisions — GCing
    /// from a single Space's view would delete other Spaces' live Blocks. The
    /// `dir` you point at only selects the account / Vault / Coordinator; the
    /// sweep covers the whole account. Requires a Coordinator (a staging-only
    /// mount errors). Dry-run unless [`GcOptions::apply`]. See the module docs for
    /// the safety model.
    pub async fn gc(&mut self, opts: GcOptions) -> Result<GcReport> {
        if self.coordinator.is_none() {
            return Err(EngineError::SpaceState(
                "gc requires a Coordinator; this context was mounted for staging only".to_string(),
            ));
        }
        // Every Space of the account shares this Vault. Gather reachability roots
        // (ALL Revisions of every Space — orphan-sweep retains full history) and
        // meta blobs, plus a snapshot of each Space head for the concurrency guard.
        // `list_mine` scopes to the caller's own Account (derived from the JWT).
        let spaces = self
            .coordinator
            .as_mut()
            .expect("coordinator present")
            .list_mine()
            .await?;

        // Each root is paired with its owning Space id so the mark can name that
        // Space's `keys/<space_id>/<cid>` sidecars (`§4.5`): the sidecar key is
        // per-Space even though the Block object it attaches to is Account-wide.
        let mut root_cids: Vec<(SpaceId, Cid)> = Vec::new();
        let mut meta_cids: Vec<Cid> = Vec::new();
        let mut retained_revisions = 0usize;
        let heads_before = head_snapshot(&spaces);
        for space in &spaces {
            meta_cids.push(space.meta_blob_cid);
            // Retain ALL Revisions (min_seq = 0): history-pruning is deferred (see
            // the module docs), so the GC removes only objects reachable from NO
            // Revision — true orphans (e.g. aborted-commit debris).
            let roots = self
                .coordinator
                .as_mut()
                .expect("coordinator present")
                .list_revisions_from(&space.space_id, 0)
                .await?;
            // Safety: a Space with a head but no Revisions listed is a backend
            // anomaly — refuse the WHOLE GC rather than treat live objects as junk.
            if roots.is_empty() && space.head_revision_id.is_some() {
                return Err(EngineError::SpaceState(format!(
                    "gc refusing to run: Space {} has a head but listFromSeq(0) returned no \
                     Revisions",
                    space.space_id.as_str()
                )));
            }
            retained_revisions += roots.len();
            root_cids.extend(
                roots
                    .into_iter()
                    .map(|r| (space.space_id.clone(), r.manifest_root_cid)),
            );
        }

        // ----- mark: every reachable Vault key across all Spaces -----
        let reachable = mark_reachable(self.vault.as_ref(), &root_cids, &meta_cids).await?;

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
        if opts.apply && !sweepable.is_empty() {
            // Concurrency guard: our reachability snapshot predates the listing, so
            // a commit that advanced a head in between could have referenced an
            // object we now deem an orphan. Re-read the heads; if any changed (or a
            // Space appeared/vanished), ABORT without deleting.
            let after = self
                .coordinator
                .as_mut()
                .expect("coordinator present")
                .list_mine()
                .await?;
            if head_snapshot(&after) != heads_before {
                return Err(EngineError::SpaceState(
                    "gc --apply aborted: a Space head changed during the sweep (concurrent commit, \
                     or a Space was created/removed); nothing was deleted — re-run when idle"
                        .to_string(),
                ));
            }
            for key in &sweepable {
                self.vault.delete(key).await?;
                deleted += 1;
            }
        }

        Ok(GcReport {
            spaces: spaces.len(),
            retained_revisions,
            reachable_objects: reachable.len(),
            scanned_objects: scanned,
            kept_by_grace,
            sweepable,
            deleted,
            applied: opts.apply,
        })
    }
}

/// A sorted snapshot of each Space's `(id, head-revision-id)` — the concurrency
/// guard compares this before vs. after the sweep to detect a racing commit (or a
/// Space created/removed) and abort the delete.
fn head_snapshot(spaces: &[ft_coordinator::Space]) -> Vec<(String, Option<String>)> {
    let mut snap: Vec<(String, Option<String>)> = spaces
        .iter()
        .map(|s| {
            (
                s.space_id.as_str().to_string(),
                s.head_revision_id.as_ref().map(|r| r.as_str().to_string()),
            )
        })
        .collect();
    snap.sort();
    snap
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
    roots: &[(SpaceId, Cid)],
    meta_cids: &[Cid],
) -> Result<HashSet<String>> {
    let mut reachable: HashSet<String> = HashSet::new();
    // Each Space's meta blob (`meta/<cid>`) is a reachability root independent of
    // the Manifest tree; its cid is not discoverable by walking. Never delete.
    for meta_cid in meta_cids {
        reachable.insert(crate::secrets::meta_key(meta_cid));
    }
    // The empty-Manifest root is the "no base yet" base a fresh Device reads.
    // Insert its key directly (do NOT walk/fetch: it may legitimately be absent
    // from the Vault, which must not fail the mark).
    let empty_root = ft_manifest::build(Vec::new()).root;
    reachable.insert(ft_hash::manifest_key(&empty_root));
    // Walk every retained Revision's tree. Shared pages/blocks dedupe by cid; a
    // sidecar, however, is per-Space, so the walk carries the owning Space id.
    for (space_id, root) in roots {
        mark_from_root(vault, space_id.as_str(), root, &mut reachable).await?;
    }
    Ok(reachable)
}

/// Adds every Vault key reachable from a single Manifest `root` to `reachable`.
/// Iterative walk with an explicit stack; pages dedupe by cid. `space_id` scopes
/// the per-Space `keys/<space_id>/<cid>` sidecars marked for the Blocks found
/// (`§4.5`); pages/blocks/blocklists are Account-scoped and need no Space id.
async fn mark_from_root(
    vault: &dyn Vault,
    space_id: &str,
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
                    mark_entry_blocks(vault, space_id, &entry, reachable).await?;
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
///
/// For every reachable Block cid it ALSO marks the Block's
/// `keys/<space_id>/<cid>` data-key sidecar reachable (`§4.5`, ADR 0015) for the
/// Space this entry's Manifest belongs to — the sidecar is per-Space, so the
/// mark must name the same Space that wrote it or the sweep would reclaim a live
/// sidecar. Marking a sidecar key that has no physical object (an `alg=0` Block
/// never wrote one) is harmless: a reachable key with no listed object simply
/// never matches during the sweep. This is what keeps a live encrypted Block's
/// sidecar from being collected, and — with the `keys/` prefix now swept — lets
/// an orphan sidecar be reclaimed.
async fn mark_entry_blocks(
    vault: &dyn Vault,
    space_id: &str,
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
                reachable.insert(ft_diff::keys_key(space_id, &c));
            }
        }
        None => {
            for c in &entry.bk {
                reachable.insert(ft_hash::block_key(c));
                reachable.insert(ft_diff::keys_key(space_id, c));
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

        let reachable = mark_reachable(&vault, &[(SpaceId::new("s1"), root)], &[meta])
            .await
            .unwrap();

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

        let reachable = mark_reachable(&vault, &[(SpaceId::new("s1"), root)], &[meta])
            .await
            .unwrap();

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

        let err = mark_reachable(&vault, &[(SpaceId::new("s1"), root)], &[cid(200)])
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::SpaceState(_)));
    }

    #[tokio::test]
    async fn mark_retains_the_sidecar_of_a_live_block_and_leaves_orphans_unmarked() {
        // A live (reachable) Block's `keys/<space_id>/<cid>` sidecar must be
        // marked reachable so the GC never collects it (§4.5, ADR 0015 — sidecar
        // lives with its Block). A sidecar whose Block is NOT referenced stays
        // unmarked, so the `keys/` sweep can reclaim it.
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let meta = cid(200);
        let live_block = cid(1);
        let orphan_block = cid(2);

        let root = upload_manifest(&vault, vec![file_entry("a.txt", vec![live_block])]).await;
        let reachable = mark_reachable(&vault, &[(SpaceId::new("s1"), root)], &[meta])
            .await
            .unwrap();

        // The live Block AND its sidecar (under THIS Space's subtree) are reachable.
        assert!(reachable.contains(&ft_hash::block_key(&live_block)));
        assert!(reachable.contains(&ft_diff::keys_key("s1", &live_block)));
        // A Block referenced by nothing — and thus its sidecar — is NOT reachable,
        // so both would be swept (subject to the grace-period).
        assert!(!reachable.contains(&ft_hash::block_key(&orphan_block)));
        assert!(!reachable.contains(&ft_diff::keys_key("s1", &orphan_block)));
    }

    #[tokio::test]
    async fn mark_scopes_each_spaces_sidecar_and_never_crosses_spaces() {
        // Two Spaces of one Account share the SAME Block cid (the Block object is
        // Account-deduped) but each has its OWN per-Space sidecar. The mark, run
        // over both Spaces' roots, must reach `keys/<A>/<cid>` AND `keys/<B>/<cid>`
        // — and must NOT mark Space B's sidecar reachable only because Space A
        // references the shared Block. If it did, a real two-Space vault could
        // sweep a live sidecar (BUG this fix guards against).
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let meta = cid(200);
        let shared_block = cid(1);

        // Both Spaces reference the same shared Block from their own Manifest.
        let root_a = upload_manifest(&vault, vec![file_entry("a.txt", vec![shared_block])]).await;
        let root_b = upload_manifest(&vault, vec![file_entry("b.txt", vec![shared_block])]).await;
        // (root_a == root_b would collapse the point; different paths keep them
        // distinct so the walk genuinely visits two Spaces' trees.)
        assert_ne!(root_a, root_b);

        let reachable = mark_reachable(
            &vault,
            &[
                (SpaceId::new("space-a"), root_a),
                (SpaceId::new("space-b"), root_b),
            ],
            &[meta],
        )
        .await
        .unwrap();

        // The shared Block AND both Spaces' sidecars are reachable.
        assert!(reachable.contains(&ft_hash::block_key(&shared_block)));
        assert!(reachable.contains(&ft_diff::keys_key("space-a", &shared_block)));
        assert!(reachable.contains(&ft_diff::keys_key("space-b", &shared_block)));

        // A THIRD Space that references nothing has no reachable sidecar even for
        // the shared cid — the mark is strictly per-Space, never cross-Space.
        assert!(!reachable.contains(&ft_diff::keys_key("space-c", &shared_block)));
    }

    #[test]
    fn partition_sweep_reclaims_an_orphan_sidecar_under_the_keys_prefix() {
        // With `keys/` now a swept prefix, an orphan `keys/<space_id>/<cid>` object (its Block
        // gone or never live) that is old enough is reclaimed exactly like any
        // other orphan, while a live block's sidecar (in the reachable set) is kept.
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let grace = Duration::from_secs(3600);
        let mut reachable = HashSet::new();
        reachable.insert("keys/aa/live".to_string());

        let objects = vec![
            VaultObject {
                key: "keys/aa/live".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
            VaultObject {
                key: "keys/bb/orphan-old".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
        ];
        let (sweepable, _kept) = partition_sweep(objects, &reachable, now, grace);
        assert_eq!(sweepable, vec!["keys/bb/orphan-old".to_string()]);
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
