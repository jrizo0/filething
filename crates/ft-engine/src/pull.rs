//! `pull` — the read path + three-way reconcile (`docs/format.md §8`, `§10`).
//!
//! [`SpaceContext::pull`] brings this Device in line with the Space head:
//!
//! - reads the current head (`§8`) — its `manifestRoot`, `seq` and `RevisionId`;
//! - if the head root equals the synced base, returns [`PullOutcome::UpToDate`];
//! - otherwise it `scan`s to learn the local on-disk state and decides:
//!   - **no local changes** ⇒ [`PullOutcome::FastForwarded`]: `diff` the base
//!     against the head and `apply` the changes to disk (`§8.3`/`§8.4`), marking
//!     each materialized file in the shared [`AppliedState`] for echo suppression
//!     (`§9`), then advance the base;
//!   - **local changes + the head moved** ⇒ [`PullOutcome::Reconciled`]: a
//!     three-way merge per path against the common base (`§10`). For every path in
//!     `base ∪ local ∪ remote`, [`ft_conflict::resolve`] decides; the engine then
//!     materializes the remote winner, writes a conflict copy for the local loser
//!     (so NO edit is ever lost), honors deletions, and never lets a casefold/NFC
//!     collision overwrite (`§5.2`, [`ft_conflict::collision_is_conflict`]).
//!
//! After a reconcile the disk holds the merged tree; a later
//! [`commit`](SpaceContext::commit) (driven by
//! [`commit_and_reconcile`](SpaceContext::commit_and_reconcile)) pushes the
//! resolution. "Changed" is causal (`pcid`/type identity), never the clock.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ft_conflict::{
    collision_is_conflict, conflict_copy_name, is_conflict_copy_name, merge3, resolve, Merge3,
    Resolution,
};
use ft_coordinator::RevisionId;
use ft_core::{CanonicalPath, CasefoldKey, Cid, FileEntry, FileType, Pcid};
use ft_diff::{apply, diff, fetch_file_bytes, materialize, Change};
use futures::StreamExt;

use crate::context::{join_canonical, SpaceContext};
use crate::error::{EngineError, Result};

/// Maximum [`commit`](SpaceContext::commit) retries inside
/// [`commit_and_reconcile`](SpaceContext::commit_and_reconcile) before giving up
/// (each retry pulls + reconciles first). A small bound: a healthy Space converges
/// in one or two rounds; a persistent loop signals a real problem.
const MAX_COMMIT_RETRIES: usize = 8;

/// How many distinct conflict-copy names [`pick_conflict_path`](SpaceContext::pick_conflict_path)
/// will try for one path before refusing.
///
/// A copy must never overwrite anything, so a taken name is retried under a
/// suffixed label. Needing more than a handful means the path already carries a
/// pile of copies nobody has resolved; refusing (and saying so) beats destroying
/// the N+1-th edit, and a Space in that state needs a human either way (`§10`).
const MAX_CONFLICT_COPY_SLOTS: usize = 32;

/// The outcome of a [`SpaceContext::pull`] (`§8`/`§10`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    /// The head root already equals the synced base: nothing to do.
    UpToDate,

    /// No local changes and the head advanced: the diff was applied straight to
    /// disk and the base advanced to the head.
    FastForwarded {
        /// Number of per-file changes applied (added/modified/deleted).
        applied: usize,
    },

    /// Local changes AND the head advanced: a three-way reconcile ran. `conflicts`
    /// lists the conflict-copy paths written (empty when every path
    /// fast-forwarded one-sidedly). The base advanced to the head; the merged tree
    /// is on disk awaiting the next commit.
    Reconciled {
        /// The conflict-copy paths created for divergent local edits (`§10`).
        conflicts: Vec<String>,
    },
}

/// The current Space head as the read path needs it (`§8`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeadState {
    /// The head Revision id, or `None` for a Space with no Revisions.
    pub revision_id: Option<RevisionId>,
    /// The head Revision's `seq`, or `None`.
    pub seq: Option<i64>,
    /// The head `manifestRoot`, or `None`.
    pub root: Option<Cid>,
}

impl SpaceContext {
    /// Reads the current head from the Coordinator (`§8`).
    ///
    /// Implemented via a one-shot `subscribe_head`: Convex pushes the current
    /// value on subscribe, so the first stream item is the live head. The
    /// subscription is dropped immediately after. Errors if no Coordinator is
    /// attached (a staging-only mount).
    pub(crate) async fn read_head(&mut self) -> Result<HeadState> {
        let space_id = self.space_id.clone();
        let coordinator = self.coordinator.as_mut().ok_or_else(|| {
            EngineError::SpaceState(
                "pull requires a Coordinator; this context was mounted for staging only"
                    .to_string(),
            )
        })?;
        let mut stream = coordinator.subscribe_head(&space_id).await?;
        let update = stream
            .next()
            .await
            .ok_or_else(|| {
                EngineError::SpaceState("head subscription closed before first value".to_string())
            })?
            .map_err(EngineError::Coordinator)?;
        Ok(HeadState {
            revision_id: update.head_revision_id,
            seq: update.seq.map(|s| s as i64),
            root: update.manifest_root,
        })
    }

    /// Pulls the Space head into this Device (`§8`/`§10`). See the module docs.
    ///
    /// Reads the current head from the Coordinator and delegates to
    /// [`apply_head`](SpaceContext::apply_head). A Space with no Revisions yet is
    /// [`PullOutcome::UpToDate`].
    pub async fn pull(&mut self) -> Result<PullOutcome> {
        let head = self.read_head().await?;
        let Some(head_root) = head.root else {
            return Ok(PullOutcome::UpToDate);
        };
        self.apply_head(head_root, head.seq, head.revision_id).await
    }

    /// Applies a KNOWN head (root + `seq` + `RevisionId`) into this Device —
    /// the body of [`pull`](SpaceContext::pull) minus the Coordinator head read.
    ///
    /// Public so a caller that already holds a head (e.g. the daemon, from a
    /// change-feed update) can apply it without a redundant head fetch, and so the
    /// read path is exercisable against a Vault alone (no Coordinator). The
    /// fast-forward / reconcile decision and base advance are identical to
    /// [`pull`](SpaceContext::pull).
    pub async fn apply_head(
        &mut self,
        head_root: Cid,
        head_seq: Option<i64>,
        head_revision_id: Option<RevisionId>,
    ) -> Result<PullOutcome> {
        let head = HeadState {
            revision_id: head_revision_id,
            seq: head_seq,
            root: Some(head_root),
        };

        // Head unchanged vs the synced base -> up to date. Adopt the head's
        // RevisionId if we did not have it (e.g. after a fresh open) and PERSIST it
        // (`§9`): on an already-synced Space this is the only path that learns the
        // base id, so without persisting here `status` (a fresh process) would
        // reload `None` and forever report a false "behind — pull pending".
        if head_root == self.last_synced.root {
            if self.last_synced_revision_id.is_none() && head.revision_id.is_some() {
                self.last_synced_revision_id = head.revision_id.clone();
                // Propagate a failed durability write: RECORDING the base id is the
                // entire point of this branch, so swallowing the failure leaves a
                // fresh `status` reporting a false "behind — pull pending" forever
                // with nothing pointing at the broken index (`§9`).
                self.persist_space_state()?;
            }
            return Ok(PullOutcome::UpToDate);
        }

        // Learn the local on-disk state. scan() also reconciles the index with
        // disk and gives us the local FileEntry set + its manifest root.
        let scan = self.scan()?;
        let local_root_cid = ft_manifest::build(scan.entries.clone()).root;
        let has_local_changes = local_root_cid != self.last_synced.root;

        if !has_local_changes {
            // Fast-forward: apply the base->head diff straight to disk (§8).
            let applied = self
                .fast_forward(&self.last_synced.root.clone(), &head_root)
                .await?;
            self.advance_base_to(&head, head_root)?;
            Ok(PullOutcome::FastForwarded { applied })
        } else {
            // Both moved: three-way reconcile per path (§10).
            let conflicts = self
                .reconcile(&self.last_synced.root.clone(), &head_root, &scan.entries)
                .await?;
            self.advance_base_to(&head, head_root)?;
            Ok(PullOutcome::Reconciled { conflicts })
        }
    }

    /// Advances the synced base to `head` (root + seq + RevisionId) and persists
    /// it. After a reconcile the local tree may differ from `head_root`, but the
    /// BASE for the next diff/commit is the head we just merged against (`§10`).
    ///
    /// A failed persist is PROPAGATED, and the in-memory base is rolled back so it
    /// still agrees with `space_state`. The files are already on disk: a base that
    /// is not durably recorded makes the next scan read the applied REMOTE content
    /// as local edits (`§9`), and an in-memory base left ahead of the persisted one
    /// would hide that from the retry — the next pull would see `head == base` and
    /// short-circuit to [`PullOutcome::UpToDate`].
    fn advance_base_to(&mut self, head: &HeadState, head_root: Cid) -> Result<()> {
        let previous_base = self.last_synced;
        let previous_revision_id = self.last_synced_revision_id.clone();
        self.last_synced = crate::context::LastSynced {
            seq: head.seq.unwrap_or(self.last_synced.seq),
            root: head_root,
        };
        self.last_synced_revision_id = head.revision_id.clone();
        if let Err(e) = self.persist_space_state() {
            self.last_synced = previous_base;
            self.last_synced_revision_id = previous_revision_id;
            return Err(e);
        }
        Ok(())
    }

    /// Fast-forward: `diff(base -> head)` then `apply` every change to disk,
    /// marking each materialized file for echo suppression and updating the local
    /// index. Returns the number of changes applied.
    async fn fast_forward(&self, base_root: &Cid, head_root: &Cid) -> Result<usize> {
        let started = std::time::Instant::now();
        // A base that is still the "no base yet" empty Manifest is diffed WITHOUT
        // fetching its page: every head entry is an addition (see
        // [`empty_manifest_root`] for why that object must never be required).
        let changes = if *base_root == empty_manifest_root() {
            self.added_changes_from(head_root).await?
        } else {
            diff(self.vault.as_ref(), base_root, head_root).await?
        };

        // The inbound trust boundary for THIS file (`§5.2`): `apply` validates its
        // own batch, but the recording pass below joins every entry path onto the
        // Space root, so no path here may act on an entry nobody checked.
        validate_entries(changes.iter().map(acted_entry))?;

        // Pre-sign every GET the upcoming `apply` will issue, in one batch
        // (`Vault::warm`, ADR 0016) — best effort, never blocks the apply.
        let warm_ops = self.read_warm_ops(changes.iter().filter_map(|c| match c {
            Change::Added(entry) | Change::Modified { new: entry, .. } => Some(entry),
            Change::Deleted(_) => None,
        }));
        self.warm_reads(warm_ops, "fast_forward").await;

        let total = changes.len();
        tracing::info!(total, "fast-forwarding changes");
        // Apply to disk (materialize adds/mods, remove deletes) then mark echoes +
        // update the index per change.
        apply(
            self.vault.as_ref(),
            self.fs.as_ref(),
            &self.local_root,
            &changes,
            self.crypto.as_ref(),
        )
        .await?;
        self.record_applied_changes(&changes)?;
        tracing::info!(
            total,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "fast-forward applied"
        );
        Ok(changes.len())
    }

    /// The base->head diff for an EMPTY base: every [`FileEntry`] of the Manifest
    /// rooted at `root`, as [`Change::Added`] (`§8.3`).
    ///
    /// Walks the page tree here so the empty base's own page is never fetched (see
    /// [`empty_manifest_root`]). Pages go through
    /// [`ft_manifest::decode_page_verified`] — re-hashed against the cid that named
    /// them (`§4.3`) — exactly as [`ft_diff::diff`] does: a page NAMES every other
    /// object, so an unverified one voids the integrity of its whole subtree. That
    /// same check is why the walk cannot loop: a page reachable from itself would be
    /// a BLAKE3 cycle.
    async fn added_changes_from(&self, root: &Cid) -> Result<Vec<Change>> {
        use ft_manifest::Page;
        let mut out = Vec::new();
        let mut stack = vec![*root];
        while let Some(cid) = stack.pop() {
            let obj = self.vault.get(&ft_hash::manifest_key(&cid)).await?;
            match ft_manifest::decode_page_verified(&obj, &cid)? {
                Page::Leaf(leaf) => out.extend(leaf.e.into_iter().map(Change::Added)),
                Page::Index(index) => stack.extend(index.children.into_iter().map(|c| c.cid)),
            }
        }
        Ok(out)
    }

    /// Builds the [`ft_vault::WarmOp`]s that materializing `entries` will issue: a
    /// `Get` of the externalized blocklist (`bk_ref`) when set, otherwise a `Get`
    /// per inline Block id (`entry.bk`), plus the matching
    /// `keys/<space_id>/<cid>` sidecar `Get` for each Block when encryption is on
    /// (mirrors exactly what [`materialize`] reads, `ft_diff::materialize`). A
    /// pure hint: including an entry that ends up not being materialized (e.g. a
    /// reconcile loser) is harmless — over-warming is cheap.
    fn read_warm_ops<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a FileEntry>,
    ) -> Vec<ft_vault::WarmOp> {
        use ft_vault::{WarmMethod, WarmOp};
        let mut ops = Vec::new();
        for entry in entries {
            if let Some(bk_ref) = entry.bk_ref {
                ops.push(WarmOp {
                    key: ft_hash::blocklist_key(&bk_ref),
                    method: WarmMethod::Get,
                });
            }
            for cid in &entry.bk {
                ops.push(WarmOp {
                    key: ft_hash::block_key(cid),
                    method: WarmMethod::Get,
                });
                if let Some(crypto) = self.crypto.as_ref() {
                    ops.push(WarmOp {
                        key: ft_diff::keys_key(&crypto.space_id, cid),
                        method: WarmMethod::Get,
                    });
                }
            }
        }
        ops
    }

    /// Announces `ops` to the Vault (`Vault::warm`, ADR 0016) and swallows any
    /// error: warming is a pure hint, so a failure here must never block the read
    /// path — the real `get` still reports any genuine failure. `label` names the
    /// caller for the debug log.
    async fn warm_reads(&self, ops: Vec<ft_vault::WarmOp>, label: &str) {
        if ops.is_empty() {
            return;
        }
        if let Err(e) = self.vault.warm(&ops).await {
            tracing::debug!(error = %e, label, "vault warm failed; continuing without it");
        }
    }

    /// Updates the local index and the echo-suppression marks for a whole batch of
    /// applied [`Change`]s: Added/Modified upsert the row + mark the write; Deleted
    /// drop the row. The Block presence cache (`local_block`) records the bytes we
    /// now hold.
    ///
    /// The rows and the Block ids go in ONE transaction each
    /// ([`ft_index::Index::upsert_entries`] / [`ft_index::Index::put_blocks`]):
    /// one durable transaction per row dominates the cost of a big fast-forward.
    /// This is only safe because the caller runs it AFTER [`apply`] returned `Ok`,
    /// and apply is all-or-nothing — so every row recorded here really is on disk.
    /// Batching rows for files not yet written would be the opposite of safe: the
    /// `§9` size/mtime fast path would then read a MISSING file as unchanged.
    fn record_applied_changes(&self, changes: &[Change]) -> Result<()> {
        let space_id = self.space_id.as_str();
        let mut rows = Vec::new();
        let mut cids: Vec<Cid> = Vec::new();
        for change in changes {
            match change {
                Change::Added(entry) | Change::Modified { new: entry, .. } => {
                    rows.push(self.local_entry_for(entry));
                    // Their bytes came FROM the Vault, so claiming presence is
                    // accurate (see [`index_upsert_materialized`]).
                    cids.extend(entry.bk.iter().copied());
                    match entry.t {
                        FileType::File => self.mark_applied_for(&entry.p, entry.pcid),
                        // A symlink's identity is its target; a dir carries no
                        // content (ADR 0019). Both mark with the same contentless
                        // zero pcid the scan computes for them, so this path and
                        // `record_materialized` stay consistent on what a Dir echo
                        // looks like.
                        FileType::Symlink | FileType::Dir => {
                            self.mark_applied_for(&entry.p, Pcid::new([0u8; 32]));
                        }
                        // Derived bytes never travel: nothing to echo-suppress.
                        FileType::Derived => {}
                    }
                }
                Change::Deleted(entry) => {
                    self.index.delete_entry(space_id, &entry.p)?;
                }
            }
        }
        self.index.upsert_entries(space_id, &rows)?;
        self.index.put_blocks(space_id, &cids)?;
        Ok(())
    }

    /// Upserts the local-index row for a freshly materialized [`FileEntry`] and
    /// records its Blocks as locally present (`§9`). The per-path `base_seq` is set
    /// to the head `seq` we are advancing to.
    ///
    /// Only for entries whose bytes came FROM the Vault: the block table is what
    /// lets `upload_blocks` skip a PUT, so claiming a Block here asserts it is
    /// already up there. For bytes that came from the local disk use
    /// [`index_upsert_row`](Self::index_upsert_row) instead.
    fn index_upsert_materialized(&self, entry: &FileEntry) -> Result<()> {
        self.index_upsert_row(entry)?;
        // One transaction for the entry's whole Block list, not one per Block: the
        // file is already on disk when this runs, so the batch's all-or-nothing
        // semantics cannot claim presence for bytes we do not hold.
        self.index.put_blocks(self.space_id.as_str(), &entry.bk)?;
        Ok(())
    }

    /// Upserts the local-index row WITHOUT claiming its Blocks are in the Vault.
    /// For entries written from LOCAL bytes (a conflict-copy loser whose edit was
    /// never committed): the next commit must still see those Blocks as
    /// not-yet-uploaded, or it publishes a Manifest referencing objects the Vault
    /// does not have and every other Device's pull fails with `object not found`.
    fn index_upsert_row(&self, entry: &FileEntry) -> Result<()> {
        self.index
            .upsert_entry(self.space_id.as_str(), &self.local_entry_for(entry))?;
        Ok(())
    }

    /// Builds the local-index row for `entry` (`§9`) — the shared body of
    /// [`index_upsert_row`](Self::index_upsert_row) and the batched
    /// [`record_applied_changes`](Self::record_applied_changes).
    fn local_entry_for(&self, entry: &FileEntry) -> ft_index::LocalEntry {
        use ft_index::{BlockRef, LocalEntry};
        let casefold_key = ft_fsmap::casefold_key(&entry.p);
        let blocks: Vec<BlockRef> = entry
            .bk
            .iter()
            .map(|cid| BlockRef {
                // The per-chunk pcid is set equal to the cid here. This is exact
                // for `alg=0` (cid == pcid) and only APPROXIMATE for `alg=1`
                // (where the two diverge): recovering the true per-chunk pcid
                // would require decrypting the Block, which materialize already
                // did but does not surface. This is safe because the per-chunk
                // pcid in a local-index BlockRef is not read by any wired path —
                // block presence keys off `cid` (`local_block`/`has_block`) and
                // the per-chunk `dedup_local` table is not yet consulted. The
                // whole-file plaintext pcid (`entry.pcid`, set below) stays exact.
                pcid: Pcid::new(*cid.as_bytes()),
                cid: *cid,
            })
            .collect();
        let mtime = self.real_mtime_secs(&entry.p);
        // A dir (like a file/symlink) syncs, so it is NOT local_only; only derived
        // paths are (their bytes never travel). ADR 0019.
        let local_only = entry.t == FileType::Derived;
        let pcid = match entry.t {
            FileType::File => Some(entry.pcid),
            FileType::Symlink => entry.lt.as_ref().map(|t| ft_hash::pcid_of(t.as_bytes())),
            // Derived and dir entries carry no whole-file pcid.
            FileType::Derived | FileType::Dir => None,
        };
        LocalEntry {
            path: entry.p.clone(),
            casefold_key,
            file_type: entry.t,
            exec: entry.x,
            // The Manifest's own claim, not a post-write `stat`. For a File that is
            // the SAME number: `ft_diff` checks the reassembled bytes against
            // `sz`/`pcid` before the rename (`Error::ContentMismatch`), and for the
            // contentless types both sides are 0 (the scan records 0 too). It is also
            // the safer of the two for the `§9` fast path: recording an OBSERVED size
            // would let an edit landing between the write and the `stat` be recorded
            // as ours, and the fast path would then skip re-hashing it.
            size: entry.sz,
            mtime,
            pcid,
            base_seq: self.last_synced.seq.max(0),
            blocks,
            local_only,
        }
    }

    /// Reads the real on-disk mtime (seconds) of a canonical path for the index;
    /// `0` if unavailable. Re-scan only — never used for conflicts (`§9`).
    fn real_mtime_secs(&self, path: &CanonicalPath) -> i64 {
        let abs = join_canonical(&self.local_root, path);
        self.fs
            .real_mtime(&abs)
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Three-way reconcile against the common base (`§10`), in three phases so the
    /// (network-bound) materializations run concurrently while everything
    /// order-sensitive stays sequential (ADR 0018).
    ///
    /// Builds the base/local/remote [`FileEntry`] maps (base + remote from the
    /// Manifest pages, local from `scan_entries`), then:
    ///
    /// - **Phase A (sequential):** for every key in `base ∪ local ∪ remote`, in a
    ///   stable order, call [`ft_conflict::resolve`] / the casefold-collision guard
    ///   and execute everything that MUST stay ordered or is local-only:
    ///   [`write_conflict_copy`](Self::write_conflict_copy) for `ConflictCopy`
    ///   losers (which reads the local bytes at the winner's path — so every copy
    ///   MUST happen before any winner overwrites it in phase B),
    ///   [`remote_delete`](Self::remote_delete) for `TakeRemoteDeletion`, and
    ///   no-ops for the local-wins arms. The remote winners to materialize (the
    ///   casefold-renamed remote, `FastForwardToRemote`, a surviving-remote
    ///   `DeleteVsEditKeepEdit`, a `ConflictCopy` winner) are COLLECTED, not
    ///   materialized here. Conflict-copy paths are pushed into `conflicts` at the
    ///   same points as before, so the returned order is unchanged.
    /// - **Phase B (concurrent materialize + incremental record):** fan the
    ///   collected winners through [`ft_diff::materialize`] with
    ///   `buffer_unordered(8)` (mirrors `commit::upload_blocks`, ADR 0017/0018),
    ///   draining the stream sequentially so each winner is recorded in the local
    ///   index + echo-marked ([`record_materialized`](Self::record_materialized))
    ///   as ITS download completes — rusqlite writes stay OUT of the concurrent
    ///   futures (ADR 0017). Concurrency is safe because every collected winner
    ///   writes a DISTINCT canonical path (union keys are unique, and
    ///   [`pick_conflict_path`](Self::pick_conflict_path) keeps every conflict-copy
    ///   name off both the winner paths and the other copies); this is asserted up
    ///   front and a duplicate is a hard error, not a race.
    ///
    /// A casefold/NFC collision between a remote and a DIFFERENT local path is
    /// forced into a conflict copy so the next commit's Manifest never sees two
    /// entries with one key (`§5.2`) — and, because such a collision never resolves
    /// itself, an already-parked copy is REUSED instead of minting one per round
    /// (which used to fill the Space with copies forever, ADR 0006). On any error
    /// (including the actionable [`EngineError::Refused`] for a dir→file replacement
    /// blocked by unsynced local content) the reconcile aborts: the caller
    /// does not advance the base (it advances only on `Ok`), and because winners
    /// are recorded incrementally as they materialize, every winner reached before
    /// the error is fully consistent (materialized + indexed + echo-marked) while
    /// the un-reached ones simply never ran. A retry re-resolves against the same
    /// base and self-heals — a path already materialized resolves to a no-op.
    ///
    /// The per-key loop visits keys in ASCENDING order, which puts a parent dir
    /// before its children. Two verdict classes must NOT run in that order or a
    /// populated deleted tree resurrects (a parent `remove_dir` hits `ENOTEMPTY`,
    /// keeps the dir + its index row, and the next commit re-publishes it):
    /// - a `TakeRemoteDeletion` of a `Dir` is DEFERRED and replayed deepest-first
    ///   AFTER the loop, so every child is gone before its parent is removed;
    /// - a materialization whose target path currently holds a local/base `Dir`
    ///   while the incoming entry is NOT a dir (a dir→file/symlink replacement) is
    ///   DEFERRED and replayed after the deferred deletions, so the dir is empty
    ///   before `materialize`'s `remove_dir` runs. One that is STILL populated (real
    ///   unsynced local content) is never force-deleted: it is skipped, the other
    ///   replacements still run, and the reconcile ends in [`EngineError::Refused`]
    ///   naming the directories and the action that unblocks the Space.
    ///
    /// Returns the conflict-copy paths written.
    async fn reconcile(
        &self,
        base_root: &Cid,
        head_root: &Cid,
        scan_entries: &[(CasefoldKey, FileEntry)],
    ) -> Result<Vec<String>> {
        // A base that is still the "no base yet" empty Manifest has no entries, so
        // there is nothing to read — and its page must never be required (see
        // [`empty_manifest_root`]).
        let base = if *base_root == empty_manifest_root() {
            HashMap::new()
        } else {
            self.read_manifest_entries(base_root).await?
        };
        let remote = self.read_manifest_entries(head_root).await?;
        // The inbound trust boundary for THIS file (`§5.2`). Both maps came out of
        // Manifest pages fetched from the Vault, and the arms below act on them
        // DIRECTLY — `remote_delete` joins a path onto the Space root and unlinks
        // it, `write_conflict_copy` writes through one — where `ft_diff` only ever
        // sees the subset that reaches `materialize`. A `p` of `../../.ssh/config`
        // must be a hard error, so validate BOTH whole sides before any effect: a
        // hostile Manifest then aborts the pull having changed nothing.
        validate_entries(base.values().chain(remote.values()))?;
        let local: HashMap<CasefoldKey, FileEntry> = scan_entries.iter().cloned().collect();

        // Pre-sign every GET a materialize of a `remote` entry might issue, before
        // the per-path resolution loop below. Over-warming the whole `remote` map
        // is cheap and simpler than predicting which entries the resolver below
        // will actually pick as winners.
        let warm_ops = self.read_warm_ops(remote.values());
        self.warm_reads(warm_ops, "reconcile").await;

        // The union of every key seen on any side, in a stable order.
        let mut keys: BTreeSet<CasefoldKey> = BTreeSet::new();
        keys.extend(base.keys().cloned());
        keys.extend(local.keys().cloned());
        keys.extend(remote.keys().cloned());

        // The conflict-copy label: the human-readable Device name when set, else
        // the opaque device_id (issue #14). It only names copies THIS Device
        // writes, so a per-Device value never breaks cross-Device convergence.
        let label = self
            .device_display_name
            .clone()
            .unwrap_or_else(|| self.device_id.as_str().to_string());
        let seq = self.last_synced.seq.max(0) as u64;
        // Names every conflict copy this reconcile writes, and keeps them out of
        // each other's (and every winner's) way — see [`CopyNamer`].
        let mut namer = CopyNamer {
            label: &label,
            seq,
            blocked: base.keys().chain(remote.keys()).cloned().collect(),
            claimed: HashSet::new(),
        };
        let mut conflicts: Vec<String> = Vec::new();
        // Verdicts that must not run in the ascending-key loop (see fn docs):
        // Dir deletions (replayed deepest-first) and dir→non-dir replacements
        // (replayed after those deletions), so a populated deleted tree never
        // resurrects via a parent `remove_dir` ENOTEMPTY.
        let mut deferred_dir_deletes: Vec<FileEntry> = Vec::new();
        let mut deferred_dir_replacements: Vec<FileEntry> = Vec::new();

        // Phase A: sequential per-key resolution. Local-only / ordered effects run
        // now; remote winners are collected for the concurrent phase B.
        let mut to_materialize: Vec<FileEntry> = Vec::new();
        for key in keys {
            let b = base.get(&key);
            let l = local.get(&key);
            let r = remote.get(&key);

            // Does the target path currently hold a directory on the local/base
            // side? A materialization of a NON-dir incoming entry onto it is a
            // dir→file/symlink replacement whose `remove_dir` needs the dir empty
            // first, so it is deferred past the dir deletions.
            let currently_dir = l.map(|e| e.t == FileType::Dir).unwrap_or(false)
                || b.map(|e| e.t == FileType::Dir).unwrap_or(false);

            // Guard against a casefold/NFC collision bringing a remote path that
            // collides with a DIFFERENT local path (§5.2): same casefold key, but
            // byte-distinct canonical paths. Keep the local path untouched and
            // move the REMOTE aside under a conflict-copy name, so the merged tree
            // has no duplicate casefold key for a later manifest::build (`§5.2`).
            if let (Some(l), Some(r)) = (l, r) {
                if collision_is_conflict(&key, &key, &l.p, &r.p) {
                    // Idempotency (ADR 0006). Nothing about a casefold/NFC collision
                    // converges on its own: the remote keeps its name, we keep ours,
                    // and the pair collides again on EVERY round. Minting a fresh
                    // copy each time is what fills the Space with copies forever, so
                    // recognize the one an earlier round already parked aside — same
                    // origin path, same content identity — and leave it alone.
                    if let Some(existing) = existing_conflict_copy(&local, r) {
                        tracing::debug!(
                            space = %self.space_id,
                            original = %r.p.as_str(),
                            conflict_copy = %existing.p.as_str(),
                            "casefold/NFC collision already parked aside; keeping that copy"
                        );
                        continue;
                    }
                    let mut renamed = r.clone();
                    renamed.p = self.pick_conflict_path(&mut namer, &r.p, r, &local)?;
                    tracing::warn!(
                        space = %self.space_id,
                        original = %r.p.as_str(),
                        conflict_copy = %renamed.p.as_str(),
                        "casefold/NFC collision: remote path moved aside to a conflict copy"
                    );
                    conflicts.push(renamed.p.as_str().to_string());
                    to_materialize.push(renamed);
                    continue;
                }
            }

            match resolve(b, l, r, &label, seq) {
                Resolution::NoChange
                | Resolution::FastForwardToLocal(_)
                | Resolution::KeepLocal => {
                    // Local already holds the winning state (or there is nothing to
                    // do); leave disk untouched. A later commit pushes local edits.
                }
                Resolution::FastForwardToRemote(entry) => {
                    // A dir→file/symlink replacement is deferred past the dir
                    // deletions (its `remove_dir` needs the dir empty first);
                    // everything else is a phase-B winner.
                    if currently_dir && entry.t != FileType::Dir {
                        deferred_dir_replacements.push(entry);
                    } else {
                        to_materialize.push(entry);
                    }
                }
                Resolution::TakeRemoteDeletion => {
                    let target = b.or(l);
                    if let Some(dir) = target.filter(|e| e.t == FileType::Dir) {
                        // Defer: a populated dir must have its children deleted
                        // first, else `remove_dir` ENOTEMPTY resurrects it.
                        deferred_dir_deletes.push(dir.clone());
                    } else {
                        self.remote_delete(target)?;
                    }
                }
                Resolution::DeleteVsEditKeepEdit(entry) => {
                    // The edit wins. If the surviving edit is the REMOTE side
                    // (local had deleted it), materialize it; if it is the LOCAL
                    // side (remote deleted, local edited), the bytes are already on
                    // disk — leave them and do NOT apply the deletion.
                    if r.is_some() {
                        if currently_dir && entry.t != FileType::Dir {
                            deferred_dir_replacements.push(entry);
                        } else {
                            to_materialize.push(entry);
                        }
                    }
                }
                Resolution::ConflictCopy { winner, mut loser } => {
                    // Before keeping both, try a textual 3-way content merge: when
                    // BOTH sides are Files and a common base entry exists, the two
                    // divergent edits may not overlap (appends / disjoint line
                    // regions) and can be fused into one file. Only Files carry
                    // mergeable content; a symlink/derived winner or loser, or a
                    // base with no entry (created on both sides, no ancestor),
                    // skips straight to the conflict copy.
                    if winner.t == FileType::File
                        && loser.t == FileType::File
                        && base.get(&key).is_some_and(|be| be.t == FileType::File)
                    {
                        let base_entry = base.get(&key).expect("checked is_some_and above");
                        if let Some(merged) = self.try_auto_merge(base_entry, &winner).await {
                            // Non-overlapping edits fused: write the merged bytes to
                            // the real path and skip the conflict copy entirely. We
                            // deliberately do NOT record this in the index/block
                            // table nor echo-mark it (see [`write_merged`]): the
                            // merged content is a brand-new local change the NEXT
                            // commit re-scans, chunks and uploads — never a phantom
                            // block. Also NOT pushed to `to_materialize`, so phase B
                            // cannot overwrite the merge with the remote winner.
                            //
                            // The MODE is merged too: `x` is half of a File's content
                            // identity (`§5.1`, ft_conflict's `same_content` and
                            // ft_diff's `same_identity` both key on `pcid` AND `x`),
                            // so taking the winner's bit would silently drop a local
                            // `chmod +x` — a real local change, and the fused write
                            // is the only place left to carry it.
                            let exec = merged_exec_bit(base_entry.x, loser.x, winner.x);
                            self.write_merged(&winner, &merged, exec)?;
                            tracing::info!(
                                space = %self.space_id,
                                path = %winner.p.as_str(),
                                exec,
                                "auto-merged divergent edits (3-way content merge)"
                            );
                            continue;
                        }
                    }

                    // Keep BOTH: remote winner at the real path, local loser moved
                    // aside to its conflict-copy name. The loser's bytes are the
                    // LOCAL ones already on disk at the winner's path, so copy them
                    // NOW (phase A) — before any winner overwrites that path in
                    // phase B.
                    //
                    // `resolve` already named the loser, but that name is only
                    // guaranteed to be DETERMINISTIC, not free: the head may legally
                    // carry a path equal to it (a copy another Device committed) and
                    // phase B would then materialize straight over the copy whose one
                    // job is to preserve this edit. Re-pick it against everything this
                    // batch touches. The winner's path is the loser's origin — after
                    // the collision guard above, `l.p == winner.p`.
                    let copy_path =
                        self.pick_conflict_path(&mut namer, &winner.p, &loser, &local)?;
                    loser.p = copy_path;
                    tracing::warn!(
                        space = %self.space_id,
                        original = %winner.p.as_str(),
                        conflict_copy = %loser.p.as_str(),
                        "divergent edit: local version kept as a conflict copy"
                    );
                    self.write_conflict_copy(l, &loser).await?;
                    conflicts.push(loser.p.as_str().to_string());
                    if currently_dir && winner.t != FileType::Dir {
                        deferred_dir_replacements.push(winner);
                    } else {
                        to_materialize.push(winner);
                    }
                }
            }
        }

        // Phase B: materialize the collected (non-dir-affected) winners
        // concurrently, RECORDING each one sequentially as it completes.
        let total = to_materialize.len();
        if total > 0 {
            // Distinct-path guard: two winners aimed at the same canonical path
            // would race two concurrent materializes onto the same `.ft-tmp`
            // sibling. Well-formed input never produces this (union keys are
            // unique; conflict-copy names derive from distinct paths and never
            // equal a winner path), so a duplicate is a hard bug — fail loudly
            // rather than risk silent on-disk corruption.
            let mut seen: HashSet<&str> = HashSet::with_capacity(total);
            for entry in &to_materialize {
                if !seen.insert(entry.p.as_str()) {
                    return Err(EngineError::SpaceState(format!(
                        "reconcile: two winners target the same path {:?}; \
                         refusing concurrent materialize",
                        entry.p.as_str()
                    )));
                }
            }

            tracing::info!(total, "reconcile materializing winners");
            let started = Instant::now();
            let completed = AtomicUsize::new(0);
            let mut stream = futures::stream::iter(to_materialize.iter())
                .map(|entry| {
                    let completed = &completed;
                    async move {
                        materialize(
                            self.vault.as_ref(),
                            self.fs.as_ref(),
                            &self.local_root,
                            entry,
                            self.crypto.as_ref(),
                        )
                        .await?;
                        let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                        if n.is_multiple_of(25) {
                            tracing::info!(completed = n, total, "reconcile materializing winners");
                        }
                        Result::Ok(entry)
                    }
                })
                .buffer_unordered(8);

            // Drain sequentially: as each winner's download completes, record it
            // in the local index + echo marks (rusqlite stays OUT of the
            // concurrent futures, ADR 0017). This keeps up to 8 materializations
            // in flight while restoring per-path atomicity — a mid-batch error
            // aborts with every already-completed winner fully recorded, never
            // written-but-unrecorded.
            while let Some(res) = stream.next().await {
                let entry = res?;
                self.record_materialized(entry)?;
            }

            tracing::info!(
                total,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "reconcile materialized"
            );
        }

        // Now the deferred directory verdicts, which MUST run after phase B and in
        // a strict order so a populated deleted tree never resurrects (ADR 0019):
        //
        // (1) dir deletions deepest-first — every child (deleted in-loop above, or
        //     a deeper dir deleted here first) is gone before its parent's
        //     `remove_dir`, so ENOTEMPTY never resurrects a parent. `remote_delete`
        //     keeps its "keep dir + row" ENOTEMPTY semantics for genuine local
        //     unsynced content.
        deferred_dir_deletes.sort_by_key(|e| std::cmp::Reverse(path_depth(&e.p)));
        for entry in &deferred_dir_deletes {
            self.remote_delete(Some(entry))?;
        }
        // (2) dir→non-dir replacements: the local dir is empty now (its children
        //     were removed above), so materialize's `remove_dir` succeeds. A dir
        //     still holding unsynced local content surfaces materialize's error
        //     rather than being force-deleted. Sequential is fine — a directory
        //     replacement downloads at most one small file's blocks, and this keeps
        //     the rusqlite record path out of any concurrent future (ADR 0017).
        //
        // A dir that is STILL populated is the one failure that no retry can clear,
        // so it does not abort the rest: the other replacements are independent
        // paths and are applied, and the blocked ones are collected into ONE
        // actionable error below. Aborting at the first one left the remainder of
        // the head unapplied while the identical failure re-fired every backstop
        // tick with a bare `ENOTEMPTY` and no hint of what to do.
        let mut blocked_dirs: Vec<String> = Vec::new();
        for entry in &deferred_dir_replacements {
            match materialize(
                self.vault.as_ref(),
                self.fs.as_ref(),
                &self.local_root,
                entry,
                self.crypto.as_ref(),
            )
            .await
            {
                Ok(()) => self.record_materialized(entry)?,
                Err(ft_diff::Error::Remove { ref source, .. }) if dir_not_empty(source) => {
                    tracing::error!(
                        space = %self.space_id,
                        path = %entry.p.as_str(),
                        "the Space head replaces this directory with a file, but it still holds \
                         local files no Revision has; refusing to delete them (ADR 0019)"
                    );
                    blocked_dirs.push(entry.p.as_str().to_string());
                }
                Err(e) => return Err(EngineError::Diff(e)),
            }
        }
        if !blocked_dirs.is_empty() {
            // Typed and actionable: the daemon can recognize it (a `Refused` is
            // never transient — no retry clears it) and the message says exactly
            // which paths block the Space and what the user must do.
            return Err(EngineError::Refused(format!(
                "the Space head replaces {} with a file, but each still holds local files that no \
                 Revision has, so they were NOT deleted. This Space cannot advance past the \
                 current head until you move or delete that content (or the directory itself) \
                 and sync again; the rest of the head has been applied.",
                blocked_dirs.join(", ")
            )));
        }

        Ok(conflicts)
    }

    /// Picks the path a conflict copy of `copy` is written to, so that NOTHING can
    /// destroy it: not a winner this same reconcile materializes, not a deletion it
    /// applies, not an unrelated local file, and not a copy an EARLIER reconcile
    /// already left there (`§10`).
    ///
    /// [`ft_conflict::conflict_copy_name`] is deterministic but not free: the head
    /// may legitimately carry a path equal to the copy's name (e.g. a copy another
    /// Device resolved and committed), and two reconciles that run at the same base
    /// `seq` mint the identical name twice. Either way the file whose entire purpose
    /// is "no edit is ever lost" would be the one lost.
    ///
    /// `original` is the path the copy is made FROM. Candidates are
    /// `conflict_copy_name(original, label, seq)`, then the same scheme with the
    /// label suffixed `label 2`, `label 3`, … — inside the parenthetical on purpose,
    /// so [`ft_conflict::is_conflict_copy_name`] (and therefore `filething status`)
    /// still recognizes every copy we write. A candidate is taken when it is FREE,
    /// or when what already sits there IS this very copy (same type + same content
    /// identity), which makes a retried reconcile idempotent instead of minting one
    /// copy per round.
    fn pick_conflict_path(
        &self,
        namer: &mut CopyNamer<'_>,
        original: &CanonicalPath,
        copy: &FileEntry,
        local: &HashMap<CasefoldKey, FileEntry>,
    ) -> Result<CanonicalPath> {
        for n in 0..MAX_CONFLICT_COPY_SLOTS {
            let candidate = if n == 0 {
                conflict_copy_name(original, namer.label, namer.seq)
            } else {
                conflict_copy_name(original, &format!("{} {}", namer.label, n + 1), namer.seq)
            };
            let key = ft_fsmap::casefold_key(&candidate);
            // Already spoken for by another copy this same reconcile writes.
            if namer.claimed.contains(&key) {
                continue;
            }
            // A key the reconcile itself may write (a remote winner) or delete (a
            // base path absent from the head): parking a copy there loses it.
            if namer.blocked.contains(&key) {
                continue;
            }
            match local.get(&key) {
                // Our own copy from an earlier round: reuse it (rewriting identical
                // bytes is a no-op) instead of growing a new one every sync.
                Some(existing) if same_copy(existing, copy) => {
                    namer.claimed.insert(key);
                    return Ok(candidate);
                }
                // Some OTHER local file lives there — never overwrite it.
                Some(_) => continue,
                // Unknown to the scan: it may still exist on disk (an ignored or
                // platform-junk path the Manifest never carries), and overwriting
                // that is data loss just the same.
                None => {
                    if join_canonical(&self.local_root, &candidate)
                        .symlink_metadata()
                        .is_ok()
                    {
                        continue;
                    }
                    namer.claimed.insert(key);
                    return Ok(candidate);
                }
            }
        }
        Err(EngineError::Refused(format!(
            "cannot keep the local version of {:?} aside: its first {MAX_CONFLICT_COPY_SLOTS} \
             conflict-copy names are all taken by other files. Resolve the existing conflict \
             copies of that path (keep or delete them) and sync again — no edit was overwritten.",
            original.as_str()
        )))
    }

    /// Records a freshly materialized remote [`FileEntry`]: upserts its local-index
    /// row + Block presence and marks it for echo suppression (`§9`). The sequential
    /// tail of a materialization — kept out of the concurrent phase B so rusqlite
    /// writes stay serialized (ADR 0017).
    fn record_materialized(&self, entry: &FileEntry) -> Result<()> {
        self.index_upsert_materialized(entry)?;
        let pcid = match entry.t {
            FileType::File => entry.pcid,
            _ => Pcid::new([0u8; 32]),
        };
        self.mark_applied_for(&entry.p, pcid);
        Ok(())
    }

    /// Applies a remote deletion: removes the path from disk (idempotent) and drops
    /// its local-index row. `entry` is the base/local entry naming the path.
    ///
    /// A directory deletion uses `remove_dir` (never recursive, ADR 0019): a dir
    /// that still holds local (unsynced) content is a SILENT keep — it is never
    /// force-deleted, and its index row is left in place so the next scan/commit
    /// re-adds the still-present path cleanly instead of publishing a Manifest that
    /// drops it. NotFound (already gone) drops the row like a real deletion. A
    /// file/symlink deletion is unchanged (`remove_file`).
    fn remote_delete(&self, entry: Option<&FileEntry>) -> Result<()> {
        if let Some(entry) = entry {
            let abs = join_canonical(&self.local_root, &entry.p);
            if entry.t == FileType::Dir {
                match std::fs::remove_dir(&abs) {
                    Ok(()) => {
                        self.index.delete_entry(self.space_id.as_str(), &entry.p)?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        self.index.delete_entry(self.space_id.as_str(), &entry.p)?;
                    }
                    // Still-populated dir: keep it AND its index row (do not error).
                    Err(e) if dir_not_empty(&e) => {}
                    Err(e) => return Err(EngineError::Io(e)),
                }
            } else {
                match std::fs::remove_file(&abs) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(EngineError::Io(e)),
                }
                self.index.delete_entry(self.space_id.as_str(), &entry.p)?;
            }
        }
        Ok(())
    }

    /// Writes the conflict copy for a `ConflictCopy` loser: copies the CURRENT
    /// on-disk local bytes (the loser's content) to the loser's renamed path,
    /// BEFORE the winner overwrites the original path. Falls back to materializing
    /// the loser from the Vault if its local file is absent. Marks the copy as an
    /// echo and indexes it.
    async fn write_conflict_copy(
        &self,
        local: Option<&FileEntry>,
        loser: &FileEntry,
    ) -> Result<()> {
        let dest = join_canonical(&self.local_root, &loser.p);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(EngineError::Io)?;
        }

        // The loser's original path (the winner's path) — its current on-disk
        // bytes ARE the local content we must preserve.
        let original = local
            .map(|l| join_canonical(&self.local_root, &l.p))
            .unwrap_or_else(|| join_canonical(&self.local_root, &loser.p));

        // Whether the copy's bytes verifiably came FROM the Vault. Decides which
        // index upsert runs below: an offline loser's Blocks were never uploaded
        // by anyone, and claiming them in the block table would make the next
        // commit skip their upload — publishing a Manifest that references
        // objects the Vault does not have (the "bloque fantasma" bug).
        let mut from_vault = false;
        match loser.t {
            FileType::Symlink => {
                let target = loser.lt.clone().unwrap_or_default();
                let _ = std::fs::remove_file(&dest);
                self.fs.create_symlink(&target, &dest)?;
            }
            FileType::Derived => { /* derived bytes never travel */ }
            FileType::Dir => {
                // A dir loser: create the directory at the conflict-copy name so
                // the (empty) directory is preserved aside (ADR 0019). No bytes.
                std::fs::create_dir_all(&dest).map_err(EngineError::Io)?;
            }
            FileType::File => {
                match std::fs::read(&original) {
                    Ok(bytes) => {
                        self.fs.write_bytes(&dest, &bytes, loser.x)?;
                    }
                    Err(_) => {
                        // Local file gone: best-effort recover the loser from the
                        // Vault (its blocks may be present from a prior commit).
                        materialize(
                            self.vault.as_ref(),
                            self.fs.as_ref(),
                            &self.local_root,
                            loser,
                            self.crypto.as_ref(),
                        )
                        .await?;
                        from_vault = true;
                    }
                }
            }
        }
        if from_vault {
            self.index_upsert_materialized(loser)?;
        } else {
            self.index_upsert_row(loser)?;
        }
        let pcid = match loser.t {
            FileType::File => loser.pcid,
            _ => Pcid::new([0u8; 32]),
        };
        self.mark_applied_for(&loser.p, pcid);
        Ok(())
    }

    /// Attempts a textual 3-way content merge for a divergent File edit, returning
    /// the merged bytes when the two sides do NOT overlap (appends / disjoint line
    /// regions / identical edit), or `None` to fall back to a conflict copy.
    ///
    /// The three sides (`§10`, issue #14 point 4):
    /// - **base** — the last common version, fetched from the Vault via
    ///   [`fetch_file_bytes`] from the `base_entry`. Its Blocks are retained by the
    ///   `base_seq` GC guard; if the fetch still fails (a corrupt/missing object),
    ///   we return `None` and let the caller keep both — a merge failure must never
    ///   abort the reconcile.
    /// - **remote** — the winning remote version, fetched from the Vault via
    ///   [`fetch_file_bytes`] from `winner`.
    /// - **local** — the loser's bytes, which are the ones CURRENTLY on disk at the
    ///   winner's path (nothing has overwritten them yet in phase A), read from the
    ///   filesystem exactly as [`write_conflict_copy`](Self::write_conflict_copy)
    ///   reads its `original`.
    ///
    /// Returns `Some(bytes)` only for [`Merge3::Clean`]; [`Merge3::Conflict`],
    /// [`Merge3::Binary`], and any Vault/fs read error all yield `None`.
    async fn try_auto_merge(&self, base_entry: &FileEntry, winner: &FileEntry) -> Option<Vec<u8>> {
        let base_bytes =
            match fetch_file_bytes(self.vault.as_ref(), base_entry, self.crypto.as_ref()).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        space = %self.space_id,
                        path = %winner.p.as_str(),
                        error = %e,
                        "auto-merge: base bytes unavailable, falling back to conflict copy"
                    );
                    return None;
                }
            };
        let remote_bytes =
            match fetch_file_bytes(self.vault.as_ref(), winner, self.crypto.as_ref()).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        space = %self.space_id,
                        path = %winner.p.as_str(),
                        error = %e,
                        "auto-merge: remote bytes unavailable, falling back to conflict copy"
                    );
                    return None;
                }
            };
        let local_path = join_canonical(&self.local_root, &winner.p);
        let local_bytes = match std::fs::read(&local_path) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(
                    space = %self.space_id,
                    path = %winner.p.as_str(),
                    error = %e,
                    "auto-merge: local bytes unavailable, falling back to conflict copy"
                );
                return None;
            }
        };

        match merge3(&base_bytes, &local_bytes, &remote_bytes) {
            Merge3::Clean(merged) => Some(merged),
            Merge3::Conflict | Merge3::Binary => None,
        }
    }

    /// Writes auto-merged bytes to the winner's real path (phase A) with the merged
    /// mode `exec`, WITHOUT recording anything in the index/block table and WITHOUT
    /// echo-marking.
    ///
    /// This is the anti-"phantom block" contract (mirrors the reasoning in
    /// [`write_conflict_copy`](Self::write_conflict_copy)): the merged content is
    /// bytes NO Device has ever chunked or uploaded, so it must NOT claim any
    /// Block presence and must NOT overwrite the path's index row with a
    /// remote/local `pcid`. Leaving the row untouched means the next `scan`
    /// (`§9`) sees the on-disk bytes differ from the recorded `pcid`, re-chunks
    /// them, and the following commit uploads the fused Blocks naturally.
    ///
    /// Because it is deliberately NOT echo-marked, the daemon's watcher sees this
    /// write as a genuine local change and schedules the commit that uploads it —
    /// the mechanism that also covers a feed-triggered reconcile with no
    /// commit_and_reconcile in the same turn (see the module-level LIMITS note).
    fn write_merged(&self, winner: &FileEntry, merged: &[u8], exec: bool) -> Result<()> {
        let dest = join_canonical(&self.local_root, &winner.p);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(EngineError::Io)?;
        }
        // `exec` is the MERGED mode ([`merged_exec_bit`]), not `winner.x`: the exec
        // bit is half of a File's content identity (`§5.1`), so a local `chmod +x`
        // fused with a remote text edit must survive the fusion.
        self.fs.write_bytes(&dest, merged, exec)?;
        Ok(())
    }

    /// Commits local changes, reconciling on a CAS conflict and retrying (`§7`
    /// step 6 + `§10`). This is the routine the [`run`](SpaceContext::run) loop
    /// drives.
    ///
    /// Loops: `commit(expected_base = last_synced_revision_id)`. On
    /// [`CommitOutcome::Committed`]/[`CommitOutcome::NoChange`] it returns; on
    /// [`CommitOutcome::Conflict`] it [`pull`](SpaceContext::pull)s (which
    /// reconciles per file and advances the base) and retries with the new
    /// `expected_base`, up to [`MAX_COMMIT_RETRIES`] times.
    ///
    /// Returns the [`CommitOutcome`] AND the conflict-copy paths written by the
    /// reconciling pulls it ran to clear a CAS conflict (issue #9). Those pulls are
    /// invisible to the daemon's feed/backstop branches, so without surfacing their
    /// conflicts here the `conflicts` metric stayed 0 for the most common conflict
    /// case (a concurrent edit that only shows up as a CAS conflict on commit). The
    /// caller folds the returned paths into [`SyncMetrics`](crate::SyncMetrics); the
    /// retry pulls are NOT counted as `pulls_applied` (see
    /// [`SyncMetrics::record_conflicts`](crate::SyncMetrics::record_conflicts)).
    pub async fn commit_and_reconcile(&mut self) -> Result<(crate::CommitOutcome, Vec<String>)> {
        use crate::CommitOutcome;
        // Conflict copies accumulated across the reconciling retry pulls below.
        let mut conflicts: Vec<String> = Vec::new();
        for _ in 0..MAX_COMMIT_RETRIES {
            let expected_base = self.last_synced_revision_id.clone();
            match self.commit(expected_base).await? {
                CommitOutcome::Committed { seq, root } => {
                    return Ok((CommitOutcome::Committed { seq, root }, conflicts));
                }
                CommitOutcome::NoChange => return Ok((CommitOutcome::NoChange, conflicts)),
                CommitOutcome::Conflict { .. } => {
                    // The head moved under us: reconcile against the new head, then
                    // retry the commit with the advanced base. A reconcile that
                    // writes conflict copies must not be lost (issue #9) — collect
                    // them for the caller's metrics.
                    if let PullOutcome::Reconciled { conflicts: written } = self.pull().await? {
                        conflicts.extend(written);
                    }
                }
            }
        }
        // The Err path cannot carry the conflict-copy paths, and the copies ARE
        // already on disk — surface them in the log so they are not silently
        // dropped with the error (issue #9 reviewer finding).
        if !conflicts.is_empty() {
            tracing::warn!(
                space = %self.space_id,
                conflict_copies = conflicts.len(),
                paths = ?conflicts,
                "commit_and_reconcile failed to converge AFTER writing conflict copies; \
                 they are on disk but not folded into metrics"
            );
        }
        Err(EngineError::SpaceState(format!(
            "commit_and_reconcile did not converge after {MAX_COMMIT_RETRIES} retries"
        )))
    }
}

/// The per-reconcile state that names conflict copies: the `(label, seq)` pair
/// every copy name is built from (`§10`) plus the keys a copy must stay off.
///
/// `blocked` is `base ∪ remote`: every key the reconcile itself may materialize a
/// winner onto or apply a deletion to. `claimed` grows as copies are minted, so two
/// copies in one batch cannot land on one path either. See
/// [`SpaceContext::pick_conflict_path`].
struct CopyNamer<'a> {
    label: &'a str,
    seq: u64,
    blocked: HashSet<CasefoldKey>,
    claimed: HashSet<CasefoldKey>,
}

/// The root cid of the EMPTY Manifest — the "no base yet" base a fresh Device
/// starts from (`clone_space` / `init_space` seed it, `§4.2`).
///
/// Built in process: `ft_manifest::build(Vec::new())` is deterministic, so the read
/// path must never need the OBJECT to exist. It used to be HEAD-then-PUT into the
/// Vault, which was a cross-tenant hazard: this cid folds in no account/Space id, so
/// it is GLOBALLY CONSTANT — one key shared by every tenant of a deployment — and
/// HEAD-then-PUT never repairs a present-but-wrong object. Any authenticated user
/// could be the first to create that key with garbage and break the FIRST pull of
/// every fresh Space for everyone, permanently (the Coordinator signs create-only
/// PUTs, so nothing can overwrite it afterwards). Building it locally removes the
/// attack surface and a Vault round-trip with it.
pub(crate) fn empty_manifest_root() -> Cid {
    ft_manifest::build(Vec::new()).root
}

/// The [`FileEntry`] a [`Change`] acts ON — the one whose path is written, removed
/// or recorded. The `old` side of a `Modified` is deliberately not it: no phase
/// touches that path (mirrors `ft_diff::apply`).
fn acted_entry(change: &Change) -> &FileEntry {
    match change {
        Change::Added(e) | Change::Modified { new: e, .. } | Change::Deleted(e) => e,
    }
}

/// The inbound trust boundary for entries this file acts on itself (`§5.2`):
/// [`ft_core::FileEntry::validate_untrusted`] over every one of them, before any
/// side effect. Everything decoded from a Manifest page is remote-controlled, so a
/// `p` like `../../.ssh/authorized_keys` is a HARD error — never a sanitization,
/// which would act on the wrong file.
fn validate_entries<'a>(entries: impl IntoIterator<Item = &'a FileEntry>) -> Result<()> {
    for entry in entries {
        entry.validate_untrusted()?;
    }
    Ok(())
}

/// The three-way merge of the executable bit for a fused File (`§10`).
///
/// `x` is half of a File's content identity (`§5.1`), so it needs the same causal
/// treatment as the bytes: the side that CHANGED it against base wins. A boolean
/// cannot conflict — if both sides moved off `base`, they both moved to `!base`, so
/// they agree — which is why an auto-merge never has to decline over the mode.
fn merged_exec_bit(base: bool, local: bool, remote: bool) -> bool {
    if local != base {
        local
    } else {
        remote
    }
}

/// Do two entries carry the same materialized identity, i.e. is one already ON DISK
/// as the other? Type-keyed exactly like `ft_conflict::same_content` and
/// `ft_diff::same_identity` (`pcid` + `x` for a File, `lt` for a symlink, the type
/// alone for a dir/derived), so "the copy is already there" means the same thing
/// here as "unchanged" does to the resolver and the diff.
fn same_copy(a: &FileEntry, b: &FileEntry) -> bool {
    a.t == b.t
        && match a.t {
            FileType::File => a.pcid == b.pcid && a.x == b.x,
            FileType::Symlink => a.lt == b.lt,
            FileType::Derived | FileType::Dir => true,
        }
}

/// The local entry that is ALREADY the conflict copy of `entry`, if any: a path
/// whose conflict-copy marker strips back to `entry.p` and whose content identity
/// matches. Any `(label, seq)` counts — a copy written at an earlier `seq`, or by
/// this Device under an older name, is still the same rescue (`§10`).
fn existing_conflict_copy<'a>(
    local: &'a HashMap<CasefoldKey, FileEntry>,
    entry: &FileEntry,
) -> Option<&'a FileEntry> {
    local.values().find(|candidate| {
        conflict_copy_origin(candidate.p.as_str()).as_deref() == Some(entry.p.as_str())
            && same_copy(candidate, entry)
    })
}

/// Reverses [`ft_conflict::conflict_copy_name`]: the ORIGINAL path a conflict copy
/// was made from, or `None` when `path` is not a conflict copy.
///
/// The rename inserts exactly `" (conflicto <label>, seq <n>)"` before the
/// extension, and the label is sanitized of parentheses, so the first `)` after the
/// marker closes it. The parenthetical is validated by
/// [`ft_conflict::is_conflict_copy_name`] rather than re-parsed here, so both
/// formats it accepts (current and legacy) strip identically. The LAST marker is
/// stripped, so a copy of a copy peels one level.
fn conflict_copy_origin(path: &str) -> Option<String> {
    const MARKER: &str = " (conflicto ";
    let start = path.rfind(MARKER)?;
    let after = &path[start + MARKER.len()..];
    let end = after.find(')')?;
    if !is_conflict_copy_name(&format!("(conflicto {})", &after[..end])) {
        return None;
    }
    Some(format!("{}{}", &path[..start], &after[end + 1..]))
}

/// True if `e` reports a non-empty directory from `remove_dir` (ADR 0019): the
/// portable `ErrorKind::DirectoryNotEmpty`, or the raw `ENOTEMPTY` as a fallback
/// for toolchains that still map it to `ErrorKind::Other` — `39` on Linux, `66` on
/// macOS/BSD.
fn dir_not_empty(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::DirectoryNotEmpty
        || matches!(e.raw_os_error(), Some(39) | Some(66))
}

/// Number of path components in a canonical path — its directory depth. Used to
/// order deferred `Dir` deletions deepest-first so a parent is removed only after
/// its children (BLOCKER 2).
fn path_depth(p: &CanonicalPath) -> usize {
    p.as_str().split('/').filter(|s| !s.is_empty()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- merged_exec_bit: the mode is merged causally, like the bytes ----

    #[test]
    fn merged_exec_bit_takes_the_side_that_changed_it_against_base() {
        // Local chmod +x, remote left the bit alone -> the chmod survives the fuse.
        assert!(merged_exec_bit(false, true, false));
        // Remote chmod +x, local left it alone -> the remote bit wins.
        assert!(merged_exec_bit(false, false, true));
        // Local chmod -x on an executable base -> the removal survives.
        assert!(!merged_exec_bit(true, false, true));
    }

    #[test]
    fn merged_exec_bit_keeps_base_when_neither_side_touched_it() {
        assert!(!merged_exec_bit(false, false, false));
        assert!(merged_exec_bit(true, true, true));
    }

    #[test]
    fn merged_exec_bit_never_conflicts_because_both_sides_agree() {
        // A boolean has one other value: if both moved off base they moved to the
        // SAME bit, so the merge is always defined (no decline needed).
        assert!(merged_exec_bit(false, true, true));
        assert!(!merged_exec_bit(true, false, false));
    }

    // ---- validate_entries: this file's own inbound trust boundary --------

    /// A File entry at `path`, contentless — enough to exercise the path policy.
    fn entry_at(path: &str) -> FileEntry {
        FileEntry {
            p: CanonicalPath(path.to_string()),
            t: FileType::File,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: Vec::new(),
            bk_ref: None,
            lt: None,
            wu: None,
        }
    }

    #[test]
    fn validate_entries_rejects_a_batch_holding_a_path_that_escapes_the_space_root() {
        // One bad entry rejects the WHOLE batch: the arms below act on these maps
        // directly (`remote_delete` unlinks, the copy writer writes), so a hostile
        // Manifest must abort before any of it runs (`§5.2`).
        let entries = [entry_at("keep.txt"), entry_at("../../.ssh/authorized_keys")];
        let err = validate_entries(entries.iter()).unwrap_err();
        assert!(
            matches!(err, EngineError::Core(ft_core::Error::UnsafePath { .. })),
            "expected an UnsafePath refusal, got {err}"
        );
    }

    #[test]
    fn validate_entries_accepts_ordinary_manifest_paths() {
        let entries = [entry_at("a.txt"), entry_at("src/deep/b.rs")];
        assert!(validate_entries(entries.iter()).is_ok());
    }

    // ---- conflict_copy_origin: reverses ft_conflict's rename --------------

    #[test]
    fn conflict_copy_origin_round_trips_conflict_copy_name() {
        for original in ["notes.txt", "a/b/report.tar.gz", ".gitignore", "README"] {
            let p = CanonicalPath(original.to_string());
            let copy = conflict_copy_name(&p, "Julian's Mac", 7);
            assert_eq!(
                conflict_copy_origin(copy.as_str()).as_deref(),
                Some(original),
                "must recover the origin of {}",
                copy.as_str()
            );
        }
    }

    #[test]
    fn conflict_copy_origin_round_trips_the_suffixed_label_variant() {
        // The numbered variant `pick_conflict_path` falls back to is still a
        // recognizable conflict copy of the SAME origin.
        let p = CanonicalPath("notes.txt".to_string());
        let copy = conflict_copy_name(&p, "devB 3", 0);
        assert!(is_conflict_copy_name(copy.as_str()));
        assert_eq!(
            conflict_copy_origin(copy.as_str()).as_deref(),
            Some("notes.txt")
        );
    }

    #[test]
    fn conflict_copy_origin_rejects_a_path_that_is_not_a_conflict_copy() {
        assert_eq!(conflict_copy_origin("notes.txt"), None);
        // A parenthetical that is not the marker, or has no seq number.
        assert_eq!(conflict_copy_origin("notes (draft 2).txt"), None);
        assert_eq!(conflict_copy_origin("notes (conflicto devB).txt"), None);
    }

    #[test]
    fn conflict_copy_origin_peels_one_level_from_a_copy_of_a_copy() {
        let p = CanonicalPath("notes.txt".to_string());
        let once = conflict_copy_name(&p, "devB", 1);
        let twice = conflict_copy_name(&once, "devB", 2);
        assert_eq!(
            conflict_copy_origin(twice.as_str()).as_deref(),
            Some(once.as_str())
        );
    }
}
