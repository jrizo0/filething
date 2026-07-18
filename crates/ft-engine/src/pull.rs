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

use ft_conflict::{collision_is_conflict, conflict_copy_name, resolve, Resolution};
use ft_coordinator::RevisionId;
use ft_core::{CanonicalPath, CasefoldKey, Cid, FileEntry, FileType, Pcid};
use ft_diff::{apply, diff, materialize, Change};
use futures::StreamExt;

use crate::context::{join_canonical, SpaceContext};
use crate::error::{EngineError, Result};

/// Maximum [`commit`](SpaceContext::commit) retries inside
/// [`commit_and_reconcile`](SpaceContext::commit_and_reconcile) before giving up
/// (each retry pulls + reconciles first). A small bound: a healthy Space converges
/// in one or two rounds; a persistent loop signals a real problem.
const MAX_COMMIT_RETRIES: usize = 8;

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
                // Best-effort persist; a failure surfaces on the next index op.
                let _ = self.persist_space_state();
            }
            return Ok(PullOutcome::UpToDate);
        }

        // The diff reads the base root's page from the Vault. The "no base yet"
        // base is the empty-Manifest root, which a freshly created/opened Device
        // may never have uploaded; ensure it is present (idempotent) so the diff
        // can start from it (`§4.2`).
        self.ensure_empty_root_present().await?;

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
            self.advance_base_to(&head, head_root);
            Ok(PullOutcome::FastForwarded { applied })
        } else {
            // Both moved: three-way reconcile per path (§10).
            let conflicts = self
                .reconcile(&self.last_synced.root.clone(), &head_root, &scan.entries)
                .await?;
            self.advance_base_to(&head, head_root);
            Ok(PullOutcome::Reconciled { conflicts })
        }
    }

    /// Ensures the base root's page is fetchable when the base is the
    /// "no base yet" empty-Manifest root: a fresh Device may never have uploaded
    /// it, yet the first diff reads it. Content-addressed PUT is idempotent, and
    /// this is a no-op once the base has advanced to a real root.
    async fn ensure_empty_root_present(&self) -> Result<()> {
        let empty = ft_manifest::build(Vec::new());
        if self.last_synced.root == empty.root {
            for (cid, obj) in &empty.pages {
                let key = ft_hash::manifest_key(cid);
                if !self.vault.head(&key).await? {
                    self.vault.put(&key, obj.clone()).await?;
                }
            }
        }
        Ok(())
    }

    /// Advances the synced base to `head` (root + seq + RevisionId) and persists
    /// it. After a reconcile the local tree may differ from `head_root`, but the
    /// BASE for the next diff/commit is the head we just merged against (`§10`).
    fn advance_base_to(&mut self, head: &HeadState, head_root: Cid) {
        self.last_synced = crate::context::LastSynced {
            seq: head.seq.unwrap_or(self.last_synced.seq),
            root: head_root,
        };
        self.last_synced_revision_id = head.revision_id.clone();
        // Best-effort persist; a failure here is surfaced by the next index op.
        let _ = self.persist_space_state();
    }

    /// Fast-forward: `diff(base -> head)` then `apply` every change to disk,
    /// marking each materialized file for echo suppression and updating the local
    /// index. Returns the number of changes applied.
    async fn fast_forward(&self, base_root: &Cid, head_root: &Cid) -> Result<usize> {
        let started = std::time::Instant::now();
        let changes = diff(self.vault.as_ref(), base_root, head_root).await?;

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
        for change in &changes {
            self.record_applied_change(change)?;
        }
        tracing::info!(
            total,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "fast-forward applied"
        );
        Ok(changes.len())
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

    /// Updates the local index and the echo-suppression marks for one applied
    /// [`Change`]: Added/Modified upsert the row + mark the write; Deleted drop the
    /// row. The Block presence cache (`local_block`) records the bytes we now hold.
    fn record_applied_change(&self, change: &Change) -> Result<()> {
        match change {
            Change::Added(entry) | Change::Modified { new: entry, .. } => {
                self.index_upsert_materialized(entry)?;
                match entry.t {
                    FileType::File => self.mark_applied_for(&entry.p, entry.pcid),
                    // A symlink's identity is its target; a dir carries no content
                    // (ADR 0019). Both mark with the same contentless zero pcid the
                    // scan computes for them, so this path and `record_materialized`
                    // stay consistent on what a Dir echo looks like.
                    FileType::Symlink | FileType::Dir => {
                        self.mark_applied_for(&entry.p, Pcid::new([0u8; 32]));
                    }
                    // Derived bytes never travel: nothing to echo-suppress.
                    FileType::Derived => {}
                }
            }
            Change::Deleted(entry) => {
                self.index.delete_entry(self.space_id.as_str(), &entry.p)?;
            }
        }
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
        let space_id = self.space_id.as_str();
        for cid in &entry.bk {
            self.index.put_block(space_id, cid)?;
        }
        Ok(())
    }

    /// Upserts the local-index row WITHOUT claiming its Blocks are in the Vault.
    /// For entries written from LOCAL bytes (a conflict-copy loser whose edit was
    /// never committed): the next commit must still see those Blocks as
    /// not-yet-uploaded, or it publishes a Manifest referencing objects the Vault
    /// does not have and every other Device's pull fails with `object not found`.
    fn index_upsert_row(&self, entry: &FileEntry) -> Result<()> {
        use ft_index::{BlockRef, LocalEntry};
        let space_id = self.space_id.as_str();
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
        self.index.upsert_entry(
            space_id,
            &LocalEntry {
                path: entry.p.clone(),
                casefold_key,
                file_type: entry.t,
                exec: entry.x,
                size: entry.sz,
                mtime,
                pcid,
                base_seq: self.last_synced.seq.max(0),
                blocks,
                local_only,
            },
        )?;
        Ok(())
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
    ///   writes a DISTINCT canonical path (union keys are unique; conflict-copy
    ///   names derive from distinct paths and never equal a winner path); this is
    ///   asserted up front and a duplicate is a hard error, not a race.
    ///
    /// A casefold/NFC collision between a remote and a DIFFERENT local path is
    /// forced into a conflict copy so the next commit's Manifest never sees two
    /// entries with one key (`§5.2`). On any error the reconcile aborts: the caller
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
    ///   before `materialize`'s `remove_dir` runs.
    ///
    /// Returns the conflict-copy paths written.
    async fn reconcile(
        &self,
        base_root: &Cid,
        head_root: &Cid,
        scan_entries: &[(CasefoldKey, FileEntry)],
    ) -> Result<Vec<String>> {
        let base = self.read_manifest_entries(base_root).await?;
        let remote = self.read_manifest_entries(head_root).await?;
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

        let device_id = self.device_id.as_str().to_string();
        let seq = self.last_synced.seq.max(0) as u64;
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
                    let mut renamed = r.clone();
                    renamed.p = conflict_copy_name(&r.p, &device_id, seq);
                    conflicts.push(renamed.p.as_str().to_string());
                    to_materialize.push(renamed);
                    continue;
                }
            }

            match resolve(b, l, r, &device_id, seq) {
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
                Resolution::ConflictCopy { winner, loser } => {
                    // Keep BOTH: remote winner at the real path, local loser moved
                    // aside to its conflict-copy name. The loser's bytes are the
                    // LOCAL ones already on disk at the winner's path, so copy them
                    // NOW (phase A) — before any winner overwrites that path in
                    // phase B.
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
        for entry in &deferred_dir_replacements {
            materialize(
                self.vault.as_ref(),
                self.fs.as_ref(),
                &self.local_root,
                entry,
                self.crypto.as_ref(),
            )
            .await?;
            self.record_materialized(entry)?;
        }

        Ok(conflicts)
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

    /// Commits local changes, reconciling on a CAS conflict and retrying (`§7`
    /// step 6 + `§10`). This is the routine the [`run`](SpaceContext::run) loop
    /// drives.
    ///
    /// Loops: `commit(expected_base = last_synced_revision_id)`. On
    /// [`CommitOutcome::Committed`]/[`CommitOutcome::NoChange`] it returns; on
    /// [`CommitOutcome::Conflict`] it [`pull`](SpaceContext::pull)s (which
    /// reconciles per file and advances the base) and retries with the new
    /// `expected_base`, up to [`MAX_COMMIT_RETRIES`] times.
    pub async fn commit_and_reconcile(&mut self) -> Result<crate::CommitOutcome> {
        use crate::CommitOutcome;
        for _ in 0..MAX_COMMIT_RETRIES {
            let expected_base = self.last_synced_revision_id.clone();
            match self.commit(expected_base).await? {
                CommitOutcome::Committed { seq, root } => {
                    return Ok(CommitOutcome::Committed { seq, root });
                }
                CommitOutcome::NoChange => return Ok(CommitOutcome::NoChange),
                CommitOutcome::Conflict { .. } => {
                    // The head moved under us: reconcile against the new head, then
                    // retry the commit with the advanced base.
                    self.pull().await?;
                }
            }
        }
        Err(EngineError::SpaceState(format!(
            "commit_and_reconcile did not converge after {MAX_COMMIT_RETRIES} retries"
        )))
    }
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
