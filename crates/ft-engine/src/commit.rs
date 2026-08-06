//! `commit` — the exact commit protocol of `docs/format.md §7`, plus
//! [`SpaceContext::init_space`] for creating a fresh Space.
//!
//! [`SpaceContext::commit`] runs the strict §7 order:
//!
//! 1. **scan** ([`SpaceContext::scan`]).
//! 2. **dedup + upload Blocks**: the first Revision uses idempotent direct PUTs;
//!    later commits `HEAD` each unique `(cid, bytes)` and PUT only when absent.
//!    Every confirmed Block is then recorded locally (`§7` step 2).
//! 3. **build Manifest** ([`ft_manifest::build`]).
//! 4. **upload** every Manifest page (`manifest/<aa>/<cid>`) and externalized
//!    blocklist (`blocklist/<aa>/<cid>`) to the Vault. INVARIANT after this step:
//!    everything is in the Vault, nothing in the Coordinator yet (`§7`).
//! 5. **CAS** ([`Coordinator::commit_revision`]). On success the `space_state`
//!    base advances and [`CommitOutcome::Committed`] is returned; on
//!    [`CommitError::Conflict`] no retry/reconcile happens here (that is Part 2)
//!    — [`CommitOutcome::Conflict`] is returned.
//!
//! If the scanned tree's `manifestRoot` already equals the synced base root,
//! [`CommitOutcome::NoChange`] is returned without touching the Coordinator.

use ft_coordinator::{AccountId, CommitError, Coordinator, DeviceId, RevisionId, SpaceId};
use ft_core::{CasefoldKey, Cid, FileEntry, SpaceCrypto};
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::{Index, SpaceState};

use crate::context::{LastSynced, SpaceContext};
use crate::error::{EngineError, Result};
use crate::scan::{ScanResult, CONTROL_DIR};
use crate::secrets::{generate_chunk_secret, write_meta_blob};

/// Block PUTs carry meaningful payload bytes, so keep their fan-out conservative
/// enough not to swamp a Device's uplink.
const BLOCK_UPLOAD_CONCURRENCY: usize = 16;
/// Key sidecars are tiny (~100 B) and latency-bound; a wider fan-out hides the
/// per-object R2 round trip without materially increasing bandwidth or memory.
const SIDECAR_UPLOAD_CONCURRENCY: usize = 64;

/// Below this many tracked paths a Space is TRIVIAL for the purposes of the
/// mass-delete guard: clearing out a handful of files by hand is ordinary work and
/// must never need an override.
const DELETE_GUARD_MIN_ENTRIES: usize = 50;

/// The net shrink — as a percentage of the tree this Device already knew about —
/// at or above which a commit stops looking like an edit and starts looking like a
/// root that is not really there.
///
/// Deliberately high: deleting a whole directory of build output is normal
/// (`target/`, `dist/`), so the guard must not fire on it; losing ~everything is
/// not. 90% keeps every plausible bulk edit under the bar while still catching the
/// cases that motivated the guard, where the observed tree is empty or a handful of
/// stragglers (a volume that failed to mount, a root moved aside mid-sync).
const DELETE_GUARD_MAX_SHRINK_PERCENT: usize = 90;

/// The one-shot authorization file — under the control dir, so it is never itself
/// synced — that lets a commit past [`SpaceContext::guard_mass_delete`].
///
/// A file rather than a flag because `commit` is driven by the daemon's `run` loop,
/// which has no user in front of it; the CLI cannot pass an argument down a
/// debounce timer. It is consumed on the commit that used it, so it authorizes ONE
/// mass delete and cannot silently disable the guard forever.
const ALLOW_MASS_DELETE_FILE: &str = "allow-mass-delete";

/// True when going from `tracked_before` to `remaining` Manifest-tracked paths
/// stops looking like an edit and starts looking like a Space root that is not
/// really there ([`DELETE_GUARD_MIN_ENTRIES`] / [`DELETE_GUARD_MAX_SHRINK_PERCENT`]).
///
/// ONE rule, shared by the two places that must agree about it: the guard in
/// [`SpaceContext::guard_mass_delete`], which refuses to publish such a Revision,
/// and the scan, which for exactly the same shrink keeps the vanished paths' index
/// rows so the guard still has a baseline on the next commit
/// ([`ScanResult::held_deletions`](crate::ScanResult)). If they could drift, a
/// shrink one of them called massive and the other did not would either hold rows
/// forever or lose the evidence again.
pub(crate) fn is_mass_delete(tracked_before: usize, remaining: usize) -> bool {
    let deleted = tracked_before.saturating_sub(remaining);
    tracked_before >= DELETE_GUARD_MIN_ENTRIES
        && deleted * 100 >= tracked_before * DELETE_GUARD_MAX_SHRINK_PERCENT
}

/// The result of a [`SpaceContext::commit`] (`§7`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The CAS succeeded: a new Revision at `seq` with manifest root `root` is the
    /// Space head, and the local base advanced to it.
    Committed {
        /// The committed Revision's per-Space `seq`.
        seq: i64,
        /// The committed `manifestRoot`.
        root: Cid,
    },

    /// The CAS conflicted: the Space head moved under `expected_base`. No retry
    /// or reconcile is done here (Part 2). `current_head` is the head id at the
    /// time of the conflict if it could be fetched, else `None`.
    Conflict {
        /// The Space head id observed after the conflict (best-effort).
        current_head: Option<RevisionId>,
    },

    /// The scanned tree is byte-identical to the synced base (`manifestRoot`
    /// unchanged): nothing to commit, the Coordinator was not touched.
    NoChange,
}

/// The outcome of [`SpaceContext::stage_to_vault`]: everything written to the
/// Vault for a would-be commit, before the Coordinator CAS (`§7` steps 1–4).
#[derive(Debug, Clone)]
pub struct StagedCommit {
    /// The Manifest root that the CAS would commit.
    pub root: Cid,
    /// Number of distinct Manifest pages produced.
    pub pages: usize,
    /// Number of externalized blocklist objects produced.
    pub blocklists: usize,
    /// Number of Block objects actually `PUT` this stage (after dedup). A
    /// re-stage with no changes uploads `0`.
    pub blocks_uploaded: usize,
    /// The scan that produced this stage (FileEntries + the Blocks set).
    pub scan: ScanResult,
}

/// How the Vault-side write path establishes object presence.
///
/// A brand-new Space can write directly: Block PUTs are content-addressed and
/// idempotent, while its `keys/<space_id>/` sidecar namespace is guaranteed to
/// be empty. Later commits retain HEAD-before-PUT because GC may have removed an
/// object that the local index still records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadStrategy {
    Initial,
    VerifyPresence,
}

/// Builds the Manifest of `entries` on the blocking pool.
///
/// [`ft_manifest::build`] is pure but O(tree): it CBOR-encodes every FileEntry and
/// hashes every page. The daemon drives EVERY Space of the Device on ONE task (the
/// `run` future is `!Send`, so `ft-daemon` multiplexes the Spaces with `join_all`
/// instead of `tokio::spawn`), so doing that work inline stalls every other Space's
/// change feed and staleness watchdog for its duration. Handing it to
/// `spawn_blocking` lets the shared task poll the siblings while it runs.
///
/// A `JoinError` here means the build panicked (a bug in `ft-manifest`) or the
/// runtime is shutting down; it is surfaced as an IO error because [`EngineError`]
/// has no join variant and a commit must keep one error type.
async fn build_manifest_off_task(
    entries: Vec<(CasefoldKey, FileEntry)>,
) -> Result<ft_manifest::ManifestBuild> {
    tokio::task::spawn_blocking(move || ft_manifest::build(entries))
        .await
        .map_err(|e| EngineError::Io(std::io::Error::other(format!("manifest build task: {e}"))))
}

impl SpaceContext {
    /// Runs the §7 commit protocol against `expected_base` (the Revision id the
    /// caller believes is the current head; `None` for the very first commit).
    ///
    /// Returns [`CommitOutcome::NoChange`] when the tree matches the synced base,
    /// [`CommitOutcome::Conflict`] when the CAS fails, or
    /// [`CommitOutcome::Committed`] on success (after advancing the local base).
    pub async fn commit(&mut self, expected_base: Option<RevisionId>) -> Result<CommitOutcome> {
        // What the last published Revision says this Space contains. Read BEFORE
        // the scan because the scan verifies every entry it did not produce itself
        // against it (`scan_with_base`): no Manifest this commit publishes may
        // reference a Block that is neither uploaded by this very commit nor
        // already reachable from the head.
        let base = self.base_manifest_view().await?;

        // How much tree this Device knew about BEFORE the scan, for the
        // mass-delete guard below. `scan` reconciles the index with disk by
        // deleting the rows of vanished paths (`scan.rs`) — the very evidence the
        // guard needs — so the count is taken first AND the scan holds those rows
        // back whenever dropping them would be a mass delete, which is what makes
        // this baseline survive into the next commit (see `guard_mass_delete`).
        let tracked_before = self.tracked_entry_count()?;

        // (a) scan the tree → FileEntries + Blocks to upload.
        let mut scan = self.scan_with_base(Some(&base))?;

        // Build the Manifest once, up front, so we know the root before any
        // upload. Pure, but O(tree) CBOR + hashing, so it runs on the blocking
        // pool: every Space of this Device shares ONE task (see
        // `build_manifest_off_task`). `entries` is MOVED out of the scan — it is
        // not read again on this path (only `blocks_to_upload`/`sidecars` are) and
        // a whole-tree clone is exactly the cost we are trying not to pay.
        let entry_count = scan.entries.len();
        let manifest = build_manifest_off_task(std::mem::take(&mut scan.entries)).await?;
        let root = manifest.root;

        // NoChange: only when there IS a prior sync (seq >= 0) and the tree's
        // root equals the synced base root. A brand-new Space (seq < 0) always
        // commits its first Revision, even when empty.
        if self.last_synced.seq >= 0 && root == self.last_synced.root {
            return Ok(CommitOutcome::NoChange);
        }

        // Refuse to publish a Revision that wipes the tree out (a root that is not
        // really there), unless the user authorized it. Deliberately AFTER the
        // NoChange check — an unchanged tree deletes nothing — and BEFORE any
        // upload, so a refusal costs no Vault traffic.
        let mass_delete_authorized = self.guard_mass_delete(tracked_before, entry_count)?;

        // (b)/(c)/(d) stage everything to the Vault (Blocks, then pages +
        // blocklists). INVARIANT after this: everything is in the Vault, nothing
        // in Convex yet (§7).
        let strategy = if self.last_synced.seq < 0 {
            UploadStrategy::Initial
        } else {
            UploadStrategy::VerifyPresence
        };
        self.upload_blocks(&scan, strategy).await?;
        self.upload_manifest(&manifest).await?;

        // (e) the atomic Space-head CAS. A context mounted only for staging has
        // no Coordinator — committing then is a usage error, not a sync failure.
        let space_id = self.space_id.clone();
        let device_id = self.device_id.clone();
        let coordinator = self.coordinator.as_mut().ok_or_else(|| {
            EngineError::SpaceState(
                "commit requires a Coordinator; this context was mounted for staging only"
                    .to_string(),
            )
        })?;
        let outcome = coordinator
            .commit_revision(&space_id, expected_base.as_ref(), &root, &device_id)
            .await;

        match outcome {
            Ok(ok) => {
                let seq = ok.seq as i64;
                // Advance the local base and persist it (§9). Also remember the
                // new head's RevisionId as the next commit's expected_base (§7).
                self.last_synced = LastSynced { seq, root };
                self.last_synced_revision_id = Some(ok.revision_id.clone());
                self.persist_space_state()?;
                // The Revision that carries the shrink has landed, so the rows the
                // scan held back as the guard's evidence have served their purpose
                // (`ScanResult::held_deletions`). Purging them now is what stops the
                // NEXT commit from refusing a wipe that is already published.
                self.purge_held_deletions(&scan.held_deletions);
                // The authorization is spent only now that the mass delete really
                // landed: consuming it earlier would leave a transient CAS/Vault
                // failure unable to retry its own commit.
                if mass_delete_authorized {
                    self.consume_mass_delete_authorization();
                }
                Ok(CommitOutcome::Committed { seq, root })
            }
            Err(CommitError::Conflict) => {
                // Best-effort fetch of the current head so Part 2 can reconcile;
                // never mask the conflict with a secondary lookup failure.
                let current_head = match self.coordinator.as_mut() {
                    Some(c) => c
                        .get_space(&self.space_id)
                        .await
                        .ok()
                        .and_then(|s| s.head_revision_id),
                    None => None,
                };
                Ok(CommitOutcome::Conflict { current_head })
            }
            Err(CommitError::Other(e)) => Err(EngineError::Coordinator(e)),
        }
    }

    /// Runs the Vault-side of a commit WITHOUT the Coordinator CAS: scan, build
    /// the Manifest, then upload Blocks and Manifest pages/blocklists (`§7` steps
    /// 1–4). A fresh Space uses direct PUTs; a synced Space uses HEAD-before-PUT.
    /// Returns a [`StagedCommit`] describing what landed in the Vault.
    ///
    /// This is the network-free core that [`SpaceContext::commit`] wraps with the
    /// CAS; it is also the staging step Part 2 can reuse. It does NOT short-circuit
    /// on NoChange (that decision belongs to `commit`, which owns the base state).
    pub async fn stage_to_vault(&self) -> Result<StagedCommit> {
        // Same base-verified scan as `commit`: this stage produces the exact
        // Manifest a CAS would publish, so it must not reference a Block that only
        // the local index believes in (`scan_with_base`).
        let base = self.base_manifest_view().await?;
        let scan = self.scan_with_base(Some(&base))?;
        // The returned `StagedCommit` hands the caller the scan back, so the
        // entries are cloned here rather than moved (unlike `commit`); the build
        // itself still runs off the async task.
        let manifest = build_manifest_off_task(scan.entries.clone()).await?;
        let strategy = if self.last_synced.seq < 0 {
            UploadStrategy::Initial
        } else {
            UploadStrategy::VerifyPresence
        };
        let blocks_uploaded = self.upload_blocks(&scan, strategy).await?;
        self.upload_manifest(&manifest).await?;
        Ok(StagedCommit {
            root: manifest.root,
            pages: manifest.pages.len(),
            blocklists: manifest.blocklists.len(),
            blocks_uploaded,
            scan,
        })
    }

    /// The entries of the last PUBLISHED Revision (`last_synced`), which
    /// [`scan_with_base`](SpaceContext::scan_with_base) proves this commit's reused
    /// and republished entries against.
    ///
    /// Empty — never a Vault read — for a Space with no published Revision yet
    /// (`seq < 0`) or whose base is still the empty Manifest: the object of the
    /// empty root must never be required (see `pull::empty_manifest_root`), and an
    /// empty base is exactly right anyway, since nothing has been published and no
    /// row can be proved by it.
    ///
    /// This costs one page-tree read per commit. It replaces per-Block `HEAD`s for
    /// unchanged files — O(pages) instead of O(Blocks) round trips — so it keeps
    /// the fast path's win while restoring the invariant `gc.rs` depends on.
    async fn base_manifest_view(&self) -> Result<crate::scan::BaseEntries> {
        if self.last_synced.seq < 0 || self.last_synced.root == crate::pull::empty_manifest_root() {
            return Ok(crate::scan::BaseEntries::new());
        }
        self.read_manifest_entries(&self.last_synced.root).await
    }

    /// Drops the index rows a scan held back as the mass-delete guard's evidence
    /// ([`ScanResult::held_deletions`](crate::ScanResult)), now that the Revision
    /// carrying those deletions is published.
    ///
    /// Best-effort, like [`consume_mass_delete_authorization`](Self::consume_mass_delete_authorization):
    /// the Revision already landed, and failing the commit over a leftover row would
    /// be strictly worse than the (logged) cost of the next commit re-refusing a
    /// wipe that is already public — which the user can clear with the same
    /// authorization marker.
    fn purge_held_deletions(&self, paths: &[ft_core::CanonicalPath]) {
        for path in paths {
            if let Err(e) = self.index.delete_entry(self.space_id.as_str(), path) {
                tracing::warn!(
                    error = %e,
                    path = %path.as_str(),
                    "could not drop the index row of a path this Revision deleted; the \
                     mass-delete guard may refuse the next commit until it is cleared"
                );
            }
        }
    }

    /// How many paths the local index tracks for this Space that WOULD appear in a
    /// Manifest — the baseline for [`guard_mass_delete`](Self::guard_mass_delete).
    ///
    /// Membership mirrors the scan's rule (`§5.1`, ADR 0019) via the shared
    /// [`tracked_in_manifest`](crate::scan::tracked_in_manifest): a local-only
    /// symlink is NOT in the Manifest, while a Derived path IS (it is `local_only`
    /// in the index only because its bytes never travel).
    ///
    /// Counting ROWS rather than the base Manifest's entries is deliberate: the
    /// count must be available before the scan and without a network read, and it
    /// stays truthful across scans because a scan that would drop most of these rows
    /// keeps them instead ([`ScanResult::held_deletions`](crate::ScanResult)).
    fn tracked_entry_count(&self) -> Result<usize> {
        Ok(self
            .index
            .list_entries(self.space_id.as_str())?
            .iter()
            .filter(|e| crate::scan::tracked_in_manifest(e))
            .count())
    }

    /// Refuses to publish a Revision that deletes most of the Space (`§7`).
    ///
    /// `tracked_before` is how many Manifest-tracked paths this Device knew about
    /// before the scan; `scanned` is how many the scan just found. A large NET
    /// shrink of a non-trivial tree is far more often a root that is not really
    /// there than an intentional delete: an external volume that failed to mount
    /// leaves its mountpoint as an empty directory, so the walk SUCCEEDS and finds
    /// nothing, and a Space root the user moved aside behaves the same. A commit is
    /// how a delete propagates (`§8`: a delete is an absence), so publishing that
    /// Revision would delete the files on every other Device — the safe direction is
    /// to refuse and let a human look.
    ///
    /// NET shrink, not "paths that disappeared": a rename, or a generator that
    /// rewrites a whole tree, deletes and adds in equal measure and must never trip
    /// the guard.
    ///
    /// It refuses EVERY commit that would publish the wipe, not just the first.
    /// `tracked_before` counts index rows, and the scan that runs between it and
    /// this check used to delete the rows of every vanished path — so the refusal
    /// destroyed its own evidence and the next commit (a daemon restart, a remount
    /// attempt, an intervening pull) compared 0 against 0, said nothing, and
    /// published the empty Manifest that deletes the tree on every other Device.
    /// [`scan_with_base`](SpaceContext::scan_with_base) now HOLDS those rows
    /// whenever dropping them would be a mass delete, and only a commit that really
    /// published the shrink purges them, so the baseline survives every retry.
    ///
    /// Returns whether an explicit authorization was found, so the caller can spend
    /// it only if the commit actually lands.
    fn guard_mass_delete(&self, tracked_before: usize, scanned: usize) -> Result<bool> {
        let deleted = tracked_before.saturating_sub(scanned);
        if !is_mass_delete(tracked_before, scanned) {
            return Ok(false);
        }
        let marker = self.mass_delete_marker();
        if marker.exists() {
            tracing::warn!(
                space = %self.space_id,
                deleted,
                tracked_before,
                marker = %marker.display(),
                "publishing a mass delete: authorized by the marker file (consumed on success)"
            );
            return Ok(true);
        }
        Err(EngineError::Refused(format!(
            "this commit would delete {deleted} of the {tracked_before} paths this Device tracks \
             for the Space ({}%), leaving {scanned}. That usually means the Space root is not \
             really there — an external volume that failed to mount, or a root that was moved \
             aside — so nothing was published and no other Device lost anything. Check {}; if the \
             deletion IS intended, authorize it once with: touch {}",
            deleted * 100 / tracked_before.max(1),
            self.local_root.display(),
            marker.display()
        )))
    }

    /// Path of the [`ALLOW_MASS_DELETE_FILE`] authorization for this Space.
    fn mass_delete_marker(&self) -> std::path::PathBuf {
        self.local_root
            .join(CONTROL_DIR)
            .join(ALLOW_MASS_DELETE_FILE)
    }

    /// Spends the mass-delete authorization after the Revision landed, so it can
    /// never authorize a SECOND unintended wipe. Best-effort: the Revision is
    /// already published, and failing the commit over a leftover marker would be
    /// strictly worse than the (logged) risk of one extra authorized delete.
    fn consume_mass_delete_authorization(&self) {
        let marker = self.mass_delete_marker();
        if let Err(e) = std::fs::remove_file(&marker) {
            tracing::warn!(
                error = %e,
                marker = %marker.display(),
                "could not consume the mass-delete authorization; remove it by hand or it will \
                 authorize the next one too"
            );
        }
    }

    /// §7 step 2: direct-PUT each unique scanned Block for the initial Revision;
    /// on later Revisions, `HEAD` and `PUT` only when absent. Record confirmed
    /// presence locally. Returns the number of objects actually uploaded.
    ///
    /// Later commits deliberately do NOT trust the local block index (`has_block`)
    /// to skip `HEAD`: GC (`gc.rs`) can delete a Block the index still records.
    /// The initial Revision is the safe exception: content-addressed PUT is
    /// idempotent and establishes presence directly before the CAS.
    ///
    /// The network HEAD/PUT round-trips run CONCURRENTLY (`buffer_unordered`,
    /// bounded to 16 in flight) since each Block is independent; the local index
    /// writes (`self.index.put_block`) run AFTERWARDS, sequentially, over the
    /// collected results — `ft_index` is a local SQLite handle with no benefit
    /// from concurrency and no need to share it across the fan-out. Before the
    /// fan-out, `Vault::warm` announces the exact upcoming operations so a backend
    /// with per-operation setup cost can prepare them together (ADR 0016/0020);
    /// it is a pure hint and its failure never blocks the upload.
    async fn upload_blocks(&self, scan: &ScanResult, strategy: UploadStrategy) -> Result<usize> {
        use futures::stream::{self, StreamExt, TryStreamExt};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;

        let space_id = self.space_id.as_str();

        let operation_count = if strategy == UploadStrategy::Initial {
            1
        } else {
            2
        };
        let mut warm_ops = Vec::with_capacity(
            (scan.blocks_to_upload.len() + scan.sidecars.len()) * operation_count,
        );
        for (cid, _) in &scan.blocks_to_upload {
            let key = ft_hash::block_key(cid);
            if strategy == UploadStrategy::VerifyPresence {
                warm_ops.push(ft_vault::WarmOp {
                    key: key.clone(),
                    method: ft_vault::WarmMethod::Head,
                });
            }
            warm_ops.push(ft_vault::WarmOp {
                key,
                method: ft_vault::WarmMethod::Put,
            });
        }
        for (cid, _) in &scan.sidecars {
            let key = ft_diff::keys_key(space_id, cid);
            if strategy == UploadStrategy::VerifyPresence {
                warm_ops.push(ft_vault::WarmOp {
                    key: key.clone(),
                    method: ft_vault::WarmMethod::Head,
                });
            }
            warm_ops.push(ft_vault::WarmOp {
                key,
                method: ft_vault::WarmMethod::Put,
            });
        }
        if let Err(e) = self.vault.warm(&warm_ops).await {
            tracing::debug!(error = %e, "vault warm failed for block upload; continuing without it");
        }

        let total = scan.blocks_to_upload.len();
        tracing::info!(total, "uploading blocks");
        let started = Instant::now();
        let completed = AtomicUsize::new(0);

        // HEAD, then PUT if absent, for every Block — concurrently.
        let block_results: Vec<(Cid, bool)> = stream::iter(scan.blocks_to_upload.iter())
            .map(|(cid, encoded)| {
                let completed = &completed;
                async move {
                    let key = ft_hash::block_key(cid);
                    let uploaded = match strategy {
                        UploadStrategy::Initial => {
                            self.vault.put(&key, encoded.clone()).await?;
                            true
                        }
                        UploadStrategy::VerifyPresence => {
                            if self.vault.head(&key).await? {
                                false
                            } else {
                                self.vault.put(&key, encoded.clone()).await?;
                                true
                            }
                        }
                    };
                    let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_multiple_of(25) {
                        tracing::info!(completed = n, total, "uploading blocks");
                    }
                    Result::Ok((*cid, uploaded))
                }
            })
            .buffer_unordered(BLOCK_UPLOAD_CONCURRENCY)
            .try_collect()
            .await?;

        // Sequential local-index writes over the collected network results.
        let mut uploaded = 0usize;
        for (cid, was_uploaded) in &block_results {
            self.index.put_block(space_id, cid)?;
            if *was_uploaded {
                uploaded += 1;
            }
        }
        tracing::info!(
            total,
            uploaded,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "blocks uploaded"
        );

        // Encryption ON (`alg=1`): each Block has a `keys/<space_id>/<cid>`
        // data-key sidecar to upload alongside it (`§4.5`, ADR 0015 — the sidecar
        // lives and dies with its Block). The key is scoped by THIS Space: the
        // sidecar is wrapped with the Space key, so a chunk shared with another
        // Space needs its own sidecar there. Same HEAD-before-PUT skip: the wrap
        // uses a fresh nonce each call so the bytes differ run-to-run, but it
        // unwraps to the same data key, so writing it once is enough. Empty with
        // encryption off. A new Space PUTs directly because its sidecar namespace
        // is empty; later commits retain HEAD-before-PUT. No index write here
        // (sidecars are not tracked in the Block-presence table).
        let sidecar_total = scan.sidecars.len();
        tracing::info!(total = sidecar_total, "uploading key sidecars");
        let sidecar_started = Instant::now();
        let sidecars_completed = AtomicUsize::new(0);

        stream::iter(scan.sidecars.iter())
            .map(|(cid, sidecar)| {
                let sidecars_completed = &sidecars_completed;
                async move {
                    let key = ft_diff::keys_key(space_id, cid);
                    match strategy {
                        UploadStrategy::Initial => {
                            self.vault.put(&key, sidecar.clone()).await?;
                        }
                        UploadStrategy::VerifyPresence => {
                            if !self.vault.head(&key).await? {
                                self.vault.put(&key, sidecar.clone()).await?;
                            }
                        }
                    }
                    let n = sidecars_completed.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_multiple_of(25) {
                        tracing::info!(
                            completed = n,
                            total = sidecar_total,
                            "uploading key sidecars"
                        );
                    }
                    Result::Ok(())
                }
            })
            .buffer_unordered(SIDECAR_UPLOAD_CONCURRENCY)
            .try_collect::<Vec<()>>()
            .await?;
        tracing::info!(
            total = sidecar_total,
            elapsed_ms = sidecar_started.elapsed().as_millis() as u64,
            "key sidecars uploaded"
        );

        Ok(uploaded)
    }

    /// §7 step 3/4: upload every Manifest page and externalized blocklist to the
    /// Vault. The blocklist object is the bare CBOR `ft_manifest` produced (no
    /// header). Each PUT must close OK before the CAS runs.
    ///
    /// `Vault::warm` announces every page/blocklist PUT in one batch first (a
    /// best-effort hint, ADR 0016); the PUTs themselves then run concurrently
    /// (`buffer_unordered`, bounded to 16) since pages and blocklists are
    /// independent content-addressed objects with no ordering requirement among
    /// themselves — only "all of them before the CAS" matters (`§7`).
    async fn upload_manifest(&self, manifest: &ft_manifest::ManifestBuild) -> Result<()> {
        use futures::stream::{self, StreamExt, TryStreamExt};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;

        let warm_ops: Vec<ft_vault::WarmOp> = manifest
            .pages
            .iter()
            .map(|(cid, _)| ft_vault::WarmOp {
                key: ft_hash::manifest_key(cid),
                method: ft_vault::WarmMethod::Put,
            })
            .chain(manifest.blocklists.iter().map(|(cid, _)| ft_vault::WarmOp {
                key: ft_hash::blocklist_key(cid),
                method: ft_vault::WarmMethod::Put,
            }))
            .collect();
        if let Err(e) = self.vault.warm(&warm_ops).await {
            tracing::debug!(error = %e, "vault warm failed for manifest upload; continuing without it");
        }

        let total = manifest.pages.len() + manifest.blocklists.len();
        tracing::info!(total, "uploading manifest pages and blocklists");
        let started = Instant::now();
        let completed = AtomicUsize::new(0);

        let objects = manifest
            .pages
            .iter()
            .map(|(cid, bytes)| (ft_hash::manifest_key(cid), bytes))
            .chain(
                manifest
                    .blocklists
                    .iter()
                    .map(|(cid, bytes)| (ft_hash::blocklist_key(cid), bytes)),
            );

        stream::iter(objects)
            .map(|(key, bytes)| {
                let completed = &completed;
                async move {
                    self.vault.put(&key, bytes.clone()).await?;
                    let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_multiple_of(25) {
                        tracing::info!(
                            completed = n,
                            total,
                            "uploading manifest pages and blocklists"
                        );
                    }
                    Result::Ok(())
                }
            })
            .buffer_unordered(16)
            .try_collect::<Vec<()>>()
            .await?;

        tracing::info!(
            total,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "manifest uploaded"
        );
        Ok(())
    }

    /// Creates a brand-new Space and commits its first Revision (`seq` 0).
    ///
    /// Generates a random per-Space `chunk_secret` (`§3`), writes the meta blob to
    /// the Vault ([`write_meta_blob`]), registers the Space with the Coordinator
    /// (`create_space`, recording the `metaBlobCid` and escrowing `crypto.space_key`,
    /// `§4.5`), persists the initial `space_state` (`§9`), assembles the
    /// [`SpaceContext`], **attaches `crypto`** so the very first Revision is written
    /// encrypted (`alg=1`, `§4.4`), and runs the first `commit(None)`.
    ///
    /// `crypto` bundles the Account `dedup_secret` and the freshly-generated
    /// per-Space `space_key`; the same `space_key` is escrowed with the Coordinator
    /// so any Device of the Account can clone the Space (see [`SpaceContext::clone_space`]).
    /// Its `space_id` field is ignored on input and overwritten with the id the
    /// Coordinator assigns (the caller cannot know it before `create_space`).
    ///
    /// On success returns the mounted context (whose `last_synced` reflects the
    /// committed first Revision). A first-commit [`CommitOutcome::Conflict`] (a
    /// racing `create_space`) surfaces as [`EngineError::SpaceState`]; an empty
    /// toy dir still commits an empty first Revision.
    #[allow(clippy::too_many_arguments)]
    pub async fn init_space(
        index: Index,
        vault: Box<dyn ft_vault::Vault>,
        coordinator: Coordinator,
        account_id: AccountId,
        device_id: DeviceId,
        name: &[u8],
        local_root: impl Into<std::path::PathBuf>,
        crypto: SpaceCrypto,
    ) -> Result<Self> {
        Self::init_space_with_fs(
            index,
            vault,
            coordinator,
            Box::new(LinuxFs),
            account_id,
            device_id,
            name,
            local_root,
            crypto,
        )
        .await
    }

    /// [`SpaceContext::init_space`] with an explicit [`OsFs`] adapter. Takes the
    /// `vault`/`coordinator` by value: they are used (meta-blob PUT, create_space)
    /// and then moved into the assembled context.
    #[allow(clippy::too_many_arguments)]
    pub async fn init_space_with_fs(
        index: Index,
        vault: Box<dyn ft_vault::Vault>,
        mut coordinator: Coordinator,
        fs: Box<dyn OsFs + Send + Sync>,
        account_id: AccountId,
        device_id: DeviceId,
        name: &[u8],
        local_root: impl Into<std::path::PathBuf>,
        mut crypto: SpaceCrypto,
    ) -> Result<Self> {
        let local_root = local_root.into();

        // (1) per-Space chunk secret + (2) meta blob → Vault → metaBlobCid.
        let chunk_secret = generate_chunk_secret();
        let meta_cid = write_meta_blob(vault.as_ref(), &chunk_secret).await?;

        // (3) register the Space with the Coordinator (head starts null),
        // escrowing the client-generated `space_key` (`§4.5`).
        let space_id: SpaceId = coordinator
            .create_space(name, &meta_cid, &crypto.space_key)
            .await?;

        // The Coordinator assigns the Space id, so the caller could not set it on
        // `crypto` up front — stamp it now so the first commit's `keys/<space_id>/
        // <cid>` sidecars land under this Space's subtree (`§4.5`).
        crypto.space_id = space_id.as_str().to_string();

        // (4) persist the initial space_state: seq = -1 marks "never synced",
        // so the first commit is never short-circuited as NoChange. The base
        // root is the empty-manifest root (a valid Cid placeholder).
        let empty_root = ft_manifest::build(Vec::new()).root;
        let state = SpaceState {
            space_id: space_id.as_str().to_string(),
            last_synced_seq: -1,
            last_synced_root: empty_root,
            // No Revision committed yet (the first `commit` below sets it and
            // re-persists); `None` is the correct seed (`§7`/`§9`).
            last_synced_revision_id: None,
            chunk_secret: chunk_secret.to_vec(),
            dedup_secret: None,
            local_root_path: local_root.to_string_lossy().into_owned(),
        };
        index.upsert_space_state(&state)?;

        // Assemble the context, moving the vault + coordinator in.
        let mut ctx = Self::from_state(
            index,
            vault,
            Some(coordinator),
            fs,
            account_id,
            device_id,
            space_id,
            &state,
        )?;

        // Turn ON encryption BEFORE the first commit so seq 0 is already `alg=1`
        // (each Block encrypted + a `keys/<space_id>/<cid>` sidecar, `§4.4`/`§4.5`).
        ctx.attach_crypto(crypto);

        // (5) first commit (seq 0). expected_base = None.
        match ctx.commit(None).await? {
            CommitOutcome::Committed { .. } | CommitOutcome::NoChange => Ok(ctx),
            CommitOutcome::Conflict { .. } => Err(EngineError::SpaceState(
                "first commit conflicted (concurrent create_space?)".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ft_index::Index;

    use super::*;

    /// Mounts a Coordinator-less context over `root`, the same offline seam
    /// `tests/watch_resilience.rs` uses: everything up to the CAS runs, and the CAS
    /// itself fails with a distinctive [`EngineError::SpaceState`] — which is exactly
    /// what tells these tests "the guard let the commit through".
    fn mount(root: &Path, seq: i64) -> SpaceContext {
        let index = Index::open_in_memory().unwrap();
        let state = SpaceState {
            space_id: "space-guard".to_string(),
            last_synced_seq: seq,
            last_synced_root: ft_manifest::build(Vec::new()).root,
            last_synced_revision_id: None,
            chunk_secret: [3u8; 32].to_vec(),
            dedup_secret: None,
            local_root_path: root.to_string_lossy().into_owned(),
        };
        index.upsert_space_state(&state).unwrap();
        // The Vault lives under the control dir, which the scan never walks.
        let vault = ft_vault::FsVault::new(root.join(CONTROL_DIR).join("vault"));
        SpaceContext::mount(
            index,
            Box::new(vault),
            Box::new(LinuxFs),
            AccountId::new("acct"),
            DeviceId::new("devA"),
            SpaceId::new("space-guard"),
        )
        .unwrap()
    }

    /// Writes `n` files into `root`, PUBLISHES them (stages every Block and
    /// Manifest page into this mount's Vault) and makes that tree the synced base —
    /// the state a Device is in before its root goes missing. Staging rather than
    /// merely scanning is what makes the base a real published Revision, which is
    /// what the next scan verifies its entries against.
    async fn populate_and_publish(ctx: &mut SpaceContext, root: &Path, n: usize) {
        for i in 0..n {
            std::fs::write(root.join(format!("f{i}.txt")), format!("body {i}")).unwrap();
        }
        let staged = ctx.stage_to_vault().await.unwrap();
        assert_eq!(staged.scan.entries.len(), n);
        ctx.last_synced = LastSynced {
            seq: 0,
            root: staged.root,
        };
    }

    fn remove_all(root: &Path) {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().and_then(|n| n.to_str()) != Some(CONTROL_DIR) {
                std::fs::remove_file(path).unwrap();
            }
        }
    }

    /// THE guard: a Space root that is not really there (an external volume that
    /// failed to mount leaves an EMPTY mountpoint, so the walk succeeds and finds
    /// nothing) must not publish a Revision that deletes the whole tree — which is
    /// how every other Device would then delete its copies (`§8`: a delete is an
    /// absence). Nothing is uploaded and nothing is published.
    #[tokio::test]
    async fn commit_refuses_to_publish_a_revision_that_wipes_a_non_trivial_tree() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = mount(dir.path(), 0);
        populate_and_publish(&mut ctx, dir.path(), DELETE_GUARD_MIN_ENTRIES + 10).await;
        remove_all(dir.path());

        match ctx.commit(None).await {
            Err(EngineError::Refused(msg)) => {
                assert!(
                    msg.contains(ALLOW_MASS_DELETE_FILE),
                    "the message must say how to proceed: {msg}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The refusal must survive its own scan. The guard's baseline is the tracked
    /// index rows, and the scan that runs just before it used to DELETE the row of
    /// every vanished path — so the first commit refused and destroyed the evidence,
    /// and the retry (a daemon restart, a remount attempt, an intervening pull,
    /// anything) saw 0 tracked vs 0 scanned, said nothing, and published the empty
    /// Manifest that deletes the tree on every other Device. Every commit after the
    /// wipe-scan must refuse exactly like the first.
    #[tokio::test]
    async fn every_commit_after_the_wipe_scan_is_refused_too_not_just_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = mount(dir.path(), 0);
        populate_and_publish(&mut ctx, dir.path(), DELETE_GUARD_MIN_ENTRIES + 10).await;
        remove_all(dir.path());

        for attempt in 1..=3 {
            match ctx.commit(None).await {
                Err(EngineError::Refused(msg)) => assert!(
                    msg.contains(ALLOW_MASS_DELETE_FILE),
                    "attempt {attempt} must still say how to proceed: {msg}"
                ),
                other => panic!("attempt {attempt} must be refused too, got {other:?}"),
            }
            assert_eq!(
                ctx.tracked_entry_count().unwrap(),
                DELETE_GUARD_MIN_ENTRIES + 10,
                "attempt {attempt} scanned away the very baseline the next one needs"
            );
        }

        // And the escape hatch still works: the user authorizes the wipe once, and
        // the commit runs all the way to the CAS (which this Coordinator-less mount
        // then rejects).
        let marker = ctx.mass_delete_marker();
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, b"").unwrap();
        match ctx.commit(None).await {
            Err(EngineError::SpaceState(_)) => {}
            other => panic!("the authorization must let the commit through, got {other:?}"),
        }
    }

    /// Clearing out a handful of files is ordinary work and must never need an
    /// override: the guard stays out of the way and the commit runs all the way to
    /// the CAS (which this Coordinator-less mount then rejects).
    #[tokio::test]
    async fn clearing_a_trivial_tree_needs_no_authorization() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = mount(dir.path(), 0);
        populate_and_publish(&mut ctx, dir.path(), 5).await;
        remove_all(dir.path());

        match ctx.commit(None).await {
            Err(EngineError::SpaceState(_)) => {}
            other => panic!("the guard must not fire on a trivial tree, got {other:?}"),
        }
    }

    /// A genuinely empty Space still commits: with nothing tracked there is nothing
    /// to delete, so the guard is silent even at seq -1 (the first Revision of a new
    /// Space, which `init_space` publishes from a possibly-empty folder).
    #[tokio::test]
    async fn a_genuinely_empty_space_still_commits() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = mount(dir.path(), -1);
        match ctx.commit(None).await {
            Err(EngineError::SpaceState(_)) => {}
            other => panic!("an empty first commit must reach the CAS, got {other:?}"),
        }
    }

    /// The marker file authorizes the wipe — and survives a commit that did NOT land
    /// (here the CAS is unreachable), so the retry still has its authorization. It is
    /// spent only by a Revision that really published, which needs a live Coordinator
    /// (covered by the E2E runbook, like the other CAS-dependent behaviors).
    #[tokio::test]
    async fn the_marker_file_authorizes_a_mass_delete_and_survives_a_commit_that_did_not_land() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = mount(dir.path(), 0);
        populate_and_publish(&mut ctx, dir.path(), DELETE_GUARD_MIN_ENTRIES + 10).await;
        remove_all(dir.path());

        let marker = ctx.mass_delete_marker();
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, b"").unwrap();

        match ctx.commit(None).await {
            Err(EngineError::SpaceState(_)) => {}
            other => panic!("the authorization must let the commit reach the CAS, got {other:?}"),
        }
        assert!(
            marker.exists(),
            "an unpublished commit must keep its authorization, or the retry is refused"
        );
    }

    /// The threshold itself: only a LARGE shrink of a NON-TRIVIAL tree is refused.
    /// Deleting a directory of build output (even most of the tree) stays legal;
    /// losing ~everything does not. Net shrink, so a rename — which deletes and adds
    /// in equal measure — can never trip it.
    #[tokio::test]
    async fn the_delete_guard_fires_only_on_a_large_shrink_of_a_non_trivial_tree() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = mount(dir.path(), 0);
        // (tracked_before, scanned, refused?)
        let cases = [
            (5_000, 0, true),      // an unmounted volume: nothing left
            (5_000, 100, true),    // a partially populated root
            (5_000, 500, true),    // exactly at the 90% bar
            (5_000, 501, false),   // just under it: a big but plausible cleanup
            (5_000, 4_999, false), // one file deleted
            (5_000, 5_000, false), // a rename: net zero
            (5_000, 6_000, false), // the tree grew
            (49, 0, false),        // a trivial tree, wiped by hand
            (60, 0, true),         // non-trivial, wiped
        ];
        for (before, scanned, refused) in cases {
            let got = ctx.guard_mass_delete(before, scanned);
            assert_eq!(
                got.is_err(),
                refused,
                "guard_mass_delete({before}, {scanned}) = {got:?}"
            );
        }
    }
}
