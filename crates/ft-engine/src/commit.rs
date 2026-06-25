//! `commit` — the exact commit protocol of `docs/format.md §7`, plus
//! [`SpaceContext::init_space`] for creating a fresh Space.
//!
//! [`SpaceContext::commit`] runs the strict §7 order:
//!
//! 1. **scan** ([`SpaceContext::scan`]).
//! 2. **dedup + upload Blocks**: for each unique `(cid, bytes)`, skip when the
//!    index already records the Block or the Vault `HEAD`s it present; otherwise
//!    `PUT` the encoded object and record it locally. (`HEAD` before `PUT` saves
//!    bandwidth, `§7` step 2.)
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
use ft_core::Cid;
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::{Index, SpaceState};

use crate::context::{LastSynced, SpaceContext};
use crate::error::{EngineError, Result};
use crate::scan::ScanResult;
use crate::secrets::{generate_chunk_secret, write_meta_blob};

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

impl SpaceContext {
    /// Runs the §7 commit protocol against `expected_base` (the Revision id the
    /// caller believes is the current head; `None` for the very first commit).
    ///
    /// Returns [`CommitOutcome::NoChange`] when the tree matches the synced base,
    /// [`CommitOutcome::Conflict`] when the CAS fails, or
    /// [`CommitOutcome::Committed`] on success (after advancing the local base).
    pub async fn commit(&mut self, expected_base: Option<RevisionId>) -> Result<CommitOutcome> {
        // (a) scan the tree → FileEntries + Blocks to upload.
        let scan = self.scan()?;

        // Build the Manifest once, up front, so we know the root before any
        // upload. Cheap (pure) and lets us short-circuit on NoChange.
        let manifest = ft_manifest::build(scan.entries.clone());
        let root = manifest.root;

        // NoChange: only when there IS a prior sync (seq >= 0) and the tree's
        // root equals the synced base root. A brand-new Space (seq < 0) always
        // commits its first Revision, even when empty.
        if self.last_synced.seq >= 0 && root == self.last_synced.root {
            return Ok(CommitOutcome::NoChange);
        }

        // (b)/(c)/(d) stage everything to the Vault (Blocks, then pages +
        // blocklists). INVARIANT after this: everything is in the Vault, nothing
        // in Convex yet (§7).
        self.upload_blocks(&scan).await?;
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
    /// the Manifest, then upload Blocks (HEAD-before-PUT dedup) and Manifest
    /// pages/blocklists (`§7` steps 1–4). Returns a [`StagedCommit`] describing
    /// what landed in the Vault.
    ///
    /// This is the network-free core that [`SpaceContext::commit`] wraps with the
    /// CAS; it is also the staging step Part 2 can reuse. It does NOT short-circuit
    /// on NoChange (that decision belongs to `commit`, which owns the base state).
    pub async fn stage_to_vault(&self) -> Result<StagedCommit> {
        let scan = self.scan()?;
        let manifest = ft_manifest::build(scan.entries.clone());
        let blocks_uploaded = self.upload_blocks(&scan).await?;
        self.upload_manifest(&manifest).await?;
        Ok(StagedCommit {
            root: manifest.root,
            pages: manifest.pages.len(),
            blocklists: manifest.blocklists.len(),
            blocks_uploaded,
            scan,
        })
    }

    /// §7 step 2: for each unique scanned Block, skip when the index already has
    /// it or the Vault `HEAD`s it present; otherwise `PUT` the encoded object and
    /// record it locally. Returns the number of objects actually uploaded.
    async fn upload_blocks(&self, scan: &ScanResult) -> Result<usize> {
        let space_id = self.space_id.as_str();
        let mut uploaded = 0usize;
        for (cid, encoded) in &scan.blocks_to_upload {
            let key = ft_hash::block_key(cid);
            // Already known locally? Skip without a network round-trip.
            if self.index.has_block(space_id, cid)? {
                continue;
            }
            // Otherwise HEAD the Vault before PUT (§7 step 2).
            if self.vault.head(&key).await? {
                // Present remotely but not in our local index: record it.
                self.index.put_block(space_id, cid)?;
                continue;
            }
            self.vault.put(&key, encoded.clone()).await?;
            self.index.put_block(space_id, cid)?;
            uploaded += 1;
        }
        Ok(uploaded)
    }

    /// §7 step 3/4: upload every Manifest page and externalized blocklist to the
    /// Vault. The blocklist object is the bare CBOR `ft_manifest` produced (no
    /// header). Each PUT must close OK before the CAS runs.
    async fn upload_manifest(&self, manifest: &ft_manifest::ManifestBuild) -> Result<()> {
        for (page_cid, page_bytes) in &manifest.pages {
            self.vault
                .put(&ft_hash::manifest_key(page_cid), page_bytes.clone())
                .await?;
        }
        for (bl_cid, bl_bytes) in &manifest.blocklists {
            self.vault
                .put(&ft_hash::blocklist_key(bl_cid), bl_bytes.clone())
                .await?;
        }
        Ok(())
    }

    /// Creates a brand-new Space and commits its first Revision (`seq` 0).
    ///
    /// Generates a random per-Space `chunk_secret` (`§3`), writes the meta blob to
    /// the Vault ([`write_meta_blob`]), registers the Space with the Coordinator
    /// (`create_space`, recording the `metaBlobCid`), persists the initial
    /// `space_state` (`§9`), assembles the [`SpaceContext`] and runs the first
    /// `commit(None)`.
    ///
    /// On success returns the mounted context (whose `last_synced` reflects the
    /// committed first Revision). A first-commit [`CommitOutcome::Conflict`] (a
    /// racing `create_space`) surfaces as [`EngineError::SpaceState`]; an empty
    /// toy dir still commits an empty first Revision.
    pub async fn init_space(
        index: Index,
        vault: Box<dyn ft_vault::Vault>,
        coordinator: Coordinator,
        account_id: AccountId,
        device_id: DeviceId,
        name: &[u8],
        local_root: impl Into<std::path::PathBuf>,
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
    ) -> Result<Self> {
        let local_root = local_root.into();

        // (1) per-Space chunk secret + (2) meta blob → Vault → metaBlobCid.
        let chunk_secret = generate_chunk_secret();
        let meta_cid = write_meta_blob(vault.as_ref(), &chunk_secret).await?;

        // (3) register the Space with the Coordinator (head starts null).
        let space_id: SpaceId = coordinator
            .create_space(&account_id, name, &meta_cid)
            .await?;

        // (4) persist the initial space_state: seq = -1 marks "never synced",
        // so the first commit is never short-circuited as NoChange. The base
        // root is the empty-manifest root (a valid Cid placeholder).
        let empty_root = ft_manifest::build(Vec::new()).root;
        let state = SpaceState {
            space_id: space_id.as_str().to_string(),
            last_synced_seq: -1,
            last_synced_root: empty_root,
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

        // (5) first commit (seq 0). expected_base = None.
        match ctx.commit(None).await? {
            CommitOutcome::Committed { .. } | CommitOutcome::NoChange => Ok(ctx),
            CommitOutcome::Conflict { .. } => Err(EngineError::SpaceState(
                "first commit conflicted (concurrent create_space?)".to_string(),
            )),
        }
    }
}
