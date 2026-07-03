//! `clone_space` — materialize an existing Space onto a new Device
//! (`docs/format.md §6.2`, `§3`, `§8`).
//!
//! Cloning is the read-path counterpart of `init_space`: instead of creating a
//! Space it joins one that already exists. It reads the Space document to find the
//! `metaBlobCid`, loads the per-Space `chunk_secret` from that meta blob
//! ([`crate::secrets::load_meta_blob`], `§3`) — so this Device cuts files
//! identically to every other Device — persists a fresh `space_state` with NO
//! base yet, mounts the [`SpaceContext`], and [`pull`](SpaceContext::pull)s to
//! materialize the entire head tree into `local_root`.

use ft_coordinator::{AccountId, Coordinator, DeviceId, SpaceId};
use ft_core::SpaceCrypto;
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::{Index, SpaceState};

use crate::context::SpaceContext;
use crate::error::Result;
use crate::secrets::load_meta_blob;

impl SpaceContext {
    /// Clones an existing Space onto this Device and materializes its whole tree.
    ///
    /// Steps:
    /// 1. `get_space(space_id)` → the `metaBlobCid`.
    /// 2. [`load_meta_blob`] → the per-Space `chunk_secret` (`§3`).
    /// 3. Persist `space_state` with the "no base yet" convention: `seq = -1`,
    ///    `root` = the empty-Manifest root, `dedup_secret = None`.
    /// 4. Mount the [`SpaceContext`].
    /// 5. [`pull`](SpaceContext::pull) — a fast-forward from the empty base to the
    ///    head materializes every file in `local_root`.
    ///
    /// Returns the mounted, fully-materialized context (its `last_synced` now the
    /// head). Uses the default [`LinuxFs`]; see [`SpaceContext::clone_space_with_fs`]
    /// to inject another adapter.
    ///
    /// `dedup_secret` is the caller's per-Account escrow secret (`§4.4`, from
    /// `ensure_device`). Combined with the `space_key` the Coordinator returns in
    /// the Space document, it lets this Device decrypt `alg=1` Blocks while
    /// materializing. A legacy Space with no escrowed `space_key` stays on the
    /// cleartext (`alg=0`) path — `dedup_secret` is then unused.
    #[allow(clippy::too_many_arguments)]
    pub async fn clone_space(
        index: Index,
        vault: Box<dyn ft_vault::Vault>,
        coordinator: Coordinator,
        account_id: AccountId,
        device_id: DeviceId,
        space_id: SpaceId,
        local_root: impl Into<std::path::PathBuf>,
        dedup_secret: [u8; 32],
    ) -> Result<Self> {
        Self::clone_space_with_fs(
            index,
            vault,
            coordinator,
            Box::new(LinuxFs),
            account_id,
            device_id,
            space_id,
            local_root,
            dedup_secret,
        )
        .await
    }

    /// [`SpaceContext::clone_space`] with an explicit [`OsFs`] adapter.
    #[allow(clippy::too_many_arguments)]
    pub async fn clone_space_with_fs(
        index: Index,
        vault: Box<dyn ft_vault::Vault>,
        mut coordinator: Coordinator,
        fs: Box<dyn OsFs + Send + Sync>,
        account_id: AccountId,
        device_id: DeviceId,
        space_id: SpaceId,
        local_root: impl Into<std::path::PathBuf>,
        dedup_secret: [u8; 32],
    ) -> Result<Self> {
        let local_root = local_root.into();
        std::fs::create_dir_all(&local_root).map_err(crate::error::EngineError::Io)?;

        // (1)/(2) read the Space doc, then the chunk secret from its meta blob.
        let space = coordinator.get_space(&space_id).await?;
        let chunk_secret = load_meta_blob(vault.as_ref(), &space.meta_blob_cid).await?;
        // The escrowed per-Space key (if any) turns ON `alg=1` decryption below.
        let space_key = space.space_key;

        // (3) persist the "no base yet" space_state: seq = -1, empty-Manifest root.
        // The first pull's `ensure_empty_root_present` uploads the empty page so
        // the diff can start from it (the head was committed by init_space, which
        // never uploads the empty page).
        let empty_root = ft_manifest::build(Vec::new()).root;
        let state = SpaceState {
            space_id: space_id.as_str().to_string(),
            last_synced_seq: -1,
            last_synced_root: empty_root,
            // "No base yet": the `pull` in step (5) fast-forwards to the head and
            // persists the real Revision id via `advance_base_to` (`§9`).
            last_synced_revision_id: None,
            chunk_secret: chunk_secret.to_vec(),
            dedup_secret: None,
            local_root_path: local_root.to_string_lossy().into_owned(),
        };
        index.upsert_space_state(&state)?;

        // (4) mount the context with the live Coordinator.
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

        // Turn ON `alg=1` decryption BEFORE the pull materializes the tree: an
        // escrowed `space_key` + the Account `dedup_secret` let `materialize`
        // unwrap each Block's data key from its `keys/<space_id>/<cid>` sidecar
        // (`§4.5`). A legacy Space without a `space_key` stays on the cleartext
        // path.
        if let Some(space_key) = space_key {
            let space_id = ctx.space_id.as_str().to_string();
            ctx.attach_crypto(SpaceCrypto {
                dedup_secret,
                space_key,
                space_id,
            });
        }

        // (5) pull: fast-forward from the empty base to the head materializes the
        // whole tree. With an empty local dir there are never local changes, so
        // this is always a fast-forward (or UpToDate for an empty Space).
        ctx.pull().await?;
        Ok(ctx)
    }
}
