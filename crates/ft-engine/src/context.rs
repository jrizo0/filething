//! [`SpaceContext`] — the handle to one Space mounted on this Device.
//!
//! Bundles everything the write path (`scan` + `commit`, `§7`) needs: the local
//! [`Index`](ft_index::Index), the [`Vault`], the [`Coordinator`], the
//! [`OsFs`](ft_fsmap::OsFs) adapter, the per-Space FastCDC `chunk_secret` and its
//! derived [`Chunker`], the identity ids, the local root folder and the
//! `last_synced` base (`seq` + `root`) read from `space_state` (`§9`).
//!
//! Constructors:
//! - [`SpaceContext::open`] mounts an EXISTING Space whose `space_state` row is
//!   already persisted (it loads `chunk_secret` and the `last_synced` base).
//! - [`SpaceContext::init_space`](crate::SpaceContext::init_space) (in
//!   `commit.rs`) creates a brand-new Space.

use std::path::PathBuf;
use std::sync::Arc;

use ft_chunker::Chunker;
use ft_coordinator::{AccountId, Coordinator, DeviceId, RevisionId, SpaceId};
use ft_core::{Cid, SpaceCrypto};
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::{Index, SpaceState};
use ft_vault::Vault;
use ft_watcher::AppliedState;

use crate::error::{EngineError, Result};

/// The last Revision this Device synced for the Space: its `seq` and the
/// `manifestRoot` it pointed at (the base for the next diff/commit, `§7`/`§9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastSynced {
    /// `seq` of the base Revision (`space_state.last_synced_seq`).
    pub seq: i64,
    /// `manifestRoot` of that base Revision (`space_state.last_synced_root`).
    pub root: Cid,
}

/// A Space mounted on this Device: the unit the engine commits and (Part 2)
/// pulls. Construct with [`SpaceContext::open`] for an existing Space or
/// [`SpaceContext::init_space`](crate::SpaceContext::init_space) for a new one.
pub struct SpaceContext {
    /// Local SQLite index (`§9`).
    pub index: Index,
    /// The data-plane object store (`§6.1`).
    pub vault: Box<dyn Vault>,
    /// The control-plane client (`§6.2`). `None` for a context mounted only for
    /// scanning / staging to the Vault (no live control plane); `Some` for one
    /// that can [`commit`](SpaceContext::commit). A `Coordinator` cannot be built
    /// offline, so `scan`/`stage_to_vault` deliberately do not require one.
    pub coordinator: Option<Coordinator>,
    /// Host filesystem adapter (`§5.2`); `Send + Sync` so the context can move
    /// across tasks.
    pub fs: Box<dyn OsFs + Send + Sync>,
    /// Per-Space FastCDC chunk secret (`§3`). Identical on every Device.
    pub chunk_secret: [u8; 32],
    /// Chunker derived from [`Self::chunk_secret`] (`Chunker::new`).
    pub chunker: Chunker,
    /// Owning Account.
    pub account_id: AccountId,
    /// This Device.
    pub device_id: DeviceId,
    /// The Space being synced.
    pub space_id: SpaceId,
    /// Local folder mapped one-to-one to this Space.
    pub local_root: PathBuf,
    /// Base Revision of the last successful sync (`§9`).
    pub last_synced: LastSynced,
    /// The `RevisionId` of the synced base, when known — the `expected_base` for
    /// the next commit's CAS (`§7`). It is NOT persisted in `space_state` (which
    /// keeps only `seq`/`root`); it is filled in as the engine learns it: from a
    /// successful [`commit`](SpaceContext::commit), a [`pull`](SpaceContext::pull),
    /// or a head read. `None` means "no base committed yet" (a fresh Space or a
    /// freshly reopened Device whose head id has not yet been resolved).
    pub last_synced_revision_id: Option<RevisionId>,
    /// Echo-suppression marks shared with the [`Watcher`](ft_watcher::Watcher)
    /// when the [`run`](SpaceContext::run) loop is active (`§9`). [`pull`] records
    /// every file it materializes here so the watcher event it triggers is
    /// recognized as our own write and not re-committed. `None` for a one-shot
    /// pull/clone with no watcher (marking is then a harmless no-op).
    pub applied: Option<Arc<AppliedState>>,
    /// Runtime encryption key material for this Space (`§4.4`/`§4.5`). `None`
    /// (the default) ⇒ Blocks ship in cleartext (`alg=0`) and NOTHING about the
    /// scan/commit/pull behavior changes. `Some` ⇒ each scanned Block is encrypted
    /// (`alg=1`) with a `keys/<space_id>/<cid>` sidecar on commit, and each `alg=1` Block is
    /// decrypted on materialize. Set by the caller via
    /// [`attach_crypto`](SpaceContext::attach_crypto) after mounting; it is NOT
    /// persisted in `space_state` (the escrow/keyring that supplies it lives
    /// outside the engine).
    pub crypto: Option<SpaceCrypto>,
}

impl SpaceContext {
    /// Mounts an EXISTING Space: reads its `space_state` row (`§9`) to recover the
    /// `chunk_secret` and the `last_synced` base, builds the [`Chunker`], and
    /// assembles the context.
    ///
    /// The default [`LinuxFs`] adapter is used; pass a different one with
    /// [`SpaceContext::open_with_fs`]. Errors with [`EngineError::SpaceState`] if
    /// no row exists for `space_id` or its `chunk_secret` is not 32 bytes.
    pub fn open(
        index: Index,
        vault: Box<dyn Vault>,
        coordinator: Coordinator,
        account_id: AccountId,
        device_id: DeviceId,
        space_id: SpaceId,
    ) -> Result<Self> {
        Self::open_with_fs(
            index,
            vault,
            Some(coordinator),
            Box::new(LinuxFs),
            account_id,
            device_id,
            space_id,
        )
    }

    /// Like [`SpaceContext::open`] but with an explicit [`OsFs`] adapter and an
    /// optional [`Coordinator`] (so a scan/stage-only context can be mounted with
    /// `None`, or the macOS adapter / a test double injected).
    pub fn open_with_fs(
        index: Index,
        vault: Box<dyn Vault>,
        coordinator: Option<Coordinator>,
        fs: Box<dyn OsFs + Send + Sync>,
        account_id: AccountId,
        device_id: DeviceId,
        space_id: SpaceId,
    ) -> Result<Self> {
        let state = index.get_space_state(space_id.as_str())?.ok_or_else(|| {
            EngineError::SpaceState(format!(
                "no space_state for {space_id}; call init_space first"
            ))
        })?;
        Self::from_state(
            index,
            vault,
            coordinator,
            fs,
            account_id,
            device_id,
            space_id,
            &state,
        )
    }

    /// Mounts an existing Space for scanning / staging ONLY — no live control
    /// plane (`coordinator = None`). [`scan`](SpaceContext::scan) and
    /// [`stage_to_vault`](SpaceContext::stage_to_vault) work; `commit` returns an
    /// error until a [`Coordinator`] is attached. Useful offline (Gate 4) and in
    /// network-free tests.
    pub fn mount(
        index: Index,
        vault: Box<dyn Vault>,
        fs: Box<dyn OsFs + Send + Sync>,
        account_id: AccountId,
        device_id: DeviceId,
        space_id: SpaceId,
    ) -> Result<Self> {
        Self::open_with_fs(index, vault, None, fs, account_id, device_id, space_id)
    }

    /// Assembles a context from an already-loaded [`SpaceState`]. Shared by
    /// [`SpaceContext::open_with_fs`] and `init_space` (which writes the row, then
    /// builds the context from it).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_state(
        index: Index,
        vault: Box<dyn Vault>,
        coordinator: Option<Coordinator>,
        fs: Box<dyn OsFs + Send + Sync>,
        account_id: AccountId,
        device_id: DeviceId,
        space_id: SpaceId,
        state: &SpaceState,
    ) -> Result<Self> {
        let chunk_secret: [u8; 32] = state.chunk_secret.as_slice().try_into().map_err(|_| {
            EngineError::SpaceState(format!(
                "chunk_secret must be 32 bytes, got {}",
                state.chunk_secret.len()
            ))
        })?;
        let chunker = Chunker::new(&chunk_secret);
        Ok(Self {
            index,
            vault,
            coordinator,
            fs,
            chunk_secret,
            chunker,
            account_id,
            device_id,
            space_id,
            local_root: PathBuf::from(&state.local_root_path),
            last_synced: LastSynced {
                seq: state.last_synced_seq,
                root: state.last_synced_root,
            },
            // Recover the persisted head Revision id (`§9`). Without this the
            // `behind?` check in `status` always saw `None` on a fresh process and
            // reported a false "pull pending"; now a synced Device reloads its
            // real base id. `None` for a fresh/just-cloned Space or a DB migrated
            // before the column existed (filled in by the next commit/pull).
            last_synced_revision_id: state
                .last_synced_revision_id
                .as_ref()
                .map(|s| RevisionId::new(s.clone())),
            applied: None,
            // Encryption is OFF unless the caller attaches key material (§4.4).
            // Not read from `space_state`: the space_key is not persisted there.
            crypto: None,
        })
    }

    /// Attaches a shared [`AppliedState`] (the watcher's echo-suppression marks)
    /// so a subsequent [`pull`](SpaceContext::pull) records every materialized
    /// file. The [`run`](SpaceContext::run) loop calls this with the
    /// [`Watcher`](ft_watcher::Watcher)'s state; a one-shot pull/clone leaves it
    /// unset.
    pub fn attach_applied_state(&mut self, applied: Arc<AppliedState>) {
        self.applied = Some(applied);
    }

    /// Turns ON runtime `alg=1` encryption for this mounted Space by attaching the
    /// key material ([`SpaceCrypto`]: the Account `dedup_secret` + the `space_key`,
    /// `§4.4`/`§4.5`). After this call the scan encrypts each Block and produces
    /// its `keys/<space_id>/<cid>` sidecar, the commit uploads both, and materialize decrypts
    /// `alg=1` Blocks. Without it the Space stays on the cleartext (`alg=0`) path.
    /// The caller obtains the material from the escrow/keyring (outside the engine)
    /// and attaches it after [`open`](SpaceContext::open) / `init_space` /
    /// `clone_space`.
    pub fn attach_crypto(&mut self, crypto: SpaceCrypto) {
        self.crypto = Some(crypto);
    }

    /// The `expected_base` `RevisionId` is NOT stored in `space_state` (which
    /// only keeps the base `seq`/`root`). The caller passes it to
    /// [`commit`](crate::SpaceContext::commit) explicitly; Part 2 resolves it from
    /// the head subscription / `revision_by_seq`. This accessor returns the base
    /// `seq` so a caller can look the id up.
    pub fn base_seq(&self) -> i64 {
        self.last_synced.seq
    }

    /// Persists the current `last_synced` (and `chunk_secret`, `local_root`) back
    /// to `space_state`. Used after a successful commit to advance the base.
    pub(crate) fn persist_space_state(&self) -> Result<()> {
        let state = SpaceState {
            space_id: self.space_id.as_str().to_string(),
            last_synced_seq: self.last_synced.seq,
            last_synced_root: self.last_synced.root,
            // Persist the head Revision id so a later fresh process (e.g. a one-shot
            // `status`) recovers the real base instead of defaulting to `None` and
            // reporting a false "behind — pull pending" (`§7`/`§9`). Stored as the
            // raw id string to keep `ft-index` decoupled from `RevisionId`.
            last_synced_revision_id: self
                .last_synced_revision_id
                .as_ref()
                .map(|r| r.as_str().to_string()),
            chunk_secret: self.chunk_secret.to_vec(),
            dedup_secret: None, // cleartext MVP: cid == pcid, no dedup secret (§4.4).
            local_root_path: self.local_root.to_string_lossy().into_owned(),
        };
        self.index.upsert_space_state(&state)?;
        Ok(())
    }

    /// Reads EVERY [`FileEntry`](ft_core::FileEntry) of the Manifest rooted at
    /// `root` into a `casefold_key -> FileEntry` map by walking the B-tree pages
    /// directly (`§5.3`).
    ///
    /// This is the "read the base/remote Manifest" primitive the three-way
    /// reconcile needs (`§10`). It downloads pages (no hash pruning) because
    /// reconcile must see whole entries by path; for the toy MVP trees this is
    /// cheap. The empty-Manifest root yields an empty map.
    pub(crate) async fn read_manifest_entries(
        &self,
        root: &Cid,
    ) -> Result<std::collections::HashMap<ft_core::CasefoldKey, ft_core::FileEntry>> {
        use ft_manifest::{decode_page, Page};
        let mut out = std::collections::HashMap::new();
        let mut stack = vec![*root];
        while let Some(cid) = stack.pop() {
            let obj = self.vault.get(&ft_hash::manifest_key(&cid)).await?;
            match decode_page(&obj)? {
                Page::Leaf(leaf) => {
                    for entry in leaf.e {
                        let key = ft_fsmap::casefold_key(&entry.p);
                        out.insert(key, entry);
                    }
                }
                Page::Index(index) => {
                    for child in index.children {
                        stack.push(child.cid);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Records an echo-suppression mark for the file just materialized at
    /// canonical `path`: reads the REAL on-disk `mtime` and uses `pcid`, so the
    /// resulting watcher event is recognized as our own write and not re-committed
    /// (`§9`). A no-op when no [`AppliedState`] is attached (one-shot pull/clone).
    pub(crate) fn mark_applied_for(&self, path: &ft_core::CanonicalPath, pcid: ft_core::Pcid) {
        if let Some(applied) = &self.applied {
            let abs = join_canonical(&self.local_root, path);
            let mtime = self
                .fs
                .real_mtime(&abs)
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            applied.mark_applied(path.clone(), mtime, pcid);
        }
    }
}

/// Joins a Space root with a canonical (forward-slash) path, segment by segment.
pub(crate) fn join_canonical(root: &std::path::Path, path: &ft_core::CanonicalPath) -> PathBuf {
    let mut dest = root.to_path_buf();
    for part in path.as_str().split('/').filter(|s| !s.is_empty()) {
        dest.push(part);
    }
    dest
}

impl std::fmt::Debug for SpaceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpaceContext")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("space_id", &self.space_id)
            .field("local_root", &self.local_root)
            .field("last_synced", &self.last_synced)
            .finish_non_exhaustive()
    }
}
