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
//!
//! A mount that can publish Revisions also takes the Space's exclusive
//! [`SpaceLock`] and holds it for the context's whole lifetime, so two processes
//! never drive one Space at once (`§9`).

use std::fs::File;
use std::path::{Path, PathBuf};
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

/// Name of the per-Space lock file inside the control dir
/// ([`CONTROL_DIR`](crate::scan::CONTROL_DIR)).
const LOCK_FILE: &str = "space.lock";

/// The exclusive advisory lock over one Space root, held for as long as the
/// [`SpaceContext`] that took it lives.
///
/// Two processes driving the same Space corrupt the tree: a one-shot `filething
/// sync` that scans while the daemon is halfway through materializing a pull sees
/// neither the old nor the new name of a renamed file, plus a
/// `.<name>`[`TMP_SUFFIX`](ft_diff::TMP_SUFFIX) scratch file — and commits THAT as
/// a Revision, which then replicates to every Device (`§7`/`§9`).
///
/// It is `flock(2)` on an open descriptor and NOT a pid file because the kernel
/// drops the lock when the holder dies: a `kill -9`d daemon leaves a lock file
/// behind but no lock, so the next process mounts normally instead of finding the
/// Space bricked. Nothing ever unlocks explicitly — closing the descriptor (that
/// is, dropping this value) IS the release.
pub(crate) struct SpaceLock {
    /// Held only for its side effect: the lock lives on this descriptor, so the
    /// lock lives exactly as long as this value.
    _file: File,
}

impl SpaceLock {
    /// Takes the Space's exclusive lock, creating `<root>/.filething/space.lock`
    /// if needed, and stamps this process into it so a contender can name the
    /// holder.
    ///
    /// Fails fast with [`EngineError::SpaceLocked`] instead of waiting: the holder
    /// that contends in practice is the daemon, which keeps its lock for its whole
    /// lifetime, so a bounded wait could only add latency to an error it cannot
    /// avoid. (It would also have to block: this is a sync fn the daemon calls
    /// inside its async task, where sleeping stalls the other Spaces.)
    pub(crate) fn acquire(root: &Path) -> Result<Self> {
        let dir = root.join(crate::scan::CONTROL_DIR);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(LOCK_FILE);
        let file = open_lock_file(&path)?;
        if try_lock_exclusive(&file)? {
            stamp_holder(&file);
            Ok(Self { _file: file })
        } else {
            Err(EngineError::SpaceLocked {
                root: root.display().to_string(),
                holder: read_holder(&path),
            })
        }
    }
}

/// Opens (or creates, `0600`) the lock file for locking.
///
/// Deliberately does NOT truncate: the current holder's identity must survive
/// until we know whether we got the lock, otherwise a contender would erase the
/// very line it is about to report.
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// `flock(LOCK_EX | LOCK_NB)`: `Ok(true)` = ours, `Ok(false)` = someone else holds
/// it, `Err` = a real failure.
#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd as _;

    // Declared here rather than pulling in a locking crate: the workspace has no
    // `libc`/`nix`/`fs2` direct dependency, and `flock` plus these two operation
    // bits are identical on the only two platforms filething ships for (Linux,
    // macOS).
    const LOCK_EX: std::os::raw::c_int = 2;
    const LOCK_NB: std::os::raw::c_int = 4;
    extern "C" {
        fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
    }

    // SAFETY: `fd` is open for the whole call (we hold `file`), and `flock` only
    // reads the two scalars it is given.
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    // EWOULDBLOCK is the contended answer, not a failure: the lock is simply held.
    if err.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(err)
    }
}

/// filething ships for macOS and Linux only, so there is no other `flock`. This
/// arm refuses rather than pretending the Space was locked: an unlocked mount that
/// believes it is locked is exactly the corruption this guard exists to prevent.
#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no Space lock implementation for this platform",
    ))
}

/// Writes `pid <n> (<exe>)` into the lock file we just locked, so the NEXT process
/// can name us in its [`EngineError::SpaceLocked`]. Best-effort: the lock itself is
/// the descriptor, never this text.
fn stamp_holder(file: &File) {
    use std::io::Write as _;
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "filething".to_string());
    let mut file = file;
    let _ = file.set_len(0);
    let _ = write!(file, "pid {} ({exe})", std::process::id());
    let _ = file.flush();
}

/// Reads the holder line a previous [`stamp_holder`] left. Truncated and defaulted
/// because it is untrusted decoration inside an error message, not data.
fn read_holder(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        // The holder locks before it stamps, so a contender can land in that window.
        return "another process".to_string();
    }
    line.chars().take(120).collect()
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
    /// A human-readable name for this Device (from `filething login --name`,
    /// cached in the CLI config), used to label conflict copies so they read
    /// `notas (conflicto <name>, seq N).md` instead of exposing the opaque
    /// [`device_id`](Self::device_id). `None` (the default) falls back to the
    /// `device_id`. Set via [`set_device_display_name`](Self::set_device_display_name);
    /// it is NOT persisted in `space_state` (the CLI plumbs it in on each mount).
    pub device_display_name: Option<String>,
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
    /// The Space's exclusive [`SpaceLock`], held until this context is dropped.
    /// `Some` for a mount that can publish Revisions, `None` for the scan-only
    /// [`mount`](SpaceContext::mount) (see [`from_state`](Self::from_state)).
    _space_lock: Option<SpaceLock>,
}

impl SpaceContext {
    /// Mounts an EXISTING Space: reads its `space_state` row (`§9`) to recover the
    /// `chunk_secret` and the `last_synced` base, builds the [`Chunker`], and
    /// assembles the context.
    ///
    /// The default [`LinuxFs`] adapter is used; pass a different one with
    /// [`SpaceContext::open_with_fs`]. Errors with [`EngineError::SpaceState`] if
    /// no row exists for `space_id` or its `chunk_secret` is not 32 bytes, and with
    /// [`EngineError::SpaceLocked`] if another process is already driving this Space
    /// — the [`SpaceLock`] this takes is held until the context is dropped.
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
    ///
    /// Takes NO [`SpaceLock`]: it cannot publish a Revision, so it is safe (and
    /// necessary — `filething status` mounts this way) alongside a daemon holding it.
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
        let local_root = PathBuf::from(&state.local_root_path);

        // A mount that can publish Revisions takes the Space's exclusive lock and
        // holds it for the context's lifetime, so `filething sync`, `clone`, `gc`
        // and the daemon can never drive one Space concurrently (`§9`, see
        // [`SpaceLock`]). Having a live Coordinator is exactly that property:
        // `open`/`init_space`/`clone_space` all pass one, and only a context with
        // one can commit or pull.
        //
        // The scan-only `mount` (Coordinator `None`) deliberately does NOT lock: it
        // never writes the tree and cannot publish anything, and `filething status`
        // mounts that way — locking it would make `status` fail exactly when the
        // daemon is doing its job.
        let space_lock = if coordinator.is_some() {
            Some(SpaceLock::acquire(&local_root)?)
        } else {
            None
        };

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
            device_display_name: None,
            local_root,
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
            _space_lock: space_lock,
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

    /// Sets the human-readable Device name used to label conflict copies
    /// ([`device_display_name`](Self::device_display_name)). The CLI calls this
    /// after mounting with the name cached in its config; `None` (or an empty
    /// string, treated the same) falls back to the opaque `device_id`.
    pub fn set_device_display_name(&mut self, name: Option<String>) {
        self.device_display_name = name.filter(|s| !s.is_empty());
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
    ///
    /// Everything it admits crosses the INBOUND trust boundary first: each page is
    /// verified against the `page_cid` that referenced it and each entry against
    /// [`FileEntry::validate_untrusted`](ft_core::FileEntry::validate_untrusted).
    /// The map this returns is the base/remote view the reconcile treats as truth,
    /// so an unchecked entry here is an unchecked write later.
    pub(crate) async fn read_manifest_entries(
        &self,
        root: &Cid,
    ) -> Result<std::collections::HashMap<ft_core::CasefoldKey, ft_core::FileEntry>> {
        use ft_manifest::{decode_page_verified, Page};
        let mut out: std::collections::HashMap<ft_core::CasefoldKey, ft_core::FileEntry> =
            std::collections::HashMap::new();
        let mut stack = vec![*root];
        while let Some(cid) = stack.pop() {
            let obj = self.vault.get(&ft_hash::manifest_key(&cid)).await?;
            // A page NAMES every other object of the tree, so substituted page bytes
            // void the integrity of all of them — it takes only a rewritten `p` to
            // aim an entry at `../../.ssh/authorized_keys`, or a dropped run of
            // entries for the reconcile to read the gap as mass deletion (`§5.3`).
            // Verification also rules out a page cycle: no page can reference itself
            // or an ancestor under content addressing, so this walk terminates.
            let page =
                decode_page_verified(&obj, &cid).map_err(|e| manifest_decode_error(&cid, e))?;
            match page {
                Page::Leaf(leaf) => {
                    for entry in leaf.e {
                        // The inbound half of the path policy (`§5.2`): a path from
                        // the Vault is untrusted input, and the reconcile joins these
                        // onto `local_root` to materialize them.
                        entry.validate_untrusted()?;
                        let key = ft_fsmap::casefold_key(&entry.p);
                        if let Some(prev) = out.get(&key) {
                            // `§5.2`: one casefold key names one entry. Inserting over
                            // the previous one would drop it from the base/remote view
                            // the three-way reconcile compares, where an absent entry
                            // means "deleted" — so a Manifest holding both `README.md`
                            // and `readme.md` (authored on a case-sensitive Device)
                            // would make the pull DELETE one of them, silently. This
                            // map cannot express two entries under one key, so refuse
                            // the whole read instead of picking a winner.
                            return Err(EngineError::Refused(format!(
                                "manifest page {cid} holds two entries with the same \
                                 case-insensitive name ({:?} and {:?}); one of them \
                                 would silently disappear on this Device, so the sync \
                                 stopped. Rename one of the two on the Device that \
                                 created them, then sync again (§5.2)",
                                prev.p.as_str(),
                                entry.p.as_str()
                            )));
                        }
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

/// Turns a Manifest-page decode failure into the error the user can act on,
/// separating "this build is too old" from "this object is corrupt".
///
/// [`ft_manifest::decode_page_verified`] checks the page against its `page_cid`
/// BEFORE decoding the payload, so a `Cbor`/`UnknownKind` failure cannot be
/// corruption: those bytes are exactly what the writer produced and hash to the
/// cid the Revision promised — we simply do not understand them. Two Devices on
/// different filething versions is a normal state (`filething update` is manual,
/// ADR 0019: a pre-Dir binary cannot decode a `t=3` entry), so that case must say
/// so instead of surfacing a bare `invalid file type: 4`.
///
/// An unknown header version is remapped for the same reason. A `PageCidMismatch`
/// or a malformed/short header is NOT: those mean substituted or damaged bytes,
/// which no update fixes.
fn manifest_decode_error(page_cid: &Cid, err: ft_manifest::ManifestError) -> EngineError {
    use ft_manifest::ManifestError as Me;
    let too_old = matches!(
        &err,
        Me::Cbor(_) | Me::UnknownKind(_) | Me::Header(ft_core::Error::UnsupportedHeaderVersion(_))
    );
    if too_old {
        EngineError::Refused(format!(
            "manifest page {page_cid} was written by a newer filething than this build \
             can read ({err}); run `filething update` on this Device, then sync again \
             (ADR 0019)"
        ))
    } else {
        EngineError::Manifest(err)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ft_core::{CanonicalPath, CasefoldKey, FileEntry, FileType, Pcid};
    use ft_vault::FsVault;

    /// A minimal File entry at `path` with no blocks — enough for the trust-boundary
    /// checks below, which only ever look at `p`/`t`.
    fn file_entry(path: &str) -> (CasefoldKey, FileEntry) {
        let p = CanonicalPath(path.to_string());
        let key = ft_fsmap::casefold_key(&p);
        let entry = FileEntry {
            p,
            t: FileType::File,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: Vec::new(),
            bk_ref: None,
            lt: None,
            wu: None,
        };
        (key, entry)
    }

    /// Uploads every page of the Manifest of `entries`; returns its root.
    async fn upload_manifest(vault: &FsVault, entries: Vec<(CasefoldKey, FileEntry)>) -> Cid {
        let m = ft_manifest::build(entries);
        for (page_cid, bytes) in &m.pages {
            vault
                .put(&ft_hash::manifest_key(page_cid), bytes.clone())
                .await
                .unwrap();
        }
        m.root
    }

    /// Mounts a scan-only context (no Coordinator, so no Space lock) over `root`.
    fn mount_scan_only(root: &Path, vault: FsVault) -> SpaceContext {
        let index = Index::open_in_memory().unwrap();
        index
            .upsert_space_state(&SpaceState {
                space_id: "sp".to_string(),
                last_synced_seq: -1,
                last_synced_root: ft_manifest::build(Vec::new()).root,
                last_synced_revision_id: None,
                chunk_secret: [0x11; 32].to_vec(),
                dedup_secret: None,
                local_root_path: root.to_string_lossy().into_owned(),
            })
            .unwrap();
        SpaceContext::mount(
            index,
            Box::new(vault),
            Box::new(LinuxFs),
            AccountId::new("acct"),
            DeviceId::new("dev"),
            SpaceId::new("sp"),
        )
        .unwrap()
    }

    // ----- read_manifest_entries: the inbound trust boundary (§5.2/§5.3) -----

    /// A page swapped for another VALID page: it decodes cleanly, so only the
    /// `page_cid` check catches it. Without that check the reconcile would treat
    /// the substituted tree as the Space's real base/remote view.
    #[tokio::test]
    async fn read_manifest_entries_rejects_a_page_substituted_under_another_pages_cid() {
        let vdir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vdir.path());

        let honest = upload_manifest(&vault, vec![file_entry("notes.md")]).await;
        let forged = ft_manifest::build(vec![file_entry("evil.md")]);
        vault
            .put(&ft_hash::manifest_key(&honest), forged.pages[0].1.clone())
            .await
            .unwrap();

        let ctx = mount_scan_only(root.path(), vault);
        let err = ctx.read_manifest_entries(&honest).await.unwrap_err();
        assert!(
            matches!(
                err,
                EngineError::Manifest(ft_manifest::ManifestError::PageCidMismatch { .. })
            ),
            "expected a page cid mismatch, got {err}"
        );
    }

    /// A hostile path in an otherwise well-formed Manifest must not reach the
    /// reconcile's view at all — `..` there becomes a write outside the Space.
    #[tokio::test]
    async fn read_manifest_entries_rejects_an_entry_whose_path_climbs_out_of_the_space_root() {
        let vdir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vdir.path());

        let head = upload_manifest(&vault, vec![file_entry("../../.zshrc")]).await;

        let ctx = mount_scan_only(root.path(), vault);
        let err = ctx.read_manifest_entries(&head).await.unwrap_err();
        assert!(
            matches!(err, EngineError::Core(ft_core::Error::UnsafePath { .. })),
            "expected an UnsafePath rejection, got {err}"
        );
    }

    /// `README.md` + `readme.md` authored on a case-sensitive Device: both are
    /// legitimate entries that collapse onto one casefold key. Collapsing them
    /// silently would make the reconcile read the loser as deleted and delete it.
    #[tokio::test]
    async fn read_manifest_entries_refuses_a_manifest_whose_entries_share_one_casefold_key() {
        let vdir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vdir.path());

        let head = upload_manifest(
            &vault,
            vec![file_entry("README.md"), file_entry("readme.md")],
        )
        .await;

        let ctx = mount_scan_only(root.path(), vault);
        let err = ctx.read_manifest_entries(&head).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, EngineError::Refused(_)),
            "expected a refusal, got {err}"
        );
        assert!(
            msg.contains("README.md") && msg.contains("readme.md"),
            "the refusal must name both colliding entries: {msg}"
        );
    }

    /// A leaf page carrying an entry type this build does not know — what a NEWER
    /// filething writes once it adds a `t` (ADR 0019: `t=3` Dir was such an
    /// addition, and a pre-Dir binary cannot read it). Field names and order mirror
    /// `LeafPage`/`FileEntry` (`§5.1`/`§5.3`) so the decode fails on `t`, nothing else.
    #[derive(serde::Serialize)]
    struct FuturePage {
        k: u8,
        v: u8,
        first: String,
        last: String,
        e: Vec<FutureEntry>,
    }

    #[derive(serde::Serialize)]
    struct FutureEntry {
        p: String,
        t: u8,
        x: bool,
        sz: u64,
        #[serde(with = "serde_bytes")]
        pcid: Vec<u8>,
    }

    /// The version-skew case: the page is AUTHENTIC (it hashes to the cid that
    /// referenced it) but undecodable, which can only mean the writer's format is
    /// newer than ours. The user needs `filething update`, not a discriminant.
    #[tokio::test]
    async fn read_manifest_entries_advises_an_update_for_an_authentic_page_it_cannot_decode() {
        let vdir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let vault = FsVault::new(vdir.path());

        let page = FuturePage {
            k: ft_manifest::KIND_LEAF,
            v: ft_manifest::PAGE_VERSION,
            first: "new.txt".to_string(),
            last: "new.txt".to_string(),
            e: vec![FutureEntry {
                p: "new.txt".to_string(),
                // A type no released filething defines yet: the next `t` after Dir.
                t: 4,
                x: false,
                sz: 0,
                pcid: vec![0u8; 32],
            }],
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&page, &mut payload).unwrap();
        // Address the object by its own bytes, so the cid check passes and only the
        // decode fails.
        let cid = ft_hash::cid_of(&payload);
        let mut obj = ft_core::BlockHeader::new_manifest(payload.len() as u64)
            .encode()
            .to_vec();
        obj.extend_from_slice(&payload);
        vault.put(&ft_hash::manifest_key(&cid), obj).await.unwrap();

        let ctx = mount_scan_only(root.path(), vault);
        let err = ctx.read_manifest_entries(&cid).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, EngineError::Refused(_)),
            "expected a refusal carrying update advice, got {err}"
        );
        assert!(
            msg.contains("filething update"),
            "the error must tell the user how to fix it: {msg}"
        );
        assert!(
            msg.contains("FileType") && msg.contains('4'),
            "the error must keep the offending discriminant for support: {msg}"
        );
    }

    // ----- SpaceLock: one process per Space (§9) -----

    /// The whole point: while one holder lives, a second mount of the same root is
    /// refused and can name who holds it.
    #[test]
    fn a_second_holder_cannot_take_a_space_lock_the_first_still_holds() {
        let root = tempfile::tempdir().unwrap();
        let first = SpaceLock::acquire(root.path()).unwrap();
        assert!(root
            .path()
            .join(crate::scan::CONTROL_DIR)
            .join(LOCK_FILE)
            .exists());

        match SpaceLock::acquire(root.path()) {
            Err(EngineError::SpaceLocked { holder, .. }) => assert!(
                holder.contains(&format!("pid {}", std::process::id())),
                "the error must name the holder, got {holder:?}"
            ),
            Err(other) => panic!("expected SpaceLocked, got {other}"),
            Ok(_) => panic!("the same Space lock must never be handed out twice"),
        }

        // Closing the descriptor is the release — the same thing the kernel does for
        // the holder's process when it dies.
        drop(first);
        SpaceLock::acquire(root.path()).expect("the lock is free once the holder is gone");
    }

    /// The `kill -9` case, which is exactly why this is `flock(2)` and not a pid
    /// file: the file survives the dead holder, the LOCK does not, so the Space is
    /// not bricked.
    #[test]
    fn a_lock_file_left_behind_by_a_dead_holder_does_not_brick_the_space() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(crate::scan::CONTROL_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(LOCK_FILE), b"pid 999999 (filething)").unwrap();

        let lock = SpaceLock::acquire(root.path()).expect("a stale lock file must not block");
        drop(lock);
    }

    /// `filething status` mounts scan-only WHILE the daemon holds the lock, so that
    /// mount must not take (or need) it.
    #[test]
    fn a_scan_only_mount_takes_no_space_lock_so_status_still_works_under_the_daemon() {
        let vdir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let held = SpaceLock::acquire(root.path()).unwrap();

        let ctx = mount_scan_only(root.path(), FsVault::new(vdir.path()));
        assert_eq!(ctx.local_root, root.path());

        drop(held);
    }
}
