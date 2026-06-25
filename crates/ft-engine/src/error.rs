//! Engine errors (`docs/BUILD-PLAN.md §3` — one `thiserror` enum per crate).
//!
//! [`EngineError`] folds in the errors of every crate the engine consumes on the
//! write and read paths (`ft-index`, `ft-vault`, `ft-manifest`, `ft-block`,
//! `ft-fsmap`, `ft-coordinator`, `ft-diff`, `ft-watcher`, `ft-core`, plus
//! `std::io`) so a caller handles a single result type. (`ft-conflict` is a pure
//! resolver with no error type, so it contributes none.) The commit CAS conflict
//! (`§7` step 6) is NOT an error: it is a first-class
//! [`crate::CommitOutcome::Conflict`] outcome, so [`EngineError`] carries only
//! genuine failures.

use thiserror::Error;

/// Anything that can go wrong on the engine's write path (scan + commit).
#[derive(Debug, Error)]
pub enum EngineError {
    /// A local-index (SQLite) operation failed. `§9`.
    #[error("local index: {0}")]
    Index(#[from] ft_index::Error),

    /// A Vault (object store) operation failed. `§6.1`.
    #[error("vault: {0}")]
    Vault(#[from] ft_vault::VaultError),

    /// Decoding a Manifest page failed (build never fails, but the type is
    /// folded in for completeness / future read paths). `§5`.
    #[error("manifest: {0}")]
    Manifest(#[from] ft_manifest::ManifestError),

    /// Encoding/decoding/verifying a Block object failed. `§4`.
    #[error("block: {0}")]
    Block(#[from] ft_block::Error),

    /// A tree diff / apply / materialize failed (`§8`).
    #[error("diff: {0}")]
    Diff(#[from] ft_diff::Error),

    /// The file watcher backend failed to start or watch the root (`§9`).
    #[error("watcher: {0}")]
    Watcher(#[from] ft_watcher::Error),

    /// Mapping the filesystem failed (canonicalize, symlink read, …). `§5.2`.
    #[error("fsmap: {0}")]
    FsMap(#[from] ft_fsmap::FsMapError),

    /// A non-conflict Coordinator failure (transport, bad response, …). `§6.2`.
    /// A commit CAS *conflict* is surfaced as [`crate::CommitOutcome::Conflict`],
    /// not as this error.
    #[error("coordinator: {0}")]
    Coordinator(#[from] ft_coordinator::CoordinatorError),

    /// A foundation (`ft-core`) error surfaced (e.g. decoding a stored id). `§4`.
    #[error("core: {0}")]
    Core(#[from] ft_core::Error),

    /// A raw filesystem IO error not already attributed to a Vault key.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A CBOR (de)serialization of the Space meta blob failed. `§4.4`/`§6.2`.
    #[error("meta blob codec: {0}")]
    MetaBlob(String),

    /// The persisted `space_state` for a mounted Space was missing or malformed
    /// (e.g. a `chunk_secret` that is not exactly 32 bytes). `§9`.
    #[error("space state: {0}")]
    SpaceState(String),
}

/// Crate-wide `Result` alias over [`EngineError`].
pub type Result<T> = std::result::Result<T, EngineError>;
