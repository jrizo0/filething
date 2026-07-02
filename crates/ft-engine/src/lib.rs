//! ft-engine — the INTEGRATOR (`docs/format.md §7`, `§8`, `§10`, re-scan `§9`).
//!
//! This crate is the engine that turns a Device's on-disk Space into committed
//! Revisions and (Part 2) applies Revisions pulled from the change feed back to
//! disk. It owns no format of its own; it orchestrates the foundation crates
//! ([`ft_chunker`], [`ft_block`], [`ft_hash`], [`ft_manifest`], [`ft_fsmap`],
//! [`ft_index`], [`ft_vault`], [`ft_coordinator`]) along the commit protocol.
//!
//! # Part 1 (this build): the WRITE path
//!
//! - [`SpaceContext`] — the handle to one Space mounted on this Device.
//! - [`SpaceContext::scan`] — walk the local root → the [`ScanResult`] (the
//!   FileEntry set + the Blocks to upload), updating the local index (`§9`).
//! - [`SpaceContext::commit`] — the strict `§7` order: scan → dedup+upload Blocks
//!   → build Manifest → upload pages/blocklists → atomic Space-head CAS, yielding
//!   a [`CommitOutcome`] (`Committed` / `Conflict` / `NoChange`). On a CAS
//!   conflict it does NOT reconcile — that is Part 2.
//! - [`SpaceContext::init_space`] — create a fresh Space (generate the per-Space
//!   `chunk_secret`, write the meta blob, `create_space`, first commit).
//!
//! # Part 2: the READ path + the sync loop
//!
//! - [`SpaceContext::pull`] — read the Space head (`§8`), then fast-forward
//!   (`diff` + `apply`, with echo marks) or three-way reconcile (`§10`), yielding
//!   a [`PullOutcome`].
//! - [`SpaceContext::commit_and_reconcile`] — commit, and on a CAS conflict pull
//!   (reconcile) and retry (`§7` step 6).
//! - [`SpaceContext::clone_space`] — join an existing Space on a new Device:
//!   load the per-Space `chunk_secret` from the meta blob and materialize the
//!   whole head tree.
//! - [`SpaceContext::run`] — the continuous bidirectional loop: a
//!   [`Watcher`](ft_watcher::Watcher) over the root + the head feed, with echo
//!   suppression so an applied change never re-commits (`§9`).

mod clone;
mod commit;
mod context;
mod error;
mod gc;
mod metrics;
mod pull;
mod run;
mod scan;
pub mod secrets;

pub use commit::{CommitOutcome, StagedCommit};
pub use context::{LastSynced, SpaceContext};
pub use error::{EngineError, Result};
pub use gc::{GcOptions, GcReport, DEFAULT_GRACE};
pub use metrics::SyncMetrics;
pub use pull::PullOutcome;
pub use scan::{ScanResult, CONTROL_DIR, IGNORE_FILE};
pub use secrets::{load_meta_blob, write_meta_blob, MetaBlob};

// Re-export the coordinator id/outcome types a caller needs to drive commit, so
// downstream crates (ft-daemon, apps/cli) depend on ft-engine alone for the
// write- and read-path vocabulary.
pub use ft_coordinator::{AccountId, CommitError, Coordinator, DeviceId, RevisionId, SpaceId};
// Re-export the read-path collaborator types a caller may want to surface
// (e.g. the daemon's status / change-feed view).
pub use ft_vault::Vault;
pub use ft_watcher::{AppliedState, ChangeEvent, ChangeKind};
