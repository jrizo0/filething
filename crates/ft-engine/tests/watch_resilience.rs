//! Integration tests for the `run` loop's startup resilience (`§7`/`§9`).
//!
//! These target HUECO 1: at mount, `run` must not only PULL the head but also
//! COMMIT local changes made while the daemon was down (an offline edit or a
//! deletion). Historically `run` did the initial pull alone, so an offline change
//! sat uncommitted until some later FS event happened to arm the commit debounce
//! — a file deleted while the daemon was off could stay on the head forever.
//!
//! `SpaceContext::run` and `startup_sync` both need a live `Coordinator` (the head
//! subscription + the CAS), which cannot be constructed offline. So these drive
//! the two offline-testable seams the startup path is built from — `apply_head`
//! (the pull half, no Coordinator) and `commit` / `stage_to_vault` (the commit
//! half's staging, which short-circuits before the CAS) — exactly the "two
//! indices + one shared Vault" pattern of `tests/pull_reconcile.rs` and
//! `tests/scan_commit.rs`.
//!
//! The load-bearing fact these tests pin down: after a device is caught up to the
//! head (so an initial pull is a no-op `UpToDate`), an OFFLINE local change is
//! still pending. The OLD startup (pull-only) would miss it; the NEW startup's
//! commit step detects it — `commit` does NOT return `NoChange`, it reaches the
//! push. An unchanged tree, by contrast, commits as `NoChange` cheaply, before
//! the Coordinator is ever touched (`commit.rs:94-96`), so the added startup
//! commit is free when there is nothing to push.
//!
//! HUECO 2 (the `FALLBACK_PULL_INTERVAL` backstop pull in the `select!`) is a
//! property of the live loop's timer wiring; with no offline `Coordinator` there
//! is no non-flaky way to exercise it here without long real-time sleeps. It is
//! covered by the E2E validation instead (a separate agent runs Mac↔VPS with an
//! induced feed stall). See the `run` module docs for the wiring.

use std::path::Path;

use ft_core::{CanonicalPath, CasefoldKey, Cid, FileEntry, FileType};
use ft_engine::{CommitOutcome, PullOutcome, SpaceContext};
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::{Index, SpaceState};
use ft_vault::{FsVault, Vault};

// ---------------------------------------------------------------------------
// Helpers (mirroring tests/pull_reconcile.rs so the fake/fs-vault setup is
// identical: build + upload manifests/blocks into a shared FsVault, mount a
// Coordinator-less SpaceContext).
// ---------------------------------------------------------------------------

/// Builds a single-file FileEntry whose content is `bytes` and uploads its one
/// Block to `vault`. Returns the `(casefold_key, entry)`.
async fn file_entry_uploaded(
    vault: &FsVault,
    path: &str,
    bytes: &[u8],
    exec: bool,
) -> (CasefoldKey, FileEntry) {
    let cid = ft_block::cid_for(bytes);
    vault
        .put(&ft_hash::block_key(&cid), ft_block::encode(bytes))
        .await
        .unwrap();
    let p = CanonicalPath(path.to_string());
    let entry = FileEntry {
        p: p.clone(),
        t: FileType::File,
        x: exec,
        sz: bytes.len() as u64,
        pcid: ft_hash::pcid_of(bytes),
        bk: vec![cid],
        bk_ref: None,
        lt: None,
        wu: None,
    };
    (ft_fsmap::casefold_key(&p), entry)
}

/// Builds the Manifest of `entries`, uploads every page + blocklist to `vault`,
/// and returns the root Cid.
async fn build_and_upload(vault: &FsVault, entries: Vec<(CasefoldKey, FileEntry)>) -> Cid {
    let build = ft_manifest::build(entries);
    for (cid, obj) in &build.pages {
        vault
            .put(&ft_hash::manifest_key(cid), obj.clone())
            .await
            .unwrap();
    }
    for (cid, obj) in &build.blocklists {
        vault
            .put(&ft_hash::blocklist_key(cid), obj.clone())
            .await
            .unwrap();
    }
    build.root
}

/// Seeds a `space_state` row whose synced base is `base_root` at `base_seq`.
fn seed_state(index: &Index, space_id: &str, root: &Path, base_root: Cid, base_seq: i64) {
    index
        .upsert_space_state(&SpaceState {
            space_id: space_id.to_string(),
            last_synced_seq: base_seq,
            last_synced_root: base_root,
            last_synced_revision_id: None,
            chunk_secret: [0x42; 32].to_vec(),
            dedup_secret: None,
            local_root_path: root.to_string_lossy().into_owned(),
        })
        .unwrap();
}

/// Mounts a Coordinator-less SpaceContext over `dir` + `index` + `vault`.
fn mount(index: Index, vault: Box<dyn Vault>, space_id: &str) -> SpaceContext {
    SpaceContext::mount(
        index,
        vault,
        Box::new(LinuxFs),
        ft_engine::AccountId::new("acct"),
        ft_engine::DeviceId::new("devA"),
        ft_engine::SpaceId::new(space_id),
    )
    .unwrap()
}

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let mut p = root.to_path_buf();
    for part in rel.split('/') {
        p.push(part);
    }
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    LinuxFs.write_bytes(&p, bytes, false).unwrap();
}

// ---------------------------------------------------------------------------
// HUECO 1: an offline change made while the daemon was down is pending at mount.
// ---------------------------------------------------------------------------

/// A file DELETED while the daemon was off is a pending commit at startup: the
/// device is otherwise caught up to the head (so the initial pull is a no-op
/// `UpToDate` — the OLD pull-only startup would push nothing), yet the offline
/// deletion leaves a scanned root that differs from the synced base. The commit
/// half of `startup_sync` picks it up; here we assert it via the offline staging
/// seam (`stage_to_vault`) plus a scan-root comparison.
#[tokio::test]
async fn offline_deletion_is_pending_at_startup() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // The head (== the device's synced base): two files.
    let head = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "keep.txt", b"keep", false).await,
            file_entry_uploaded(&vault, "gone.txt", b"gone", false).await,
        ],
    )
    .await;

    // Device A is caught up: both files on disk, base == head.
    let adir = tempfile::tempdir().unwrap();
    write(adir.path(), "keep.txt", b"keep");
    write(adir.path(), "gone.txt", b"gone");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-offdel";
    seed_state(&index, space_id, adir.path(), head, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap(); // index now reflects the head; local root == base.

    // The startup pull is a genuine no-op: the head has not moved.
    let pulled = ctx.apply_head(head, Some(0), None).await.unwrap();
    assert_eq!(
        pulled,
        PullOutcome::UpToDate,
        "device is caught up; the pull half of startup does nothing"
    );

    // Now the "daemon was down": a file is deleted offline. The OLD pull-only
    // startup would end here, leaving gone.txt on the head forever.
    std::fs::remove_file(adir.path().join("gone.txt")).unwrap();

    // The commit half of startup: the scanned tree no longer matches the base, so
    // there IS something to push — this is exactly what the initial commit catches.
    let staged = ctx.stage_to_vault().await.unwrap();
    assert_ne!(
        staged.root, ctx.last_synced.root,
        "an offline deletion must leave a root that differs from the synced base"
    );
    let paths: Vec<&str> = staged
        .scan
        .entries
        .iter()
        .map(|(_, e)| e.p.as_str())
        .collect();
    assert_eq!(
        paths,
        vec!["keep.txt"],
        "the deleted file must be gone from the tree the startup commit would push"
    );
}

/// A file EDITED while the daemon was off is likewise pending at startup.
#[tokio::test]
async fn offline_edit_is_pending_at_startup() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let head = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"BEFORE", false).await],
    )
    .await;

    let adir = tempfile::tempdir().unwrap();
    write(adir.path(), "notes.txt", b"BEFORE");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-offedit";
    seed_state(&index, space_id, adir.path(), head, 0);
    let ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();

    // Offline edit while the daemon was down.
    write(adir.path(), "notes.txt", b"AFTER (edited offline)");

    let staged = ctx.stage_to_vault().await.unwrap();
    assert_ne!(
        staged.root, ctx.last_synced.root,
        "an offline edit must leave a root that differs from the synced base"
    );
}

/// The added startup commit is free when there is nothing to push: an UNCHANGED
/// tree commits as `NoChange` after only a scan + a pure `ft_manifest::build`,
/// WITHOUT touching the Coordinator — which is why `commit` can be called on a
/// Coordinator-less context here at all and still succeed. This pins the no-op
/// claim (`commit.rs:94-96`) that makes the extra startup commit cheap.
#[tokio::test]
async fn startup_commit_is_free_when_no_offline_change() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let head = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "a.txt", b"same", false).await],
    )
    .await;

    let adir = tempfile::tempdir().unwrap();
    write(adir.path(), "a.txt", b"same");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-nochange";
    seed_state(&index, space_id, adir.path(), head, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap(); // local root == base; nothing changed offline.

    // No offline change: `commit` short-circuits to NoChange BEFORE it needs the
    // Coordinator (commit.rs:94-96), so it succeeds even on this None-coordinator
    // mount. If the extra startup commit were expensive, this call could not
    // return without a live backend.
    let outcome = ctx.commit(None).await.unwrap();
    assert_eq!(
        outcome,
        CommitOutcome::NoChange,
        "an unchanged tree must commit as NoChange, touching neither Vault nor Coordinator"
    );
    // The base did not move.
    assert_eq!(ctx.last_synced.root, head);
}
