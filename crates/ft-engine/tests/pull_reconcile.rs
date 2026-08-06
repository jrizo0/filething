//! Integration tests for the ft-engine READ path (pull / reconcile / echo).
//!
//! These drive the read path WITHOUT a Coordinator by calling the public
//! `apply_head(root, seq, revid)` seam with roots built via `ft_manifest` and
//! uploaded to a shared [`FsVault`] — exactly the "two indices + one shared
//! Vault" setup of the brief. The live two-device end-to-end test against Convex
//! is in `tests/two_devices.rs` (`#[ignore]`d).

use std::path::Path;
use std::sync::Arc;

use ft_core::{CanonicalPath, CasefoldKey, Cid, FileEntry, FileType, Pcid};
use ft_engine::{AppliedState, PullOutcome, SpaceContext};
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::{Index, SpaceState};
use ft_vault::{FsVault, Vault};
use ft_watcher::is_echo;

// ---------------------------------------------------------------------------
// Helpers: build + upload manifests/blocks into a shared FsVault.
// ---------------------------------------------------------------------------

/// Builds a single-file FileEntry whose content is `bytes` and uploads its one
/// Block to `vault`. Returns the (casefold_key, entry).
async fn file_entry_uploaded(
    vault: &FsVault,
    path: &str,
    bytes: &[u8],
    exec: bool,
) -> (CasefoldKey, FileEntry) {
    // One block per small file (MVP cid == pcid).
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

/// The empty-Manifest root (the "no base yet" convention), with its page uploaded.
async fn empty_root(vault: &FsVault) -> Cid {
    build_and_upload(vault, Vec::new()).await
}

/// The empty-Manifest root with GARBAGE stored under its object key.
///
/// That cid folds in no account or Space id, so it is one GLOBALLY CONSTANT key
/// shared by every tenant of a deployment, and the backend signs create-only PUTs:
/// whoever writes the key first owns its bytes forever. The read path must therefore
/// build the page in process and never fetch it — this helper is that attack.
async fn poisoned_empty_root(vault: &FsVault) -> Cid {
    let root = ft_manifest::build(Vec::new()).root;
    vault
        .put(
            &ft_hash::manifest_key(&root),
            b"not a manifest page at all".to_vec(),
        )
        .await
        .unwrap();
    root
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

/// Mounts a coordinator-less SpaceContext over `dir` + `index` + `vault`.
fn mount(index: Index, vault: Box<dyn Vault>, space_id: &str) -> SpaceContext {
    SpaceContext::mount(
        index,
        vault,
        Box::new(LinuxFs),
        ft_engine::AccountId::new("acct"),
        ft_engine::DeviceId::new("devB"),
        ft_engine::SpaceId::new(space_id),
    )
    .unwrap()
}

fn read(root: &Path, rel: &str) -> Vec<u8> {
    let mut p = root.to_path_buf();
    for part in rel.split('/') {
        p.push(part);
    }
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    write_mode(root, rel, bytes, false);
}

/// [`write`] with an explicit executable bit, so a test can stage a local
/// `chmod +x` (`x` is half of a File's content identity, `§5.1`).
fn write_mode(root: &Path, rel: &str, bytes: &[u8], exec: bool) {
    let mut p = root.to_path_buf();
    for part in rel.split('/') {
        p.push(part);
    }
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    LinuxFs.write_bytes(&p, bytes, exec).unwrap();
}

/// The basenames in `root` that look like conflict copies — how a test proves the
/// reconcile did NOT mint a new copy on a round that should have reused one.
fn conflict_copies_in(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| ft_engine::is_conflict_copy_name(name))
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// (1) FAST-FORWARD: empty Device pulls a head and materializes it byte-identical.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fast_forward_materializes_head_tree_byte_identical() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // The base is the empty tree; the head is three files. Upload everything.
    let base = empty_root(&vault).await;
    let head = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "src/main.rs", b"fn main() {}\n", false).await,
            file_entry_uploaded(&vault, "README.md", b"# title\n", false).await,
            file_entry_uploaded(&vault, "run.sh", b"#!/bin/sh\necho hi\n", true).await,
        ],
    )
    .await;

    // Device B: empty dir, base = empty root, seq = -1.
    let bdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-ff";
    seed_state(&index, space_id, bdir.path(), base, -1);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    let outcome = ctx.apply_head(head, Some(0), None).await.unwrap();
    assert_eq!(outcome, PullOutcome::FastForwarded { applied: 3 });

    // B's dir now holds the head tree byte-for-byte.
    assert_eq!(read(bdir.path(), "src/main.rs"), b"fn main() {}\n");
    assert_eq!(read(bdir.path(), "README.md"), b"# title\n");
    assert_eq!(read(bdir.path(), "run.sh"), b"#!/bin/sh\necho hi\n");

    // The exec bit was honored.
    let meta = std::fs::symlink_metadata(bdir.path().join("run.sh")).unwrap();
    assert!(LinuxFs.exec_bit(&meta), "run.sh must be executable");

    // The base advanced to the head, and the local index was updated.
    assert_eq!(ctx.last_synced.root, head);
    assert_eq!(ctx.last_synced.seq, 0);
    let row = ctx
        .index
        .get_entry(space_id, &CanonicalPath("src/main.rs".to_string()))
        .unwrap()
        .unwrap();
    assert_eq!(row.file_type, FileType::File);
    assert_eq!(row.blocks.len(), 1);

    // A second apply of the same head is UpToDate (idempotent, no re-work).
    let again = ctx.apply_head(head, Some(0), None).await.unwrap();
    assert_eq!(again, PullOutcome::UpToDate);
}

#[tokio::test]
async fn fast_forward_applies_modify_and_delete() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // Base tree: a.txt=A0, b.txt=B0. Head: a.txt=A1 (modified), b.txt deleted,
    // c.txt=C0 (added).
    let base = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "a.txt", b"A0", false).await,
            file_entry_uploaded(&vault, "b.txt", b"B0", false).await,
        ],
    )
    .await;
    let head = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "a.txt", b"A1", false).await,
            file_entry_uploaded(&vault, "c.txt", b"C0", false).await,
        ],
    )
    .await;

    // Device B starts AT the base: materialize the base onto disk first.
    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "a.txt", b"A0");
    write(bdir.path(), "b.txt", b"B0");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-ffmod";
    seed_state(&index, space_id, bdir.path(), base, 0);
    // Prime the index so B's scan sees no local change vs the base.
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap(); // index now reflects A0/B0; root == base.

    let outcome = ctx.apply_head(head, Some(1), None).await.unwrap();
    assert_eq!(outcome, PullOutcome::FastForwarded { applied: 3 });

    assert_eq!(read(bdir.path(), "a.txt"), b"A1");
    assert_eq!(read(bdir.path(), "c.txt"), b"C0");
    assert!(
        !bdir.path().join("b.txt").exists(),
        "b.txt must be deleted by the fast-forward"
    );
}

// ---------------------------------------------------------------------------
// (2) RECONCILE: base F; local edits F->X; remote edits F->Y -> conflict copy.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reconcile_divergent_edit_keeps_both_with_conflict_copy() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base: notes.txt = "BASE". remote: notes.txt = "REMOTE".
    let base = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"BASE", false).await],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"REMOTE", false).await],
    )
    .await;

    // Device B at the base, but with a LOCAL edit on disk: notes.txt = "LOCAL".
    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "notes.txt", b"BASE");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-rec";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap(); // index reflects BASE; local root == base.

    // The local divergent edit.
    write(bdir.path(), "notes.txt", b"LOCAL");

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    let conflicts = match outcome {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };

    // The real path now holds the REMOTE winner; no data is lost: the LOCAL edit
    // survives under a conflict-copy name (device "devB", seq 0 = the base seq).
    assert_eq!(read(bdir.path(), "notes.txt"), b"REMOTE");
    assert_eq!(conflicts.len(), 1, "exactly one conflict copy");
    let copy = &conflicts[0];
    assert!(
        copy.starts_with("notes (conflicto devB, seq ") && copy.ends_with(").txt"),
        "unexpected conflict-copy name: {copy}"
    );
    assert_eq!(read(bdir.path(), copy), b"LOCAL", "local edit preserved");

    // Base advanced to the remote head.
    assert_eq!(ctx.last_synced.root, remote);
}

#[tokio::test]
async fn reconcile_one_sided_local_edit_keeps_local_no_conflict() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base has a.txt and b.txt. remote ONLY changed b.txt; local ONLY changed
    // a.txt. No path changed on both sides -> no conflict; b fast-forwards,
    // a stays local.
    let base = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "a.txt", b"A0", false).await,
            file_entry_uploaded(&vault, "b.txt", b"B0", false).await,
        ],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "a.txt", b"A0", false).await,
            file_entry_uploaded(&vault, "b.txt", b"B1", false).await,
        ],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "a.txt", b"A0");
    write(bdir.path(), "b.txt", b"B0");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-rec1";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();

    // Local edit to a.txt only.
    write(bdir.path(), "a.txt", b"A_LOCAL");

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    match outcome {
        PullOutcome::Reconciled { conflicts } => {
            assert!(conflicts.is_empty(), "no path changed on both sides");
        }
        other => panic!("expected Reconciled, got {other:?}"),
    }

    // a.txt keeps the LOCAL edit; b.txt fast-forwarded to the remote change.
    assert_eq!(read(bdir.path(), "a.txt"), b"A_LOCAL");
    assert_eq!(read(bdir.path(), "b.txt"), b"B1");
}

// Multiple remote winners in one reconcile: the concurrent-materialize phase
// drains its stream sequentially, RECORDING each winner as it completes (ADR
// 0018). This checks all winners are both materialized to disk AND recorded
// (echo-marked) — i.e. the drain loop records every entry, not just one.
#[tokio::test]
async fn reconcile_multiple_remote_winners_all_materialized_and_recorded() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base = local content for w1..w3 + local.txt. remote edited w1..w3 (three
    // FastForwardToRemote winners); local edited ONLY local.txt (one-sided, so
    // the reconcile path runs but produces no conflict copies).
    let base = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "w1.txt", b"W1_0", false).await,
            file_entry_uploaded(&vault, "w2.txt", b"W2_0", false).await,
            file_entry_uploaded(&vault, "w3.txt", b"W3_0", false).await,
            file_entry_uploaded(&vault, "local.txt", b"L0", false).await,
        ],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "w1.txt", b"W1_REMOTE", false).await,
            file_entry_uploaded(&vault, "w2.txt", b"W2_REMOTE", false).await,
            file_entry_uploaded(&vault, "w3.txt", b"W3_REMOTE", false).await,
            file_entry_uploaded(&vault, "local.txt", b"L0", false).await,
        ],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "w1.txt", b"W1_0");
    write(bdir.path(), "w2.txt", b"W2_0");
    write(bdir.path(), "w3.txt", b"W3_0");
    write(bdir.path(), "local.txt", b"L0");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-multi";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    let applied = Arc::new(AppliedState::new());
    ctx.attach_applied_state(Arc::clone(&applied));
    ctx.scan().unwrap();

    // The one-sided local edit that forces the reconcile path.
    write(bdir.path(), "local.txt", b"L_LOCAL");

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    match outcome {
        PullOutcome::Reconciled { conflicts } => {
            assert!(conflicts.is_empty(), "no path changed on both sides");
        }
        other => panic!("expected Reconciled, got {other:?}"),
    }

    // Every remote winner was materialized to disk, and the local edit survived.
    for (rel, want) in [
        ("w1.txt", b"W1_REMOTE".as_slice()),
        ("w2.txt", b"W2_REMOTE".as_slice()),
        ("w3.txt", b"W3_REMOTE".as_slice()),
    ] {
        assert_eq!(read(bdir.path(), rel), want, "{rel} materialized to remote");
        // And RECORDED: the drain echo-marked each winner (record_materialized).
        let abs = bdir.path().join(rel);
        let mtime = std::fs::symlink_metadata(&abs)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let pcid = ft_hash::pcid_of(&std::fs::read(&abs).unwrap());
        assert!(
            is_echo(&applied, &CanonicalPath(rel.to_string()), mtime, &pcid),
            "{rel} winner must be echo-marked (recorded by the drain)"
        );
    }
    assert_eq!(read(bdir.path(), "local.txt"), b"L_LOCAL");
    assert_eq!(ctx.last_synced.root, remote);
}

#[tokio::test]
async fn reconcile_delete_vs_remote_edit_keeps_the_remote_edit() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base: doomed.txt = D0 (+ keep.txt so local has SOME other change, forcing
    // the reconcile path rather than a pure fast-forward). remote EDITED
    // doomed.txt -> D1; local DELETED doomed.txt and edited keep.txt.
    let base = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "doomed.txt", b"D0", false).await,
            file_entry_uploaded(&vault, "keep.txt", b"K0", false).await,
        ],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "doomed.txt", b"D1", false).await,
            file_entry_uploaded(&vault, "keep.txt", b"K0", false).await,
        ],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "doomed.txt", b"D0");
    write(bdir.path(), "keep.txt", b"K0");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-dve";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();

    // Local: delete doomed.txt, edit keep.txt -> there ARE local changes.
    std::fs::remove_file(bdir.path().join("doomed.txt")).unwrap();
    write(bdir.path(), "keep.txt", b"K_LOCAL");

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    assert!(matches!(outcome, PullOutcome::Reconciled { .. }));

    // Delete-vs-edit: the remote EDIT wins -> doomed.txt is restored as D1.
    assert_eq!(
        read(bdir.path(), "doomed.txt"),
        b"D1",
        "remote edit must win over the local delete"
    );
    // keep.txt kept the LOCAL edit (one-sided).
    assert_eq!(read(bdir.path(), "keep.txt"), b"K_LOCAL");
}

#[tokio::test]
async fn reconcile_casefold_collision_keeps_both_under_distinct_names() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base empty. local creates readme.md; remote creates README.md (same
    // casefold key, byte-distinct path). The merged tree must not feed two
    // entries with one key into manifest::build: keep local, move remote aside.
    let base = empty_root(&vault).await;
    let remote = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "README.md", b"REMOTE caps", false).await],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "readme.md", b"local lower");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-coll";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    // Do NOT scan-prime: base is empty, local has readme.md -> local change.

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    let conflicts = match outcome {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };

    // Local readme.md is untouched; the remote README.md was moved aside.
    assert_eq!(read(bdir.path(), "readme.md"), b"local lower");
    assert_eq!(conflicts.len(), 1, "the colliding remote is moved aside");
    assert!(
        conflicts[0].contains("(conflicto "),
        "remote collision became a conflict copy: {}",
        conflicts[0]
    );
    assert_eq!(read(bdir.path(), &conflicts[0]), b"REMOTE caps");
}

// ---------------------------------------------------------------------------
// (3) ECHO SUPPRESSION: a fast-forward marks AppliedState so the watcher event
//     it triggers is recognized as our own write (is_echo == true).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn applied_writes_are_marked_as_echoes() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let base = empty_root(&vault).await;
    let head = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "echo.txt", b"hello echo", false).await],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-echo";
    seed_state(&index, space_id, bdir.path(), base, -1);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    // Attach a shared AppliedState (what the run loop shares with the Watcher).
    let applied = Arc::new(AppliedState::new());
    ctx.attach_applied_state(Arc::clone(&applied));

    ctx.apply_head(head, Some(0), None).await.unwrap();

    // The engine recorded a mark for echo.txt. Recompute (mtime, pcid) the way the
    // run loop would on the resulting FS event and confirm is_echo == true.
    let path = CanonicalPath("echo.txt".to_string());
    let abs = bdir.path().join("echo.txt");
    let mtime = std::fs::symlink_metadata(&abs)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let pcid = ft_hash::pcid_of(&std::fs::read(&abs).unwrap());

    assert!(
        is_echo(&applied, &path, mtime, &pcid),
        "the applied write must be recognized as our own echo"
    );
    // A DIFFERENT content at the same path (a real user edit) is NOT an echo.
    let other = Pcid::new([0xAB; 32]);
    assert!(!is_echo(&applied, &path, mtime, &other));
}

// ---------------------------------------------------------------------------
// (5) OFFLINE CONFLICT REGRESSION ("bloque fantasma", diario 2026-07-01): the
// conflict-copy LOSER's content came from the local disk and was never
// committed by anyone — the next stage/commit MUST upload its Block, or the
// published Manifest references an object the Vault does not have and every
// other Device's pull dies with `object not found`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn conflict_copy_loser_block_reaches_vault_on_next_stage() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base: notes.txt = "BASE"; remote head: notes.txt = "REMOTE".
    let base = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"BASE", false).await],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"REMOTE", false).await],
    )
    .await;

    // Device B at the base; the divergent edit happened with the daemon DOWN,
    // so "LOCAL" was never scanned by a commit nor uploaded anywhere.
    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "notes.txt", b"BASE");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-phantom";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();
    write(bdir.path(), "notes.txt", b"LOCAL");

    // The startup pull reconciles: REMOTE wins the path, LOCAL survives as the
    // conflict copy on disk.
    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    let conflicts = match outcome {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };
    assert_eq!(conflicts.len(), 1);
    let copy = conflicts[0].clone();

    // The startup commit stages the merged tree. The loser's Block must land in
    // the Vault HERE — nobody else ever had its bytes.
    let staged = ctx.stage_to_vault().await.unwrap();
    let loser_cid = ft_block::cid_for(b"LOCAL");
    assert!(
        vault.head(&ft_hash::block_key(&loser_cid)).await.unwrap(),
        "the conflict-copy loser's Block must be uploaded by the next stage \
         (a Manifest referencing a missing Block poisons every other Device's pull)"
    );

    // End-to-end: a Device already at the remote head pulls the reconciled
    // root — the exact pull that died with `object not found` on the VPS.
    let cdir = tempfile::tempdir().unwrap();
    write(cdir.path(), "notes.txt", b"REMOTE");
    let index_c = Index::open_in_memory().unwrap();
    seed_state(&index_c, space_id, cdir.path(), remote, 1);
    let mut ctx_c = mount(index_c, Box::new(FsVault::new(vdir.path())), space_id);
    ctx_c.scan().unwrap();
    let applied = ctx_c
        .apply_head(staged.root, Some(2), None)
        .await
        .expect("a peer must be able to materialize the reconciled head");
    assert_eq!(applied, PullOutcome::FastForwarded { applied: 1 });
    assert_eq!(
        read(cdir.path(), &copy),
        b"LOCAL",
        "loser content intact on the peer"
    );
}

// ---------------------------------------------------------------------------
// (6) DIRECTORIES as first-class entries (ADR 0019): empty dirs materialize,
// emptied dirs are removed, a remote dir-delete keeps a dir still holding local
// unsynced content, and a deep chain deletes deepest-first.
// ---------------------------------------------------------------------------

/// A `FileType::Dir` manifest entry at `path` (no blocks to upload).
fn dir_entry(path: &str) -> (CasefoldKey, FileEntry) {
    let p = CanonicalPath(path.to_string());
    let entry = FileEntry {
        p: p.clone(),
        t: FileType::Dir,
        x: false,
        sz: 0,
        pcid: Pcid::new([0u8; 32]),
        bk: vec![],
        bk_ref: None,
        lt: None,
        wu: None,
    };
    (ft_fsmap::casefold_key(&p), entry)
}

#[tokio::test]
async fn fast_forward_materializes_an_empty_directory() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());
    let base = empty_root(&vault).await;
    let head = build_and_upload(&vault, vec![dir_entry("emptydir")]).await;

    let bdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-ff-dir";
    seed_state(&index, space_id, bdir.path(), base, -1);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    let outcome = ctx.apply_head(head, Some(0), None).await.unwrap();
    assert_eq!(outcome, PullOutcome::FastForwarded { applied: 1 });
    assert!(
        bdir.path().join("emptydir").is_dir(),
        "the empty directory must materialize on the peer"
    );
    assert_eq!(ctx.last_synced.root, head);
}

#[tokio::test]
async fn fast_forward_removes_an_emptied_directory() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());
    // base has dir "d"; the head removed it (rmdir on the other Device).
    let base = build_and_upload(&vault, vec![dir_entry("d")]).await;
    let head = empty_root(&vault).await;

    let bdir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(bdir.path().join("d")).unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-rmdir";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap(); // index reflects the local dir; root == base.

    let outcome = ctx.apply_head(head, Some(1), None).await.unwrap();
    assert_eq!(outcome, PullOutcome::FastForwarded { applied: 1 });
    assert!(
        !bdir.path().join("d").exists(),
        "the emptied directory must be removed on the peer"
    );
}

#[tokio::test]
async fn remote_dir_delete_keeps_a_dir_that_holds_unsynced_local_content() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());
    // base has dir "X"; the remote head removed it.
    let base = build_and_upload(&vault, vec![dir_entry("X")]).await;
    let head = empty_root(&vault).await;

    let bdir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(bdir.path().join("X")).unwrap();
    // An unsynced local file lives inside X (never committed anywhere).
    write(bdir.path(), "X/keep.txt", b"local only");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-dirsafe";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    // No scan-prime: X/keep.txt is a local change vs base -> the reconcile path.

    let outcome = ctx.apply_head(head, Some(1), None).await.unwrap();
    assert!(
        matches!(outcome, PullOutcome::Reconciled { .. }),
        "a local unsynced file forces the reconcile path"
    );

    // The dir survived (it still holds local content) and the file is intact —
    // remove_dir must never force-delete a populated directory (ADR 0019).
    assert!(
        bdir.path().join("X").is_dir(),
        "a dir with unsynced local content must be kept"
    );
    assert_eq!(read(bdir.path(), "X/keep.txt"), b"local only");
}

#[tokio::test]
async fn deep_empty_dir_chain_propagates_then_deletes_deepest_first() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());
    let base = empty_root(&vault).await;
    // A deep chain of empty directories.
    let head1 = build_and_upload(
        &vault,
        vec![dir_entry("a"), dir_entry("a/b"), dir_entry("a/b/c")],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-chain";
    seed_state(&index, space_id, bdir.path(), base, -1);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    // Pull the chain -> all three directories materialize.
    let o1 = ctx.apply_head(head1, Some(0), None).await.unwrap();
    assert_eq!(o1, PullOutcome::FastForwarded { applied: 3 });
    assert!(bdir.path().join("a").join("b").join("c").is_dir());

    // The whole chain is removed remotely (back to the empty tree). The
    // deepest-first Phase-B ordering must remove all three, not leave `a`/`a/b`.
    let o2 = ctx.apply_head(base, Some(1), None).await.unwrap();
    assert_eq!(o2, PullOutcome::FastForwarded { applied: 3 });
    assert!(
        !bdir.path().join("a").exists(),
        "the whole empty chain must be removed deepest-first"
    );
}

#[tokio::test]
async fn reconcile_remote_deletes_populated_dir_tree_without_resurrection() {
    // The RECONCILE path (a local change on an unrelated file forces it, not a
    // fast-forward) with the remote head having deleted a POPULATED dir tree.
    // Reconcile visits keys ascending, so the parent `a` sorts BEFORE `a/f`;
    // executing its TakeRemoteDeletion in-loop would hit ENOTEMPTY, keep the dir
    // + its index row, and resurrect it into the next commit — the deletion would
    // NEVER propagate. Deferring the dir delete (deepest-first, after the loop)
    // removes `a/f` before its parent `a`, so the whole tree really disappears.
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base: dir a + file a/f (a populated tree), plus an unrelated other.txt.
    let base = build_and_upload(
        &vault,
        vec![
            dir_entry("a"),
            file_entry_uploaded(&vault, "a/f", b"inside", false).await,
            file_entry_uploaded(&vault, "other.txt", b"O0", false).await,
        ],
    )
    .await;
    // remote head: the whole a/ tree deleted; other.txt unchanged.
    let remote = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "other.txt", b"O0", false).await],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(bdir.path().join("a")).unwrap();
    write(bdir.path(), "a/f", b"inside");
    write(bdir.path(), "other.txt", b"O0");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-dirtree-del";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap(); // index reflects base; local root == base.

    // A local edit on the UNRELATED file forces the reconcile branch while the
    // a/ tree still matches the base (so it resolves to TakeRemoteDeletion).
    write(bdir.path(), "other.txt", b"O_LOCAL");

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    assert!(
        matches!(outcome, PullOutcome::Reconciled { .. }),
        "the unrelated local edit forces the reconcile path"
    );

    // The whole populated tree is gone from disk, with no error.
    assert!(!bdir.path().join("a").join("f").exists(), "a/f deleted");
    assert!(
        !bdir.path().join("a").exists(),
        "the parent dir a must be deleted too (no ENOTEMPTY resurrection)"
    );

    // The regression assertion: B's next scan must NOT re-emit `a` — a resurrected
    // dir row would re-publish a deletion that never propagates.
    let scan = ctx.scan().unwrap();
    assert!(
        !scan.entries.iter().any(|(_, e)| e.p.as_str() == "a"),
        "the deleted dir must not resurrect in the next scan"
    );
}

#[tokio::test]
async fn fast_forward_dir_gains_then_loses_content() {
    // Cross-device pipeline: an empty dir `d` in the base gains a child `d/file.txt`
    // in the head (fast-forward materializes both), then the head drops the file
    // but keeps `d` (fast-forward removes only the file, the dir stays).
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let base = build_and_upload(&vault, vec![dir_entry("d")]).await;
    let head1 = build_and_upload(
        &vault,
        vec![
            dir_entry("d"),
            file_entry_uploaded(&vault, "d/file.txt", b"content", false).await,
        ],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(bdir.path().join("d")).unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-dir-content";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap(); // index reflects the empty dir d; root == base.

    // The dir gains a file: both exist on disk after the fast-forward.
    let o1 = ctx.apply_head(head1, Some(1), None).await.unwrap();
    assert_eq!(o1, PullOutcome::FastForwarded { applied: 1 });
    assert!(bdir.path().join("d").is_dir());
    assert_eq!(read(bdir.path(), "d/file.txt"), b"content");

    // Reverse: the head drops the file but keeps the dir.
    let o2 = ctx.apply_head(base, Some(2), None).await.unwrap();
    assert_eq!(o2, PullOutcome::FastForwarded { applied: 1 });
    assert!(
        !bdir.path().join("d").join("file.txt").exists(),
        "the file must be gone"
    );
    assert!(
        bdir.path().join("d").is_dir(),
        "the now-empty dir must remain (only the file was deleted)"
    );
}

// ---------------------------------------------------------------------------
// AUTO-MERGE (issue #14 point 4): a divergent edit over the SAME text file may
// be fused when the two sides do not overlap; otherwise (overlap or binary) it
// falls back to a conflict copy exactly as before.
// ---------------------------------------------------------------------------

// base F; local and remote edit the SAME text file in DISJOINT regions (append
// at opposite ends) -> 3-way content merge, NO conflict copy, the fused bytes on
// disk, and uploaded by the next stage (no phantom block).
#[tokio::test]
async fn reconcile_non_overlapping_text_edits_auto_merge_no_conflict_copy() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base: notes.txt = "l1\nl2\n". remote APPENDED a trailing line; local
    // PREPENDED a heading — disjoint edits over the same file.
    let base = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"l1\nl2\n", false).await],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"l1\nl2\nREMOTE\n", false).await],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "notes.txt", b"l1\nl2\n");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-merge-ok";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();

    // The local divergent (but disjoint) edit.
    write(bdir.path(), "notes.txt", b"HEAD\nl1\nl2\n");

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    match outcome {
        PullOutcome::Reconciled { conflicts } => {
            assert!(
                conflicts.is_empty(),
                "a clean auto-merge must not write a conflict copy: {conflicts:?}"
            );
        }
        other => panic!("expected Reconciled, got {other:?}"),
    }

    // The real path now holds the FUSED content (both edits) ...
    assert_eq!(read(bdir.path(), "notes.txt"), b"HEAD\nl1\nl2\nREMOTE\n");

    // ... and staging for the next commit uploads the merged Block, so it is in
    // the Vault (a Manifest referencing a missing Block would poison peers).
    let staged = ctx.stage_to_vault().await.unwrap();
    let merged_cid = ft_block::cid_for(b"HEAD\nl1\nl2\nREMOTE\n");
    assert!(
        vault.head(&ft_hash::block_key(&merged_cid)).await.unwrap(),
        "the auto-merged Block must be uploaded by the next stage (no phantom block)"
    );
    // The staged root differs from remote — it carries the merge.
    assert_ne!(staged.root, remote);
}

// OVERLAP: local and remote edit the SAME line differently -> no merge,
// conflict copy exactly as before (auto-merge declines on overlap).
#[tokio::test]
async fn reconcile_overlapping_text_edits_fall_back_to_conflict_copy() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let base = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"a\nb\nc\n", false).await],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"a\nREMOTE\nc\n", false).await],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "notes.txt", b"a\nb\nc\n");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-merge-overlap";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();

    // Local edits the SAME middle line differently -> overlapping change.
    write(bdir.path(), "notes.txt", b"a\nLOCAL\nc\n");

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    let conflicts = match outcome {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };
    assert_eq!(
        conflicts.len(),
        1,
        "overlap must keep both via a conflict copy"
    );
    let copy = &conflicts[0];
    assert_eq!(read(bdir.path(), "notes.txt"), b"a\nREMOTE\nc\n");
    assert_eq!(
        read(bdir.path(), copy),
        b"a\nLOCAL\nc\n",
        "local edit preserved"
    );
}

// BINARY: a divergent NON-text file never auto-merges -> conflict copy.
#[tokio::test]
async fn reconcile_binary_divergent_falls_back_to_conflict_copy() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // Content with an embedded NUL byte => detected as binary by merge3.
    let base_bytes: &[u8] = b"\x00\x01\x02BASE\x00";
    let remote_bytes: &[u8] = b"\x00\x01\x02REMOTE\x00\xff";
    let local_bytes: &[u8] = b"\x00\x01\x02LOCAL\x00\xfe";

    let base = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "blob.bin", base_bytes, false).await],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "blob.bin", remote_bytes, false).await],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "blob.bin", base_bytes);
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-merge-binary";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();

    write(bdir.path(), "blob.bin", local_bytes);

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    let conflicts = match outcome {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };
    assert_eq!(
        conflicts.len(),
        1,
        "a binary file must never be textually merged"
    );
    let copy = &conflicts[0];
    assert_eq!(read(bdir.path(), "blob.bin"), remote_bytes);
    assert_eq!(
        read(bdir.path(), copy),
        local_bytes,
        "local binary preserved"
    );
}

// ---------------------------------------------------------------------------
// CONFLICT-COPY PATHS must be collision-proof: the one file whose entire purpose
// is "no edit is ever lost" must not itself be lost — not to a winner applied in
// the same batch, and not to a copy from a PREVIOUS reconcile (`§10`).
// ---------------------------------------------------------------------------

// The head legitimately carries a path equal to the conflict-copy name this Device
// is about to mint (a copy another Device resolved and committed). Phase A wrote the
// local loser there and phase B then materialized the remote winner straight over
// it: the preserved edit was destroyed.
#[tokio::test]
async fn conflict_copy_is_not_overwritten_by_a_remote_winner_at_the_same_path() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // The name this Device mints for a divergent notes.txt at base seq 0.
    let taken = "notes (conflicto devB, seq 0).txt";

    let base = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"BASE", false).await],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "notes.txt", b"REMOTE", false).await,
            file_entry_uploaded(&vault, taken, b"COPY FROM ANOTHER DEVICE", false).await,
        ],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "notes.txt", b"BASE");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-copy-clobber";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();

    // The local divergent edit (single line on every side -> no auto-merge).
    write(bdir.path(), "notes.txt", b"LOCAL");

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    let conflicts = match outcome {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };

    assert_eq!(read(bdir.path(), "notes.txt"), b"REMOTE");
    assert_eq!(
        read(bdir.path(), taken),
        b"COPY FROM ANOTHER DEVICE",
        "the head's own file must land at its path"
    );
    assert_eq!(conflicts.len(), 1);
    assert_ne!(
        conflicts[0], taken,
        "the copy must not be parked where the head writes"
    );
    assert_eq!(
        read(bdir.path(), &conflicts[0]),
        b"LOCAL",
        "the local edit must survive"
    );
}

// Two reconciles at the SAME base seq mint the identical conflict-copy name, so the
// second copy used to overwrite the first — losing the edit the first one rescued.
#[tokio::test]
async fn a_second_conflict_at_the_same_base_seq_does_not_overwrite_the_first_copy() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let base = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"BASE", false).await],
    )
    .await;
    let remote1 = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"REMOTE1", false).await],
    )
    .await;
    let remote2 = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "notes.txt", b"REMOTE2", false).await],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "notes.txt", b"BASE");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-copy-twice";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();

    // Round 1. `None` for the head seq keeps the base seq (as a head read with no
    // seq does), which is exactly what makes both rounds mint the same name.
    write(bdir.path(), "notes.txt", b"LOCAL1");
    let first = match ctx.apply_head(remote1, None, None).await.unwrap() {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };
    assert_eq!(first.len(), 1);

    // Round 2: a second divergence over the same path at the same base seq.
    write(bdir.path(), "notes.txt", b"LOCAL2");
    let second = match ctx.apply_head(remote2, None, None).await.unwrap() {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };
    assert_eq!(second.len(), 1);
    assert_ne!(
        first[0], second[0],
        "the second copy must not reuse the first copy's name"
    );

    // Both rescued edits are on disk, and the head's version holds the real path.
    assert_eq!(read(bdir.path(), &first[0]), b"LOCAL1");
    assert_eq!(read(bdir.path(), &second[0]), b"LOCAL2");
    assert_eq!(read(bdir.path(), "notes.txt"), b"REMOTE2");
}

// ---------------------------------------------------------------------------
// AUTO-MERGE + MODE: the exec bit is half of a File's content identity (`§5.1`),
// so fusing two text edits must reconcile it too.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auto_merged_edits_keep_a_local_chmod_plus_x() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base: run.sh non-executable. remote: appended a line, still non-executable.
    let base = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "run.sh", b"l1\nl2\n", false).await],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "run.sh", b"l1\nl2\nREMOTE\n", false).await],
    )
    .await;

    // Local change: `chmod +x` and NOTHING else. Both sides changed against base
    // (identity is pcid AND x), so this is a ConflictCopy whose contents auto-merge.
    let bdir = tempfile::tempdir().unwrap();
    write_mode(bdir.path(), "run.sh", b"l1\nl2\n", true);
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-merge-mode";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    let outcome = ctx.apply_head(remote, Some(1), None).await.unwrap();
    match outcome {
        PullOutcome::Reconciled { conflicts } => {
            assert!(
                conflicts.is_empty(),
                "a clean auto-merge writes no conflict copy: {conflicts:?}"
            );
        }
        other => panic!("expected Reconciled, got {other:?}"),
    }

    // The remote text edit landed ...
    assert_eq!(read(bdir.path(), "run.sh"), b"l1\nl2\nREMOTE\n");
    // ... and the local chmod +x was NOT silently dropped by the fuse.
    let meta = std::fs::symlink_metadata(bdir.path().join("run.sh")).unwrap();
    assert!(
        LinuxFs.exec_bit(&meta),
        "the local exec-bit change must survive the auto-merge"
    );
}

// ---------------------------------------------------------------------------
// CASEFOLD/NFC COLLISION must converge: the collision recurs on every round (each
// side keeps its own name), so minting a copy per round filled the Space forever
// (ADR 0006).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_casefold_collision_does_not_mint_a_new_conflict_copy_every_round() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let base = empty_root(&vault).await;
    let remote1 = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "README.md", b"REMOTE caps", false).await],
    )
    .await;
    // The head advances but still carries README.md, so the collision recurs.
    let remote2 = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "README.md", b"REMOTE caps", false).await,
            file_entry_uploaded(&vault, "other.txt", b"O0", false).await,
        ],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "readme.md", b"local lower");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-coll-loop";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    let first = match ctx.apply_head(remote1, Some(1), None).await.unwrap() {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };
    assert_eq!(first.len(), 1, "the colliding remote is moved aside once");
    assert_eq!(conflict_copies_in(bdir.path()).len(), 1);

    let second = match ctx.apply_head(remote2, Some(2), None).await.unwrap() {
        PullOutcome::Reconciled { conflicts } => conflicts,
        other => panic!("expected Reconciled, got {other:?}"),
    };
    assert!(
        second.is_empty(),
        "the collision is already parked aside; no new copy: {second:?}"
    );
    assert_eq!(
        conflict_copies_in(bdir.path()),
        first,
        "the Space must not accumulate one conflict copy per sync round"
    );
    // The round still applied the rest of the head, and kept both names' content.
    assert_eq!(read(bdir.path(), "other.txt"), b"O0");
    assert_eq!(read(bdir.path(), "readme.md"), b"local lower");
    assert_eq!(read(bdir.path(), &first[0]), b"REMOTE caps");
}

// ---------------------------------------------------------------------------
// A DIR→FILE replacement blocked by unsynced local content must be actionable, not
// a wedged Space: refusing to recursively delete is right (ADR 0019), abandoning
// the rest of the head and re-firing a bare ENOTEMPTY every 30s is not.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_dir_holding_unsynced_files_refuses_with_an_actionable_error_and_applies_the_rest() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // base: two directories + an unrelated file. head: BOTH dirs became files.
    let base = build_and_upload(
        &vault,
        vec![
            dir_entry("blocked"),
            dir_entry("clean"),
            file_entry_uploaded(&vault, "other.txt", b"O0", false).await,
        ],
    )
    .await;
    let head = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "blocked", b"now a file", false).await,
            file_entry_uploaded(&vault, "clean", b"also a file", false).await,
            file_entry_uploaded(&vault, "other.txt", b"O0", false).await,
        ],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(bdir.path().join("blocked")).unwrap();
    std::fs::create_dir_all(bdir.path().join("clean")).unwrap();
    write(bdir.path(), "other.txt", b"O0");
    // The content that makes the replacement impossible: never committed anywhere.
    write(bdir.path(), "blocked/keep.txt", b"never synced");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-dir-wedge";
    seed_state(&index, space_id, bdir.path(), base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    // No scan-prime: blocked/keep.txt is a local change -> the reconcile path.

    let err = ctx.apply_head(head, Some(1), None).await.unwrap_err();
    let message = err.to_string();
    assert!(
        matches!(err, ft_engine::EngineError::Refused(_)),
        "a blocked replacement must be a typed refusal, not a raw IO error: {message}"
    );
    assert!(
        message.contains("blocked"),
        "the error must name the directory that blocks the Space: {message}"
    );

    // Nothing was destroyed: the dir and its unsynced file are intact.
    assert!(bdir.path().join("blocked").is_dir());
    assert_eq!(read(bdir.path(), "blocked/keep.txt"), b"never synced");

    // And the REST of the batch was applied — `clean` (empty, alphabetically after
    // the blocked one) really became the head's file.
    assert_eq!(
        read(bdir.path(), "clean"),
        b"also a file",
        "one blocked directory must not abandon the rest of the head"
    );
}

// ---------------------------------------------------------------------------
// DURABILITY: the sync base must be recorded, or the next scan reads the applied
// remote content as local edits (`§9`).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failure_to_persist_the_sync_base_fails_the_pull_instead_of_continuing() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let base = empty_root(&vault).await;
    let head = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "a.txt", b"A0", false).await],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-nopersist";
    seed_state(&index, space_id, bdir.path(), base, -1);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    // Break the durability write the pull ends with (the mounted context already
    // holds the state it needs, so everything up to the base advance still runs).
    ctx.index
        .connection()
        .execute_batch("DROP TABLE space_state")
        .unwrap();

    let err = ctx.apply_head(head, Some(0), None).await.unwrap_err();
    assert!(
        matches!(err, ft_engine::EngineError::Index(_)),
        "a failed base persist must surface, not be swallowed: {err}"
    );
    // And the in-memory base must not be left ahead of what is stored, or the retry
    // would see head == base and short-circuit to UpToDate forever.
    assert_eq!(
        ctx.last_synced.root, base,
        "the base must roll back to what is (not) persisted"
    );
}

// ---------------------------------------------------------------------------
// TRUST BOUNDARY: Manifest entries are remote-controlled. ft-diff validates the
// ones IT applies; the reconcile's own arms (`remote_delete`, the copy writer, every
// join onto the Space root) need the same check here (`§5.2`).
// ---------------------------------------------------------------------------

// End-to-end fail-closed guarantee, now held by TWO independent layers (the
// Manifest read and the reconcile's own boundary): whichever one catches it, a
// Manifest naming a path outside the Space stops the pull with nothing applied.
#[tokio::test]
async fn a_manifest_entry_whose_path_escapes_the_space_root_aborts_the_pull_with_nothing_applied() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    // The base Manifest names a path that climbs out of the Space. `remote_delete`
    // would join it onto the root and unlink it — ft-diff never sees that path.
    let base = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "../victim.txt", b"outside", false).await,
            file_entry_uploaded(&vault, "keep.txt", b"K0", false).await,
        ],
    )
    .await;
    let remote = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "keep.txt", b"K0", false).await,
            file_entry_uploaded(&vault, "added.txt", b"A0", false).await,
        ],
    )
    .await;

    // The Space root is a SUBdirectory, so `..` names a real file we can watch.
    let home = tempfile::tempdir().unwrap();
    let victim = home.path().join("victim.txt");
    std::fs::write(&victim, b"outside the Space").unwrap();
    let sroot = home.path().join("space");
    std::fs::create_dir_all(&sroot).unwrap();
    write(&sroot, "keep.txt", b"K0");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-escape";
    seed_state(&index, space_id, &sroot, base, 0);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);
    ctx.scan().unwrap();
    // A local edit forces the reconcile path (where pull.rs acts on entries itself).
    write(&sroot, "keep.txt", b"K_LOCAL");

    let err = ctx.apply_head(remote, Some(1), None).await.unwrap_err();
    assert!(
        matches!(
            err,
            ft_engine::EngineError::Core(ft_core::Error::UnsafePath { .. })
        ),
        "an escaping entry must be a hard error: {err}"
    );

    // Fail-closed: nothing from that Manifest was applied and the base stands.
    assert!(
        !sroot.join("added.txt").exists(),
        "no part of a hostile Manifest may be applied"
    );
    assert_eq!(ctx.last_synced.root, base);
    assert_eq!(std::fs::read(&victim).unwrap(), b"outside the Space");
}

// ---------------------------------------------------------------------------
// The EMPTY-Manifest root page is built in process, never fetched: its cid is
// account-independent, so on a shared deployment one poisoned object would break
// the first pull of every fresh Space for every tenant.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_first_fast_forward_ignores_a_poisoned_empty_root_page() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let base = poisoned_empty_root(&vault).await;
    let head = build_and_upload(
        &vault,
        vec![
            file_entry_uploaded(&vault, "src/main.rs", b"fn main() {}\n", false).await,
            file_entry_uploaded(&vault, "README.md", b"# title\n", false).await,
        ],
    )
    .await;

    let bdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-poison-ff";
    seed_state(&index, space_id, bdir.path(), base, -1);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    let outcome = ctx.apply_head(head, Some(0), None).await.unwrap();
    assert_eq!(outcome, PullOutcome::FastForwarded { applied: 2 });
    assert_eq!(read(bdir.path(), "src/main.rs"), b"fn main() {}\n");
    assert_eq!(read(bdir.path(), "README.md"), b"# title\n");
    assert_eq!(ctx.last_synced.root, head);
}

#[tokio::test]
async fn a_first_reconcile_ignores_a_poisoned_empty_root_page() {
    let vdir = tempfile::tempdir().unwrap();
    let vault = FsVault::new(vdir.path());

    let base = poisoned_empty_root(&vault).await;
    let head = build_and_upload(
        &vault,
        vec![file_entry_uploaded(&vault, "remote.txt", b"R0", false).await],
    )
    .await;

    // A local file with no base makes this the reconcile path, which reads the base
    // Manifest itself instead of diffing it.
    let bdir = tempfile::tempdir().unwrap();
    write(bdir.path(), "local.txt", b"L0");
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-poison-rec";
    seed_state(&index, space_id, bdir.path(), base, -1);
    let mut ctx = mount(index, Box::new(FsVault::new(vdir.path())), space_id);

    let outcome = ctx.apply_head(head, Some(0), None).await.unwrap();
    assert!(matches!(outcome, PullOutcome::Reconciled { .. }));
    assert_eq!(read(bdir.path(), "remote.txt"), b"R0");
    assert_eq!(read(bdir.path(), "local.txt"), b"L0");
    assert_eq!(ctx.last_synced.root, head);
}
