//! Live end-to-end test: two Devices over one Convex + one shared FsVault.
//!
//! `#[ignore]`d so the normal build never needs the network. Run with infra up
//! (`source infra/.env`):
//!
//! ```text
//! set -a && . infra/.env && set +a
//! cargo test -p ft-engine --test two_devices -- --ignored two_devices_end_to_end
//! ```

use std::path::Path;

use ft_engine::{CommitOutcome, PullOutcome, SpaceContext};
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::Index;
use ft_vault::{FsVault, Vault};

fn write(root: &Path, rel: &str, bytes: &[u8], exec: bool) {
    let mut p = root.to_path_buf();
    for part in rel.split('/') {
        p.push(part);
    }
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    LinuxFs.write_bytes(&p, bytes, exec).unwrap();
}

fn read(root: &Path, rel: &str) -> Vec<u8> {
    let mut p = root.to_path_buf();
    for part in rel.split('/') {
        p.push(part);
    }
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// A/B share ONE FsVault (the data plane) and ONE Convex (the control plane);
/// each has its own local dir + index — two Devices on one machine, exactly the
/// MVP demo topology (`docs/BUILD-PLAN.md §0`).
#[tokio::test]
#[ignore = "requires a live self-hosted Convex backend (CONVEX_SELF_HOSTED_URL / _ADMIN_KEY)"]
async fn two_devices_end_to_end() {
    use convex::ConvexClient;
    use ft_engine::Coordinator;

    let url = std::env::var("CONVEX_SELF_HOSTED_URL")
        .unwrap_or_else(|_| "http://localhost:3210".to_string());
    let admin_key = std::env::var("CONVEX_SELF_HOSTED_ADMIN_KEY")
        .expect("CONVEX_SELF_HOSTED_ADMIN_KEY must be set to run this test");

    let connect = || async {
        let mut client = ConvexClient::new(&url).await.expect("connect to Convex");
        client.set_admin_auth(admin_key.clone(), None).await;
        Coordinator::from_client(client)
    };

    // Shared vault dir for both Devices; per-Device local dirs + indexes.
    let work = tempfile::tempdir().unwrap();
    let vault_dir = work.path().join("vault");
    let dir_a = work.path().join("device-a");
    let dir_b = work.path().join("device-b");
    std::fs::create_dir_all(&dir_a).unwrap();

    // Bootstrap one Account + Device A.
    let mut coord_a = connect().await;
    let boot = coord_a.bootstrap("device-a").await.expect("bootstrap");

    // Device A: init_space with a toy tree.
    write(&dir_a, "hello.txt", b"hello from A\n", false);
    write(&dir_a, "src/lib.rs", b"pub fn x() {}\n", false);
    write(&dir_a, "run.sh", b"#!/bin/sh\necho ok\n", true);

    let index_a = Index::open_in_memory().unwrap();
    let vault_a: Box<dyn Vault> = Box::new(FsVault::new(&vault_dir));
    let mut ctx_a = SpaceContext::init_space(
        index_a,
        vault_a,
        coord_a.clone(),
        boot.account_id.clone(),
        boot.device_id.clone(),
        b"two-device-space",
        &dir_a,
    )
    .await
    .expect("A init_space");
    let space_id = ctx_a.space_id.clone();

    // Device B: clone_space into a fresh dir, sharing the SAME vault + account.
    // (One account, multi-seat, in the v1 model — B reuses A's device id here for
    // simplicity; conflict-copy names would differ in a real pairing.)
    let index_b = Index::open_in_memory().unwrap();
    let vault_b: Box<dyn Vault> = Box::new(FsVault::new(&vault_dir));
    let mut ctx_b = SpaceContext::clone_space(
        index_b,
        vault_b,
        coord_a.clone(),
        boot.account_id.clone(),
        boot.device_id.clone(),
        space_id.clone(),
        &dir_b,
    )
    .await
    .expect("B clone_space");

    // B's tree == A's tree, byte for byte.
    assert_eq!(read(&dir_b, "hello.txt"), read(&dir_a, "hello.txt"));
    assert_eq!(read(&dir_b, "src/lib.rs"), read(&dir_a, "src/lib.rs"));
    assert_eq!(read(&dir_b, "run.sh"), read(&dir_a, "run.sh"));
    let meta = std::fs::symlink_metadata(dir_b.join("run.sh")).unwrap();
    assert!(LinuxFs.exec_bit(&meta), "B must preserve the exec bit");

    // A edits one file and commits.
    write(&dir_a, "hello.txt", b"hello from A, EDITED\n", false);
    match ctx_a.commit_and_reconcile().await.expect("A commit edit") {
        CommitOutcome::Committed { .. } => {}
        other => panic!("expected A's edit to commit, got {other:?}"),
    }

    // B pulls and reflects the change.
    match ctx_b.pull().await.expect("B pull A's edit") {
        PullOutcome::FastForwarded { .. } => {}
        other => panic!("expected B to fast-forward A's edit, got {other:?}"),
    }
    assert_eq!(read(&dir_b, "hello.txt"), b"hello from A, EDITED\n");

    // Bidirectional: B edits a DIFFERENT file and commits; A pulls and reflects it.
    write(
        &dir_b,
        "src/lib.rs",
        b"pub fn x() { /* from B */ }\n",
        false,
    );
    match ctx_b.commit_and_reconcile().await.expect("B commit edit") {
        CommitOutcome::Committed { .. } => {}
        other => panic!("expected B's edit to commit, got {other:?}"),
    }
    match ctx_a.pull().await.expect("A pull B's edit") {
        PullOutcome::FastForwarded { .. } => {}
        other => panic!("expected A to fast-forward B's edit, got {other:?}"),
    }
    assert_eq!(read(&dir_a, "src/lib.rs"), b"pub fn x() { /* from B */ }\n");

    // No phantom conflict copies were created on either side (no false conflicts).
    let count_conflicts = |dir: &Path| -> usize { walkdir_count(dir, "(conflicto ") };
    assert_eq!(count_conflicts(&dir_a), 0, "A has no false conflict copies");
    assert_eq!(count_conflicts(&dir_b), 0, "B has no false conflict copies");
}

/// Counts files under `dir` whose name contains `needle` (used to assert there
/// are no conflict copies).
fn walkdir_count(dir: &Path, needle: &str) -> usize {
    let mut n = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(needle))
            {
                n += 1;
            }
        }
    }
    n
}
