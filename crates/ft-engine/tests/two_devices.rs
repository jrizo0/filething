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
#[ignore = "requires a live self-hosted Convex backend + a user JWT (FILETHING_TEST_JWT)"]
async fn two_devices_end_to_end() {
    use convex::ConvexClient;
    use ft_core::SpaceCrypto;
    use ft_engine::Coordinator;

    let url = std::env::var("CONVEX_SELF_HOSTED_URL")
        .unwrap_or_else(|_| "http://localhost:3210".to_string());
    // Since Fase 3 the contract is authenticated (`ctx.auth`): a real user JWT
    // (Better Auth, Convex audience) is required, not the deployment admin key.
    // Obtain one the way the CLI does (see `apps/cli` login).
    let jwt = std::env::var("FILETHING_TEST_JWT")
        .expect("FILETHING_TEST_JWT (a Better Auth Convex-audience JWT) must be set");

    let connect = || async {
        let mut client = ConvexClient::new(&url).await.expect("connect to Convex");
        client.set_auth(Some(jwt.clone())).await;
        Coordinator::from_client(client)
    };

    // Shared vault dir for both Devices; per-Device local dirs + indexes.
    let work = tempfile::tempdir().unwrap();
    let vault_dir = work.path().join("vault");
    let dir_a = work.path().join("device-a");
    let dir_b = work.path().join("device-b");
    std::fs::create_dir_all(&dir_a).unwrap();

    // ensureDevice: get-or-create the Account + Device A, and the escrow dedup
    // secret every Device of this Account shares.
    let mut coord_a = connect().await;
    let ensured = coord_a
        .ensure_device("device-a", &[7u8; 32])
        .await
        .expect("ensure_device");

    // Device A: init_space with a toy tree. A client-generated space_key turns on
    // `alg=1` encryption for the whole Space.
    write(&dir_a, "hello.txt", b"hello from A\n", false);
    write(&dir_a, "src/lib.rs", b"pub fn x() {}\n", false);
    write(&dir_a, "run.sh", b"#!/bin/sh\necho ok\n", true);

    let crypto = SpaceCrypto {
        dedup_secret: ensured.dedup_secret,
        space_key: [42u8; 32],
        // `init_space` stamps the real id from `create_space`; placeholder here.
        space_id: String::new(),
    };
    let index_a = Index::open_in_memory().unwrap();
    let vault_a: Box<dyn Vault> = Box::new(FsVault::new(&vault_dir));
    let mut ctx_a = SpaceContext::init_space(
        index_a,
        vault_a,
        coord_a.clone(),
        ensured.account_id.clone(),
        ensured.device_id.clone(),
        b"two-device-space",
        &dir_a,
        crypto,
    )
    .await
    .expect("A init_space");
    let space_id = ctx_a.space_id.clone();

    // Device B: clone_space into a fresh dir, sharing the SAME vault + account.
    // (One account, multi-seat, in the v1 model — B reuses A's device id here for
    // simplicity; conflict-copy names would differ in a real pairing.) B fetches
    // the escrowed space_key from the Space doc and decrypts with the shared
    // dedup_secret.
    let index_b = Index::open_in_memory().unwrap();
    let vault_b: Box<dyn Vault> = Box::new(FsVault::new(&vault_dir));
    let mut ctx_b = SpaceContext::clone_space(
        index_b,
        vault_b,
        coord_a.clone(),
        ensured.account_id.clone(),
        ensured.device_id.clone(),
        space_id.clone(),
        &dir_b,
        ensured.dedup_secret,
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
    match ctx_a.commit_and_reconcile().await.expect("A commit edit").0 {
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
    match ctx_b.commit_and_reconcile().await.expect("B commit edit").0 {
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

/// Regression for issue #9: a divergent edit that surfaces only as a CAS conflict
/// on commit (the common case — B never pulled A's edit) must have its
/// conflict copy COUNTED. `commit_and_reconcile` runs the reconciling pull
/// internally, so before the fix the returned outcome (and thus the daemon's
/// `conflicts` metric) hid it. Here we assert `commit_and_reconcile` surfaces the
/// conflict copies its retry pull wrote, and that a copy landed on disk.
///
/// Needs the same live infra as `two_devices_end_to_end` (see its docs).
#[tokio::test]
#[ignore = "requires a live self-hosted Convex backend + a user JWT (FILETHING_TEST_JWT)"]
async fn commit_retry_reconcile_conflicts_are_counted() {
    use convex::ConvexClient;
    use ft_core::SpaceCrypto;
    use ft_engine::Coordinator;

    let url = std::env::var("CONVEX_SELF_HOSTED_URL")
        .unwrap_or_else(|_| "http://localhost:3210".to_string());
    let jwt = std::env::var("FILETHING_TEST_JWT")
        .expect("FILETHING_TEST_JWT (a Better Auth Convex-audience JWT) must be set");

    let connect = || async {
        let mut client = ConvexClient::new(&url).await.expect("connect to Convex");
        client.set_auth(Some(jwt.clone())).await;
        Coordinator::from_client(client)
    };

    let work = tempfile::tempdir().unwrap();
    let vault_dir = work.path().join("vault");
    let dir_a = work.path().join("device-a");
    let dir_b = work.path().join("device-b");
    std::fs::create_dir_all(&dir_a).unwrap();

    let mut coord_a = connect().await;
    let ensured = coord_a
        .ensure_device("device-a", &[9u8; 32])
        .await
        .expect("ensure_device");

    // A starts a Space with one shared file; both Devices converge on seq 0.
    write(&dir_a, "shared.txt", b"base\n", false);
    let crypto = SpaceCrypto {
        dedup_secret: ensured.dedup_secret,
        space_key: [24u8; 32],
        space_id: String::new(),
    };
    let index_a = Index::open_in_memory().unwrap();
    let vault_a: Box<dyn Vault> = Box::new(FsVault::new(&vault_dir));
    let mut ctx_a = SpaceContext::init_space(
        index_a,
        vault_a,
        coord_a.clone(),
        ensured.account_id.clone(),
        ensured.device_id.clone(),
        b"conflict-count-space",
        &dir_a,
        crypto,
    )
    .await
    .expect("A init_space");
    let space_id = ctx_a.space_id.clone();

    let index_b = Index::open_in_memory().unwrap();
    let vault_b: Box<dyn Vault> = Box::new(FsVault::new(&vault_dir));
    let mut ctx_b = SpaceContext::clone_space(
        index_b,
        vault_b,
        coord_a.clone(),
        ensured.account_id.clone(),
        ensured.device_id.clone(),
        space_id.clone(),
        &dir_b,
        ensured.dedup_secret,
    )
    .await
    .expect("B clone_space");

    // A edits the shared file and commits: the head advances to seq 1.
    write(&dir_a, "shared.txt", b"edited by A\n", false);
    match ctx_a.commit_and_reconcile().await.expect("A commit").0 {
        CommitOutcome::Committed { .. } => {}
        other => panic!("expected A to commit, got {other:?}"),
    }

    // B edits the SAME file WITHOUT pulling A's change, then commits. B's base is
    // still seq 0, so the commit CAS-conflicts; commit_and_reconcile pulls (which
    // reconciles B's edit against A's, writing a conflict copy) and retries.
    write(&dir_b, "shared.txt", b"edited by B\n", false);
    let (outcome, conflicts) = ctx_b.commit_and_reconcile().await.expect("B commit");
    match outcome {
        CommitOutcome::Committed { .. } => {}
        other => panic!("expected B to converge after the retry, got {other:?}"),
    }

    // The crux: the retry pull's conflict copy is surfaced (not discarded), so the
    // daemon can count it. Before the fix this vec was unreachable and `conflicts`
    // stayed 0.
    assert_eq!(
        conflicts.len(),
        1,
        "the CAS-conflict retry reconcile must surface its one conflict copy"
    );
    assert_eq!(
        walkdir_count(&dir_b, "(conflicto "),
        1,
        "the conflict copy must exist on B's disk"
    );
    assert_eq!(
        read(&dir_b, &conflicts[0]),
        b"edited by B\n",
        "B's losing edit is preserved in the conflict copy"
    );
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
