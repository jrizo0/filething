//! Live end-to-end CLI flow: two Devices via the real `filething` binary
//! (`docs/BUILD-PLAN.md §3` verification).
//!
//! `#[ignore]`d so the normal `cargo test` never needs the network. It drives the
//! actual compiled binary (`CARGO_BIN_EXE_filething`) against a live self-hosted
//! Convex (`CONVEX_SELF_HOSTED_URL` / `_ADMIN_KEY`) and a live S3/MinIO Vault
//! (`S3_*`), with two separate `FILETHING_HOME` config homes simulating two
//! Devices on one machine — the MVP demo topology.
//!
//! Run with infra up (`source infra/.env`):
//!
//! ```text
//! set -a && . infra/.env && set +a
//! cargo test -p filething --test cli_flow -- --ignored two_device_cli_flow
//! ```
//!
//! Flow: login(A bootstrap) -> init(dirA with a file) -> login(B --code) ->
//! clone(B) -> assert B has A's file -> edit in A -> sync(A) -> sync(B) ->
//! assert B reflects the edit.

use std::path::Path;
use std::process::{Command, Output};

/// Runs the `filething` binary with `FILETHING_HOME` set to `home`, inheriting
/// the rest of the environment (the live Convex + S3 vars). Returns the captured
/// output; the caller asserts success.
fn run(home: &Path, args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_filething");
    Command::new(bin)
        .args(args)
        .env("FILETHING_HOME", home)
        .output()
        .expect("spawn filething")
}

/// Runs `filething` and panics with stderr if it did not exit 0.
fn run_ok(home: &Path, args: &[&str]) -> String {
    let out = run(home, args);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "`filething {}` failed: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        args.join(" "),
        out.status.code(),
    );
    stdout
}

/// Extracts the pairing code printed by `login` (bootstrap). The bootstrap output
/// prints the code on its own indented line after the "Pairing code" heading; the
/// code itself is the last non-empty line.
fn parse_pairing_code(stdout: &str) -> String {
    stdout
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .expect("pairing code line")
        .to_string()
}

#[test]
#[ignore = "requires live self-hosted Convex (CONVEX_SELF_HOSTED_*) + S3 (S3_*) infra"]
fn two_device_cli_flow() {
    // Skip cleanly if the infra env is absent (so an accidental --ignored run
    // without infra does not hard-fail on a missing admin key).
    if std::env::var("CONVEX_SELF_HOSTED_ADMIN_KEY").is_err() || std::env::var("S3_BUCKET").is_err()
    {
        eprintln!("infra env not set; skipping two_device_cli_flow");
        return;
    }

    let work = tempfile::tempdir().unwrap();
    let home_a = work.path().join("home-a");
    let home_b = work.path().join("home-b");
    let dir_a = work.path().join("space-a");
    let dir_b = work.path().join("space-b");

    // Device A: bootstrap login (first Device of a new Account).
    let boot = run_ok(&home_a, &["login", "--name", "device-a"]);
    let code = parse_pairing_code(&boot);
    assert!(!code.is_empty(), "bootstrap must print a pairing code");

    // Device A: init a Space with one file.
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::write(dir_a.join("hello.txt"), b"hello from A\n").unwrap();
    let init_out = run_ok(
        &home_a,
        &["init", dir_a.to_str().unwrap(), "--name", "cli-space"],
    );
    // The init output prints "Created Space <id>"; pull the id out for clone.
    let space_id = init_out
        .lines()
        .find_map(|l| l.strip_prefix("Created Space "))
        .expect("init must print the Space id")
        .trim()
        .to_string();
    assert!(!space_id.is_empty());

    // Device B: claim into the same Account with A's pairing code.
    run_ok(&home_b, &["login", "--code", &code, "--name", "device-b"]);

    // Device B: clone the Space. It must materialize A's file.
    run_ok(&home_b, &["clone", &space_id, dir_b.to_str().unwrap()]);
    assert_eq!(
        std::fs::read(dir_b.join("hello.txt")).expect("B should have hello.txt"),
        b"hello from A\n",
    );

    // Device A: edit the file, then one-shot sync (commit).
    std::fs::write(dir_a.join("hello.txt"), b"hello from A, EDITED\n").unwrap();
    let sync_a = run_ok(&home_a, &["sync", dir_a.to_str().unwrap()]);
    assert!(
        sync_a.contains("commit: committed"),
        "A sync should commit; got:\n{sync_a}"
    );

    // Device B: sync pulls A's edit.
    let sync_b = run_ok(&home_b, &["sync", dir_b.to_str().unwrap()]);
    assert!(
        sync_b.contains("pull: fast-forwarded") || sync_b.contains("pull: reconciled"),
        "B sync should pull A's edit; got:\n{sync_b}"
    );
    assert_eq!(
        std::fs::read(dir_b.join("hello.txt")).expect("B reads edited file"),
        b"hello from A, EDITED\n",
    );

    // status + ls smoke-checks on B.
    let status_b = run_ok(&home_b, &["status", dir_b.to_str().unwrap()]);
    assert!(status_b.contains(&space_id), "status should name the Space");
    let ls_b = run_ok(&home_b, &["ls", dir_b.to_str().unwrap()]);
    assert!(ls_b.contains("hello.txt"), "ls should list the synced file");
}
