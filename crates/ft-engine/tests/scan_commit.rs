//! Integration tests for the ft-engine WRITE path (scan + stage/commit, §7).
//!
//! These exercise the real crates end to end against an [`FsVault`] (no Docker,
//! no network) plus a live-backend test gated behind `#[ignore]`.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ft_core::{CanonicalPath, FileType};
use ft_engine::SpaceContext;
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::{Index, SpaceState};
use ft_vault::{FsVault, Vault, VaultResult};

// ---------------------------------------------------------------------------
// Test scaffolding
// ---------------------------------------------------------------------------

/// A [`Vault`] decorator that forwards to an inner vault and counts the PUTs by
/// key prefix — so a test can assert exactly how many Blocks/pages were uploaded
/// (the "only changed Blocks move" claim, §7 / Gate 5).
struct CountingVault {
    inner: FsVault,
    block_puts: Arc<AtomicUsize>,
    manifest_puts: Arc<AtomicUsize>,
    total_puts: Arc<AtomicUsize>,
}

impl CountingVault {
    fn new(inner: FsVault) -> Self {
        Self {
            inner,
            block_puts: Arc::new(AtomicUsize::new(0)),
            manifest_puts: Arc::new(AtomicUsize::new(0)),
            total_puts: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn counters(&self) -> (Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        (
            self.block_puts.clone(),
            self.manifest_puts.clone(),
            self.total_puts.clone(),
        )
    }
}

#[async_trait]
impl Vault for CountingVault {
    async fn head(&self, key: &str) -> VaultResult<bool> {
        self.inner.head(key).await
    }
    async fn get(&self, key: &str) -> VaultResult<Vec<u8>> {
        self.inner.get(key).await
    }
    async fn put(&self, key: &str, body: Vec<u8>) -> VaultResult<()> {
        self.total_puts.fetch_add(1, Ordering::SeqCst);
        if key.starts_with("blocks/") {
            self.block_puts.fetch_add(1, Ordering::SeqCst);
        } else if key.starts_with("manifest/") {
            self.manifest_puts.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.put(key, body).await
    }
}

/// Seeds a `space_state` row for `space_id` (a fresh, never-synced Space) so a
/// no-coordinator context can be `mount`ed for scan/stage tests.
fn seed_space_state(index: &Index, space_id: &str, local_root: &Path, chunk_secret: [u8; 32]) {
    index
        .upsert_space_state(&SpaceState {
            space_id: space_id.to_string(),
            // seq = -1: never synced, so a stage/commit is never short-circuited.
            last_synced_seq: -1,
            last_synced_root: ft_manifest::build(Vec::new()).root,
            last_synced_revision_id: None,
            chunk_secret: chunk_secret.to_vec(),
            dedup_secret: None,
            local_root_path: local_root.to_string_lossy().into_owned(),
        })
        .unwrap();
}

/// Mounts a scan/stage-only [`SpaceContext`] (no Coordinator) over an in-memory
/// index, a counting FsVault and the LinuxFs adapter.
fn mount_ctx(index: Index, vault: Box<dyn Vault>, space_id: &str) -> SpaceContext {
    SpaceContext::mount(
        index,
        vault,
        Box::new(LinuxFs),
        ft_engine::AccountId::new("acct-test"),
        ft_engine::DeviceId::new("dev-test"),
        ft_engine::SpaceId::new(space_id),
    )
    .unwrap()
}

fn write_file(root: &Path, rel: &str, bytes: &[u8], exec: bool) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    LinuxFs.write_bytes(&path, bytes, exec).unwrap();
}

fn entry_for<'a>(
    entries: &'a [(ft_core::CasefoldKey, ft_core::FileEntry)],
    path: &str,
) -> Option<&'a ft_core::FileEntry> {
    entries
        .iter()
        .map(|(_, e)| e)
        .find(|e| e.p.as_str() == path)
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

#[test]
fn scan_classifies_files_exec_and_skips_control_dir() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // A normal file, a nested file, an executable script, and a .filething/
    // control directory that MUST be ignored.
    write_file(root, "readme.md", b"hello world\n", false);
    write_file(root, "src/main.rs", b"fn main() {}\n", false);
    write_file(root, "scripts/run.sh", b"#!/bin/sh\necho hi\n", true);
    write_file(root, ".filething/state.db", b"internal control data", false);
    write_file(root, ".filething/nested/x", b"more internal", false);

    let vdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-scan";
    seed_space_state(&index, space_id, root, [0x11; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(vdir.path()));
    let ctx = mount_ctx(index, vault, space_id);

    let scan = ctx.scan().unwrap();

    // The three real files appear; nothing under .filething/ does.
    let paths: Vec<&str> = scan.entries.iter().map(|(_, e)| e.p.as_str()).collect();
    assert!(paths.contains(&"readme.md"));
    assert!(paths.contains(&"src/main.rs"));
    assert!(paths.contains(&"scripts/run.sh"));
    assert_eq!(
        scan.entries.len(),
        3,
        "control dir must be skipped: {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.starts_with(".filething")),
        "no .filething/ path may be synced"
    );

    // Canonical paths are forward-slash, relative, byte-exact.
    let main = entry_for(&scan.entries, "src/main.rs").unwrap();
    assert_eq!(main.t, FileType::File);
    assert!(!main.x);
    assert_eq!(main.sz, b"fn main() {}\n".len() as u64);

    // The exec bit round-trips on the script.
    let script = entry_for(&scan.entries, "scripts/run.sh").unwrap();
    assert!(script.x, "scripts/run.sh must have the exec bit set");

    // Each small file is exactly one Block, and the bk cid == whole-file pcid
    // (single chunk, MVP cid == pcid).
    assert_eq!(main.bk.len(), 1);
    assert_eq!(main.bk[0].as_bytes(), main.pcid.as_bytes());

    // The local index is populated for the synced paths.
    let idx_entry = ctx
        .index
        .get_entry(space_id, &CanonicalPath("src/main.rs".to_string()))
        .unwrap()
        .unwrap();
    assert_eq!(idx_entry.file_type, FileType::File);
    assert_eq!(idx_entry.blocks.len(), 1);
    assert_eq!(idx_entry.blocks[0].cid, main.bk[0]);
    // scan records the path row + its ordered Block list, but does NOT mark the
    // Blocks present in `local_block` — that is the commit's upload-dedup cache.
    assert!(
        !ctx.index.has_block(space_id, &main.bk[0]).unwrap(),
        "scan must not pre-mark Blocks as uploaded"
    );

    // A control-dir path is NOT in the index.
    assert!(ctx
        .index
        .get_entry(space_id, &CanonicalPath(".filething/state.db".to_string()))
        .unwrap()
        .is_none());
}

#[test]
fn scan_large_file_produces_multiple_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // > 256 KiB of pseudo-random bytes (deterministic) so FastCDC cuts several
    // chunks: the bk must have more than one Block.
    let big = pseudo_random(700 * 1024, 0xC0FFEE);
    write_file(root, "data/big.bin", &big, false);
    write_file(root, "small.txt", b"tiny", false);

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-big";
    seed_space_state(&index, space_id, root, [0x22; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let scan = ctx.scan().unwrap();
    let big_entry = entry_for(&scan.entries, "data/big.bin").unwrap();
    assert!(
        big_entry.bk.len() > 1,
        "a >256 KiB file must chunk into several Blocks, got {}",
        big_entry.bk.len()
    );
    assert_eq!(big_entry.sz, big.len() as u64);

    // Reassembling the bk payloads reproduces the file exactly: read each Block
    // back out of blocks_to_upload, strip the 64-byte header, concatenate.
    let mut reassembled = Vec::new();
    for cid in &big_entry.bk {
        let (_, obj) = scan
            .blocks_to_upload
            .iter()
            .find(|(c, _)| c == cid)
            .expect("every bk cid must be in blocks_to_upload");
        let (_, payload) = ft_block::decode(obj).unwrap();
        reassembled.extend_from_slice(&payload);
    }
    assert_eq!(
        reassembled, big,
        "concatenated Block payloads must equal the file"
    );

    // The small file is still a single Block.
    let small = entry_for(&scan.entries, "small.txt").unwrap();
    assert_eq!(small.bk.len(), 1);
}

#[test]
fn scan_symlink_preserve_vs_local_only_and_derived() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, "docs/readme.md", b"docs", false);
    // A relative symlink that stays inside the Space -> Preserve.
    std::os::unix::fs::symlink("docs/readme.md", root.join("link-inside")).unwrap();
    // An absolute symlink -> LocalOnly (not in the Manifest).
    std::os::unix::fs::symlink("/etc/hostname", root.join("link-abs")).unwrap();
    // A derived directory -> one t=2 entry, not descended.
    write_file(
        root,
        "node_modules/dep/index.js",
        b"module.exports={}",
        false,
    );

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-syms";
    seed_space_state(&index, space_id, root, [0x33; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let scan = ctx.scan().unwrap();
    let paths: Vec<&str> = scan.entries.iter().map(|(_, e)| e.p.as_str()).collect();

    // Preserved symlink is in the Manifest with lt set.
    let preserved = entry_for(&scan.entries, "link-inside").unwrap();
    assert_eq!(preserved.t, FileType::Symlink);
    assert_eq!(preserved.lt.as_deref(), Some("docs/readme.md"));

    // Absolute symlink is local-only: NOT in the Manifest, but recorded in the
    // index with local_only = true.
    assert!(
        !paths.contains(&"link-abs"),
        "absolute symlink must not enter the Manifest"
    );
    let abs_row = ctx
        .index
        .get_entry(space_id, &CanonicalPath("link-abs".to_string()))
        .unwrap()
        .unwrap();
    assert!(abs_row.local_only);

    // node_modules yields exactly ONE derived entry; its contents are not walked.
    let derived: Vec<&str> = paths
        .iter()
        .copied()
        .filter(|p| p.starts_with("node_modules"))
        .collect();
    assert_eq!(
        derived,
        vec!["node_modules"],
        "one derived entry, not descended"
    );
    let nm = entry_for(&scan.entries, "node_modules").unwrap();
    assert_eq!(nm.t, FileType::Derived);
    assert!(nm.bk.is_empty(), "derived entries carry no Blocks");
}

#[test]
fn scan_drops_index_rows_for_deleted_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "keep.txt", b"keep", false);
    write_file(root, "gone.txt", b"gone", false);

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-del";
    seed_space_state(&index, space_id, root, [0x44; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    // First scan records both files.
    let first = ctx.scan().unwrap();
    assert_eq!(first.entries.len(), 2);

    // Delete one on disk, re-scan: it drops from both the entries and the index.
    std::fs::remove_file(root.join("gone.txt")).unwrap();
    let second = ctx.scan().unwrap();
    let paths: Vec<&str> = second.entries.iter().map(|(_, e)| e.p.as_str()).collect();
    assert_eq!(paths, vec!["keep.txt"]);
    assert!(ctx
        .index
        .get_entry(space_id, &CanonicalPath("gone.txt".to_string()))
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// stage_to_vault (the network-free Vault side of commit, §7 steps 1-4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stage_uploads_blocks_and_pages_and_root_matches_build() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "a.rs", b"fn a() {}\n", false);
    write_file(root, "b/c.rs", b"fn c() {}\n", false);

    let vdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-stage";
    seed_space_state(&index, space_id, root, [0x55; 32]);
    let counting = CountingVault::new(FsVault::new(vdir.path()));
    let (block_puts, manifest_puts, _total) = counting.counters();
    let vault: Box<dyn Vault> = Box::new(counting);
    let ctx = mount_ctx(index, vault, space_id);

    let staged = ctx.stage_to_vault().await.unwrap();

    // The staged root equals ft_manifest::build of the SAME scan.
    let rebuilt = ft_manifest::build(staged.scan.entries.clone());
    assert_eq!(staged.root, rebuilt.root);
    assert_eq!(staged.root, staged.scan.manifest_root());

    // Two small files -> two Blocks, one leaf page.
    assert_eq!(block_puts.load(Ordering::SeqCst), 2);
    assert_eq!(manifest_puts.load(Ordering::SeqCst), 1);
    assert_eq!(staged.blocks_uploaded, 2);
    assert_eq!(staged.pages, 1);

    // Every Block object and the root page object exist in the Vault (head=true).
    for (_, e) in &staged.scan.entries {
        for cid in &e.bk {
            assert!(
                ctx.vault.head(&ft_hash::block_key(cid)).await.unwrap(),
                "blocks/<cid> must exist after stage"
            );
        }
    }
    assert!(
        ctx.vault
            .head(&ft_hash::manifest_key(&staged.root))
            .await
            .unwrap(),
        "manifest/<root> must exist after stage"
    );
}

#[tokio::test]
async fn restage_after_one_file_change_uploads_only_new_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Several files so the Manifest is non-trivial; one will change.
    write_file(root, "one.txt", b"file one contents\n", false);
    write_file(root, "two.txt", b"file two contents\n", false);
    write_file(root, "three.txt", b"file three contents\n", false);

    let vdir = tempfile::tempdir().unwrap();
    let index = Index::open_in_memory().unwrap();
    let space_id = "space-delta";
    seed_space_state(&index, space_id, root, [0x66; 32]);
    let counting = CountingVault::new(FsVault::new(vdir.path()));
    let (block_puts, _manifest_puts, _total) = counting.counters();
    let vault: Box<dyn Vault> = Box::new(counting);
    let ctx = mount_ctx(index, vault, space_id);

    // First stage uploads all three Blocks.
    let first = ctx.stage_to_vault().await.unwrap();
    assert_eq!(first.blocks_uploaded, 3);
    assert_eq!(block_puts.load(Ordering::SeqCst), 3);

    // Change exactly one file; re-stage. Only the ONE new Block uploads (the
    // other two dedup against the local index — Gate 5).
    write_file(root, "two.txt", b"file two CHANGED contents\n", false);
    let block_puts_before = block_puts.load(Ordering::SeqCst);
    let second = ctx.stage_to_vault().await.unwrap();
    assert_eq!(
        second.blocks_uploaded, 1,
        "only the changed file's new Block should upload"
    );
    assert_eq!(
        block_puts.load(Ordering::SeqCst) - block_puts_before,
        1,
        "exactly one new blocks/ PUT after a one-file change"
    );

    // The new root differs from the first (the tree changed).
    assert_ne!(first.root, second.root);
}

// ---------------------------------------------------------------------------
// LIVE integration — requires a self-hosted Convex backend (§7 full commit).
// ---------------------------------------------------------------------------

/// Full commit against a live Coordinator: bootstrap -> init_space (toy dir) ->
/// the Space head advances -> a second commit with no changes is NoChange.
///
/// `#[ignore]`d so the normal build never needs the network. Run with infra up:
///
/// ```text
/// eval "$(infra/scripts/print-env.sh --exports)"   # or source infra/.env
/// cargo test -p ft-engine --test scan_commit -- --ignored commit_against_live_backend
/// ```
#[tokio::test]
#[ignore = "requires a live self-hosted Convex backend + an S3/MinIO or FsVault"]
async fn commit_against_live_backend() {
    use convex::ConvexClient;
    use ft_engine::Coordinator;

    let url = std::env::var("CONVEX_SELF_HOSTED_URL")
        .unwrap_or_else(|_| "http://localhost:3210".to_string());
    let admin_key = std::env::var("CONVEX_SELF_HOSTED_ADMIN_KEY")
        .expect("CONVEX_SELF_HOSTED_ADMIN_KEY must be set to run this test");

    // Connect as a deployment admin (same wiring as the ft-coordinator live test).
    let mut client = ConvexClient::new(&url)
        .await
        .expect("connect to self-hosted Convex");
    client.set_admin_auth(admin_key, None).await;
    let mut coord = Coordinator::from_client(client);

    // bootstrap: first Account + Device.
    let boot = coord.bootstrap("it-engine").await.expect("bootstrap");

    // A toy dir with 2-3 files + an FsVault temp dir (no MinIO needed).
    let work = tempfile::tempdir().unwrap();
    let toy = work.path().join("toy");
    write_file(&toy, "hello.txt", b"hello from filething\n", false);
    write_file(&toy, "src/lib.rs", b"pub fn x() {}\n", false);
    write_file(&toy, "run.sh", b"#!/bin/sh\necho ok\n", true);

    let index = Index::open_in_memory().unwrap();
    let vault: Box<dyn Vault> = Box::new(FsVault::new(work.path().join("vault")));

    // init_space: writes the meta blob, create_space, persists state, first
    // commit (seq 0).
    let mut ctx = SpaceContext::init_space(
        index,
        vault,
        coord.clone(),
        boot.account_id.clone(),
        boot.device_id.clone(),
        b"it-engine-space",
        toy,
    )
    .await
    .expect("init_space must succeed against the live backend");

    let first_seq = ctx.last_synced.seq;
    assert_eq!(first_seq, 0, "first Revision seq should be 0");
    let first_root = ctx.last_synced.root;

    // The Space head advanced to the committed Revision.
    let space = coord
        .get_space(&ctx.space_id)
        .await
        .expect("get_space after init");
    assert!(
        space.head_revision_id.is_some(),
        "the Space head must have advanced after init_space"
    );

    // A second commit with NO changes is NoChange (and does not touch Convex).
    // expected_base is the current head id.
    let head_id = space.head_revision_id.clone();
    let outcome = ctx
        .commit(head_id)
        .await
        .expect("second commit must succeed");
    assert_eq!(
        outcome,
        ft_engine::CommitOutcome::NoChange,
        "an unchanged tree must commit as NoChange"
    );
    // The base did not move.
    assert_eq!(ctx.last_synced.seq, first_seq);
    assert_eq!(ctx.last_synced.root, first_root);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Deterministic pseudo-random bytes (xorshift64*) so a "large file" is
/// identical on every machine without pulling `rand` into the test.
fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.truncate(n);
    out
}
