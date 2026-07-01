//! Integration tests for built-in platform-junk exclusion on the scanner side
//! (ADR 0011). `.DS_Store` / `Thumbs.db` / `desktop.ini` are OS sidecars that
//! must NEVER enter the Manifest, in any directory, regardless of the user's
//! `.filethingignore`. The match is by EXACT entry name (case-sensitive, no
//! glob), so a look-alike (`DS_Store`, `.DS_Store.bak`, `mythumbs.db`) still
//! syncs.
//!
//! These mount an offline (no-Coordinator) [`SpaceContext`] over an in-memory
//! index + a temp `FsVault`, mirroring the scaffolding in `scan_commit.rs`.

use std::path::Path;

use ft_core::{CanonicalPath, FileType};
use ft_engine::SpaceContext;
use ft_fsmap::{LinuxFs, OsFs};
use ft_index::{Index, SpaceState};
use ft_vault::{FsVault, Vault};

// ---------------------------------------------------------------------------
// Test scaffolding (same shape as scan_commit.rs)
// ---------------------------------------------------------------------------

/// Seeds a fresh, never-synced `space_state` row so an offline context mounts.
fn seed_space_state(index: &Index, space_id: &str, local_root: &Path, chunk_secret: [u8; 32]) {
    index
        .upsert_space_state(&SpaceState {
            space_id: space_id.to_string(),
            last_synced_seq: -1,
            last_synced_root: ft_manifest::build(Vec::new()).root,
            last_synced_revision_id: None,
            chunk_secret: chunk_secret.to_vec(),
            dedup_secret: None,
            local_root_path: local_root.to_string_lossy().into_owned(),
        })
        .unwrap();
}

/// Mounts a scan-only [`SpaceContext`] (no Coordinator).
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

fn write_file(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    LinuxFs.write_bytes(&path, bytes, false).unwrap();
}

/// The canonical paths in a scan's Manifest entries.
fn scanned_paths(ctx: &SpaceContext) -> Vec<String> {
    ctx.scan()
        .unwrap()
        .entries
        .iter()
        .map(|(_, e)| e.p.as_str().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[test]
fn scan_excludes_ds_store_in_root_and_subdir_keeps_normal_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, "readme.md", b"hello\n");
    write_file(root, "src/main.rs", b"fn main() {}\n");
    // .DS_Store in the root AND in a subdirectory — both must vanish.
    write_file(root, ".DS_Store", b"junk\0finder");
    write_file(root, "src/.DS_Store", b"junk\0finder");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-dsstore";
    seed_space_state(&index, space_id, root, [0x11; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let paths = scanned_paths(&ctx);

    // Normal files survive.
    assert!(paths.contains(&"readme.md".to_string()));
    assert!(paths.contains(&"src/main.rs".to_string()));
    // No .DS_Store anywhere.
    assert!(
        !paths.iter().any(|p| p.ends_with(".DS_Store")),
        "no .DS_Store may enter the Manifest: {paths:?}"
    );
    assert_eq!(paths.len(), 2, "only the two real files: {paths:?}");

    // And it is not recorded in the local index either.
    assert!(ctx
        .index
        .get_entry(space_id, &CanonicalPath(".DS_Store".to_string()))
        .unwrap()
        .is_none());
    assert!(ctx
        .index
        .get_entry(space_id, &CanonicalPath("src/.DS_Store".to_string()))
        .unwrap()
        .is_none());
}

#[test]
fn scan_excludes_thumbs_db_and_desktop_ini() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, "photo.jpg", b"\xff\xd8\xff\xe0jpeg");
    write_file(root, "gallery/pic.png", b"\x89PNGpng");
    // Windows junk in root and subdir.
    write_file(root, "Thumbs.db", b"thumbs cache");
    write_file(root, "gallery/Thumbs.db", b"thumbs cache");
    write_file(root, "desktop.ini", b"[.ShellClassInfo]");
    write_file(root, "gallery/desktop.ini", b"[.ShellClassInfo]");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-winjunk";
    seed_space_state(&index, space_id, root, [0x22; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let mut paths = scanned_paths(&ctx);
    paths.sort();

    assert_eq!(
        paths,
        vec!["gallery/pic.png".to_string(), "photo.jpg".to_string()],
        "only the two images survive: {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.ends_with("Thumbs.db")),
        "no Thumbs.db may enter the Manifest"
    );
    assert!(
        !paths.iter().any(|p| p.ends_with("desktop.ini")),
        "no desktop.ini may enter the Manifest"
    );
}

#[test]
fn scan_keeps_lookalike_names_exact_match_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Names that are close but NOT one of the three junk names — they sync.
    write_file(root, "DS_Store", b"no leading dot");
    write_file(root, ".DS_Store.bak", b"suffix");
    write_file(root, "mythumbs.db", b"prefix");
    write_file(root, "Desktop.ini", b"capital D differs, case-sensitive");
    write_file(root, "notes/thumbs.db", b"lowercase t differs");
    // A real junk file to prove exclusion still runs alongside the look-alikes.
    write_file(root, ".DS_Store", b"the real junk");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-lookalike";
    seed_space_state(&index, space_id, root, [0x33; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let mut paths = scanned_paths(&ctx);
    paths.sort();

    assert_eq!(
        paths,
        vec![
            ".DS_Store.bak".to_string(),
            "DS_Store".to_string(),
            "Desktop.ini".to_string(),
            "mythumbs.db".to_string(),
            "notes/thumbs.db".to_string(),
        ],
        "exact-name match only: look-alikes must sync, the real .DS_Store must not: {paths:?}"
    );
}

#[test]
fn scan_after_fix_reports_previously_indexed_junk_as_deleted() {
    // A Space that already carries a `.DS_Store` in its local index (e.g. from a
    // commit made before this fix). After the fix, the next scan no longer sees
    // it, so the index row is dropped and it drops out of the next Manifest — a
    // delete is an absence (ADR 0011 auto-clean consequence).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, "keep.txt", b"keep");
    write_file(root, ".DS_Store", b"junk");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-autoclean";
    seed_space_state(&index, space_id, root, [0x44; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    // Pre-seed the index as if a pre-fix scan had recorded the junk file, so we
    // can prove this scan drops it (independent of the walk never emitting it).
    ctx.index
        .upsert_entry(
            space_id,
            &ft_index::LocalEntry {
                path: CanonicalPath(".DS_Store".to_string()),
                casefold_key: ft_fsmap::casefold_key(&CanonicalPath(".DS_Store".to_string())),
                file_type: FileType::File,
                exec: false,
                size: 4,
                mtime: 0,
                pcid: Some(ft_hash::pcid_of(b"junk")),
                base_seq: -1,
                blocks: Vec::new(),
                local_only: false,
            },
        )
        .unwrap();
    assert!(
        ctx.index
            .get_entry(space_id, &CanonicalPath(".DS_Store".to_string()))
            .unwrap()
            .is_some(),
        "precondition: the junk row is present before the fix scan"
    );

    let paths = scanned_paths(&ctx);
    assert_eq!(paths, vec!["keep.txt".to_string()]);

    // The stale junk row is gone from the index (scan drops vanished paths),
    // so the next Manifest reports it deleted; the file on disk is untouched.
    assert!(
        ctx.index
            .get_entry(space_id, &CanonicalPath(".DS_Store".to_string()))
            .unwrap()
            .is_none(),
        "the stale .DS_Store index row must be dropped after the fix scan"
    );
    assert!(
        root.join(".DS_Store").exists(),
        "the local .DS_Store file must NOT be touched on disk"
    );
}
