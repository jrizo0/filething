//! Integration tests for built-in platform-junk exclusion on the scanner side
//! (ADR 0011). `.DS_Store` / `Thumbs.db` / `desktop.ini` are OS sidecars that
//! must NEVER enter the Manifest, in any directory, regardless of the user's
//! `.filethingignore`. The match is by EXACT entry name (case-sensitive, no
//! glob), so a look-alike (`DS_Store`, `.DS_Store.bak`, `mythumbs.db`) still
//! syncs.
//!
//! It also covers the two OTHER things the walk excludes: ft-diff's in-flight
//! `.<file>.ft-tmp` scratch files, and the user's `.filethingignore` — whose
//! patterns must actually work (a `*.key` that silently does nothing is a
//! confidentiality failure) and whose exclusions must STOP a path from syncing
//! without publishing a deletion that destroys it on the other Devices.
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

    // Normal files survive; the `src` directory is now a first-class entry too
    // (ADR 0019).
    assert!(paths.contains(&"readme.md".to_string()));
    assert!(paths.contains(&"src".to_string()));
    assert!(paths.contains(&"src/main.rs".to_string()));
    // No .DS_Store anywhere.
    assert!(
        !paths.iter().any(|p| p.ends_with(".DS_Store")),
        "no .DS_Store may enter the Manifest: {paths:?}"
    );
    assert_eq!(
        paths.len(),
        3,
        "the two real files plus the src directory: {paths:?}"
    );

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
        vec![
            "gallery".to_string(),
            "gallery/pic.png".to_string(),
            "photo.jpg".to_string()
        ],
        "the two images plus the gallery directory survive: {paths:?}"
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
            "notes".to_string(),
            "notes/thumbs.db".to_string(),
        ],
        "exact-name match only: look-alikes (and the notes dir) sync, the real .DS_Store must not: {paths:?}"
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

// ---------------------------------------------------------------------------
// ft-diff scratch files (ft_diff::TMP_SUFFIX)
// ---------------------------------------------------------------------------

#[test]
fn scan_excludes_ft_diff_temp_files_but_keeps_look_alikes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, "doc.txt", b"the real file");
    // Exactly what ft-diff writes before its rename; a crash leaves one behind and
    // committing it would replicate the turd to every Device forever.
    write_file(
        root,
        &format!(".doc.txt{}", ft_diff::TMP_SUFFIX),
        b"in flight",
    );
    write_file(
        root,
        &format!("nested/.other.bin{}", ft_diff::TMP_SUFFIX),
        b"in flight",
    );
    // Look-alikes that are ordinary user data: no leading dot, or no file name
    // before the suffix.
    write_file(
        root,
        &format!("doc.txt{}", ft_diff::TMP_SUFFIX),
        b"user data",
    );
    write_file(root, ft_diff::TMP_SUFFIX, b"user data");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-fttmp";
    seed_space_state(&index, space_id, root, [0x55; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let mut paths = scanned_paths(&ctx);
    paths.sort();

    assert_eq!(
        paths,
        vec![
            ".ft-tmp".to_string(),
            "doc.txt".to_string(),
            "doc.txt.ft-tmp".to_string(),
            "nested".to_string(),
        ],
        "only `.<file>.ft-tmp` is excluded: {paths:?}"
    );
}

// ---------------------------------------------------------------------------
// .filethingignore (§Ignore file)
// ---------------------------------------------------------------------------

#[test]
fn ignore_glob_excludes_matching_files_at_any_depth() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, ".filethingignore", b"*.key\nsecrets/\n/build\n");
    write_file(root, "id.key", b"PRIVATE");
    write_file(root, "deep/nested/tls.key", b"PRIVATE");
    write_file(root, "secrets/api.token", b"PRIVATE");
    write_file(root, "deep/secrets/other.token", b"PRIVATE");
    write_file(root, "build/out.o", b"derived");
    // Not matched: `keyring` is not `*.key`, and `/build` is root-anchored.
    write_file(root, "keyring", b"public");
    write_file(root, "crate/build/keep.txt", b"public");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-ignore-glob";
    seed_space_state(&index, space_id, root, [0x66; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let scan = ctx.scan().unwrap();
    let paths: Vec<&str> = scan.entries.iter().map(|(_, e)| e.p.as_str()).collect();

    for excluded in [
        "id.key",
        "deep/nested/tls.key",
        "secrets",
        "secrets/api.token",
        "deep/secrets/other.token",
        "build",
        "build/out.o",
    ] {
        assert!(
            !paths.contains(&excluded),
            "`{excluded}` must be excluded: {paths:?}"
        );
    }
    for kept in ["keyring", "crate/build", "crate/build/keep.txt"] {
        assert!(paths.contains(&kept), "`{kept}` must still sync: {paths:?}");
    }
    assert!(
        scan.ignore_warnings.is_empty(),
        "every pattern here is supported syntax: {:?}",
        scan.ignore_warnings
    );
}

#[test]
fn unsupported_ignore_pattern_is_reported_instead_of_silently_doing_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, ".filethingignore", b"secrets/**\n!keep.me\n");
    write_file(root, "readme.md", b"hi");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-ignore-warn";
    seed_space_state(&index, space_id, root, [0x77; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let scan = ctx.scan().unwrap();
    assert_eq!(scan.ignore_warnings.len(), 2, "{:?}", scan.ignore_warnings);
    assert!(scan.ignore_warnings[0].contains("secrets/**"));
    assert!(scan.ignore_warnings[0].contains("`**`"));
    assert!(scan.ignore_warnings[1].contains("!keep.me"));
}

#[test]
fn newly_ignored_path_stops_syncing_without_being_published_as_a_deletion() {
    // Adding a `.filethingignore` line must stop a path from syncing, NOT tell every
    // other Device to delete it. So the entry the last scan published is kept.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "keep.txt", b"keep");
    write_file(root, "logs/app.log", b"noisy");
    write_file(root, "notes/todo.md", b"notes");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-newly-ignored";
    seed_space_state(&index, space_id, root, [0x88; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let before = ctx.scan().unwrap();
    let entry_before = before
        .entries
        .iter()
        .find(|(_, e)| e.p.as_str() == "logs/app.log")
        .map(|(_, e)| e.clone())
        .expect("precondition: the log file synced first");

    // The user now excludes it.
    write_file(root, ".filethingignore", b"logs/\n");
    let after = ctx.scan().unwrap();

    let paths: Vec<&str> = after.entries.iter().map(|(_, e)| e.p.as_str()).collect();
    assert!(
        paths.contains(&"logs/app.log"),
        "an excluded-but-already-synced path keeps its Manifest entry so no Device deletes it: \
         {paths:?}"
    );
    let entry_after = after
        .entries
        .iter()
        .find(|(_, e)| e.p.as_str() == "logs/app.log")
        .map(|(_, e)| e.clone())
        .unwrap();
    assert_eq!(entry_after, entry_before, "frozen, not re-read");
    assert!(
        ctx.index
            .get_entry(space_id, &CanonicalPath("logs/app.log".to_string()))
            .unwrap()
            .is_some(),
        "the index row must survive, or the NEXT scan publishes the deletion"
    );

    // And the user is told, once per affected path — not once per ignored file.
    let reported: Vec<&str> = after.skipped.iter().map(|s| s.path.as_str()).collect();
    assert!(
        reported.contains(&"logs/app.log") || reported.contains(&"logs"),
        "the frozen path must be reported: {reported:?}"
    );
    assert!(
        !reported.contains(&"notes/todo.md"),
        "an unaffected path must not be reported: {reported:?}"
    );
}

// ---------------------------------------------------------------------------
// Unsyncable names (the outbound half of the pull wedge)
// ---------------------------------------------------------------------------

/// `foo\bar.txt` and `a:b.txt` are legal names here and unrepresentable on
/// Windows — and a Manifest entry carrying one used to abort every OTHER Device's
/// whole pull on that single entry, forever. The scanner must therefore treat them
/// like junk: never in the Manifest, never in the index. Unlike junk they ARE
/// reported, because they are the user's own data quietly not syncing.
#[test]
fn scan_skips_unsyncable_names_like_junk_but_reports_them() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, "readme.md", b"hello\n");
    write_file(root, "foo\\bar.txt", b"a backslash is a legal unix name\n");
    write_file(root, "a:b.txt", b"a drive-prefix look-alike\n");
    // The same file name one directory down. The old whole-path drive check only
    // looked at byte 1 of the path, so this one was accepted while `a:b.txt` was
    // rejected; the per-component rule says both are unsyncable.
    write_file(root, "docs/a:b.txt", b"same name, deeper\n");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-unsyncable";
    seed_space_state(&index, space_id, root, [0x44; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let result = ctx.scan().unwrap();
    let mut paths: Vec<String> = result
        .entries
        .iter()
        .map(|(_, e)| e.p.as_str().to_string())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec!["docs".to_string(), "readme.md".to_string()],
        "only the ordinary file and the ordinary directory may be published: {paths:?}"
    );

    // Reported (junk is not) — and reported as NOT retained, so an entry an older
    // build published converges by deletion instead of living in the Manifest
    // forever while every peer skips it.
    let mut skipped: Vec<String> = result.skipped.iter().map(|s| s.path.clone()).collect();
    skipped.sort();
    assert_eq!(
        skipped,
        vec![
            "a:b.txt".to_string(),
            "docs/a:b.txt".to_string(),
            "foo\\bar.txt".to_string()
        ],
        "every unsyncable name must be reported: {:?}",
        result.skipped
    );
    assert!(
        result
            .skipped
            .iter()
            .all(|s| !s.retained && matches!(s.reason, ft_engine::SkipReason::UnsyncableName(_))),
        "{:?}",
        result.skipped
    );
    // The message says what is wrong and what to do about it.
    let msg = result.skipped[0].reason.to_string();
    assert!(msg.contains("rename"), "{msg}");

    // Not in the local index either, so the next scan does not resurrect them.
    for p in ["foo\\bar.txt", "a:b.txt", "docs/a:b.txt"] {
        assert!(
            ctx.index
                .get_entry(space_id, &CanonicalPath(p.to_string()))
                .unwrap()
                .is_none(),
            "{p} must not get an index row"
        );
    }
    // And the files themselves are untouched — a skip is not a deletion on disk.
    assert!(root.join("foo\\bar.txt").exists());
    assert!(root.join("a:b.txt").exists());
}

/// A DIRECTORY with an unsyncable name hides its whole subtree: every child path
/// would carry the same unsyncable component, so descending only multiplies the
/// warnings.
#[test]
fn scan_prunes_the_subtree_of_an_unsyncable_directory_name() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_file(root, "keep.txt", b"kept\n");
    write_file(
        root,
        "c:weird/inside.txt",
        b"a child of an unsyncable dir\n",
    );

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-unsyncable-dir";
    seed_space_state(&index, space_id, root, [0x55; 32]);
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let result = ctx.scan().unwrap();
    let paths: Vec<String> = result
        .entries
        .iter()
        .map(|(_, e)| e.p.as_str().to_string())
        .collect();
    assert_eq!(paths, vec!["keep.txt".to_string()], "{paths:?}");
    // ONE report for the directory, not one per child.
    let reported: Vec<String> = result.skipped.iter().map(|s| s.path.clone()).collect();
    assert_eq!(
        reported,
        vec!["c:weird".to_string()],
        "{:?}",
        result.skipped
    );
}

/// The convergence path: a Manifest entry an older build published for an
/// unsyncable name must LEAVE the Manifest (like junk, ADR 0011) rather than be
/// republished forever — that is what stops every peer from having to skip it on
/// every pull. The local file is never touched.
#[test]
fn an_already_synced_unsyncable_name_converges_by_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "keep.txt", b"kept\n");
    write_file(root, "legacy\\name.txt", b"committed by an older build\n");

    let index = Index::open_in_memory().unwrap();
    let space_id = "space-legacy-unsyncable";
    seed_space_state(&index, space_id, root, [0x66; 32]);
    // What the pre-fix scanner left behind: an index row (and hence a Manifest
    // entry) for the unsyncable path.
    index
        .upsert_entry(
            space_id,
            &ft_index::LocalEntry {
                path: CanonicalPath("legacy\\name.txt".to_string()),
                casefold_key: ft_fsmap::casefold_key(&CanonicalPath(
                    "legacy\\name.txt".to_string(),
                )),
                file_type: FileType::File,
                exec: false,
                size: 28,
                mtime: 0,
                pcid: Some(ft_core::Pcid::new([7u8; 32])),
                base_seq: 0,
                blocks: Vec::new(),
                local_only: false,
            },
        )
        .unwrap();
    let vault: Box<dyn Vault> = Box::new(FsVault::new(dir.path().join("__vault")));
    let ctx = mount_ctx(index, vault, space_id);

    let result = ctx.scan().unwrap();
    let paths: Vec<String> = result
        .entries
        .iter()
        .map(|(_, e)| e.p.as_str().to_string())
        .collect();
    assert_eq!(
        paths,
        vec!["keep.txt".to_string()],
        "the legacy entry must NOT be republished: {paths:?}"
    );
    assert!(
        ctx.index
            .get_entry(space_id, &CanonicalPath("legacy\\name.txt".to_string()))
            .unwrap()
            .is_none(),
        "its index row must be dropped so it stays out of every future Manifest"
    );
    assert!(
        root.join("legacy\\name.txt").exists(),
        "the file on disk is untouched: it stops syncing, it is not deleted"
    );
}
