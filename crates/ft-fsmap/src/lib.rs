//! ft-fsmap — canonical filesystem mapping + OS adapters.
//!
//! Turns on-disk paths and metadata into the canonical surface the rest of
//! filething reasons about (`docs/format.md §5.2`, ADR-0001, ADR-0006) and
//! abstracts the host filesystem behind the [`OsFs`] trait.
//!
//! Responsibilities:
//!
//! - [`canonicalize`]: a Space-relative, forward-slash, UTF-8 [`CanonicalPath`].
//!   NFC is **NOT** applied here — the path is preserved byte-exact (`§5.2`,
//!   ADR-0006). A target that escapes the Space root is rejected.
//! - [`casefold_key`]: the ordering / collision key `casefold(NFC(p))` derived
//!   from a [`CanonicalPath`]. NFC and case folding touch only the key, never
//!   the content or a symlink target.
//! - [`classify`] / [`is_derived`]: map metadata + path to a [`FileType`]
//!   (`file` / `symlink` / `derived`, `§5.1`, ADR-0001).
//! - [`symlink_policy`]: relative symlinks that stay inside the Space are
//!   preserved byte-exact; absolute ones or ones that escape are local-only
//!   (`§5.1`).
//! - [`collides`]: two [`CasefoldKey`]s that collide signal a conflict, never an
//!   overwrite (`§5.2`, ADR-0006).
//! - [`OsFs`]: read/write bytes (+ exec bit), read/create symlinks, read the
//!   real mtime. A tested [`LinuxFs`] plus an encoded-but-untested
//!   [`MacFs`] (behind `#[cfg(target_os = "macos")]`).

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use ft_core::{CanonicalPath, CasefoldKey, FileType};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced while mapping the filesystem.
#[derive(Debug, Error)]
pub enum FsMapError {
    /// `target` resolved to a location outside the Space root (e.g. via `../..`).
    /// Such a path can never be a Manifest key. `docs/format.md §5.2`.
    #[error("path escapes the Space root: {0}")]
    EscapesRoot(String),

    /// A path component (or the whole path) was not valid UTF-8. The Manifest
    /// key surface is UTF-8 only. `docs/format.md §5.2`.
    #[error("path is not valid UTF-8: {0}")]
    NotUtf8(String),

    /// An underlying OS filesystem call failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Crate `Result` alias over [`FsMapError`].
pub type Result<T> = std::result::Result<T, FsMapError>;

// ---------------------------------------------------------------------------
// canonicalize — Space-relative, forward-slash, UTF-8 (docs/format.md §5.2)
// ---------------------------------------------------------------------------

/// Maps an on-disk `target` to its [`CanonicalPath`] relative to `space_root`.
///
/// The result is forward-slash, relative (no leading `/`), UTF-8 and **byte-exact**
/// — NFC is deliberately NOT applied (`§5.2`, ADR-0006); only [`casefold_key`]
/// normalizes, and it does so only to derive the ordering/collision key.
///
/// Both paths are resolved *lexically* (no filesystem access, so callers can
/// canonicalize paths that do not exist yet): `.` components are dropped and
/// `..` pops the previous component. A `target` that escapes `space_root`
/// (popping above it, or an absolute path under a different prefix) is rejected
/// with [`FsMapError::EscapesRoot`]; non-UTF-8 components yield
/// [`FsMapError::NotUtf8`].
///
/// `target` may be absolute (it must then live under `space_root`) or relative
/// (interpreted relative to `space_root`).
pub fn canonicalize(space_root: &Path, target: &Path) -> Result<CanonicalPath> {
    let root = lexical_normalize(space_root)?;

    // Resolve `target` against the root when it is relative.
    let abs_target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        space_root.join(target)
    };
    let target_norm = lexical_normalize(&abs_target)?;

    // The normalized target must be the root itself or sit beneath it.
    let rel = target_norm
        .strip_prefix(&root)
        .map_err(|_| FsMapError::EscapesRoot(display_lossy(target)))?;

    // Re-encode the relative path with forward slashes, validating UTF-8 per
    // component (so the error names UTF-8 problems precisely, and we never let a
    // backslash from a component leak through on the wire surface).
    let mut parts: Vec<&str> = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(os) => {
                let s = os
                    .to_str()
                    .ok_or_else(|| FsMapError::NotUtf8(display_lossy(target)))?;
                parts.push(s);
            }
            // `lexical_normalize` already collapsed `.`; a surviving `..` or any
            // root/prefix component here would mean the target escaped.
            Component::CurDir => {}
            _ => return Err(FsMapError::EscapesRoot(display_lossy(target))),
        }
    }

    Ok(CanonicalPath(parts.join("/")))
}

/// Lexically normalizes a path: collapses `.`, applies `..` by popping the
/// previous component, and rejects any `..` that would climb above the start.
/// Pure (no filesystem access). Validates UTF-8 of `Normal` components.
fn lexical_normalize(p: &Path) -> Result<PathBuf> {
    let mut out: Vec<Component<'_>> = Vec::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                match out.last() {
                    // Pop a real directory component.
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    // `..` at the very start (or after another `..`) escapes.
                    Some(Component::ParentDir) | None => {
                        return Err(FsMapError::EscapesRoot(display_lossy(p)));
                    }
                    // Cannot climb above a root / prefix.
                    Some(Component::RootDir | Component::Prefix(_)) => {
                        return Err(FsMapError::EscapesRoot(display_lossy(p)));
                    }
                    Some(Component::CurDir) => unreachable!("CurDir never pushed"),
                }
            }
            Component::Normal(os) => {
                // Validate UTF-8 eagerly so non-UTF-8 surfaces as NotUtf8.
                if os.to_str().is_none() {
                    return Err(FsMapError::NotUtf8(display_lossy(p)));
                }
                out.push(comp);
            }
            root_or_prefix => out.push(root_or_prefix),
        }
    }
    Ok(out.iter().map(|c| c.as_os_str()).collect())
}

fn display_lossy(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// casefold_key — casefold(NFC(p)) (docs/format.md §5.2)
// ---------------------------------------------------------------------------

/// Derives the ordering / collision key for a [`CanonicalPath`]:
/// `casefold(NFC(p))`.
///
/// NFC (via `unicode-normalization`) folds the precomposed vs decomposed forms
/// of the same path to one key, so a path written with a precomposed `é` and one
/// with `e` + combining acute collapse to the SAME key even though their
/// [`CanonicalPath`]s stay byte-distinct (ADR-0006). Case folding then makes the
/// key case-insensitive so a pure upper/lower-case difference also collides
/// (`§5.2`).
///
/// SIMPLIFICATION (acceptable for the MVP, `docs/BUILD-PLAN.md §3`): "casefold"
/// is implemented as Rust's [`str::to_lowercase`], i.e. simple Unicode default
/// lowercasing, NOT the full Unicode case-folding algorithm (which differs for a
/// handful of characters such as the Turkish dotless `ı`/`I` and `ß`). For ASCII
/// and the overwhelming majority of real paths this is identical; the few
/// divergent characters are out of scope for the MVP. The key is applied to the
/// FULL path string (slashes included), which is fine: `/` is unaffected by NFC
/// and lowercasing.
pub fn casefold_key(p: &CanonicalPath) -> CasefoldKey {
    // NFC first (so combining marks fold into precomposed form), then simple
    // case fold. The spec's key is exactly `casefold(NFC(p))`.
    let nfc: String = p.as_str().nfc().collect();
    CasefoldKey(nfc.to_lowercase())
}

/// Returns `true` when two [`CasefoldKey`]s collide — i.e. two distinct
/// [`CanonicalPath`]s that map to the same key. The engine treats a collision as
/// a CONFLICT (emit a conflict copy), never an overwrite (`§5.2`, ADR-0006).
///
/// This is a thin equality over the keys; it exists as a named predicate so the
/// collision rule reads the same everywhere it is checked.
pub fn collides(a: &CasefoldKey, b: &CasefoldKey) -> bool {
    a == b
}

// ---------------------------------------------------------------------------
// Derived paths (docs/format.md §5.1 t=2, ADR-0001)
// ---------------------------------------------------------------------------

/// Directory names that mark a Derived path (`FileType::Derived`, `t=2`): a
/// regenerable artifact tree whose bytes do NOT travel (`§5.1`, ADR-0001).
///
/// Per ADR-0001 the real policy keys off the detected toolchain/lockfile, but
/// the MVP recognizes this fixed name set: `node_modules`, `target`, `.next`,
/// `venv`, `.venv`.
pub const DERIVED_NAMES: &[&str] = &["node_modules", "target", ".next", "venv", ".venv"];

/// Returns `true` when `path` is (or lives under) a Derived path — any path
/// component exactly matching a name in [`DERIVED_NAMES`] (`§5.1`, ADR-0001).
///
/// The check is on path components so both `node_modules` itself and anything
/// nested inside it (`node_modules/foo/bar.js`) are Derived. Matching is
/// component-exact and case-sensitive (these are fixed lower-case tool
/// conventions), so `my_node_modules` and `targets` do NOT match.
pub fn is_derived(path: &Path) -> bool {
    path.components().any(|c| match c {
        Component::Normal(os) => os
            .to_str()
            .is_some_and(|name| DERIVED_NAMES.contains(&name)),
        _ => false,
    })
}

// ---------------------------------------------------------------------------
// classify — metadata + path -> FileType (docs/format.md §5.1)
// ---------------------------------------------------------------------------

/// Classifies an on-disk entry into a [`FileType`] (`§5.1`, ADR-0001).
///
/// A Derived path (per [`is_derived`]) wins regardless of `meta`: it is recorded
/// as `Derived` with an empty `bk` and its bytes never travel. Otherwise a
/// symlink (`meta.is_symlink()`) is `Symlink` and everything else is `File`.
///
/// `meta` must come from a NON-following stat (`fs::symlink_metadata`), so that a
/// symlink reports as a symlink rather than as its target.
pub fn classify(meta: &fs::Metadata, path: &Path) -> FileType {
    if is_derived(path) {
        FileType::Derived
    } else if meta.is_symlink() {
        FileType::Symlink
    } else {
        FileType::File
    }
}

// ---------------------------------------------------------------------------
// Symlink policy (docs/format.md §5.1)
// ---------------------------------------------------------------------------

/// The decision for a symlink encountered while scanning a Space (`§5.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymlinkDecision {
    /// The link is relative and resolves to a location inside the Space: it
    /// enters the Manifest with its target preserved BYTE-EXACT (the wrapped
    /// `String` is the literal `lt`, ADR-0006 — never NFC-normalized).
    Preserve(String),

    /// The link is absolute, or relative-but-escapes the Space: it does NOT
    /// enter the Manifest. The Device keeps it local-only (recorded in the local
    /// index), never shared.
    LocalOnly,
}

/// Applies the symlink policy of `§5.1` to a link whose literal target is
/// `link_target`, sitting at `link_path` inside `space_root`.
///
/// - Absolute target -> [`SymlinkDecision::LocalOnly`].
/// - Relative target that stays inside the Space -> [`SymlinkDecision::Preserve`]
///   carrying the target byte-exact.
/// - Relative target that escapes the Space (resolving above `space_root`) ->
///   [`SymlinkDecision::LocalOnly`].
///
/// `link_path` is the path of the symlink itself (used to resolve a relative
/// target from the symlink's own directory). It may be absolute or relative; if
/// relative it is interpreted under `space_root`. Resolution is purely lexical
/// (no filesystem access, no following) so a dangling link is still classified.
/// The preserved string is the ORIGINAL `link_target`, never the resolved form.
pub fn symlink_policy(link_target: &str, link_path: &Path, space_root: &Path) -> SymlinkDecision {
    let target = Path::new(link_target);
    if target.is_absolute() {
        return SymlinkDecision::LocalOnly;
    }

    // Resolve the relative target against the symlink's own directory, then
    // check it stays inside the Space — purely lexically.
    let link_abs = if link_path.is_absolute() {
        link_path.to_path_buf()
    } else {
        space_root.join(link_path)
    };
    let base_dir = link_abs.parent().unwrap_or(space_root);
    let resolved = base_dir.join(target);

    match (lexical_normalize(space_root), lexical_normalize(&resolved)) {
        (Ok(root), Ok(res)) if res.starts_with(&root) => {
            // Inside the Space: preserve the ORIGINAL target byte-exact.
            SymlinkDecision::Preserve(link_target.to_string())
        }
        // Escapes the Space (or could not be normalized) -> local-only.
        _ => SymlinkDecision::LocalOnly,
    }
}

// ---------------------------------------------------------------------------
// OsFs — host filesystem abstraction
// ---------------------------------------------------------------------------

/// Abstraction over the host filesystem so the engine reads/writes bytes,
/// symlinks, the executable bit and the real mtime without hard-coding OS calls.
///
/// `docs/BUILD-PLAN.md §3`: a tested [`LinuxFs`] plus an encoded-but-untested
/// [`MacFs`] (behind `#[cfg(target_os = "macos")]`). All methods take `&self` so
/// an impl may carry configuration; the provided impls are zero-sized.
pub trait OsFs {
    /// Reads the full byte contents of a regular file at `path`.
    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>>;

    /// Writes `bytes` to `path` (creating/truncating), then sets the executable
    /// bit to `exec`. On unix this sets mode `0o755` (exec) or `0o644` (not), so
    /// the `x` bit of a `FileEntry` round-trips. `§5.1` field `"x"`.
    fn write_bytes(&self, path: &Path, bytes: &[u8], exec: bool) -> Result<()>;

    /// Reads the literal target of the symlink at `path` (byte-exact, NOT
    /// resolved or normalized). `§5.1` field `"lt"`.
    fn read_symlink(&self, path: &Path) -> Result<String>;

    /// Creates a symlink at `path` pointing at the literal `target`.
    fn create_symlink(&self, target: &str, path: &Path) -> Result<()>;

    /// Returns the executable bit from `meta` (unix: any of the owner/group/other
    /// execute bits set). `§5.1` field `"x"`.
    fn exec_bit(&self, meta: &fs::Metadata) -> bool;

    /// Returns the real modification time recorded for `path` (used by the
    /// watcher's echo suppression, `§9`). NOT a content hash — only an mtime.
    fn real_mtime(&self, path: &Path) -> Result<SystemTime>;
}

/// The Linux (and, generally, unix) filesystem adapter. Tested on Linux.
///
/// Uses `std` plus `std::os::unix::fs::PermissionsExt` for the executable bit and
/// `std::os::unix::fs::symlink` to create symlinks.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxFs;

#[cfg(unix)]
impl OsFs for LinuxFs {
    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(fs::read(path)?)
    }

    fn write_bytes(&self, path: &Path, bytes: &[u8], exec: bool) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, bytes)?;
        let mode = if exec { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn read_symlink(&self, path: &Path) -> Result<String> {
        let target = fs::read_link(path)?;
        // The target is preserved byte-exact; reject non-UTF-8 so `lt` stays a
        // UTF-8 `String` (the Manifest surface, §5.2). Non-UTF-8 targets are
        // exceedingly rare and handled as local-only upstream.
        target
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| FsMapError::NotUtf8(display_lossy(&target)))
    }

    fn create_symlink(&self, target: &str, path: &Path) -> Result<()> {
        std::os::unix::fs::symlink(target, path)?;
        Ok(())
    }

    fn exec_bit(&self, meta: &fs::Metadata) -> bool {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }

    fn real_mtime(&self, path: &Path) -> Result<SystemTime> {
        Ok(fs::symlink_metadata(path)?.modified()?)
    }
}

/// The macOS filesystem adapter. CODED but NOT exercised in this crate's tests
/// (no Mac in the build environment, `docs/BUILD-PLAN.md §0`).
///
/// macOS is also unix, so the implementation is identical to [`LinuxFs`]: the
/// executable bit and symlink creation use the same `std::os::unix::fs` APIs. It
/// lives behind `#[cfg(target_os = "macos")]` so it only compiles on Mac, where
/// it can later be verified against APFS/HFS+ NFD path behavior (handled at the
/// [`casefold_key`] layer, not here).
#[cfg(target_os = "macos")]
#[derive(Debug, Default, Clone, Copy)]
pub struct MacFs;

#[cfg(target_os = "macos")]
impl OsFs for MacFs {
    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(fs::read(path)?)
    }

    fn write_bytes(&self, path: &Path, bytes: &[u8], exec: bool) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, bytes)?;
        let mode = if exec { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn read_symlink(&self, path: &Path) -> Result<String> {
        let target = fs::read_link(path)?;
        target
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| FsMapError::NotUtf8(display_lossy(&target)))
    }

    fn create_symlink(&self, target: &str, path: &Path) -> Result<()> {
        std::os::unix::fs::symlink(target, path)?;
        Ok(())
    }

    fn exec_bit(&self, meta: &fs::Metadata) -> bool {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }

    fn real_mtime(&self, path: &Path) -> Result<SystemTime> {
        Ok(fs::symlink_metadata(path)?.modified()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;
    use tempfile::tempdir;

    // ----- Test (1): NFC only on the key -----

    #[test]
    fn nfc_folds_only_the_key_not_the_canonical_path() {
        // "é" precomposed (U+00E9) vs "e" + combining acute (U+0065 U+0301).
        let precomposed = CanonicalPath("caf\u{00e9}.txt".to_string());
        let decomposed = CanonicalPath("cafe\u{0301}.txt".to_string());

        // The CanonicalPaths are byte-distinct (NFC is NOT applied to them).
        assert_ne!(precomposed, decomposed);
        assert_ne!(precomposed.as_str(), decomposed.as_str());
        assert_ne!(
            precomposed.as_str().as_bytes(),
            decomposed.as_str().as_bytes()
        );

        // But their casefold keys are EQUAL -> a collision.
        let ka = casefold_key(&precomposed);
        let kb = casefold_key(&decomposed);
        assert_eq!(ka, kb, "NFC-equivalent paths must share one key");
        assert!(collides(&ka, &kb));
    }

    // ----- Test (2): case-only collision detected by casefold_key -----

    #[test]
    fn case_only_collision_detected_by_casefold_key() {
        let lower = CanonicalPath("src/readme.md".to_string());
        let upper = CanonicalPath("src/README.md".to_string());

        // Byte-distinct canonical paths...
        assert_ne!(lower, upper);

        // ...but the same casefold key -> collision.
        let kl = casefold_key(&lower);
        let ku = casefold_key(&upper);
        assert_eq!(kl, ku);
        assert!(collides(&kl, &ku));

        // A genuinely different path does NOT collide.
        let other = casefold_key(&CanonicalPath("src/other.md".to_string()));
        assert!(!collides(&kl, &other));
    }

    // ----- Test (3): canonicalize rejects an escaping target -----

    #[test]
    fn canonicalize_rejects_target_escaping_root() {
        let root = Path::new("/space/root");

        // Relative target that climbs above the root.
        let escaping = Path::new("../../etc/passwd");
        assert!(matches!(
            canonicalize(root, escaping),
            Err(FsMapError::EscapesRoot(_))
        ));

        // Absolute target under a different prefix.
        let outside = Path::new("/elsewhere/file");
        assert!(matches!(
            canonicalize(root, outside),
            Err(FsMapError::EscapesRoot(_))
        ));
    }

    #[test]
    fn canonicalize_accepts_inside_paths_forward_slash_relative() {
        let root = Path::new("/space/root");

        // Relative inside path with a redundant `.` and an absolute equivalent.
        assert_eq!(
            canonicalize(root, Path::new("./src/main.rs")).unwrap(),
            CanonicalPath("src/main.rs".to_string())
        );
        assert_eq!(
            canonicalize(root, Path::new("/space/root/src/main.rs")).unwrap(),
            CanonicalPath("src/main.rs".to_string())
        );

        // `a/b/../c` collapses to `a/c` and stays inside.
        assert_eq!(
            canonicalize(root, Path::new("a/b/../c")).unwrap(),
            CanonicalPath("a/c".to_string())
        );

        // The root itself maps to the empty path.
        assert_eq!(
            canonicalize(root, Path::new("/space/root")).unwrap(),
            CanonicalPath(String::new())
        );
    }

    #[test]
    fn canonicalize_preserves_path_byte_exact_no_nfc() {
        let root = Path::new("/space/root");
        // A decomposed "é" in the target must survive byte-exact in the
        // CanonicalPath (NFC is NOT applied here, only in casefold_key).
        let decomposed = "cafe\u{0301}.txt";
        let cp = canonicalize(root, Path::new(decomposed)).unwrap();
        assert_eq!(cp.as_str(), decomposed);
        assert_eq!(cp.as_str().as_bytes(), decomposed.as_bytes());
    }

    // ----- Test (4): executable bit read/written correctly (LinuxFs) -----

    #[cfg(unix)]
    #[test]
    fn exec_bit_roundtrips_through_linuxfs() {
        let dir = tempdir().unwrap();
        let osfs = LinuxFs;

        // Write a non-exec file: exec_bit reads false.
        let plain = dir.path().join("plain.txt");
        osfs.write_bytes(&plain, b"hello", false).unwrap();
        let meta = stdfs::symlink_metadata(&plain).unwrap();
        assert!(!osfs.exec_bit(&meta), "0o644 file must not be executable");
        assert_eq!(osfs.read_bytes(&plain).unwrap(), b"hello");

        // Write an exec file: exec_bit reads true.
        let script = dir.path().join("run.sh");
        osfs.write_bytes(&script, b"#!/bin/sh\n", true).unwrap();
        let meta = stdfs::symlink_metadata(&script).unwrap();
        assert!(osfs.exec_bit(&meta), "0o755 file must be executable");
        assert_eq!(osfs.read_bytes(&script).unwrap(), b"#!/bin/sh\n");
    }

    #[cfg(unix)]
    #[test]
    fn real_mtime_reads_a_timestamp() {
        let dir = tempdir().unwrap();
        let osfs = LinuxFs;
        let f = dir.path().join("f");
        osfs.write_bytes(&f, b"x", false).unwrap();
        // Just assert it returns a sane SystemTime (>= UNIX_EPOCH).
        let mt = osfs.real_mtime(&f).unwrap();
        assert!(mt >= SystemTime::UNIX_EPOCH);
    }

    // ----- Test (5): symlink policy -----

    #[test]
    fn relative_symlink_inside_space_is_preserved() {
        let root = Path::new("/space/root");
        // A link at src/link -> ../docs/readme.md, which stays inside the Space.
        let decision = symlink_policy("../docs/readme.md", Path::new("src/link"), root);
        assert_eq!(
            decision,
            SymlinkDecision::Preserve("../docs/readme.md".to_string())
        );

        // A sibling-relative link stays inside too, target preserved byte-exact.
        let decision = symlink_policy("sibling.txt", Path::new("dir/link"), root);
        assert_eq!(
            decision,
            SymlinkDecision::Preserve("sibling.txt".to_string())
        );
    }

    #[test]
    fn absolute_symlink_is_local_only() {
        let root = Path::new("/space/root");
        let decision = symlink_policy("/usr/bin/python3", Path::new("link"), root);
        assert_eq!(decision, SymlinkDecision::LocalOnly);
    }

    #[test]
    fn relative_symlink_escaping_space_is_local_only() {
        let root = Path::new("/space/root");
        // src/link -> ../../outside escapes the Space.
        let decision = symlink_policy("../../outside", Path::new("src/link"), root);
        assert_eq!(decision, SymlinkDecision::LocalOnly);
    }

    // ----- Test (6): is_derived -----

    #[test]
    fn is_derived_recognizes_known_names() {
        assert!(is_derived(Path::new("node_modules")));
        assert!(is_derived(Path::new("node_modules/foo/bar.js")));
        assert!(is_derived(Path::new("crate/target/debug/app")));
        assert!(is_derived(Path::new("web/.next/cache/x")));
        assert!(is_derived(Path::new("py/venv/bin/python")));
        assert!(is_derived(Path::new("py/.venv/bin/python")));

        // Non-derived paths.
        assert!(!is_derived(Path::new("src/main.rs")));
        assert!(!is_derived(Path::new("package-lock.json")));
        // Substring matches must NOT trigger (component-exact only).
        assert!(!is_derived(Path::new("my_node_modules/x")));
        assert!(!is_derived(Path::new("targets/x")));
    }

    // ----- classify -----

    #[cfg(unix)]
    #[test]
    fn classify_distinguishes_file_symlink_and_derived() {
        let dir = tempdir().unwrap();

        // Regular file.
        let f = dir.path().join("a.txt");
        stdfs::write(&f, b"hi").unwrap();
        let fmeta = stdfs::symlink_metadata(&f).unwrap();
        assert_eq!(classify(&fmeta, Path::new("a.txt")), FileType::File);

        // Symlink (non-following metadata reports symlink).
        let link = dir.path().join("l");
        std::os::unix::fs::symlink("a.txt", &link).unwrap();
        let lmeta = stdfs::symlink_metadata(&link).unwrap();
        assert_eq!(classify(&lmeta, Path::new("l")), FileType::Symlink);

        // Derived path wins regardless of the on-disk metadata: a real file
        // sitting under node_modules classifies as Derived.
        let nm = dir.path().join("node_modules");
        stdfs::create_dir(&nm).unwrap();
        let dep = nm.join("dep.js");
        stdfs::write(&dep, b"x").unwrap();
        let dmeta = stdfs::symlink_metadata(&dep).unwrap();
        assert_eq!(
            classify(&dmeta, Path::new("node_modules/dep.js")),
            FileType::Derived
        );
    }

    // ----- read/create symlink roundtrip (LinuxFs) -----

    #[cfg(unix)]
    #[test]
    fn symlink_create_and_read_roundtrip_byte_exact() {
        let dir = tempdir().unwrap();
        let osfs = LinuxFs;
        let link = dir.path().join("mylink");
        // Target is preserved byte-exact, not resolved.
        osfs.create_symlink("../docs/x.md", &link).unwrap();
        assert_eq!(osfs.read_symlink(&link).unwrap(), "../docs/x.md");
    }
}
