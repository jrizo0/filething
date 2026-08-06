//! The CLI's identity/config store — a single `config.json` (`docs/BUILD-PLAN.md
//! §3`).
//!
//! This is the Device's local record of WHO it is (the paired Account + Device
//! ids), WHERE the Coordinator lives, and WHICH Spaces it syncs (each mapped to a
//! local folder). It deliberately holds NO secrets: the admin key and the Vault
//! `S3_*` credentials are read from the environment on every run (MVP self-hosted
//! model), never persisted.
//!
//! ## Location
//!
//! Resolved in order:
//! 1. `$FILETHING_HOME`, if set — the override that lets two Devices share one
//!    machine with separate homes (the demo topology).
//! 2. else `${XDG_CONFIG_HOME:-$HOME/.config}/filething`.
//!
//! The file itself is `<config_dir>/config.json`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The persisted CLI state (`config.json`). Serialized as pretty JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// The Coordinator deployment URL this Device is paired against. Saved on
    /// `login`; the admin key is NEVER stored here (read from env each run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_url: Option<String>,

    /// The paired Account id (a Convex `accounts` document id), once `login` ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,

    /// This Device's id (a Convex `devices` document id), once `login` ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    /// This Device's human-readable name (`filething login --name`, else the
    /// hostname), cached from `login` so the engine can label conflict copies
    /// legibly (issue #14) instead of exposing the opaque `device_id`. Optional
    /// via `serde(default)`: a config written by an older build has no field and
    /// still loads; the engine then falls back to the `device_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,

    /// The account email this Device logged in as (`filething login --email`),
    /// cached from `login` so `filething whoami` can show the human identity with
    /// no network call (issue #15). Non-secret, like the ids above. Optional via
    /// `serde(default)`: a config written before this field existed still loads
    /// (the field is then `None`, and `whoami` shows the account id alone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// The Spaces this Device syncs, each mapped one-to-one to a local folder.
    #[serde(default)]
    pub spaces: Vec<SpaceMapping>,
}

/// One Space ↔ local-folder mapping in the config (`docs/BUILD-PLAN.md §3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceMapping {
    /// The Space id (a Convex `spaces` document id).
    pub space_id: String,
    /// The absolute local root folder mapped to this Space.
    pub local_root: String,
}

/// The default per-OS basename under the config home (`<…>/filething`).
const APP_DIR: &str = "filething";
/// The config file basename.
const CONFIG_FILE: &str = "config.json";

/// Appended to every "your `config.json` is unreadable" error. Spelled out
/// because the alternative — starting from an empty config — silently forgets
/// which folders are Spaces, and the user has no way to tell that happened.
const RECOVER_HINT: &str = " This file holds this Device's identity and every \
                            Space ↔ folder mapping, so filething will not \
                            overwrite it automatically: fix the JSON, or move it \
                            aside and re-run `filething login` (then re-map each \
                            Space folder).";

impl Config {
    /// Resolves the config DIRECTORY for this run (`docs/BUILD-PLAN.md §3`):
    /// `$FILETHING_HOME`, else `${XDG_CONFIG_HOME:-$HOME/.config}/filething`.
    ///
    /// Reads only process environment — pure given the env, so the unit tests can
    /// drive it via `FILETHING_HOME`.
    pub fn config_dir() -> PathBuf {
        if let Some(home) = env_nonempty("FILETHING_HOME") {
            return PathBuf::from(home);
        }
        let base = env_nonempty("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env_nonempty("HOME").map(|h| PathBuf::from(h).join(".config")))
            // Last resort if even $HOME is unset: the current dir's .config.
            .unwrap_or_else(|| PathBuf::from(".config"));
        base.join(APP_DIR)
    }

    /// The full path to `config.json` for this run.
    pub fn config_path() -> PathBuf {
        Self::config_dir().join(CONFIG_FILE)
    }

    /// Loads the config from `config_path()`, returning [`Config::default`] when
    /// the file does not exist yet (a fresh, never-logged-in Device).
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from(&Self::config_path())
    }

    /// Loads the config from an explicit path (the testable core of [`load`]).
    ///
    /// A file that exists but does not parse is an ERROR, never a silent reset to
    /// [`Config::default`]: this file is the only record of every Space ↔ folder
    /// mapping on the Device, so defaulting would quietly unmap every Space (and
    /// the next `save` would make that permanent). The message names the file and
    /// the way out instead.
    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) if bytes.is_empty() => Err(anyhow::anyhow!(
                "{} is empty — this looks like a torn write from an interrupted \
                 command.{RECOVER_HINT}",
                path.display()
            )),
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("parsing {}: {e}.{RECOVER_HINT}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }

    /// Persists the config to `config_path()`, creating the config directory if
    /// needed. Pretty-prints so a human can inspect/edit it.
    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to(&Self::config_path())
    }

    /// Persists the config to an explicit path (the testable core of [`save`]).
    ///
    /// ATOMIC by construction: write a sibling temp file, fsync it, then
    /// `rename(2)` it over the target, so a reader only ever sees the whole old file
    /// or the whole new one. A plain truncate-and-write can be interrupted (crash,
    /// SIGKILL, a full disk) or interleaved with another process saving at the same
    /// time — `init`/`clone`/`unmap` restart the daemon, which loads this same file
    /// — and a torn `config.json` loses the identity AND every Space mapping at
    /// once, i.e. it bricks every Space on the Device.
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        // A bare filename has a `Some("")` parent, which is no directory at all —
        // leave the cwd's own mode alone in that case, as the previous
        // `create_dir_all` did.
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = parent {
            ensure_private_dir(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        // The temp file must live in the SAME directory, or the rename would cross
        // a filesystem boundary and stop being atomic. The pid keeps two processes
        // saving concurrently from writing each other's temp file.
        let name = format!(".{CONFIG_FILE}.{}.tmp", std::process::id());
        let tmp = match parent {
            Some(parent) => parent.join(name),
            None => PathBuf::from(name),
        };
        let out = write_then_rename(&tmp, path, &json);
        if out.is_err() {
            // Never leave a half-written temp file behind for the next run to trip on.
            let _ = std::fs::remove_file(&tmp);
        }
        out
    }

    /// Records (or replaces) the identity learned from a `login`, including the
    /// human-readable `device_name` used to label conflict copies (issue #14) and
    /// the account `email` shown by `whoami` (issue #15).
    pub fn set_identity(
        &mut self,
        coordinator_url: &str,
        email: &str,
        account_id: &str,
        device_id: &str,
        device_name: &str,
    ) {
        self.coordinator_url = Some(coordinator_url.to_string());
        self.email = Some(email.to_string());
        self.account_id = Some(account_id.to_string());
        self.device_id = Some(device_id.to_string());
        self.device_name = Some(device_name.to_string());
    }

    /// Registers (or updates, by `space_id`) a Space ↔ folder mapping. The
    /// `local_root` is stored as given (callers pass an absolute path).
    pub fn upsert_space(&mut self, space_id: &str, local_root: &str) {
        if let Some(existing) = self.spaces.iter_mut().find(|m| m.space_id == space_id) {
            existing.local_root = local_root.to_string();
        } else {
            self.spaces.push(SpaceMapping {
                space_id: space_id.to_string(),
                local_root: local_root.to_string(),
            });
        }
    }

    /// Removes the Space mapping whose `local_root` matches (as stored, an
    /// absolute path — callers pass a [`normalize_abs`]-ed root, the same form
    /// [`upsert_space`](Self::upsert_space) records). Returns whether a mapping
    /// was removed. Backing store for `filething unmap` (issue #15): it only
    /// forgets the mapping — the local files are left untouched.
    pub fn remove_space_by_root(&mut self, local_root: &str) -> bool {
        let before = self.spaces.len();
        self.spaces.retain(|m| m.local_root != local_root);
        self.spaces.len() != before
    }
}

/// Writes `bytes` to `tmp`, fsyncs it, and renames it over `path`.
///
/// The fsync is not paranoia: `rename(2)` is atomic with respect to concurrent
/// READERS, but on a crash the new name can still be left pointing at a
/// zero-length file if the data never reached the disk. The directory fsync
/// afterwards is what makes the rename itself durable, and is best-effort because
/// not every platform lets a directory be opened for syncing.
fn write_then_rename(tmp: &Path, path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = std::fs::File::create(tmp)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", tmp.display()))?;
    f.sync_all()
        .map_err(|e| anyhow::anyhow!("fsync {}: {e}", tmp.display()))?;
    drop(f);
    std::fs::rename(tmp, path)
        .map_err(|e| anyhow::anyhow!("renaming {} over {}: {e}", tmp.display(), path.display()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Creates `dir` (with its parents) and, on Unix, tightens it to `0700`.
///
/// The config dir holds `credentials.json` (the Better Auth session + the Account
/// escrow `dedup_secret`) and the daemon's log; a Space's control dir holds that
/// Space's `space_key`. `create_dir_all` alone leaves both at `0755` minus the
/// umask, i.e. readable by every other account on the machine. The mode is
/// re-asserted on an existing dir so a home created by an older build is tightened
/// on the next write.
///
/// Tightening is best-effort: some filesystems (exFAT/FAT sticks, some network
/// mounts) reject `chmod` outright, and failing the whole command over
/// defense-in-depth would be worse than warning — the SECRET FILES themselves are
/// still created `0600` (see `crate::credentials`).
pub fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("creating {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "could not restrict this directory to 0700; it may be readable by other \
                 accounts on this machine"
            );
        }
    }
    Ok(())
}

/// Reads an environment variable, treating an empty value as unset.
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Best-effort absolute normalization for comparing folder paths: canonicalizes
/// when the path exists, else falls back to joining the cwd. Avoids treating
/// `./dir` and `/abs/dir` as different mappings.
pub fn normalize_abs(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(p))
        .unwrap_or_else(|_| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let mut cfg = Config::default();
        cfg.set_identity(
            "http://localhost:3210",
            "julian@example.com",
            "acc_1",
            "dev_1",
            "Julian's Mac",
        );
        cfg.upsert_space("sp_1", "/home/u/proj");
        cfg.upsert_space("sp_2", "/home/u/notes");
        cfg.save_to(&path).unwrap();

        let back = Config::load_from(&path).unwrap();
        assert_eq!(back, cfg);
        assert_eq!(
            back.coordinator_url.as_deref(),
            Some("http://localhost:3210")
        );
        assert_eq!(back.email.as_deref(), Some("julian@example.com"));
        assert_eq!(back.account_id.as_deref(), Some("acc_1"));
        assert_eq!(back.device_id.as_deref(), Some("dev_1"));
        assert_eq!(back.device_name.as_deref(), Some("Julian's Mac"));
        assert_eq!(back.spaces.len(), 2);
    }

    #[test]
    fn load_missing_file_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg, Config::default());
        assert!(cfg.account_id.is_none());
        assert!(cfg.spaces.is_empty());
    }

    #[test]
    fn loads_legacy_config_without_device_name() {
        // A config written before `device_name` existed must still parse (serde
        // default), leaving the field `None` so the engine falls back to the id.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            br#"{"coordinator_url":"http://x","account_id":"acc_1","device_id":"dev_1","spaces":[]}"#,
        )
        .unwrap();
        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.device_id.as_deref(), Some("dev_1"));
        assert_eq!(cfg.device_name, None);
    }

    /// A `config.json` that does not parse must ERROR (naming the file and the way
    /// out), never fall back to `Config::default` — defaulting would silently
    /// forget every Space mapping and the next `save` would make that permanent.
    #[test]
    fn unparseable_config_errors_instead_of_resetting_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, br#"{"account_id": "acc_1", "spaces": [ trunc"#).unwrap();
        let err = Config::load_from(&path).unwrap_err().to_string();
        assert!(err.contains("config.json"), "must name the file: {err}");
        assert!(
            err.contains("filething login"),
            "must say what to do: {err}"
        );
    }

    /// The shape a torn write leaves behind (a zero-length file) gets its own
    /// message rather than serde's "EOF while parsing a value at line 1 column 0".
    #[test]
    fn empty_config_file_reports_a_torn_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, b"").unwrap();
        let err = Config::load_from(&path).unwrap_err().to_string();
        assert!(err.contains("empty"), "unexpected message: {err}");
        assert!(err.contains("torn write"), "unexpected message: {err}");
    }

    /// `save_to` must not truncate the live file: the previous config has to stay
    /// readable until the new one is complete, and the replacement has to happen in
    /// one step. Asserted by checking the target's inode/dev is REPLACED (a rename)
    /// rather than reused (an in-place rewrite), and that no temp file is left over.
    #[cfg(unix)]
    #[test]
    fn save_replaces_the_config_atomically_and_leaves_no_temp_file() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let mut first = Config::default();
        first.upsert_space("sp_1", "/a");
        first.save_to(&path).unwrap();
        let before = std::fs::metadata(&path).unwrap().ino();

        let mut second = first.clone();
        second.upsert_space("sp_2", "/b");
        second.save_to(&path).unwrap();
        let after = std::fs::metadata(&path).unwrap().ino();

        assert_ne!(
            before, after,
            "the config must be replaced by a rename, not rewritten in place"
        );
        assert_eq!(Config::load_from(&path).unwrap(), second);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
            .filter(|n| n != "config.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    /// The directory holding `credentials.json` (and the daemon log) must be 0700,
    /// not the 0755 `create_dir_all` leaves — the files inside are 0600, but a
    /// world-readable directory still leaks their names and sizes.
    #[cfg(unix)]
    #[test]
    fn save_creates_the_config_dir_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("nested").join("filething");
        Config::default()
            .save_to(&home.join("config.json"))
            .unwrap();
        let mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "config dir must be 0700, got {mode:o}");
    }

    #[test]
    fn upsert_space_replaces_by_id() {
        let mut cfg = Config::default();
        cfg.upsert_space("sp_1", "/a");
        cfg.upsert_space("sp_1", "/b"); // same id -> replace, not duplicate.
        assert_eq!(cfg.spaces.len(), 1);
        assert_eq!(cfg.spaces[0].local_root, "/b");
    }

    #[test]
    fn remove_space_by_root_removes_only_the_match() {
        let mut cfg = Config::default();
        cfg.upsert_space("sp_1", "/home/u/proj");
        cfg.upsert_space("sp_2", "/home/u/notes");

        // A root that is not mapped: nothing removed, list unchanged.
        assert!(!cfg.remove_space_by_root("/home/u/other"));
        assert_eq!(cfg.spaces.len(), 2);

        // The mapped root: removed, and only it.
        assert!(cfg.remove_space_by_root("/home/u/proj"));
        assert_eq!(cfg.spaces.len(), 1);
        assert_eq!(cfg.spaces[0].space_id, "sp_2");

        // Removing it again is a no-op that reports false.
        assert!(!cfg.remove_space_by_root("/home/u/proj"));
    }

    #[test]
    fn filething_home_override_wins() {
        // FILETHING_HOME takes precedence over XDG_CONFIG_HOME / HOME. We mutate
        // process env here; this test owns these keys (run serially is fine — the
        // assertions restore nothing the other tests read).
        let saved_ft = std::env::var("FILETHING_HOME").ok();
        let saved_xdg = std::env::var("XDG_CONFIG_HOME").ok();

        std::env::set_var("FILETHING_HOME", "/tmp/ft-home-A");
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/xdg");
        assert_eq!(Config::config_dir(), PathBuf::from("/tmp/ft-home-A"));
        assert_eq!(
            Config::config_path(),
            PathBuf::from("/tmp/ft-home-A").join("config.json")
        );

        // Without FILETHING_HOME, XDG_CONFIG_HOME/filething is used.
        std::env::remove_var("FILETHING_HOME");
        assert_eq!(
            Config::config_dir(),
            PathBuf::from("/tmp/xdg").join("filething")
        );

        // Restore.
        match saved_ft {
            Some(v) => std::env::set_var("FILETHING_HOME", v),
            None => std::env::remove_var("FILETHING_HOME"),
        }
        match saved_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn empty_env_is_treated_as_unset() {
        assert_eq!(env_nonempty("FT_DEFINITELY_UNSET_VAR_XYZ"), None);
        std::env::set_var("FT_EMPTY_TEST_VAR", "");
        assert_eq!(env_nonempty("FT_EMPTY_TEST_VAR"), None);
        std::env::remove_var("FT_EMPTY_TEST_VAR");
    }
}
