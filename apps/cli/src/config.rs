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
    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let cfg = serde_json::from_slice(&bytes)
                    .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
                Ok(cfg)
            }
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
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("creating {}: {e}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
        Ok(())
    }

    /// Records (or replaces) the identity learned from a `login`, including the
    /// human-readable `device_name` used to label conflict copies (issue #14).
    pub fn set_identity(
        &mut self,
        coordinator_url: &str,
        account_id: &str,
        device_id: &str,
        device_name: &str,
    ) {
        self.coordinator_url = Some(coordinator_url.to_string());
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
        cfg.set_identity("http://localhost:3210", "acc_1", "dev_1", "Julian's Mac");
        cfg.upsert_space("sp_1", "/home/u/proj");
        cfg.upsert_space("sp_2", "/home/u/notes");
        cfg.save_to(&path).unwrap();

        let back = Config::load_from(&path).unwrap();
        assert_eq!(back, cfg);
        assert_eq!(
            back.coordinator_url.as_deref(),
            Some("http://localhost:3210")
        );
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

    #[test]
    fn upsert_space_replaces_by_id() {
        let mut cfg = Config::default();
        cfg.upsert_space("sp_1", "/a");
        cfg.upsert_space("sp_1", "/b"); // same id -> replace, not duplicate.
        assert_eq!(cfg.spaces.len(), 1);
        assert_eq!(cfg.spaces[0].local_root, "/b");
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
