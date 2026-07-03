//! The Device's secret store — `credentials.json`, kept `0600` (`docs/adr/0014`,
//! `docs/adr/0015`).
//!
//! `config.json` holds only non-secret identity (account/device ids, the
//! Coordinator URL). The SECRETS live here, in a separate file the CLI creates
//! `0600`:
//!
//! - `session_token` — the Better Auth session (~7 days); the CLI trades it for a
//!   short-lived Convex JWT on every connection.
//! - `dedup_secret` — the per-Account escrow secret (`§4.4`) returned by
//!   `auth:ensureDevice`, hex-encoded. Combined with a Space's `space_key` it
//!   derives the `alg=1` keys.
//!
//! Per-Space `space_key`s (`§4.5`) are cached separately, one file per Space at
//! `<space_root>/.filething/space_key` (also `0600`), so opening a Space does not
//! need the network. See [`read_space_key`] / [`write_space_key`].

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::env::CONTROL_DIR;

/// The secrets file basename under the config dir.
const CREDENTIALS_FILE: &str = "credentials.json";
/// The per-Space escrow-key cache basename under a Space's control dir.
const SPACE_KEY_FILE: &str = "space_key";
/// Escrow secrets (dedup_secret / space_key) are fixed 32-byte keys.
const SECRET_LEN: usize = 32;

/// The Device's persisted secrets (`credentials.json`, `0600`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// The Better Auth session token (traded for a Convex JWT per connection).
    pub session_token: String,
    /// The per-Account escrow `dedup_secret`, hex-encoded (`§4.4`).
    pub dedup_secret_hex: String,
}

impl Credentials {
    /// The full path to `credentials.json` for this run (alongside `config.json`).
    pub fn path() -> PathBuf {
        Config::config_dir().join(CREDENTIALS_FILE)
    }

    /// Loads the credentials, returning `None` when the Device has not logged in
    /// yet (no file).
    pub fn load() -> anyhow::Result<Option<Self>> {
        Self::load_from(&Self::path())
    }

    /// Testable core of [`load`]: reads credentials from an explicit path.
    pub fn load_from(path: &Path) -> anyhow::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let creds = serde_json::from_slice(&bytes)
                    .map_err(|e| anyhow!("parsing {}: {e}", path.display()))?;
                Ok(Some(creds))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow!("reading {}: {e}", path.display())),
        }
    }

    /// Persists the credentials `0600`, creating the config dir if needed.
    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to(&Self::path())
    }

    /// Testable core of [`save`]: persists credentials `0600` to `path`.
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        write_secret_file(path, &json)
    }

    /// Decodes the escrow `dedup_secret` into its 32 bytes.
    pub fn dedup_secret(&self) -> anyhow::Result<[u8; 32]> {
        decode_secret(&self.dedup_secret_hex, "dedup_secret")
    }
}

/// Generates a fresh 32-byte escrow secret candidate (CSPRNG) — the
/// `dedup_secret` sent to `auth:ensureDevice` and the `space_key` sent to
/// `spaces:create`.
pub fn generate_secret() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// The per-Space `space_key` cache path: `<root>/.filething/space_key`.
pub fn space_key_path(root: &Path) -> PathBuf {
    root.join(CONTROL_DIR).join(SPACE_KEY_FILE)
}

/// Reads a Space's cached `space_key`, or `None` when it is not cached yet (a
/// legacy `alg=0` Space, or one this Device has not fetched the key for).
pub fn read_space_key(root: &Path) -> anyhow::Result<Option<[u8; 32]>> {
    let path = space_key_path(root);
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(decode_secret(s.trim(), "space_key")?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("reading {}: {e}", path.display())),
    }
}

/// Caches a Space's `space_key` at `<root>/.filething/space_key`, `0600`.
pub fn write_space_key(root: &Path, space_key: &[u8; 32]) -> anyhow::Result<()> {
    write_secret_file(&space_key_path(root), hex::encode(space_key).as_bytes())
}

/// Decodes a hex escrow secret and checks it is exactly 32 bytes.
fn decode_secret(hexstr: &str, what: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hexstr).map_err(|e| anyhow!("{what} is not valid hex: {e}"))?;
    if bytes.len() != SECRET_LEN {
        return Err(anyhow!(
            "{what} must be {SECRET_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Writes `bytes` to `path` with `0600` permissions, creating the parent dir.
/// On Unix the file is created `0600` from the start (never briefly world-
/// readable); the mode is re-asserted on an existing file.
fn write_secret_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("creating {}: {e}", parent.display()))?;
    }
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| anyhow!("opening {} (0600): {e}", path.display()))?;
        f.write_all(bytes)
            .map_err(|e| anyhow!("writing {}: {e}", path.display()))?;
        // Re-assert 0600 in case the file pre-existed with looser perms.
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .map_err(|e| anyhow!("chmod 0600 {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| anyhow!("writing {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_roundtrip_and_dedup_decode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let secret = [0x5au8; 32];
        let creds = Credentials {
            session_token: "sess-abc".into(),
            dedup_secret_hex: hex::encode(secret),
        };
        creds.save_to(&path).unwrap();

        let back = Credentials::load_from(&path).unwrap().unwrap();
        assert_eq!(back, creds);
        assert_eq!(back.dedup_secret().unwrap(), secret);
    }

    #[test]
    fn load_missing_credentials_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.json");
        assert!(Credentials::load_from(&path).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        Credentials {
            session_token: "s".into(),
            dedup_secret_hex: hex::encode([1u8; 32]),
        }
        .save_to(&path)
        .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credentials.json must be 0600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn space_key_cache_roundtrips_and_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(read_space_key(root).unwrap().is_none());
        let key = [0x7eu8; 32];
        write_space_key(root, &key).unwrap();
        assert_eq!(read_space_key(root).unwrap(), Some(key));
        let mode = std::fs::metadata(space_key_path(root))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "space_key must be 0600, got {mode:o}");
    }

    #[test]
    fn decode_secret_rejects_wrong_length() {
        assert!(decode_secret(&hex::encode([0u8; 16]), "x").is_err());
        assert!(decode_secret("not-hex", "x").is_err());
    }
}
