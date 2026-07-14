//! ft-vault — content-addressed storage (the data plane). `docs/format.md §6.1`.
//!
//! The async [`Vault`] trait ([`Vault::head`]/[`Vault::get`]/[`Vault::put`], plus
//! [`Vault::list`]/[`Vault::delete`] for garbage collection) with two backends:
//!
//! - [`S3Vault`] — talks to MinIO locally / Cloudflare R2 in prod, via the AWS
//!   SDK with **path-style** addressing forced on (`force_path_style(true)`) so a
//!   single endpoint+bucket reaches MinIO. Switch to R2 by changing only config.
//! - [`FsVault`] — stores each key as a file under a `root` directory, for tests
//!   and single-machine gates without Docker.
//!
//! Keys follow the `blocks|manifest|blocklist/<aa>/<cid>` fan-out built by
//! `ft-hash`; `keys/*` and `reach/*` are reserved (cifrado OFF, §4.5, §6.3). The
//! Vault is **content-addressed**: an object's key is a hash of its bytes, so a
//! `put` of a key that already holds the same object is a safe no-op. `put` is
//! therefore idempotent. Deciding whether to `head` before `put` (to save
//! bandwidth) is the CALLER's choice — the trait does not force it. The
//! Coordinator never reads the Vault (§6.1).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors (docs/BUILD-PLAN.md §3 — thiserror per crate)
// ---------------------------------------------------------------------------

/// Errors a [`Vault`] backend can surface.
#[derive(Debug, Error)]
pub enum VaultError {
    /// A `get` (or `put`-readback) referenced a key that does not exist.
    #[error("object not found: {key}")]
    NotFound {
        /// The Vault key that was missing.
        key: String,
    },

    /// A local-filesystem operation failed (the [`FsVault`] backend).
    #[error("filesystem vault io error at {key}: {source}")]
    Io {
        /// The Vault key being operated on.
        key: String,
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// An S3 / object-store request failed (the [`S3Vault`] backend).
    ///
    /// Wraps the SDK error as a string so callers depending on `ft-vault` do not
    /// need the AWS SDK types in their own signatures.
    #[error("s3 vault error at {key}: {message}")]
    S3 {
        /// The Vault key being operated on.
        key: String,
        /// A human-readable rendering of the SDK error.
        message: String,
    },
}

/// `Result` alias over [`VaultError`].
pub type VaultResult<T> = std::result::Result<T, VaultError>;

/// One object surfaced by [`Vault::list`]: its full Vault key plus a best-effort
/// last-modified time. The GC uses `last_modified` for the grace-period guard
/// (never sweep an object younger than the grace window, `docs/adr/0007`), so a
/// backend that cannot report it (`None`) forces the safe choice: such an object
/// is treated as "too young to sweep".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultObject {
    /// The object's full fan-out key (e.g. `blocks/9f/9f86…`).
    pub key: String,
    /// The object's last-modified time, when the backend reports one.
    pub last_modified: Option<SystemTime>,
}

/// The verb of a [`WarmOp`]: which [`Vault`] operation the caller is about to
/// perform on the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WarmMethod {
    /// An upcoming [`Vault::head`].
    Head,
    /// An upcoming [`Vault::get`].
    Get,
    /// An upcoming [`Vault::put`].
    Put,
}

/// One operation the caller is ABOUT to perform, announced via [`Vault::warm`]
/// so a backend with per-operation setup cost (the CLI's presigned-URL vault,
/// ADR 0016) can amortize it in batch. Purely a hint: correctness never depends
/// on having warmed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WarmOp {
    /// The full fan-out Vault key of the upcoming operation.
    pub key: String,
    /// Which operation will run on it.
    pub method: WarmMethod,
}

// ---------------------------------------------------------------------------
// The Vault trait (docs/BUILD-PLAN.md §3, F9)
// ---------------------------------------------------------------------------

/// Content-addressed object store: the data plane that holds Blocks, Manifest
/// pages and externalized blocklists. `docs/format.md §6.1`.
///
/// All three operations are keyed by a fan-out object key
/// (`blocks/<aa>/<cid>`, etc., produced by `ft-hash`). Because keys are content
/// hashes, [`Vault::put`] is **idempotent**: re-uploading the identical object
/// under the same key is a safe no-op. A caller MAY `head` before `put` to skip
/// the upload and save bandwidth, but that is an optimization the caller owns —
/// the trait does not require it.
#[async_trait]
pub trait Vault: Send + Sync {
    /// Returns `true` if an object exists at `key`, `false` otherwise. Must NOT
    /// error on a plain "absent" — only on a genuine transport/IO failure.
    async fn head(&self, key: &str) -> VaultResult<bool>;

    /// Fetches the full object bytes at `key`. Errors with
    /// [`VaultError::NotFound`] if the key does not exist.
    async fn get(&self, key: &str) -> VaultResult<Vec<u8>>;

    /// Stores `body` at `key`. Idempotent: storing the same content-addressed
    /// object again is a no-op from the caller's point of view.
    async fn put(&self, key: &str, body: Vec<u8>) -> VaultResult<()>;

    /// Lists every object whose key starts with `prefix`, following backend
    /// pagination to completion. The GC calls this over the `blocks/`,
    /// `manifest/`, `blocklist/` and `meta/` prefixes to enumerate the physical
    /// object set it then diffs against the reachable set (`docs/adr/0007`).
    /// Order is unspecified.
    async fn list(&self, prefix: &str) -> VaultResult<Vec<VaultObject>>;

    /// Deletes the object at `key`. **Idempotent**: deleting a key that does not
    /// exist is `Ok(())`, never [`VaultError::NotFound`] — a GC sweep that races
    /// another sweep (or a manual cleanup) must not fail on an already-gone
    /// object.
    async fn delete(&self, key: &str) -> VaultResult<()>;

    /// Announces operations the caller is about to perform, so a backend with
    /// per-operation setup cost can prepare them in batch (the CLI's
    /// presigned-URL vault pre-signs up to 256 URLs per Coordinator round-trip,
    /// ADR 0016). A pure HINT with best-effort semantics: backends default to a
    /// no-op, callers must work identically if it was never called, and a
    /// failure here should surface only if the underlying transport is truly
    /// down (callers may also choose to ignore it and let the real operation
    /// report the error).
    async fn warm(&self, _ops: &[WarmOp]) -> VaultResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FsVault — local-filesystem backend (tests, single-machine gates)
// ---------------------------------------------------------------------------

/// A [`Vault`] backed by a local directory: each `key` becomes the file
/// `root/<key>` (parent dirs created on demand). Lets the single-machine gates
/// and unit tests run with no Docker / MinIO. `docs/BUILD-PLAN.md §3`.
#[derive(Debug, Clone)]
pub struct FsVault {
    root: PathBuf,
}

impl FsVault {
    /// Builds an `FsVault` rooted at `root`. The directory is created lazily on
    /// the first `put`; nothing touches the filesystem here.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolves a Vault `key` to its on-disk path under `root`. The key uses
    /// forward slashes (the fan-out format) which map directly to path segments.
    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }
}

#[async_trait]
impl Vault for FsVault {
    async fn head(&self, key: &str) -> VaultResult<bool> {
        let path = self.path_for(key);
        // `try_exists` distinguishes "absent" (Ok(false)) from a real IO error.
        match tokio::fs::try_exists(&path).await {
            Ok(exists) => Ok(exists),
            Err(source) => Err(VaultError::Io {
                key: key.to_string(),
                source,
            }),
        }
    }

    async fn get(&self, key: &str) -> VaultResult<Vec<u8>> {
        let path = self.path_for(key);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(bytes),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Err(VaultError::NotFound {
                    key: key.to_string(),
                })
            }
            Err(source) => Err(VaultError::Io {
                key: key.to_string(),
                source,
            }),
        }
    }

    async fn put(&self, key: &str, body: Vec<u8>) -> VaultResult<()> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            create_dir_all(parent, key).await?;
        }
        // Content-addressed: if the object is already there, the write simply
        // rewrites identical bytes — a safe no-op for the caller.
        tokio::fs::write(&path, &body)
            .await
            .map_err(|source| VaultError::Io {
                key: key.to_string(),
                source,
            })
    }

    async fn list(&self, prefix: &str) -> VaultResult<Vec<VaultObject>> {
        // Iterative walk of the whole store rooted at `self.root`, filtering by
        // the (forward-slash) key prefix. Iterative (an explicit stack) rather
        // than recursive to avoid boxing an async recursion. A missing directory
        // is simply an empty listing (the vault may be brand new).
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = match tokio::fs::read_dir(&dir).await {
                Ok(rd) => rd,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(VaultError::Io {
                        key: dir.to_string_lossy().into_owned(),
                        source,
                    })
                }
            };
            while let Some(entry) = rd.next_entry().await.map_err(|source| VaultError::Io {
                key: dir.to_string_lossy().into_owned(),
                source,
            })? {
                let path = entry.path();
                let file_type = entry.file_type().await.map_err(|source| VaultError::Io {
                    key: path.to_string_lossy().into_owned(),
                    source,
                })?;
                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }
                // Reconstruct the Vault key from the path relative to root, always
                // with forward slashes (the fan-out key shape) regardless of OS.
                let Ok(rel) = path.strip_prefix(&self.root) else {
                    continue;
                };
                let key = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                if !key.starts_with(prefix) {
                    continue;
                }
                let last_modified = entry.metadata().await.ok().and_then(|m| m.modified().ok());
                out.push(VaultObject { key, last_modified });
            }
        }
        Ok(out)
    }

    async fn delete(&self, key: &str) -> VaultResult<()> {
        let path = self.path_for(key);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            // Idempotent: an already-absent object is a successful delete.
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(VaultError::Io {
                key: key.to_string(),
                source,
            }),
        }
    }
}

/// `create_dir_all` that attributes any failure to `key` for error context.
async fn create_dir_all(dir: &Path, key: &str) -> VaultResult<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|source| VaultError::Io {
            key: key.to_string(),
            source,
        })
}

// ---------------------------------------------------------------------------
// S3Vault — S3-compatible backend (MinIO local / Cloudflare R2)
// ---------------------------------------------------------------------------

/// Connection config for an [`S3Vault`]. Mirrors the `S3_*` env vars in
/// `infra/.env.example` / `infra/scripts/print-env.sh`.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 endpoint URL (e.g. `http://localhost:9000` for local MinIO).
    pub endpoint: String,
    /// Region label (MinIO ignores it; R2 wants `auto`/a real region). `us-east-1` locally.
    pub region: String,
    /// Access key id.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
    /// The single bucket holding `blocks/`, `manifest/`, `blocklist/`.
    pub bucket: String,
}

impl S3Config {
    /// Reads an [`S3Config`] from the `S3_ENDPOINT`/`S3_REGION`/`S3_ACCESS_KEY`/
    /// `S3_SECRET_KEY`/`S3_BUCKET` environment variables (see
    /// `infra/scripts/print-env.sh`). Returns `None` if any are missing — handy
    /// for env-gated integration tests that must skip when infra is absent.
    pub fn from_env() -> Option<Self> {
        Some(Self {
            endpoint: std::env::var("S3_ENDPOINT").ok()?,
            region: std::env::var("S3_REGION").ok()?,
            access_key: std::env::var("S3_ACCESS_KEY").ok()?,
            secret_key: std::env::var("S3_SECRET_KEY").ok()?,
            bucket: std::env::var("S3_BUCKET").ok()?,
        })
    }
}

/// A [`Vault`] backed by an S3-compatible object store. Built from [`S3Config`];
/// **forces path-style addressing** (`force_path_style(true)`) so it reaches a
/// local MinIO at `http://host:9000/<bucket>/<key>` rather than the virtual-host
/// form. Switching to Cloudflare R2 is a config change only. `docs/format.md §6.1`.
#[derive(Debug, Clone)]
pub struct S3Vault {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3Vault {
    /// Builds an `S3Vault` from explicit config. Uses behavior-version-latest,
    /// static credentials, the configured endpoint+region and forced path-style.
    pub async fn new(config: S3Config) -> Self {
        let creds = aws_credential_types::Credentials::new(
            config.access_key,
            config.secret_key,
            None, // session token
            None, // expiry
            "ft-vault-static",
        );

        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(config.region))
            .endpoint_url(config.endpoint)
            .credentials_provider(creds)
            .load()
            .await;

        // force_path_style is the load-bearing setting for MinIO.
        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(true)
            .build();

        Self {
            client: aws_sdk_s3::Client::from_conf(s3_config),
            bucket: config.bucket,
        }
    }

    /// Builds an `S3Vault` from the `S3_*` env vars, or `None` if any are unset.
    pub async fn from_env() -> Option<Self> {
        let config = S3Config::from_env()?;
        Some(Self::new(config).await)
    }
}

#[async_trait]
impl Vault for S3Vault {
    async fn head(&self, key: &str) -> VaultResult<bool> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) => {
                // A missing object is NOT an error: NoSuchKey / NotFound / 404.
                let service_err = err.into_service_error();
                if service_err.is_not_found() {
                    return Ok(false);
                }
                Err(VaultError::S3 {
                    key: key.to_string(),
                    message: format!("{service_err}"),
                })
            }
        }
    }

    async fn get(&self, key: &str) -> VaultResult<Vec<u8>> {
        let resp = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                let service_err = err.into_service_error();
                if service_err.is_no_such_key() {
                    return Err(VaultError::NotFound {
                        key: key.to_string(),
                    });
                }
                return Err(VaultError::S3 {
                    key: key.to_string(),
                    message: format!("{service_err}"),
                });
            }
        };

        let data = resp.body.collect().await.map_err(|source| VaultError::S3 {
            key: key.to_string(),
            message: format!("reading object body: {source}"),
        })?;
        Ok(data.into_bytes().to_vec())
    }

    async fn put(&self, key: &str, body: Vec<u8>) -> VaultResult<()> {
        // Idempotent by content-addressing: re-PUTting identical bytes overwrites
        // with the same content, which the caller treats as a no-op.
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(body))
            .send()
            .await
            .map_err(|err| VaultError::S3 {
                key: key.to_string(),
                message: format!("{}", err.into_service_error()),
            })?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> VaultResult<Vec<VaultObject>> {
        let mut out = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = continuation.take() {
                req = req.continuation_token(token);
            }
            let resp = req.send().await.map_err(|err| VaultError::S3 {
                key: format!("list {prefix}"),
                message: format!("{}", err.into_service_error()),
            })?;
            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    out.push(VaultObject {
                        key: key.to_string(),
                        last_modified: obj.last_modified().and_then(datetime_to_systemtime),
                    });
                }
            }
            // Follow pagination only while the response says it is truncated AND
            // hands back a token; otherwise we have the full listing.
            match (resp.is_truncated(), resp.next_continuation_token()) {
                (Some(true), Some(token)) => continuation = Some(token.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn delete(&self, key: &str) -> VaultResult<()> {
        // S3 DELETE is idempotent: deleting an absent key returns success.
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|err| VaultError::S3 {
                key: key.to_string(),
                message: format!("{}", err.into_service_error()),
            })?;
        Ok(())
    }
}

/// Converts an S3 SDK [`DateTime`](aws_sdk_s3::primitives::DateTime) to a
/// [`SystemTime`]. Returns `None` for a pre-epoch timestamp (never expected for a
/// stored object) so the caller treats it conservatively.
fn datetime_to_systemtime(dt: &aws_sdk_s3::primitives::DateTime) -> Option<SystemTime> {
    let secs = dt.secs();
    if secs < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::new(secs as u64, dt.subsec_nanos()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- FsVault roundtrip put / get / head -----

    #[tokio::test]
    async fn fs_vault_roundtrip_put_get_head() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        // §4.2 fan-out key shape; FsVault must create the nested dirs.
        let key = "blocks/9f/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let body = b"FTB1-header-and-payload-bytes".to_vec();

        // head is false BEFORE the object exists.
        assert!(!vault.head(key).await.unwrap());

        vault.put(key, body.clone()).await.unwrap();

        // head is true AFTER put.
        assert!(vault.head(key).await.unwrap());

        // get returns the EXACT bytes.
        let got = vault.get(key).await.unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn fs_vault_put_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let key = "manifest/ab/abc";
        let body = b"identical content-addressed object".to_vec();

        // Re-uploading the same content-addressed object is a safe no-op: head
        // stays true and the bytes are unchanged.
        vault.put(key, body.clone()).await.unwrap();
        vault.put(key, body.clone()).await.unwrap();
        vault.put(key, body.clone()).await.unwrap();

        assert!(vault.head(key).await.unwrap());
        assert_eq!(vault.get(key).await.unwrap(), body);
    }

    #[tokio::test]
    async fn fs_vault_get_missing_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        match vault.get("blocks/00/does-not-exist").await {
            Err(VaultError::NotFound { key }) => {
                assert_eq!(key, "blocks/00/does-not-exist");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_vault_head_false_for_absent_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        assert!(!vault.head("blocklist/zz/missing").await.unwrap());
    }

    #[tokio::test]
    async fn fs_vault_handles_empty_object() {
        // The empty BLAKE3 input is a real content-addressed case; an empty body
        // must round-trip and head must report it present.
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let key = "blocks/af/af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        vault.put(key, Vec::new()).await.unwrap();
        assert!(vault.head(key).await.unwrap());
        assert_eq!(vault.get(key).await.unwrap(), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn fs_vault_list_filters_by_prefix_and_reports_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());

        vault.put("blocks/9f/9f86aa", b"a".to_vec()).await.unwrap();
        vault.put("blocks/af/af1349", b"b".to_vec()).await.unwrap();
        vault.put("manifest/ab/abc", b"c".to_vec()).await.unwrap();
        vault.put("meta/de/def", b"d".to_vec()).await.unwrap();

        let mut blocks = vault.list("blocks/").await.unwrap();
        blocks.sort_by(|a, b| a.key.cmp(&b.key));
        let keys: Vec<&str> = blocks.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, vec!["blocks/9f/9f86aa", "blocks/af/af1349"]);
        // FsVault reports a real mtime for every listed object.
        assert!(blocks.iter().all(|o| o.last_modified.is_some()));

        // A prefix that matches nothing is an empty listing, not an error.
        assert!(vault.list("nope/").await.unwrap().is_empty());

        // Listing the whole store sees every object across prefixes.
        assert_eq!(vault.list("").await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn fs_vault_delete_removes_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let key = "blocks/9f/9f86aa";
        vault.put(key, b"payload".to_vec()).await.unwrap();
        assert!(vault.head(key).await.unwrap());

        vault.delete(key).await.unwrap();
        assert!(!vault.head(key).await.unwrap());

        // Deleting an already-absent object succeeds (idempotent).
        vault.delete(key).await.unwrap();
        vault.delete("blocks/00/never-existed").await.unwrap();
    }

    // ----- S3Vault: env-gated, only runs against a live MinIO -----

    /// Roundtrip against a real MinIO. Skips unless `FT_TEST_S3=1` AND the `S3_*`
    /// env vars are present, so the build never fails without Docker.
    /// Run with: `FT_TEST_S3=1 eval "$(infra/scripts/print-env.sh --exports)"`.
    #[tokio::test]
    async fn s3_vault_roundtrip_against_minio() {
        if std::env::var("FT_TEST_S3").as_deref() != Ok("1") {
            eprintln!("skipping s3_vault_roundtrip_against_minio: set FT_TEST_S3=1 to run");
            return;
        }
        let Some(vault) = S3Vault::from_env().await else {
            eprintln!("skipping s3_vault_roundtrip_against_minio: S3_* env vars not set");
            return;
        };

        // Unique key per run so repeated runs don't depend on cleanup.
        let key = format!(
            "blocks/ft/ft-vault-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let body = b"FTB1 minio roundtrip payload".to_vec();

        assert!(!vault.head(&key).await.unwrap());
        vault.put(&key, body.clone()).await.unwrap();
        assert!(vault.head(&key).await.unwrap());
        assert_eq!(vault.get(&key).await.unwrap(), body);

        // PUT is idempotent.
        vault.put(&key, body.clone()).await.unwrap();
        assert_eq!(vault.get(&key).await.unwrap(), body);
    }
}
