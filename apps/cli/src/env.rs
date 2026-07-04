//! Building the engine's collaborators from the environment (`docs/BUILD-PLAN.md
//! §3`, `docs/adr/0014`, `docs/adr/0015`).
//!
//! The Coordinator URL and the Vault `S3_*` credentials come from the
//! environment; the per-Device identity (the Better Auth session) comes from the
//! Device's [`Credentials`]. The normal path is authenticated: the CLI trades the
//! session for a Convex JWT and attaches it to the websocket via
//! [`ConvexClient::set_auth_callback`], which re-mints the JWT on every connect
//! and reconnect. This applies to one-shot commands too, not just the daemon: the
//! convex client's `set_auth` wraps a STATIC token in a fetcher that keeps
//! returning the same (now-expired) token forever, so a one-shot command whose
//! work outlives the ~15-min JWT expiry (e.g. a large `sync` upload) would
//! otherwise hang in an infinite AuthError/reconnect loop on its next mutation.
//! The deployment admin/deploy key is now ONLY an ops fallback for when there is
//! no session (see [`connect`]).
//!
//! Deployments (`docs/PRODUCTION-SETUP.md`): local Docker infra
//! (`CONVEX_SELF_HOSTED_URL`) or managed cloud (`CONVEX_URL`); the URL selects
//! both the Convex websocket and — via [`crate::auth::auth_base_url`] — the
//! Better Auth host.
//!
//! These helpers centralize that wiring so every subcommand builds a
//! [`Coordinator`], attaches encryption key material, and builds a [`Vault`] the
//! same way.

use std::path::Path;

use anyhow::Context as _;
use convex::{AuthTokenFetcher, AuthenticationToken, ConvexClient};
use ft_core::SpaceCrypto;
use ft_engine::{Coordinator, SpaceId, Vault};

use crate::auth;
use crate::credentials::{self, Credentials};

/// Cloud-neutral Convex deployment URL (Convex Cloud `https://<name>.convex.cloud`).
/// Preferred; falls back to [`ENV_URL_SELF_HOSTED`].
const ENV_URL: &str = "CONVEX_URL";
/// Legacy/self-hosted alias for the Convex URL (the local Docker infra).
const ENV_URL_SELF_HOSTED: &str = "CONVEX_SELF_HOSTED_URL";
/// Cloud-neutral admin credential. Preferred name.
const ENV_ADMIN_KEY: &str = "CONVEX_ADMIN_KEY";
/// Convex Cloud deploy key, used as client admin auth for personal-use Devices.
const ENV_DEPLOY_KEY: &str = "CONVEX_DEPLOY_KEY";
/// Legacy/self-hosted alias for the admin key (the local Docker infra).
const ENV_ADMIN_KEY_SELF_HOSTED: &str = "CONVEX_SELF_HOSTED_ADMIN_KEY";
/// The CONTROL_DIR subfolder of a Space root holding the local index.
pub const CONTROL_DIR: &str = ".filething";
/// The local index filename under the control dir.
pub const INDEX_FILE: &str = "index.db";

/// The first of `names` set to a non-empty value in the environment, if any.
fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
}

/// Compile-time default Coordinator URL for distributable builds: baked in by
/// setting `FILETHING_DEFAULT_CONVEX_URL` at *build* time (the release/dist
/// pipeline points it at the managed Convex Cloud deployment). `None` in a
/// plain `cargo build`, where the localhost Docker infra remains the default.
const BAKED_DEFAULT_URL: Option<&str> = option_env!("FILETHING_DEFAULT_CONVEX_URL");

/// The Coordinator URL for this run: `CONVEX_URL`, then the self-hosted alias,
/// then the baked-in distribution default, else localhost. Used both for
/// `login` (no config yet) and to verify a config's URL.
pub fn coordinator_url_from_env() -> String {
    resolve_coordinator_url(
        first_env(&[ENV_URL, ENV_URL_SELF_HOSTED]),
        BAKED_DEFAULT_URL,
    )
}

/// Pure resolution order behind [`coordinator_url_from_env`]: runtime env var >
/// baked-in build default > localhost (dev Docker infra).
fn resolve_coordinator_url(env_url: Option<String>, baked_default: Option<&str>) -> String {
    env_url
        .or_else(|| baked_default.map(str::to_string))
        .unwrap_or_else(|| "http://localhost:3210".to_string())
}

/// Builds a [`Coordinator`] connected to `url`, authenticated as this Device.
///
/// - With a Better Auth session (`creds`): trade it for a Convex JWT and attach
///   it via [`ConvexClient::set_auth_callback`], which re-mints the JWT (calling
///   `auth::convex_token` again) on every websocket connect and reconnect —
///   surviving the ~15-min expiry with no operator action, for one-shot commands
///   and the daemon alike (see the module doc comment for why one-shot commands
///   need this too).
/// - Without a session: fall back to the deployment admin/deploy key
///   ([`connect_ops_fallback`]) — an OPS escape hatch, no longer the normal flow.
pub async fn connect(url: &str, creds: Option<&Credentials>) -> anyhow::Result<Coordinator> {
    Ok(Coordinator::from_client(connect_client(url, creds).await?))
}

/// The raw authenticated [`ConvexClient`] behind [`connect`]. Exposed so the
/// data plane can share the SAME authenticated connection: [`build_vault`]
/// hands a clone of this client to the [`SignedVault`] when the `S3_*` env vars
/// are absent (the end-user path, `docs/adr/0016`).
///
/// [`SignedVault`]: crate::signed_vault::SignedVault
pub async fn connect_client(
    url: &str,
    creds: Option<&Credentials>,
) -> anyhow::Result<ConvexClient> {
    match creds {
        Some(c) if !c.session_token.is_empty() => connect_authed(url, &c.session_token).await,
        _ => connect_ops_fallback(url).await,
    }
}

/// Connects with the per-Device Better Auth session attached as a Convex JWT,
/// re-minted on every connect/reconnect via [`ConvexClient::set_auth_callback`]
/// (see [`connect`]'s doc comment).
async fn connect_authed(url: &str, session_token: &str) -> anyhow::Result<ConvexClient> {
    let base = auth::auth_base_url(url)?;
    let mut client = ConvexClient::new(url)
        .await
        .with_context(|| format!("connecting to the Coordinator at {url}"))?;

    let token = session_token.to_string();
    let fetcher: AuthTokenFetcher = Box::new(move |_force_refresh: bool| {
        let base = base.clone();
        let token = token.clone();
        Box::pin(async move {
            let jwt = auth::convex_token(&base, &token).await?;
            Ok(AuthenticationToken::User(jwt))
        })
            as std::pin::Pin<
                Box<dyn std::future::Future<Output = anyhow::Result<AuthenticationToken>> + Send>,
            >
    });
    client.set_auth_callback(Some(fetcher)).await;
    Ok(client)
}

/// Ops fallback: connect with the deployment admin/deploy key when there is no
/// session. Resolved in precedence order — `CONVEX_ADMIN_KEY`,
/// `CONVEX_DEPLOY_KEY` (Convex Cloud), `CONVEX_SELF_HOSTED_ADMIN_KEY` (local
/// infra) — and never persisted. With NONE set, connects unauthenticated (which
/// the auth-gated contract functions now reject — hence the login hint).
async fn connect_ops_fallback(url: &str) -> anyhow::Result<ConvexClient> {
    let mut client = ConvexClient::new(url)
        .await
        .with_context(|| format!("connecting to the Coordinator at {url}"))?;
    match first_env(&[ENV_ADMIN_KEY, ENV_DEPLOY_KEY, ENV_ADMIN_KEY_SELF_HOSTED]) {
        Some(admin_key) => {
            tracing::warn!(
                "no Device session found; using the deployment admin/deploy key as an OPS \
                 fallback — this is NOT the normal flow, run `filething login` to authenticate \
                 as a Device"
            );
            client.set_admin_auth(admin_key, None).await
        }
        None => tracing::warn!(
            "not logged in and no Convex admin/deploy key set — the Coordinator's functions \
             require authentication; run `filething login` first"
        ),
    }
    Ok(client)
}

/// Loads this Device's encryption key material for the Space at `root` from the
/// LOCAL caches (no network): the per-Space `space_key` cache plus the Account
/// `dedup_secret` in [`Credentials`]. `space_id` scopes the sidecar object keys
/// (`keys/<space_id>/<cid>`, `§4.5`).
///
/// The two secrets are NOT symmetric (Fix A / the "silent cleartext commit"
/// hardening): the `space_key` cache is local evidence that THIS Space is
/// encrypted (`alg=1`) — once it exists, cleartext is no longer a legitimate
/// path for this Space, credentials or not.
///
/// - Neither secret present: a legacy Space with no escrowed key. Returns `None`
///   so the Space stays on the cleartext `alg=0` path, unchanged.
/// - `space_key` cached but no credentials (deploy-key ops fallback, or a
///   session lost after it was cached): errors instead of silently falling back
///   to `None`/cleartext — a commit here would upload the whole tree
///   unencrypted under a divergent `alg=0` root. Run `filething login`.
/// - Both present: builds the [`SpaceCrypto`].
pub fn load_space_crypto(
    root: &Path,
    space_id: &SpaceId,
    creds: Option<&Credentials>,
) -> anyhow::Result<Option<SpaceCrypto>> {
    let Some(space_key) = credentials::read_space_key(root)? else {
        return Ok(None);
    };
    let creds = creds.ok_or_else(|| {
        anyhow::anyhow!(
            "Space {space_id} is encrypted (alg=1: a cached escrow key was found at \
             {}) but no Device credentials were found — refusing to proceed, which would \
             silently commit/read this Space in CLEARTEXT. Run `filething login` to \
             authenticate this Device.",
            credentials::space_key_path(root).display()
        )
    })?;
    Ok(Some(SpaceCrypto {
        dedup_secret: creds.dedup_secret()?,
        space_key,
        space_id: space_id.as_str().to_string(),
    }))
}

/// Guard-2 (Fix A, layer 2): the online-authoritative counterpart to the
/// [`load_space_crypto`] local-cache asymmetry. `escrow_key` is the Space's
/// escrow key as authoritatively resolved by [`ensure_space_key_cached`] (a
/// local cache hit, or — on a cache miss — a live Coordinator `spaces:get`);
/// `crypto` is what this run actually attached. If the Space is known to be
/// encrypted (`escrow_key` is `Some`) but crypto could not be attached, refuse
/// to proceed rather than let the caller commit/scan the Space in cleartext.
///
/// This should be unreachable once `load_space_crypto`'s guard above holds (it
/// would already have errored), but callers wire it in as a second, independent
/// check at the call sites that can commit — cheap insurance against the two
/// checks ever drifting apart.
pub fn assert_crypto_matches_escrow(
    space_id: &SpaceId,
    escrow_key: Option<[u8; 32]>,
    crypto: Option<&SpaceCrypto>,
) -> anyhow::Result<()> {
    if escrow_key.is_some() && crypto.is_none() {
        anyhow::bail!(
            "Space {space_id} is encrypted (alg=1, escrow key on file) but no crypto is \
             attached for this run — refusing to proceed and commit/read it in cleartext. \
             Run `filething login` to authenticate this Device."
        );
    }
    Ok(())
}

/// Ensures the Space's `space_key` is cached locally, fetching it from the
/// Coordinator (`spaces:get`) and writing the `0600` cache on a miss. Returns the
/// key, or `None` for a legacy Space the backend has no `space_key` for. Lets a
/// freshly-opened Space (e.g. one restored from config without its cache) recover
/// its key so later commands work offline.
pub async fn ensure_space_key_cached(
    coordinator: &mut Coordinator,
    space_id: &SpaceId,
    root: &Path,
) -> anyhow::Result<Option<[u8; 32]>> {
    if let Some(key) = credentials::read_space_key(root)? {
        return Ok(Some(key));
    }
    let space = coordinator
        .get_space(space_id)
        .await
        .context("fetching the Space to recover its space_key")?;
    if let Some(key) = space.space_key {
        credentials::write_space_key(root, &key)?;
        Ok(Some(key))
    } else {
        Ok(None)
    }
}

/// Builds the data-plane [`Vault`]. Precedence (`docs/adr/0016`):
///
/// 1. `S3_*` env vars fully set → direct [`S3Vault`](ft_vault::S3Vault): the
///    ops/self-hosted/dev path, and the ONLY one that supports `gc` (which
///    needs `list`/`delete` — presigned URLs cannot list).
/// 2. Otherwise → [`SignedVault`](crate::signed_vault::SignedVault) over
///    `client`: the end-user path. Blobs go direct to R2 via presigned URLs
///    minted by the Coordinator's auth-gated `vault:sign` action; the Device
///    never holds storage credentials.
pub async fn build_vault(client: Option<ConvexClient>) -> anyhow::Result<Box<dyn Vault>> {
    if let Some(v) = ft_vault::S3Vault::from_env().await {
        return Ok(Box::new(v));
    }
    match client {
        Some(c) => Ok(Box::new(crate::signed_vault::SignedVault::new(c))),
        None => Err(anyhow::anyhow!(
            "the Vault is not configured: run `filething login` (presigned data plane) or set \
             S3_ENDPOINT / S3_REGION / S3_ACCESS_KEY / S3_SECRET_KEY / S3_BUCKET (direct, ops)"
        )),
    }
}

/// One [`connect`] + [`build_vault`] over the SAME authenticated connection —
/// the standard preamble of every online subcommand.
pub async fn connect_and_vault(
    url: &str,
    creds: Option<&Credentials>,
) -> anyhow::Result<(Coordinator, Box<dyn Vault>)> {
    let client = connect_client(url, creds).await?;
    let vault = build_vault(Some(client.clone())).await?;
    Ok((Coordinator::from_client(client), vault))
}

/// A data plane for OFFLINE `status`: `status` must report local changes with
/// no connectivity, but mounting a [`SpaceContext`](ft_engine::SpaceContext)
/// requires a `Vault` even though scanning never touches it. Every operation
/// errors, pointing at the two real backends.
pub struct UnavailableVault;

#[async_trait::async_trait]
impl Vault for UnavailableVault {
    async fn head(&self, key: &str) -> ft_vault::VaultResult<bool> {
        Err(self.err(key))
    }
    async fn get(&self, key: &str) -> ft_vault::VaultResult<Vec<u8>> {
        Err(self.err(key))
    }
    async fn put(&self, key: &str, _body: Vec<u8>) -> ft_vault::VaultResult<()> {
        Err(self.err(key))
    }
    async fn list(&self, prefix: &str) -> ft_vault::VaultResult<Vec<ft_vault::VaultObject>> {
        Err(self.err(prefix))
    }
    async fn delete(&self, key: &str) -> ft_vault::VaultResult<()> {
        Err(self.err(key))
    }
}

impl UnavailableVault {
    fn err(&self, key: &str) -> ft_vault::VaultError {
        ft_vault::VaultError::S3 {
            key: key.to_string(),
            message: "no Vault available offline: the signed data plane needs the Coordinator \
                      reachable, or set S3_* for direct access"
                .to_string(),
        }
    }
}

/// The absolute path to a Space's local index DB: `<root>/.filething/index.db`
/// (the engine's CONTROL_DIR, already ignored by scan).
pub fn index_path(root: &Path) -> std::path::PathBuf {
    root.join(CONTROL_DIR).join(INDEX_FILE)
}

/// Opens (creating its parent dir) the local index for the Space rooted at
/// `root`. Used by `init`/`clone` (fresh) and `status`/`ls`/`sync`/`daemon`
/// (existing).
pub fn open_index(root: &Path) -> anyhow::Result<ft_index::Index> {
    let path = index_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating control dir {}", parent.display()))?;
    }
    ft_index::Index::open(&path).with_context(|| format!("opening index {}", path.display()))
}

/// Reads the single Space's `space_id` recorded in the index at `root`'s control
/// dir, erroring if the dir is not a filething Space (no `space_state` row).
///
/// The local index holds exactly one Space (one root ↔ one Space), so its single
/// `space_state` row identifies the Space — this is how `status`/`ls`/`sync`/
/// `daemon` resolve a dir to its Space id without consulting the config (a Space
/// folder is self-describing). Read via the index connection since ft-index keys
/// `space_state` by id and exposes no "the only row" accessor.
pub fn space_id_at(root: &Path) -> anyhow::Result<ft_engine::SpaceId> {
    let id = existing_space_id_at(root)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not a filething Space (no {}/{}). Run `filething init` or `clone` first.",
            root.display(),
            CONTROL_DIR,
            INDEX_FILE
        )
    })?;
    Ok(id)
}

/// Like [`space_id_at`] but returns `None` (instead of erroring) when `root` is
/// not a Space yet — no index file on disk, or an index with no `space_state`
/// row. `init`/`clone` use it as a guard: initializing over an existing Space
/// would create a second remote Space and a second `space_state` row in the same
/// index, breaking the one-root ↔ one-Space invariant this module relies on.
/// Checks the file first so probing does not create an empty control dir.
pub fn existing_space_id_at(root: &Path) -> anyhow::Result<Option<ft_engine::SpaceId>> {
    if !index_path(root).exists() {
        return Ok(None);
    }
    let index = open_index(root)?;
    let id: Option<String> = index
        .connection()
        .query_row("SELECT space_id FROM space_state LIMIT 1", [], |row| {
            row.get(0)
        })
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .with_context(|| format!("reading space_state at {}", index_path(root).display()))?;
    Ok(id.map(ft_engine::SpaceId::new))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials {
            session_token: "sess-abc".into(),
            dedup_secret_hex: hex::encode([0x11u8; 32]),
        }
    }

    fn space_id() -> SpaceId {
        SpaceId::new("space1".to_string())
    }

    #[test]
    fn resolve_coordinator_url_env_wins_over_baked_default() {
        let url = resolve_coordinator_url(
            Some("https://from-env.convex.cloud".into()),
            Some("https://baked.convex.cloud"),
        );
        assert_eq!(url, "https://from-env.convex.cloud");
    }

    #[test]
    fn resolve_coordinator_url_baked_default_wins_over_localhost() {
        let url = resolve_coordinator_url(None, Some("https://baked.convex.cloud"));
        assert_eq!(url, "https://baked.convex.cloud");
    }

    #[test]
    fn resolve_coordinator_url_falls_back_to_localhost_dev_infra() {
        let url = resolve_coordinator_url(None, None);
        assert_eq!(url, "http://localhost:3210");
    }

    #[test]
    fn load_space_crypto_none_when_neither_secret_present() {
        let dir = tempfile::tempdir().unwrap();
        // No space_key cache, no credentials: legacy cleartext Space.
        let out = load_space_crypto(dir.path(), &space_id(), None).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn load_space_crypto_none_when_only_creds_present() {
        let dir = tempfile::tempdir().unwrap();
        // Logged in, but this Space has no escrowed key on file: still legacy.
        let out = load_space_crypto(dir.path(), &space_id(), Some(&creds())).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn load_space_crypto_errors_when_space_key_cached_but_no_creds() {
        let dir = tempfile::tempdir().unwrap();
        credentials::write_space_key(dir.path(), &[0x22u8; 32]).unwrap();
        // The Space is known-encrypted (cache on file) but we have no session:
        // must error, not silently fall back to cleartext.
        let err = load_space_crypto(dir.path(), &space_id(), None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("encrypted"), "unexpected message: {msg}");
        assert!(msg.contains("login"), "unexpected message: {msg}");
    }

    #[test]
    fn load_space_crypto_some_when_both_secrets_present() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x33u8; 32];
        credentials::write_space_key(dir.path(), &key).unwrap();
        let crypto = load_space_crypto(dir.path(), &space_id(), Some(&creds()))
            .unwrap()
            .expect("crypto should be attached");
        assert_eq!(crypto.space_key, key);
        assert_eq!(crypto.dedup_secret, [0x11u8; 32]);
        assert_eq!(crypto.space_id, "space1");
    }

    #[test]
    fn assert_crypto_matches_escrow_ok_when_both_none() {
        assert_crypto_matches_escrow(&space_id(), None, None).unwrap();
    }

    #[test]
    fn assert_crypto_matches_escrow_ok_when_both_present() {
        let crypto = SpaceCrypto {
            dedup_secret: [0u8; 32],
            space_key: [1u8; 32],
            space_id: "space1".to_string(),
        };
        assert_crypto_matches_escrow(&space_id(), Some([1u8; 32]), Some(&crypto)).unwrap();
    }

    #[test]
    fn assert_crypto_matches_escrow_errors_when_escrow_known_but_crypto_missing() {
        let err = assert_crypto_matches_escrow(&space_id(), Some([1u8; 32]), None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("encrypted"), "unexpected message: {msg}");
        assert!(msg.contains("cleartext"), "unexpected message: {msg}");
    }

    #[test]
    fn assert_crypto_matches_escrow_ok_when_no_escrow_key_and_no_crypto() {
        // Legacy Space: no escrow key anywhere, no crypto — expected, not an error.
        assert_crypto_matches_escrow(&space_id(), None, None).unwrap();
    }
}
