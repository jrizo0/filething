//! Building the engine's collaborators from the environment (`docs/BUILD-PLAN.md
//! §3`, `docs/adr/0014`, `docs/adr/0015`).
//!
//! The Coordinator URL and the Vault `S3_*` credentials come from the
//! environment; the per-Device identity (the Better Auth session) comes from the
//! Device's [`Credentials`]. The normal path is authenticated: the CLI trades the
//! session for a Convex JWT and attaches it to the websocket
//! ([`ConvexClient::set_auth`] one-shot, or [`ConvexClient::set_auth_callback`]
//! for the long-running daemon so it re-mints across the ~15-min expiry). The
//! deployment admin/deploy key is now ONLY an ops fallback for when there is no
//! session (see [`connect`]).
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

/// The Coordinator URL for this run: `CONVEX_URL`, then the self-hosted alias,
/// else the localhost default. Used both for `login` (no config yet) and to
/// verify a config's URL.
pub fn coordinator_url_from_env() -> String {
    first_env(&[ENV_URL, ENV_URL_SELF_HOSTED])
        .unwrap_or_else(|| "http://localhost:3210".to_string())
}

/// Builds a [`Coordinator`] connected to `url`, authenticated as this Device.
///
/// - With a Better Auth session (`creds`): trade it for a Convex JWT and attach
///   it. `long_running` (the daemon) uses [`ConvexClient::set_auth_callback`] so
///   the JWT is re-minted on every websocket reconnect (surviving the ~15-min
///   expiry); one-shot commands use [`ConvexClient::set_auth`].
/// - Without a session: fall back to the deployment admin/deploy key
///   ([`connect_ops_fallback`]) — an OPS escape hatch, no longer the normal flow.
pub async fn connect(
    url: &str,
    creds: Option<&Credentials>,
    long_running: bool,
) -> anyhow::Result<Coordinator> {
    match creds {
        Some(c) if !c.session_token.is_empty() => {
            connect_authed(url, &c.session_token, long_running).await
        }
        _ => connect_ops_fallback(url).await,
    }
}

/// Connects with the per-Device Better Auth session attached as a Convex JWT.
async fn connect_authed(
    url: &str,
    session_token: &str,
    long_running: bool,
) -> anyhow::Result<Coordinator> {
    let base = auth::auth_base_url(url)?;
    let mut client = ConvexClient::new(url)
        .await
        .with_context(|| format!("connecting to the Coordinator at {url}"))?;

    if long_running {
        // Re-mint the JWT on connect and every reconnect (force_refresh) so a
        // daemon outlives the ~15-min JWT expiry without operator action.
        let base = base.clone();
        let token = session_token.to_string();
        let fetcher: AuthTokenFetcher = Box::new(move |_force_refresh: bool| {
            let base = base.clone();
            let token = token.clone();
            Box::pin(async move {
                let jwt = auth::convex_token(&base, &token).await?;
                Ok(AuthenticationToken::User(jwt))
            })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<Output = anyhow::Result<AuthenticationToken>>
                            + Send,
                    >,
                >
        });
        client.set_auth_callback(Some(fetcher)).await;
    } else {
        let jwt = auth::convex_token(&base, session_token).await?;
        client.set_auth(Some(jwt)).await;
    }
    Ok(Coordinator::from_client(client))
}

/// Ops fallback: connect with the deployment admin/deploy key when there is no
/// session. Resolved in precedence order — `CONVEX_ADMIN_KEY`,
/// `CONVEX_DEPLOY_KEY` (Convex Cloud), `CONVEX_SELF_HOSTED_ADMIN_KEY` (local
/// infra) — and never persisted. With NONE set, connects unauthenticated (which
/// the auth-gated contract functions now reject — hence the login hint).
async fn connect_ops_fallback(url: &str) -> anyhow::Result<Coordinator> {
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
    Ok(Coordinator::from_client(client))
}

/// Loads this Device's encryption key material for the Space at `root` from the
/// LOCAL caches (no network): the per-Space `space_key` cache plus the Account
/// `dedup_secret` in [`Credentials`]. Returns `None` (so the Space stays on the
/// cleartext `alg=0` path) when either is absent — a legacy Space with no
/// escrowed key, or a Device that has not logged in.
pub fn load_space_crypto(
    root: &Path,
    creds: Option<&Credentials>,
) -> anyhow::Result<Option<SpaceCrypto>> {
    let (Some(creds), Some(space_key)) = (creds, credentials::read_space_key(root)?) else {
        return Ok(None);
    };
    Ok(Some(SpaceCrypto {
        dedup_secret: creds.dedup_secret()?,
        space_key,
    }))
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

/// Builds the data-plane [`Vault`] from the `S3_*` env vars
/// ([`S3Vault::from_env`](ft_vault::S3Vault::from_env)). Errors with a clear
/// message when any `S3_*` var is unset.
pub async fn build_vault() -> anyhow::Result<Box<dyn Vault>> {
    match ft_vault::S3Vault::from_env().await {
        Some(v) => Ok(Box::new(v)),
        None => Err(anyhow::anyhow!(
            "the Vault is not configured: set S3_ENDPOINT / S3_REGION / S3_ACCESS_KEY / \
             S3_SECRET_KEY / S3_BUCKET (see infra/.env)"
        )),
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
