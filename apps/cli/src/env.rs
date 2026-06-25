//! Building the engine's collaborators from the environment (`docs/BUILD-PLAN.md
//! §3`, the MVP self-hosted credential model).
//!
//! For the local MVP the Coordinator URL + admin key and the Vault `S3_*`
//! credentials come from the environment (mirroring `infra/.env`); in production
//! they would come from a real auth flow. These helpers centralize that wiring so
//! every subcommand builds a [`Coordinator`] (with admin auth) and a [`Vault`] the
//! same way.

use std::path::Path;

use anyhow::Context as _;
use ft_engine::{Coordinator, Vault};

/// Env var holding the self-hosted Convex URL (default `http://localhost:3210`).
const ENV_URL: &str = "CONVEX_SELF_HOSTED_URL";
/// Env var holding the self-hosted Convex deployment admin key. Required to call
/// the contract functions on a self-hosted backend.
const ENV_ADMIN_KEY: &str = "CONVEX_SELF_HOSTED_ADMIN_KEY";
/// The CONTROL_DIR subfolder of a Space root holding the local index.
pub const CONTROL_DIR: &str = ".filething";
/// The local index filename under the control dir.
pub const INDEX_FILE: &str = "index.db";

/// The Coordinator URL for this run: the env override, else the localhost
/// default. Used both for `login` (no config yet) and to verify a config's URL.
pub fn coordinator_url_from_env() -> String {
    std::env::var(ENV_URL).unwrap_or_else(|_| "http://localhost:3210".to_string())
}

/// Builds a [`Coordinator`] connected to `url` with deployment admin auth
/// attached (the self-hosted MVP pattern: construct a [`convex::ConvexClient`],
/// `set_admin_auth`, then [`Coordinator::from_client`]).
///
/// The admin key is read from `CONVEX_SELF_HOSTED_ADMIN_KEY` and never persisted.
pub async fn connect_coordinator(url: &str) -> anyhow::Result<Coordinator> {
    let admin_key = std::env::var(ENV_ADMIN_KEY).with_context(|| {
        format!("{ENV_ADMIN_KEY} must be set (the self-hosted Convex admin key)")
    })?;
    let mut client = convex::ConvexClient::new(url)
        .await
        .with_context(|| format!("connecting to the Coordinator at {url}"))?;
    client.set_admin_auth(admin_key, None).await;
    Ok(Coordinator::from_client(client))
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
    let id = id.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not a filething Space (no {}/{}). Run `filething init` or `clone` first.",
            root.display(),
            CONTROL_DIR,
            INDEX_FILE
        )
    })?;
    Ok(ft_engine::SpaceId::new(id))
}
