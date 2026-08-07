//! Building the engine's collaborators from the environment (`docs/BUILD-PLAN.md
//! §3`, `docs/adr/0014`, `docs/adr/0015`).
//!
//! The Coordinator URL and the Vault `S3_*` credentials come from the
//! environment; the per-Device identity (the Better Auth session) comes from the
//! Device's [`Credentials`]. The normal path is authenticated: the CLI trades the
//! session for a Convex JWT and attaches it to the websocket via
//! [`ConvexClient::set_auth_callback`] with a caching fetcher, re-minting on every
//! connect/reconnect AND proactively on a background timer BEFORE the ~15-min JWT
//! expires (issue #12 — see [`connect_authed`]). Proactive refresh matters because
//! the `convex` client only re-mints reactively (on reconnect) otherwise, so a
//! token that expires mid-connection triggers an AuthError/reconnect storm; it
//! also covers one-shot commands whose work outlives the JWT (e.g. a large `sync`
//! upload). The deployment admin/deploy key is now ONLY an ops fallback for when
//! there is no session (see [`connect`]).
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use convex::{AuthTokenFetcher, AuthenticationToken, ConvexClient, ConvexClientBuilder};
use ft_core::SpaceCrypto;
use ft_engine::{Coordinator, SpaceId, Vault};

use crate::auth::{self, CachedJwt};
use crate::credentials::{self, Credentials};

/// The proactively-refreshed Convex JWT, shared between the caching
/// [`AuthTokenFetcher`] (which the `convex` client calls on connect/reconnect)
/// and the background timer (which re-mints before expiry). `None` until the
/// first mint. `std::sync::Mutex` is only ever held briefly around a clone/store,
/// never across the `await` that mints — so it can't block the async runtime.
type SharedJwt = Arc<Mutex<Option<CachedJwt>>>;

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
/// Records which data plane a Space's Blocks were written to, under the control
/// dir. See [`bind_data_plane`].
const DATA_PLANE_FILE: &str = "data_plane";
/// Opt-out for the [`bind_data_plane`] refusal, for a deliberate bucket migration.
const ENV_ALLOW_PLANE_CHANGE: &str = "FILETHING_ALLOW_DATA_PLANE_CHANGE";

/// How long to wait for the Coordinator websocket to actually come UP before
/// giving one actionable error.
///
/// `ConvexClient::new` returns `Ok` before any socket exists — it only spawns a
/// worker that dials in a `loop { connect; backoff }` forever — and nothing else
/// on the command path is time-bounded. So with the Coordinator down, or on a
/// network that blocks WebSocket upgrades (hotel/corporate wifi, captive portal,
/// proxy), `login`/`init`/`clone`/`sync`/`spaces`/`gc` used to NEVER return: the
/// only output was the convex worker's raw ERROR line every ~15s. 25s is well past
/// a slow-but-working handshake and still short enough that a human waits it out.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(25);

/// Upper bound on the proactive-refresh sleep (see [`refresh_sleep_secs`]).
/// Deliberately derived from the token's ASSUMED lifetime, not from its `exp`.
const MAX_REFRESH_SLEEP: Duration =
    Duration::from_secs(auth::JWT_ASSUMED_TTL.as_secs() - auth::JWT_REFRESH_MARGIN.as_secs());

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
///   it via [`connect_authed`], which caches the JWT, re-mints it on every
///   websocket connect/reconnect, AND re-mints proactively before the ~15-min
///   expiry — surviving expiry with no operator action and no reactive
///   AuthError/reconnect storm (issue #12), for one-shot commands and the daemon
///   alike.
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
/// Returns a CLONE of the process's connection for this (URL, session) — see
/// [`CONNECTIONS`] for why the process keeps one instead of dialing per call.
///
/// [`SignedVault`]: crate::signed_vault::SignedVault
pub async fn connect_client(
    url: &str,
    creds: Option<&Credentials>,
) -> anyhow::Result<ConvexClient> {
    let key: ConnKey = (
        url.to_string(),
        creds
            .filter(|c| !c.session_token.is_empty())
            .map(|c| c.session_token.clone()),
    );
    if let Some(client) = cached_client(&key) {
        return Ok(client);
    }
    let conn = match &key.1 {
        Some(token) => connect_authed(url, token).await?,
        None => connect_ops_fallback(url).await?,
    };
    Ok(remember_connection(key, conn))
}

/// A live Coordinator connection plus everything whose lifetime is tied to it.
///
/// The refresh timer is the interesting part: it holds a CLONE of the client, and
/// `ConvexClient` only aborts its websocket worker when the LAST clone drops, so a
/// timer that outlives its connection pins one websocket and one task open
/// forever. Owning its `JoinHandle` here — dropped, and therefore aborted, exactly
/// when the connection is dropped — is what keeps that from happening.
struct AuthedConnection {
    /// Aborted BEFORE `client` is dropped (fields drop in declaration order), so
    /// the task has already released its clone by the time ours goes.
    _refresh: Option<AbortOnDrop>,
    client: ConvexClient,
}

/// A spawned task whose lifetime is tied to this handle: dropping the handle
/// aborts the task.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Identifies a connection: the Coordinator URL plus the session token attached to
/// it (`None` = the admin/deploy-key ops fallback). Two callers with the same key
/// want the same authenticated socket; a different token needs its own.
type ConnKey = (String, Option<String>);

/// The process's Coordinator connections, at most one per [`ConnKey`].
///
/// `convex` documents its client as something to create ONCE and reuse ("you can
/// safely clone with `ConvexClient::clone()` to share the connection"): each one
/// owns a websocket plus a worker task. Dialing a fresh one per call leaked one
/// websocket, one JWT-refresh task and a token mint every ~12 min per call, and
/// the daemon reconnects on every quarantine retry of a wedged Space (backoff caps
/// at 300s ⇒ ~288 retries/day), so after a day it held hundreds of open sockets —
/// past the 256-fd soft limit launchd hands its services on macOS, at which point
/// EVERY operation fails with EMFILE, healthy Spaces included.
///
/// A `Vec` rather than a map: there is realistically one entry (two if a `login`
/// re-auths mid-process), and `Vec::new()` is const so the static needs no
/// lazy init. Never held across an `await` — the connection is built outside the
/// lock and only then inserted.
static CONNECTIONS: Mutex<Vec<(ConnKey, AuthedConnection)>> = Mutex::new(Vec::new());

/// Locks [`CONNECTIONS`], recovering a poisoned lock: a panic in another thread
/// must not make every later command unable to connect.
fn connections() -> std::sync::MutexGuard<'static, Vec<(ConnKey, AuthedConnection)>> {
    CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner())
}

/// A clone of the already-established connection for `key`, if there is one.
fn cached_client(key: &ConnKey) -> Option<ConvexClient> {
    connections()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, c)| c.client.clone())
}

/// Stores `conn` under `key` and returns a client clone. If another task
/// established the same key while we were connecting, keeps THAT one and drops
/// ours (which aborts its refresh task and closes its socket) — so the invariant
/// "one connection per key" holds even under a race.
fn remember_connection(key: ConnKey, conn: AuthedConnection) -> ConvexClient {
    let mut guard = connections();
    if let Some((_, existing)) = guard.iter().find(|(k, _)| *k == key) {
        return existing.client.clone();
    }
    let client = conn.client.clone();
    guard.push((key, conn));
    client
}

/// Opens the websocket to `url` and waits until it is genuinely CONNECTED, or
/// fails with [`CoordinatorUnreachable`] after [`CONNECT_TIMEOUT`].
///
/// `ConvexClient::new` cannot fail for an unreachable deployment (it spawns a
/// worker that retries forever), so the only way to bound the wait is to observe
/// the worker's state changes — `with_on_state_change` reports `Connected` right
/// after the WebSocket handshake completes. The channel is generous and drained in
/// a loop because the worker publishes with `try_send` and drops the message if the
/// buffer is full; once we return, our receiver is dropped and those sends become
/// no-ops.
async fn open_client(url: &str) -> anyhow::Result<ConvexClient> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let client = ConvexClientBuilder::new(url)
        .with_on_state_change(tx)
        .build()
        .await
        .with_context(|| format!("connecting to the Coordinator at {url}"))?;

    let connected = tokio::time::timeout(CONNECT_TIMEOUT, async {
        while let Some(state) = rx.recv().await {
            if matches!(state, convex::WebSocketState::Connected) {
                return true;
            }
        }
        // The worker dropped its sender: it will never report Connected.
        false
    })
    .await;

    match connected {
        Ok(true) => Ok(client),
        // Both "still dialing after CONNECT_TIMEOUT" and "the worker gave up" are
        // the same thing to the user: the Coordinator is not answering.
        _ => Err(CoordinatorUnreachable {
            url: url.to_string(),
        }
        .into()),
    }
}

/// The Coordinator's websocket did not come up. A named type (rather than an
/// `anyhow!`) so `main` can map it to its own exit code, and so no `.context()`
/// wrapper can hide which URL failed.
#[derive(Debug)]
pub struct CoordinatorUnreachable {
    /// The Coordinator URL we failed to reach.
    pub url: String,
}

impl std::fmt::Display for CoordinatorUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "could not reach the Coordinator at {} after {}s — check your network \
             (a captive portal or a proxy that blocks WebSockets looks exactly like \
             this), that the deployment is up, and that CONVEX_URL points at it",
            self.url,
            CONNECT_TIMEOUT.as_secs()
        )
    }
}

impl std::error::Error for CoordinatorUnreachable {}

/// Connects with the per-Device Better Auth session attached as a Convex JWT and
/// keeps that JWT fresh (issue #12).
///
/// Two layers, both fed by a [`SharedJwt`] cache:
/// - a caching [`AuthTokenFetcher`] the `convex` client invokes on connect and on
///   every reconnect. It reuses the cached JWT until it is within
///   [`auth::JWT_REFRESH_MARGIN`] of expiry (or `force_refresh` is set, as on a
///   reconnect), then re-mints — so a reconnect always presents a live token;
/// - a background timer ([`spawn_jwt_refresh`]) that re-mints and re-attaches the
///   JWT over the LIVE websocket *before* it expires. Without it the token would
///   silently expire mid-connection and the client would only re-auth reactively
///   after the server rejects a call — the AuthError/reconnect storm of #12.
///   `convex` 0.10.4 has no proactive-refresh hook of its own (its fetcher fires
///   only on connect/reconnect), but `set_auth_callback` pushes a fresh
///   `Authenticate` over the existing socket with no reconnect, which is what the
///   timer drives.
async fn connect_authed(url: &str, session_token: &str) -> anyhow::Result<AuthedConnection> {
    let base = auth::auth_base_url(url)?;
    let mut client = open_client(url).await?;

    let token = session_token.to_string();
    let cache: SharedJwt = Arc::new(Mutex::new(None));

    client
        .set_auth_callback(Some(make_auth_fetcher(
            base.clone(),
            token.clone(),
            cache.clone(),
        )))
        .await;
    let refresh = spawn_jwt_refresh(client.clone(), base, token, cache);
    Ok(AuthedConnection {
        _refresh: Some(AbortOnDrop(refresh)),
        client,
    })
}

/// Current unix time in whole seconds (0 before the epoch, which never happens).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Builds the caching [`AuthTokenFetcher`]. On `force_refresh` (a reconnect) it
/// always re-mints; otherwise it returns the cached JWT while it is still outside
/// the refresh margin, re-minting only when due. Every mint updates `cache` so
/// the timer sees the new expiry. Rebuilt cheaply on each timer tick since the
/// closure only captures three cloneable handles.
fn make_auth_fetcher(base: String, token: String, cache: SharedJwt) -> AuthTokenFetcher {
    Box::new(move |force_refresh: bool| {
        let base = base.clone();
        let token = token.clone();
        let cache = cache.clone();
        Box::pin(async move {
            if !force_refresh {
                let fresh = cache
                    .lock()
                    .expect("jwt cache mutex poisoned")
                    .clone()
                    .filter(|c| !c.refresh_due(now_secs(), auth::JWT_REFRESH_MARGIN));
                if let Some(c) = fresh {
                    return Ok(AuthenticationToken::User(c.jwt));
                }
            }
            let jwt = auth::convex_token(&base, &token).await?;
            *cache.lock().expect("jwt cache mutex poisoned") =
                Some(CachedJwt::new(jwt.clone(), now_secs()));
            Ok(AuthenticationToken::User(jwt))
        })
            as std::pin::Pin<
                Box<dyn std::future::Future<Output = anyhow::Result<AuthenticationToken>> + Send>,
            >
    })
}

/// Spawns the proactive refresh timer (issue #12) and returns its handle so the
/// task's lifetime can be tied to the connection's (see [`AuthedConnection`]).
///
/// It sleeps until the cached JWT is close to expiry, then INVALIDATES the cache
/// and re-attaches the caching fetcher via `set_auth_callback`; that call
/// re-invokes the fetcher (which now has nothing cached, so it re-mints) and pushes
/// a fresh `Authenticate` over the live socket — no reconnect, no reactive
/// AuthError storm. A failed re-mint leaves the cache empty, so the next sleep is
/// floored to [`auth::JWT_MIN_REFRESH_SLEEP`] and the timer retries on that cadence.
///
/// Clearing the cache is what makes the tick UNCONDITIONAL. The fetcher's own "is a
/// refresh due?" test compares the server-issued `exp` against the LOCAL wall
/// clock, so on a device whose clock is behind it would answer "not due" for a
/// token the server already considers expired and hand the stale one straight back
/// — reintroducing the very storm this timer exists to prevent.
///
/// It is spawned for one-shot commands too, which is harmless (they exit long
/// before the first tick, and nothing joins the handle) and covers a long upload
/// whose work outlives the ~15-min JWT.
fn spawn_jwt_refresh(
    mut client: ConvexClient,
    base: String,
    token: String,
    cache: SharedJwt,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let sleep_secs = {
                let cached = cache.lock().expect("jwt cache mutex poisoned");
                refresh_sleep_secs(cached.as_ref(), now_secs())
            };
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            *cache.lock().expect("jwt cache mutex poisoned") = None;
            client
                .set_auth_callback(Some(make_auth_fetcher(
                    base.clone(),
                    token.clone(),
                    cache.clone(),
                )))
                .await;
        }
    })
}

/// How long the refresh timer should sleep before its next re-mint.
///
/// [`CachedJwt::secs_until_refresh`] derives its answer from `(exp - margin) -
/// now`, which mixes the SERVER's absolute expiry with the LOCAL wall clock. On a
/// device whose clock is behind — a laptop back from suspend, a VM with no NTP —
/// that difference is inflated by the whole skew, so the timer would sleep clean
/// past the token's real expiry. Clamping to [`MAX_REFRESH_SLEEP`] (derived from
/// the token's assumed ~15-min lifetime, not from any clock) bounds the damage: we
/// re-mint at least that often no matter what the local clock believes. The floor
/// keeps a failed re-mint from busy-looping. The sleep itself is monotonic —
/// `tokio::time::sleep` measures a DURATION, so wall-clock jumps cannot stretch it.
fn refresh_sleep_secs(cached: Option<&CachedJwt>, now: u64) -> u64 {
    let requested = match cached {
        Some(c) => c.secs_until_refresh(now, auth::JWT_REFRESH_MARGIN),
        None => auth::JWT_MIN_REFRESH_SLEEP.as_secs(),
    };
    requested.clamp(
        auth::JWT_MIN_REFRESH_SLEEP.as_secs(),
        MAX_REFRESH_SLEEP.as_secs(),
    )
}

/// Ops fallback: connect with the deployment admin/deploy key when there is no
/// session. Resolved in precedence order — `CONVEX_ADMIN_KEY`,
/// `CONVEX_DEPLOY_KEY` (Convex Cloud), `CONVEX_SELF_HOSTED_ADMIN_KEY` (local
/// infra) — and never persisted. With NONE set, connects unauthenticated (which
/// the auth-gated contract functions now reject — hence the login hint).
async fn connect_ops_fallback(url: &str) -> anyhow::Result<AuthedConnection> {
    let mut client = open_client(url).await?;
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
    // No JWT to keep fresh on this path, so nothing to tie to the connection.
    Ok(AuthedConnection {
        _refresh: None,
        client,
    })
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
///
/// Which one is in use is ANNOUNCED (once per process), because precedence 1 is
/// silent otherwise: a shell that still exports an old `S3_BUCKET` sends the
/// account's Blocks to the wrong bucket, the commit succeeds, the head advances,
/// and the Blocks are orphaned where no other Device can read them. See
/// [`bind_data_plane`] for the per-Space check that turns that into a refusal.
pub async fn build_vault(client: Option<ConvexClient>) -> anyhow::Result<Box<dyn Vault>> {
    if let Some(cfg) = ft_vault::S3Config::from_env() {
        if let Some(v) = ft_vault::S3Vault::from_env().await {
            announce_data_plane_once(|| {
                tracing::warn!(
                    bucket = %cfg.bucket,
                    endpoint = %cfg.endpoint,
                    "data plane: DIRECT S3 from the environment (S3_* is set), NOT the \
                     Coordinator's presigned URLs — every Block this run writes goes to \
                     this bucket. Unset S3_ENDPOINT/S3_REGION/S3_ACCESS_KEY/\
                     S3_SECRET_KEY/S3_BUCKET to use the managed data plane."
                )
            });
            return Ok(Box::new(v));
        }
    }
    match client {
        Some(c) => {
            announce_data_plane_once(|| {
                tracing::info!("data plane: presigned URLs minted by the Coordinator")
            });
            Ok(Box::new(crate::signed_vault::SignedVault::new(c)))
        }
        None => Err(anyhow::anyhow!(
            "the Vault is not configured: run `filething login` (presigned data plane) or set \
             S3_ENDPOINT / S3_REGION / S3_ACCESS_KEY / S3_SECRET_KEY / S3_BUCKET (direct, ops)"
        )),
    }
}

/// Runs `log` at most once per process: which data plane is in use is one
/// process-level fact, and the daemon builds a Vault per Space and per retry.
fn announce_data_plane_once(log: impl FnOnce()) {
    static ANNOUNCED: std::sync::Once = std::sync::Once::new();
    ANNOUNCED.call_once(log);
}

/// The data plane this run would use, as a short stable token: `coordinator` for
/// the managed presigned plane, `s3:<bucket>` for direct `S3_*` credentials.
///
/// Only the BUCKET identifies a direct plane, not the endpoint: `localhost` and
/// `127.0.0.1` (or a hostname that gained a port) are the same store, and treating
/// those as a move would refuse healthy runs.
fn data_plane_id() -> String {
    match ft_vault::S3Config::from_env() {
        Some(cfg) => format!("s3:{}", cfg.bucket),
        None => "coordinator".to_string(),
    }
}

/// Records — and then enforces — which data plane a Space's Blocks were written to,
/// in `<root>/.filething/data_plane`.
///
/// The failure this prevents: a shell with a stale `S3_BUCKET` exported takes
/// precedence over the presigned path ([`build_vault`]), so `sync` writes this
/// Space's Blocks into a bucket no other Device can read, the Coordinator's head
/// advances anyway, and the Blocks are orphaned. Nothing about that fails at the
/// time, which is why it has to be caught before the first `put`.
///
/// Asymmetric on purpose:
/// - nothing recorded → record what this run uses and continue (a Space that
///   predates this file gets bound by the first command that opens it);
/// - same plane → continue;
/// - a DIFFERENT plane while this run holds direct `S3_*` credentials → refuse.
///   This is the hijack direction, and the only one where continuing writes Blocks
///   somewhere new;
/// - a different plane while this run is on the managed plane → warn only. Offline
///   commands (`status`, `ls`) legitimately run without `S3_*` in the shell and must
///   not fail because of it.
///
/// Whether an opt-in environment flag (`FILETHING_YES`,
/// [`ENV_ALLOW_PLANE_CHANGE`]) is SET TO YES.
///
/// These flags pre-approve destructive things — rebinding this Device to another
/// Account, absorbing a non-empty folder on `clone`, deleting Blocks with `gc
/// --apply`, re-binding a Space's data plane — and every message that names them
/// says "=1". Treating any non-empty value as yes therefore inverted the intent of
/// the obvious way to say NO in a script (`FILETHING_YES=0`, `=false`), which
/// approved the deletion it was meant to refuse. So the falsy spellings are
/// honored (case-insensitive, trimmed) and anything else non-empty is still yes.
///
/// Deliberately NOT applied to the pre-existing flags (`FILETHING_NO_AUTO_DAEMON`
/// and friends): their non-empty semantics are already documented and scripted
/// against, and they gate nothing destructive.
pub fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|v| flag_is_yes(&v))
        .unwrap_or(false)
}

/// The pure predicate behind [`env_flag_enabled`], testable without mutating
/// process-global env vars.
fn flag_is_yes(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off"
    )
}

/// [`ENV_ALLOW_PLANE_CHANGE`] re-binds instead of refusing, for an intentional
/// bucket migration.
pub fn bind_data_plane(root: &Path) -> anyhow::Result<()> {
    // Shared with `commands::assume_yes` — both gate destructive confirmations.
    let allow_change = env_flag_enabled(ENV_ALLOW_PLANE_CHANGE);
    bind_data_plane_to(root, &data_plane_id(), allow_change)
}

/// The decision half of [`bind_data_plane`], with both environment reads lifted out
/// so the rules are unit-testable without mutating process-global env vars.
fn bind_data_plane_to(root: &Path, current: &str, allow_change: bool) -> anyhow::Result<()> {
    let path = root.join(CONTROL_DIR).join(DATA_PLANE_FILE);
    let recorded = match std::fs::read_to_string(&path) {
        Ok(s) => Some(s.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    };
    let Some(recorded) = recorded.filter(|r| !r.is_empty()) else {
        return write_data_plane(&path, current);
    };
    if recorded == current {
        return Ok(());
    }
    if allow_change {
        tracing::warn!(
            from = %recorded, to = %current, root = %root.display(),
            "re-binding this Space's data plane because {ENV_ALLOW_PLANE_CHANGE} is set; \
             Blocks written earlier stay in the old location"
        );
        return write_data_plane(&path, current);
    }
    if current.starts_with("s3:") {
        anyhow::bail!(
            "{} was last synced through the data plane `{recorded}`, but this shell's \
             S3_* variables point at `{current}`. Writing here would put this Space's \
             Blocks in a bucket your other Devices cannot read, while the Coordinator's \
             head advances anyway. Unset S3_ENDPOINT/S3_REGION/S3_ACCESS_KEY/\
             S3_SECRET_KEY/S3_BUCKET to use the managed data plane, point them back at \
             `{recorded}`, or set {ENV_ALLOW_PLANE_CHANGE}=1 if the move is intentional.",
            root.display()
        );
    }
    tracing::warn!(
        recorded = %recorded, current = %current, root = %root.display(),
        "this Space's Blocks were written through direct S3 credentials that are not set \
         in this shell; the managed data plane may not have them"
    );
    Ok(())
}

/// Writes the data-plane binding, creating the control dir if needed.
fn write_data_plane(path: &Path, id: &str) -> anyhow::Result<()> {
    std::fs::write(path, format!("{id}\n"))
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))
}

/// Whether direct storage credentials (`S3_*`) are configured for this run.
///
/// When true the Vault is the operator-only [`S3Vault`](ft_vault::S3Vault),
/// which can `list`/`delete` across the bucket — the ONLY mode that supports
/// `gc`. When false the CLI is on the managed presigned-URL data plane
/// ([`SignedVault`](crate::signed_vault::SignedVault)), where `gc` runs
/// operator-side only (issue #21). Reads exactly the `S3_*` vars [`build_vault`]
/// checks, so the two always agree on which plane a run uses.
pub fn direct_s3_configured() -> bool {
    ft_vault::S3Config::from_env().is_some()
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

/// Creates a Space's control dir (`<root>/.filething`) and makes it safe to hold
/// secrets, returning its path.
///
/// Two things beyond `create_dir_all`:
/// - `0700` (via [`crate::config::ensure_private_dir`]), because the dir holds this
///   Space's `space_key`;
/// - a `.gitignore` containing `*`, so the directory ignores ITSELF. The control
///   dir lives INSIDE the user's synced folder, which for a developer folder is
///   very often a git repository, and without this a `git add -A` happily commits
///   the Space key and the local index. Self-ignoring beats relying on the repo's
///   own rules, which we do not control.
///
/// An existing `.gitignore` is left alone (the user may have customized it).
pub fn ensure_control_dir(root: &Path) -> anyhow::Result<std::path::PathBuf> {
    let dir = root.join(CONTROL_DIR);
    crate::config::ensure_private_dir(&dir)?;
    let ignore = dir.join(".gitignore");
    if !ignore.exists() {
        std::fs::write(
            &ignore,
            "# filething's control dir: this Space's key and local index live here.\n\
             # Ignore everything, this file included — never commit any of it.\n\
             *\n",
        )
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", ignore.display()))?;
    }
    Ok(dir)
}

/// Opens (creating its parent dir) the local index for the Space rooted at
/// `root`. Used by `init`/`clone` (fresh) and `status`/`ls`/`sync`/`daemon`
/// (existing).
///
/// This is also where [`bind_data_plane`] runs: it is the one place in this module
/// every Space-scoped command funnels through with the Space root in hand, and it
/// happens before any Vault is built, so a hijacked data plane is refused before
/// the first `put` rather than after a successful commit.
pub fn open_index(root: &Path) -> anyhow::Result<ft_index::Index> {
    let path = index_path(root);
    ensure_control_dir(root)?;
    bind_data_plane(root)?;
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

    /// The flags this predicate gates are destructive pre-approvals and every
    /// abort message says "=1", so the obvious ways a script says NO must not
    /// approve.
    #[test]
    fn flag_is_yes_treats_the_falsy_spellings_as_no() {
        for no in ["", " ", "0", "false", "FALSE", "No", " off ", "OFF"] {
            assert!(!flag_is_yes(no), "{no:?} must not pre-approve");
        }
        for yes in ["1", "true", "TRUE", "yes", " y ", "please"] {
            assert!(flag_is_yes(yes), "{yes:?} must pre-approve");
        }
    }

    /// An UNSET flag is no, same as before.
    #[test]
    fn env_flag_enabled_is_false_when_unset() {
        assert!(!env_flag_enabled("FILETHING_A_FLAG_NOBODY_SETS"));
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

    // ----- the proactive-refresh sleep (clock skew) -----

    /// The normal case is unchanged: sleep until `margin` before the token's expiry.
    #[test]
    fn refresh_sleep_counts_down_to_the_margin_when_the_clock_agrees() {
        let cached = CachedJwt {
            jwt: "j".into(),
            expires_at: 1_000_000,
        };
        // refresh_at = 1_000_000 - 180 = 999_820; from now=999_400 that is 420s away.
        assert_eq!(refresh_sleep_secs(Some(&cached), 999_400), 420);
    }

    /// REGRESSION: a device whose clock is BEHIND the server's sees a token that
    /// looks hours from expiring, so the raw `(exp - margin) - now` sleep would run
    /// far past the real expiry and hand the server a dead JWT — the reconnect storm
    /// the timer exists to prevent. The sleep must be capped by the token's assumed
    /// lifetime, which no clock can inflate.
    #[test]
    fn refresh_sleep_is_capped_when_the_local_clock_is_behind_the_server() {
        let cached = CachedJwt {
            jwt: "j".into(),
            expires_at: 1_000_000,
        };
        // The device's clock is an hour behind the server's, so a token minted
        // moments ago (real now = 999_400) reads as 4320s from its refresh point.
        let skewed_now = 999_400 - 3600;
        let naive = cached.secs_until_refresh(skewed_now, auth::JWT_REFRESH_MARGIN);
        assert!(naive > MAX_REFRESH_SLEEP.as_secs(), "naive sleep = {naive}");
        assert_eq!(
            refresh_sleep_secs(Some(&cached), skewed_now),
            MAX_REFRESH_SLEEP.as_secs()
        );
    }

    /// A failed re-mint leaves nothing cached; the timer must retry on the bounded
    /// floor rather than spin.
    #[test]
    fn refresh_sleep_floors_when_nothing_is_cached() {
        assert_eq!(
            refresh_sleep_secs(None, 12_345),
            auth::JWT_MIN_REFRESH_SLEEP.as_secs()
        );
    }

    /// The cap must stay inside the token's real lifetime, or it would not help.
    #[test]
    fn max_refresh_sleep_is_shorter_than_the_assumed_token_lifetime() {
        assert!(MAX_REFRESH_SLEEP < auth::JWT_ASSUMED_TTL);
        assert!(MAX_REFRESH_SLEEP > auth::JWT_MIN_REFRESH_SLEEP);
    }

    // ----- the bounded connect -----

    /// Every command used to hang forever with the Coordinator unreachable, because
    /// `ConvexClient::new` returns Ok before any socket exists. The bound must
    /// produce ONE message that names the URL and the two things a user can act on:
    /// the network, and `CONVEX_URL`.
    #[test]
    fn the_unreachable_message_names_the_url_and_what_to_check() {
        let msg = CoordinatorUnreachable {
            url: "http://localhost:3210".into(),
        }
        .to_string();
        assert!(msg.contains("http://localhost:3210"), "got: {msg}");
        assert!(msg.contains("CONVEX_URL"), "got: {msg}");
        assert!(msg.contains("network"), "got: {msg}");
        // A one-shot command has to give up while a human is still watching.
        assert!(CONNECT_TIMEOUT <= Duration::from_secs(30));
        assert!(CONNECT_TIMEOUT >= Duration::from_secs(20));
    }

    // ----- the refresh task's lifetime -----

    /// REGRESSION: the refresh task used to be spawned with no shutdown path, so
    /// every connection leaked one task (and, through the client clone it holds, one
    /// websocket). Dropping the connection must abort it.
    #[tokio::test]
    async fn dropping_the_abort_guard_stops_the_spawned_task() {
        let handle = tokio::spawn(async {
            // A task that would otherwise outlive everything, like the refresh loop.
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
        let probe = handle.abort_handle();
        assert!(!probe.is_finished());
        drop(AbortOnDrop(handle));
        // The abort is delivered at the next scheduling point.
        tokio::task::yield_now().await;
        assert!(probe.is_finished(), "the guard must abort its task on drop");
    }

    // ----- the per-Space data-plane binding -----

    #[test]
    fn first_open_records_the_data_plane_it_used() {
        let dir = tempfile::tempdir().unwrap();
        ensure_control_dir(dir.path()).unwrap();
        bind_data_plane_to(dir.path(), "coordinator", false).unwrap();
        let recorded =
            std::fs::read_to_string(dir.path().join(CONTROL_DIR).join(DATA_PLANE_FILE)).unwrap();
        assert_eq!(recorded.trim(), "coordinator");
        // Re-opening with the same plane is a no-op, not an error.
        bind_data_plane_to(dir.path(), "coordinator", false).unwrap();
    }

    /// The defect: a shell with a stale `S3_BUCKET` exported takes precedence over
    /// the presigned path, so the run writes this Space's Blocks into a bucket no
    /// other Device can read while the head advances anyway. Refuse instead.
    #[test]
    fn stale_s3_env_pointing_at_another_bucket_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        ensure_control_dir(dir.path()).unwrap();
        bind_data_plane_to(dir.path(), "coordinator", false).unwrap();

        let err = bind_data_plane_to(dir.path(), "s3:stale-bucket", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("stale-bucket"), "unexpected message: {err}");
        assert!(err.contains("coordinator"), "unexpected message: {err}");
        assert!(err.contains("S3_BUCKET"), "unexpected message: {err}");
        // Refusing must not rewrite the binding.
        let recorded =
            std::fs::read_to_string(dir.path().join(CONTROL_DIR).join(DATA_PLANE_FILE)).unwrap();
        assert_eq!(recorded.trim(), "coordinator");
    }

    /// Two different direct buckets are just as wrong as switching planes.
    #[test]
    fn switching_between_two_direct_buckets_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        ensure_control_dir(dir.path()).unwrap();
        bind_data_plane_to(dir.path(), "s3:original", false).unwrap();
        assert!(bind_data_plane_to(dir.path(), "s3:other", false).is_err());
        // …unless the operator says the move is intentional, which re-binds.
        bind_data_plane_to(dir.path(), "s3:other", true).unwrap();
        let recorded =
            std::fs::read_to_string(dir.path().join(CONTROL_DIR).join(DATA_PLANE_FILE)).unwrap();
        assert_eq!(recorded.trim(), "s3:other");
    }

    /// The other direction only warns: an offline `status`/`ls` legitimately runs in
    /// a shell with no `S3_*` set and must not fail because of it.
    #[test]
    fn running_without_the_recorded_s3_env_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        ensure_control_dir(dir.path()).unwrap();
        bind_data_plane_to(dir.path(), "s3:mybucket", false).unwrap();
        bind_data_plane_to(dir.path(), "coordinator", false).unwrap();
        // The recorded binding still points at where the Blocks actually are.
        let recorded =
            std::fs::read_to_string(dir.path().join(CONTROL_DIR).join(DATA_PLANE_FILE)).unwrap();
        assert_eq!(recorded.trim(), "s3:mybucket");
    }

    /// The control dir sits inside the user's (often git-tracked) folder, so it must
    /// ignore itself the moment it is created — before any key or index lands in it.
    #[test]
    fn ensure_control_dir_writes_a_self_ignoring_gitignore() {
        let dir = tempfile::tempdir().unwrap();
        let control = ensure_control_dir(dir.path()).unwrap();
        let body = std::fs::read_to_string(control.join(".gitignore")).unwrap();
        assert!(body.lines().any(|l| l.trim() == "*"), "got: {body:?}");

        // An existing .gitignore is left alone (the user may have customized it).
        std::fs::write(control.join(".gitignore"), "*\n!keep-me\n").unwrap();
        ensure_control_dir(dir.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(control.join(".gitignore")).unwrap(),
            "*\n!keep-me\n"
        );
    }
}
