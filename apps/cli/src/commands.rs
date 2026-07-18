//! The `filething` subcommand implementations (`docs/BUILD-PLAN.md §3`,
//! `CONTEXT.md` — CLI estilo git).
//!
//! Each function ORCHESTRATES the engine; none reimplements sync logic. They load
//! the [`Config`] identity, build the [`Vault`]/[`Coordinator`] from env
//! ([`crate::env`]), open the Space's local index, drive a `SpaceContext`, and
//! print a clear result.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use convex::ConvexClient;
use ft_core::SpaceCrypto;
use ft_engine::{
    AccountId, CommitOutcome, DeviceId, GcOptions, PullOutcome, SpaceContext, SpaceId, SyncMetrics,
};
use futures::future::LocalBoxFuture;

use crate::config::{normalize_abs, Config};
use crate::credentials::{self, Credentials};
use crate::service::ServiceAction;
use crate::{auth, env};

/// A reasonable default Device name when `--name` is omitted: the machine
/// hostname, else a generic label.
fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "filething-device".to_string())
}

/// `login` — authenticate this Device and register it (`docs/adr/0014`).
///
/// Runs the real Better Auth flow: `--signup` creates the Account (`POST
/// /sign-up/email`), otherwise it logs in an existing one (`POST /sign-in/email`)
/// — a SECOND Device is just the same user logging in elsewhere. The session is
/// traded for a Convex JWT, `auth:ensureDevice` get-or-creates the Account +
/// Device and returns the escrow `dedup_secret`. The non-secret identity lands in
/// `config.json`; the session token + `dedup_secret` land in `credentials.json`
/// (`0600`). The password comes from `$FILETHING_PASSWORD` or an interactive
/// prompt.
pub async fn login(email: String, signup: bool, name: Option<String>) -> anyhow::Result<()> {
    let url = env::coordinator_url_from_env();
    let base = auth::auth_base_url(&url)?;
    let device_name = name.clone().unwrap_or_else(default_device_name);
    let password = read_password()?;

    // (1) Better Auth: signup or login → a session token.
    let session_token = if signup {
        let display = name.clone().unwrap_or_else(|| {
            email
                .split('@')
                .next()
                .unwrap_or("filething user")
                .to_string()
        });
        auth::sign_up(&base, &display, &email, &password)
            .await
            .context("sign-up (create the Account)")?
    } else {
        auth::sign_in(&base, &email, &password)
            .await
            .context("sign-in (existing Account — omit --signup only if it exists)")?
    };

    // (2) Connect authenticated (trades the session for a Convex JWT).
    let session_only = Credentials {
        session_token: session_token.clone(),
        dedup_secret_hex: String::new(),
    };
    let mut coordinator = env::connect(&url, Some(&session_only)).await?;

    // (3) ensureDevice: get-or-create Account + Device; the server returns the
    // authoritative dedup_secret (ours if the Account is new, the existing one
    // otherwise). We always send a fresh candidate.
    let candidate = credentials::generate_secret();
    let ensured = coordinator
        .ensure_device(&device_name, &candidate)
        .await
        .context("auth:ensureDevice")?;

    // (4) Persist: identity in config.json, secrets in credentials.json (0600).
    let mut config = Config::load()?;
    config.set_identity(
        &url,
        &email,
        ensured.account_id.as_str(),
        ensured.device_id.as_str(),
        &device_name,
    );
    config.save()?;
    Credentials {
        session_token,
        dedup_secret_hex: hex::encode(ensured.dedup_secret),
    }
    .save()?;

    println!(
        "Logged in as {email} and registered this Device ({}).",
        if signup {
            "new Account"
        } else {
            "existing Account"
        }
    );
    println!("  account: {}", ensured.account_id);
    println!("  device:  {} ({device_name})", ensured.device_id);
    println!("  coordinator: {url}");
    Ok(())
}

/// Reads the login password from `$FILETHING_PASSWORD` (scripts/CI) or, failing
/// that, an interactive prompt on stderr. Note: the interactive read is NOT
/// hidden — prefer the env var for anything scripted.
fn read_password() -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("FILETHING_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    use std::io::Write as _;
    eprint!("Password: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading the password from stdin")?;
    let p = line.trim_end_matches(['\n', '\r']).to_string();
    anyhow::ensure!(
        !p.is_empty(),
        "no password provided (set FILETHING_PASSWORD or type one at the prompt)"
    );
    Ok(p)
}

/// Loads the paired identity from the config, erroring with a `login` hint if the
/// Device has not logged in yet. Returns `(coordinator_url, account, device)`.
fn require_identity(config: &Config) -> anyhow::Result<(String, AccountId, DeviceId)> {
    let url = config
        .coordinator_url
        .clone()
        .unwrap_or_else(env::coordinator_url_from_env);
    let account_id = config
        .account_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in yet — run `filething login` first"))?;
    let device_id = config
        .device_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in yet — run `filething login` first"))?;
    Ok((url, AccountId::new(account_id), DeviceId::new(device_id)))
}

/// Loads this Device's secrets, erroring with a `login` hint when absent. Used by
/// the commands that must authenticate and/or need encryption key material.
fn require_credentials() -> anyhow::Result<Credentials> {
    Credentials::load()?
        .ok_or_else(|| anyhow::anyhow!("no Device credentials found — run `filething login` first"))
}

/// `whoami` — show the logged-in identity from the local config (issue #15).
///
/// No network: everything shown is cached at `login` — the account email + id,
/// this Device's name + id, and the Coordinator URL. Errors with a `login` hint
/// if this Device has never logged in. The email may be absent for a config
/// written before it was cached; the account id is then shown alone.
pub fn whoami() -> anyhow::Result<()> {
    let config = Config::load()?;
    let (url, account_id, device_id) = require_identity(&config)?;
    match config.email.as_deref() {
        Some(email) => println!("account: {email} ({account_id})"),
        None => println!("account: {account_id}"),
    }
    match config.device_name.as_deref() {
        Some(name) => println!("device:  {name} ({device_id})"),
        None => println!("device:  {device_id}"),
    }
    println!("coordinator: {url}");
    Ok(())
}

/// `spaces` — list the Spaces owned by the logged-in account, marking which are
/// mapped to a local folder on THIS Device and where (issue #15). Needs the
/// Coordinator (`spaces:listMine`); the local mapping comes from `config.json`.
pub async fn spaces() -> anyhow::Result<()> {
    let config = Config::load()?;
    let (url, _account_id, _device_id) = require_identity(&config)?;
    let creds = Credentials::load()?;

    let mut coordinator = env::connect(&url, creds.as_ref()).await?;
    let spaces = coordinator.list_mine().await.context("spaces:listMine")?;
    if spaces.is_empty() {
        println!("no Spaces in this account yet — run `filething init` to create one.");
        return Ok(());
    }
    for space in &spaces {
        // Names are cleartext UTF-8 bytes in the MVP (`§6.2`); render lossily so
        // a malformed name never aborts the listing.
        let name = String::from_utf8_lossy(&space.name);
        println!("{name}");
        println!("  id:     {}", space.space_id);
        match config
            .spaces
            .iter()
            .find(|m| m.space_id == space.space_id.as_str())
        {
            Some(m) => println!("  mapped: {}", m.local_root),
            None => println!(
                "  mapped: no  (clone it here with `filething clone {} <dir>`)",
                space.space_id
            ),
        }
    }
    Ok(())
}

/// `unmap <dir>` — stop syncing a Space on this Device (issue #15).
///
/// KEEPS the local files; only drops the mapping from `config.json` and restarts
/// the background daemon (if installed) so it stops watching the folder. The
/// Space and its history stay on the Coordinator and on the account's other
/// Devices — this is a local un-mapping, not a delete. Matters most when a dead
/// Space is bricking the daemon (issue #8): unmapping it is the escape hatch.
pub fn unmap(dir: PathBuf) -> anyhow::Result<()> {
    let root = normalize_abs(&dir);
    let mut config = Config::load()?;
    if !config.remove_space_by_root(&root.to_string_lossy()) {
        anyhow::bail!(
            "{} is not a Space mapped on this Device — nothing to unmap. \
             Run `filething spaces` to see what is mapped.",
            root.display()
        );
    }
    config.save()?;
    println!("Unmapped {} — local files kept.", root.display());
    restart_daemon_after_unmap();
    Ok(())
}

/// `init <dir>` — make a local folder a fresh Space and commit its first Revision
/// (`docs/BUILD-PLAN.md §3`).
pub async fn init(dir: PathBuf, name: Option<String>, no_daemon: bool) -> anyhow::Result<()> {
    let config = Config::load()?;
    let (url, account_id, device_id) = require_identity(&config)?;
    let creds = require_credentials()?;
    let root = normalize_abs(&dir);
    std::fs::create_dir_all(&root)
        .with_context(|| format!("creating Space dir {}", root.display()))?;
    if let Some(existing) = env::existing_space_id_at(&root)? {
        anyhow::bail!(
            "{} is already a filething Space ({existing}) — `init` would register a \
             second remote Space over the same folder and corrupt the local index. \
             Use `filething sync` to sync it; to re-init from scratch (e.g. against \
             a new backend), delete its .filething/ dir first.",
            root.display()
        );
    }

    let space_name = name.unwrap_or_else(|| {
        root.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("space")
            .to_string()
    });

    let index = env::open_index(&root)?;
    let (coordinator, vault) = env::connect_and_vault(&url, Some(&creds)).await?;

    // Generate this Space's escrow key and turn on `alg=1`: `init_space` sends the
    // key to `spaces:create` and encrypts the first Revision. `dedup_secret` is
    // the Account escrow secret from login.
    let space_key = credentials::generate_secret();
    let crypto = SpaceCrypto {
        dedup_secret: creds.dedup_secret()?,
        space_key,
        // `init_space` stamps the real id once the Coordinator assigns it (it is
        // not known before `create_space`), so a placeholder is correct here.
        space_id: String::new(),
    };

    let ctx = SpaceContext::init_space(
        index,
        vault,
        coordinator,
        account_id,
        device_id,
        space_name.as_bytes(),
        &root,
        crypto,
    )
    .await
    .context("init_space")?;
    let space_id = ctx.space_id.clone();

    // Cache the space_key locally (0600) so later commands open the Space offline.
    credentials::write_space_key(&root, &space_key)?;

    // Record the mapping in the config.
    let mut config = Config::load()?;
    config.upsert_space(space_id.as_str(), &root.to_string_lossy());
    config.save()?;

    println!("Created Space {space_id}");
    println!("  name:  {space_name}");
    println!("  local: {}", root.display());
    println!("  encryption: on (alg=1)");
    println!(
        "  synced seq {} root {}",
        ctx.last_synced.seq,
        hex32(ctx.last_synced.root.as_bytes())
    );
    ensure_background_daemon(true, no_daemon);
    Ok(())
}

/// `clone <space_id> <dir>` — materialize an existing Space into a local folder
/// (`docs/BUILD-PLAN.md §3`).
pub async fn clone(
    space_id: String,
    dir: PathBuf,
    name: Option<String>,
    no_daemon: bool,
) -> anyhow::Result<()> {
    let _ = name; // accepted for symmetry with init; clone takes the Space's name.
    let config = Config::load()?;
    let (url, account_id, device_id) = require_identity(&config)?;
    let creds = require_credentials()?;
    let root = normalize_abs(&dir);
    let space_id = SpaceId::new(space_id);
    if let Some(existing) = env::existing_space_id_at(&root)? {
        anyhow::bail!(
            "{} is already a filething Space ({existing}) — clone into a fresh folder, \
             or delete its .filething/ dir first to re-materialize it.",
            root.display()
        );
    }

    let index = env::open_index(&root)?;
    let (mut coordinator, vault) = env::connect_and_vault(&url, Some(&creds)).await?;

    // Cache the Space's escrow key locally (0600) before materializing, so later
    // commands open it offline. `clone_space` uses it + dedup_secret to decrypt
    // `alg=1` Blocks; a legacy Space has no key (materializes cleartext).
    env::ensure_space_key_cached(&mut coordinator, &space_id, &root).await?;

    let ctx = SpaceContext::clone_space(
        index,
        vault,
        coordinator,
        account_id,
        device_id,
        space_id.clone(),
        &root,
        creds.dedup_secret()?,
    )
    .await
    .context("clone_space")?;

    // Record the mapping.
    let mut config = Config::load()?;
    config.upsert_space(space_id.as_str(), &root.to_string_lossy());
    config.save()?;

    let entries = ctx
        .index
        .list_entries(space_id.as_str())
        .context("listing entries")?;
    println!("Cloned Space {space_id} into {}", root.display());
    println!(
        "  synced seq {} root {}",
        ctx.last_synced.seq,
        hex32(ctx.last_synced.root.as_bytes())
    );
    println!("  {} path(s) materialized", entries.len());
    ensure_background_daemon(true, no_daemon);
    Ok(())
}

/// Resolves a dir argument (or the cwd) to an absolute Space root.
fn resolve_root(dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let dir = match dir {
        Some(d) => d,
        None => std::env::current_dir().context("resolving the current directory")?,
    };
    Ok(normalize_abs(&dir))
}

/// `status [<dir>]` — show the synced base, local changes, and whether this
/// Device is up to date with the remote (`docs/BUILD-PLAN.md §3`, issue #17).
///
/// Which Space(s) it reports:
/// - an explicit `dir`: just that Space (errors if the folder is not a Space);
/// - no `dir`, run INSIDE a Space: that Space;
/// - no `dir`, NOT inside a Space: every Space mapped in `config.json` (like
///   `metrics`), so `status` never dead-ends with "not a filething Space".
///
/// The local half (synced base + uncommitted changes) is computed offline from
/// the index and a re-scan. The remote half is a best-effort verdict — `up to
/// date` or `behind by N revisions (seq X → Y)` — so the user gets an answer to
/// "am I up to date?" instead of a root hash next to an incomparable revision id.
/// Raw hashes/ids are shown only with `-v` (`verbose`).
pub async fn status(dir: Option<PathBuf>, verbose: bool) -> anyhow::Result<()> {
    let config = Config::load()?;
    let (url, account_id, device_id) = require_identity(&config)?;
    let creds = Credentials::load()?;

    // Resolve the Space set + whether a per-Space failure should abort (an
    // explicit target) or just be reported inline (the mapped-Space sweep).
    let (roots, tolerate_errors) = match &dir {
        Some(d) => (vec![normalize_abs(d)], false),
        None => {
            let cwd = resolve_root(None)?;
            if env::existing_space_id_at(&cwd)?.is_some() {
                (vec![cwd], false)
            } else {
                let mapped = config
                    .spaces
                    .iter()
                    .map(|m| PathBuf::from(&m.local_root))
                    .collect::<Vec<_>>();
                (mapped, true)
            }
        }
    };
    if roots.is_empty() {
        println!("no Spaces mapped yet — run `filething init` or `clone` first.");
        return Ok(());
    }

    // One best-effort connection shared across every Space: `status` must work
    // offline (a failed connect degrades to "remote: unavailable"), and every
    // mapped Space belongs to the same account/Coordinator, so one client serves
    // all of them.
    let client = env::connect_client(&url, creds.as_ref()).await.ok();

    for (i, root) in roots.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let res = status_one(
            root,
            &account_id,
            &device_id,
            creds.as_ref(),
            client.clone(),
            verbose,
        )
        .await;
        if let Err(e) = res {
            if tolerate_errors {
                // A mapped folder that is not (yet) a Space, or a transient read
                // error: report it inline instead of aborting the whole listing.
                println!("Space at {}", root.display());
                println!("  error: {e}");
            } else {
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Reports one Space for [`status`]: the local synced base + change detection
/// (offline), then the best-effort remote verdict. Errors only on a genuinely
/// broken Space (not a Space folder, unreadable index/tree); an unreachable
/// Coordinator is NOT an error here — it degrades to "remote: unavailable".
async fn status_one(
    root: &Path,
    account_id: &AccountId,
    device_id: &DeviceId,
    creds: Option<&Credentials>,
    client: Option<ConvexClient>,
    verbose: bool,
) -> anyhow::Result<()> {
    let space_id = env::space_id_at(root)?;
    let index = env::open_index(root)?;

    // Scanning never touches the Vault, but mounting requires one; a failed
    // connect (or no client) degrades to the offline placeholder.
    let vault = match env::build_vault(client.clone()).await {
        Ok(v) => v,
        Err(_) => Box::new(env::UnavailableVault),
    };

    let mut ctx = SpaceContext::mount(
        index,
        vault,
        Box::new(ft_fsmap::LinuxFs),
        account_id.clone(),
        device_id.clone(),
        space_id.clone(),
    )
    .context("mounting Space for status")?;

    // Attach crypto from the LOCAL cache so the scanned Manifest root matches the
    // committed `alg=1` base (block cids — and hence the root — differ under
    // encryption; without the key status would always report false local changes).
    if let Some(crypto) = env::load_space_crypto(root, &space_id, creds)? {
        ctx.attach_crypto(crypto);
    }

    println!("Space {space_id}");
    println!("  local: {}", root.display());

    // Local change detection: build the scanned tree's root and compare.
    let scan = ctx.scan().context("scanning the Space")?;
    let local_root = ft_manifest::build(scan.entries.clone()).root;
    let has_local_changes = ctx.last_synced.seq < 0 || local_root != ctx.last_synced.root;

    // The synced base: the seq is human-comparable; the raw root hash is noise
    // unless verbose (issue #17).
    if verbose {
        println!(
            "  synced: seq {} root {}",
            ctx.last_synced.seq,
            hex32(ctx.last_synced.root.as_bytes())
        );
    } else {
        println!("  synced: seq {}", ctx.last_synced.seq);
    }
    if has_local_changes {
        println!("  local changes: yes (uncommitted — run `filething sync` or the daemon)");
    } else {
        println!("  local changes: none");
    }
    println!("  tracked paths: {}", scan.entries.len());

    // Unresolved conflict copies still on disk (issue #14). Recognize BOTH the
    // current and legacy name formats; match on the basename so a parent dir
    // never trips the check.
    let mut conflict_paths: Vec<&str> = scan
        .entries
        .iter()
        .map(|(_, entry)| entry.p.as_str())
        .filter(|p| {
            let name = p.rsplit('/').next().unwrap_or(p);
            ft_engine::is_conflict_copy_name(name)
        })
        .collect();
    conflict_paths.sort_unstable();
    if conflict_paths.is_empty() {
        println!("  conflicts: none");
    } else {
        println!("  conflicts: {}", conflict_paths.len());
        for p in &conflict_paths {
            println!("    {p}");
        }
    }

    // The remote verdict (issue #17): up to date / behind by N. Best-effort.
    print_remote_verdict(client, &space_id, &ctx, verbose).await;

    // If the background daemon has quarantined this Space (issue #8), say so — it
    // explains why sync appears stuck even though the config looks fine.
    let m = SyncMetrics::load(root);
    if m.quarantined {
        let err = m
            .last_quarantine_error
            .as_deref()
            .unwrap_or("unknown error");
        println!("  daemon: Space is QUARANTINED ({err})");
    }
    Ok(())
}

/// Prints the `remote:` line for [`status_one`] (issue #17): the human verdict
/// comparing the local synced base to the live Space head. `client` is the
/// shared best-effort connection; `None` or an unreachable Coordinator prints
/// "remote: unavailable (…)" rather than failing `status`.
async fn print_remote_verdict(
    client: Option<ConvexClient>,
    space_id: &SpaceId,
    ctx: &SpaceContext,
    verbose: bool,
) {
    let Some(client) = client else {
        println!("  remote: unavailable (offline — could not reach the Coordinator)");
        return;
    };
    let mut coordinator = ft_engine::Coordinator::from_client(client);
    match read_remote_head(&mut coordinator, space_id).await {
        Ok(head) => render_remote_verdict(ctx, &head, verbose),
        Err(e) => {
            // A typed Coordinator error (deleted/forbidden Space, …) → its human
            // headline (#11); anything else → its Display.
            let msg = crate::errors::find_coordinator_error(&e)
                .map(crate::errors::headline)
                .unwrap_or_else(|| e.to_string());
            println!("  remote: unavailable ({msg})");
        }
    }
}

/// Reads the current remote head (id + seq + manifest root) via a one-shot head
/// subscription — Convex pushes the current value immediately on subscribe, so
/// the first stream item is the live head. Bounded by a short timeout so
/// `status` never hangs on a wedged connection.
async fn read_remote_head(
    coordinator: &mut ft_engine::Coordinator,
    space_id: &SpaceId,
) -> anyhow::Result<ft_coordinator::HeadUpdate> {
    use futures::StreamExt as _;
    let fetch = async {
        let mut stream = coordinator.subscribe_head(space_id).await?;
        stream
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("head subscription closed before first value"))?
            .map_err(anyhow::Error::new)
    };
    tokio::time::timeout(Duration::from_secs(10), fetch)
        .await
        .map_err(|_| anyhow::anyhow!("timed out reading the remote head"))?
}

/// Renders the `remote:` verdict text (issue #17). "Up to date" is the same
/// equality the engine's fast-forward uses — the head `manifestRoot` equals the
/// synced base root — so it never disagrees with what a `sync` would do. When
/// behind, it reports the seq distance if both seqs are known and ordered. Raw
/// ids/hashes are appended only with `-v`.
fn render_remote_verdict(ctx: &SpaceContext, head: &ft_coordinator::HeadUpdate, verbose: bool) {
    let local_seq = ctx.last_synced.seq;
    match &head.manifest_root {
        // The remote Space has no Revisions yet.
        None => println!("  remote: no revisions yet"),
        Some(head_root) if *head_root == ctx.last_synced.root => {
            println!("  remote: up to date");
        }
        Some(head_root) => {
            match head.seq {
                Some(head_seq) if local_seq >= 0 && head_seq as i64 > local_seq => {
                    let n = head_seq as i64 - local_seq;
                    let unit = if n == 1 { "revision" } else { "revisions" };
                    println!("  remote: behind by {n} {unit} (seq {local_seq} → {head_seq})");
                }
                // No committed base yet (local_seq < 0), or seqs not strictly
                // ordered: still behind (roots differ), just without a clean count.
                Some(head_seq) => println!("  remote: behind (remote at seq {head_seq})"),
                None => println!("  remote: behind (pull pending)"),
            }
            if verbose {
                let head_id = head
                    .head_revision_id
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "  remote head: {head_id} root {}",
                    hex32(head_root.as_bytes())
                );
            }
        }
    }
}

/// `ls [<dir>]` — list the synced paths of the Space at `dir` (or cwd), read from
/// the local index (`docs/BUILD-PLAN.md §3`).
pub fn ls(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let root = resolve_root(dir)?;
    let space_id = env::space_id_at(&root)?;
    let index = env::open_index(&root)?;
    let mut entries = index
        .list_entries(space_id.as_str())
        .context("listing entries")?;
    entries.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    for entry in &entries {
        let kind = match entry.file_type {
            ft_core::FileType::File => {
                if entry.exec {
                    "x"
                } else {
                    "f"
                }
            }
            ft_core::FileType::Symlink => "l",
            ft_core::FileType::Derived => "d",
            ft_core::FileType::Dir => "D",
        };
        println!("{kind}  {:>10}  {}", entry.size, entry.path.as_str());
    }
    if entries.is_empty() {
        println!("(empty Space)");
    }
    Ok(())
}

/// `sync <dir>` — a one-shot pull + commit for the Space at `dir`
/// (`docs/BUILD-PLAN.md §3`). Useful for scripts and the integration gates: it
/// does NOT run the daemon. Prints both outcomes.
pub async fn sync(dir: PathBuf, no_daemon: bool) -> anyhow::Result<()> {
    let config = Config::load()?;
    let root = normalize_abs(&dir);
    let space_id = env::space_id_at(&root)?;
    let (url, account_id, device_id) = require_identity(&config)?;
    let creds = Credentials::load()?;

    let index = env::open_index(&root)?;
    let (mut coordinator, vault) = env::connect_and_vault(&url, creds.as_ref()).await?;
    // Recover the escrow key into the cache if it is missing, so encryption is
    // attached correctly below (a commit on an `alg=1` Space MUST encrypt).
    let escrow_key = env::ensure_space_key_cached(&mut coordinator, &space_id, &root).await?;

    let mut ctx = SpaceContext::open(
        index,
        vault,
        coordinator,
        account_id,
        device_id,
        space_id.clone(),
    )
    .context("opening Space")?;
    let crypto = env::load_space_crypto(&root, &space_id, creds.as_ref())?;
    // Refuse to commit an encrypted Space in cleartext if crypto could not be
    // attached (Fix A: e.g. a deploy-key ops fallback with no Device session).
    env::assert_crypto_matches_escrow(&space_id, escrow_key, crypto.as_ref())?;
    if let Some(crypto) = crypto {
        ctx.attach_crypto(crypto);
    }
    // Label conflict copies with this Device's human name (issue #14).
    ctx.set_device_display_name(config.device_name.clone());

    // Pull first (catch up to the head), then push local changes.
    let pulled = ctx.pull().await.context("pull")?;
    match &pulled {
        PullOutcome::UpToDate => println!("pull: up to date"),
        PullOutcome::FastForwarded { applied } => {
            println!("pull: fast-forwarded ({applied} change(s) applied)")
        }
        PullOutcome::Reconciled { conflicts } => {
            println!("pull: reconciled ({} conflict copy(ies))", conflicts.len());
            for c in conflicts {
                println!("  conflict copy: {c}");
            }
        }
    }

    let (committed, retry_conflicts) = ctx.commit_and_reconcile().await.context("commit")?;
    match &committed {
        CommitOutcome::NoChange => println!("commit: no local changes"),
        CommitOutcome::Committed { seq, root } => {
            println!(
                "commit: committed seq {seq} root {}",
                hex32(root.as_bytes())
            )
        }
        CommitOutcome::Conflict { .. } => {
            // commit_and_reconcile only returns Conflict if it exhausted retries.
            println!("commit: still conflicting after reconcile retries");
        }
    }
    // Conflict copies written while clearing a CAS conflict between our pull above
    // and the commit (a peer committed in that window). The pull's own conflicts
    // were already printed; surface these too so no divergence is silent.
    for c in &retry_conflicts {
        println!("  conflict copy: {c}");
    }
    ensure_background_daemon(false, no_daemon);
    Ok(())
}

/// `daemon [<dir>...]` — run the foreground Daemon over the given Space dirs, or
/// (with none given) every Space mapped in `config.json` (`docs/BUILD-PLAN.md
/// §3`, "daemon por defecto"). This no-args form is what the background service
/// invokes, so a Space added later just needs a restart to be picked up. Builds
/// one [`ft_daemon::SpaceSlot`] per dir — a factory that mounts and runs the
/// Space on every (re)try — and hands them to [`ft_daemon::serve`], which
/// supervises each independently (a failing Space is quarantined and retried, not
/// fatal to the daemon — issue #8) and shuts down on Ctrl-C.
///
/// With zero Spaces mapped (e.g. right after `service install`, before any
/// `init`/`clone` ran) there is nothing to open yet, and — critically — no
/// identity to require either: this waits idle forever instead of erroring, so
/// the OS service supervisor doesn't crash-loop it.
pub async fn daemon(dirs: Vec<PathBuf>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let dirs = if dirs.is_empty() {
        config
            .spaces
            .iter()
            .map(|m| PathBuf::from(&m.local_root))
            .collect::<Vec<_>>()
    } else {
        dirs
    };
    if dirs.is_empty() {
        tracing::info!("no Spaces mapped yet; idle (restart me after init/clone)");
        std::future::pending::<()>().await;
    }

    // Global preconditions ARE fatal: with no identity/credentials nothing can
    // sync, and exiting with that error is correct (the OS supervisor's relaunch
    // won't help, but there is genuinely nothing to do).
    let (url, account_id, device_id) = require_identity(&config)?;
    let creds = Credentials::load()?;

    // Build one supervised slot per Space. Crucially, ALL per-Space work — id
    // lookup, index open, connect, `space_key` recovery, mount, crypto attach —
    // lives INSIDE the slot's task closure, not here: [`ft_daemon::serve`] calls
    // it afresh on every (re)try, so a Space whose setup fails (e.g.
    // `ensure_space_key_cached` hitting a deleted Space) is QUARANTINED and
    // retried with backoff instead of aborting the whole daemon and crash-looping
    // the OS service (issue #8, "un Space roto brickea el daemon entero").
    let slots = dirs
        .into_iter()
        .map(|dir| {
            let root = normalize_abs(&dir);
            let label = root.display().to_string();
            // Each retry is a fresh attempt, so the closure clones this Space's
            // inputs on every call rather than moving them once.
            let url = url.clone();
            let account_id = account_id.clone();
            let device_id = device_id.clone();
            let creds = creds.clone();
            // This Device's human name, to label conflict copies (issue #14).
            let device_name = config.device_name.clone();
            let slot_root = root.clone();
            let task = move |stop: LocalBoxFuture<'static, ()>| {
                let url = url.clone();
                let account_id = account_id.clone();
                let device_id = device_id.clone();
                let creds = creds.clone();
                let device_name = device_name.clone();
                let root = slot_root.clone();
                Box::pin(async move {
                    let space_id = env::space_id_at(&root)?;
                    let index = env::open_index(&root)?;
                    // The JWT is re-minted on every connect and reconnect
                    // (set_auth_callback, see env::connect) so the daemon outlives
                    // the ~15-min token expiry.
                    let (mut coordinator, vault) =
                        env::connect_and_vault(&url, creds.as_ref()).await?;
                    let escrow_key =
                        env::ensure_space_key_cached(&mut coordinator, &space_id, &root).await?;
                    let mut ctx = SpaceContext::open(
                        index,
                        vault,
                        coordinator,
                        account_id,
                        device_id,
                        space_id.clone(),
                    )
                    .with_context(|| format!("opening Space at {}", root.display()))?;
                    let crypto = env::load_space_crypto(&root, &space_id, creds.as_ref())?;
                    env::assert_crypto_matches_escrow(&space_id, escrow_key, crypto.as_ref())?;
                    if let Some(crypto) = crypto {
                        ctx.attach_crypto(crypto);
                    }
                    // Label conflict copies with this Device's human name (issue #14).
                    ctx.set_device_display_name(device_name.clone());
                    // Mounting succeeded: if this Space was quarantined (issue #8),
                    // it has recovered — clear the flag NOW, before `run` loads its
                    // own metrics copy, so `filething metrics`/`status` stop
                    // reporting it quarantined while it runs healthily. (The
                    // engine's periodic saves would otherwise keep re-writing the
                    // stale flag until the next clean shutdown.)
                    let mut m = SyncMetrics::load(&root);
                    if m.quarantined {
                        m.record_quarantine_cleared();
                        m.save(&root);
                        tracing::info!(
                            space = %space_id,
                            root = %root.display(),
                            "space recovered from quarantine"
                        );
                    }
                    tracing::info!(
                        space = %space_id,
                        root = %root.display(),
                        "mounted Space for daemon"
                    );
                    ctx.run(stop).await?;
                    Ok(())
                }) as LocalBoxFuture<'static, anyhow::Result<()>>
            };
            ft_daemon::SpaceSlot {
                label,
                root,
                task: Box::new(task),
            }
        })
        .collect::<Vec<_>>();

    println!(
        "filething daemon running over {} Space(s); press Ctrl-C to stop.",
        slots.len()
    );
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Ctrl-C received; shutting down");
    };
    ft_daemon::serve(slots, shutdown)
        .await
        .context("daemon serve")?;
    println!("filething daemon stopped.");
    Ok(())
}

/// `gc <dir>` — mark-and-sweep the Space's Vault objects, dry-run by default
/// (`docs/format.md §6.3`, `docs/adr/0007`). Requires a Coordinator (retained
/// roots + retention floor). Pass `--apply` to actually delete.
pub async fn gc(dir: PathBuf, apply: bool, grace_secs: Option<u64>) -> anyhow::Result<()> {
    // In the managed deployment this Device holds no direct storage credentials
    // (S3_*); its data plane is the presigned SignedVault, which cannot `list`
    // or `delete` across the bucket, so gc is operator-side only there. Detect
    // that mode UP FRONT — before requiring a login, opening the index, or
    // spending ~5s minting `vault:sign` URLs only to fail on the first `list()`
    // with a duplicated operator-only error — and stop with a friendly note:
    // gc is simply not this user's job in a managed deployment (issue #21).
    if !env::direct_s3_configured() {
        println!(
            "gc: en el deployment gestionado la recolección de basura corre del lado \
             del operador; no necesitas ejecutarla."
        );
        println!(
            "  (gc necesita credenciales de almacenamiento directas S3_* que este Device \
             no tiene; su plano de datos es el firmado por el Coordinator.)"
        );
        return Ok(());
    }

    let config = Config::load()?;
    let root = normalize_abs(&dir);
    let space_id = env::space_id_at(&root)?;
    let (url, account_id, device_id) = require_identity(&config)?;
    let creds = Credentials::load()?;

    let index = env::open_index(&root)?;
    // GC walks cleartext Manifests + meta blobs and deletes Vault objects (sidecars
    // included); it never decrypts Block content, so no crypto is attached here.
    // Its sweep needs `list`/`delete`, which the signed data plane cannot offer:
    // gc is operator-only, run it with the direct `S3_*` env vars set.
    let (coordinator, vault) = env::connect_and_vault(&url, creds.as_ref()).await?;
    let mut ctx = SpaceContext::open(index, vault, coordinator, account_id, device_id, space_id)
        .context("opening Space")?;

    let grace = grace_secs
        .map(Duration::from_secs)
        .unwrap_or(ft_engine::DEFAULT_GRACE);
    let report = ctx.gc(GcOptions { apply, grace }).await.context("gc")?;

    let mode = if report.applied { "APPLIED" } else { "dry run" };
    println!(
        "GC ({mode}) — account-wide Vault, selected via {}",
        root.display()
    );
    println!("  (all your Spaces share one Vault; reachability is unioned across them)");
    println!("  mode: orphan-sweep (retains ALL history; only unreferenced objects are swept)");
    println!(
        "  {} Space(s), {} revision(s) walked",
        report.spaces, report.retained_revisions
    );
    println!(
        "  objects: {} scanned, {} reachable, {} sweepable, {} held by grace-period",
        report.scanned_objects,
        report.reachable_objects,
        report.sweepable.len(),
        report.kept_by_grace
    );
    if report.applied {
        println!("  deleted: {} object(s)", report.deleted);
    } else if report.sweepable.is_empty() {
        println!("  nothing to sweep.");
    } else {
        const SHOW: usize = 20;
        println!(
            "  would delete {} object(s) (re-run with --apply):",
            report.sweepable.len()
        );
        for key in report.sweepable.iter().take(SHOW) {
            println!("    {key}");
        }
        if report.sweepable.len() > SHOW {
            println!("    … and {} more", report.sweepable.len() - SHOW);
        }
    }
    Ok(())
}

/// `metrics [<dir>]` — print the persisted sync counters for a Space (or every
/// mapped Space). Reads `<root>/.filething/metrics.json` locally; no network.
pub fn metrics(dir: Option<PathBuf>, json: bool) -> anyhow::Result<()> {
    let roots: Vec<PathBuf> = match dir {
        Some(d) => vec![normalize_abs(&d)],
        None => Config::load()?
            .spaces
            .iter()
            .map(|m| PathBuf::from(&m.local_root))
            .collect(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if json {
        // A JSON array of raw values (durations in whole seconds), stable for
        // monitoring — the humanized text below is for people (issue #18). An
        // empty array when no Spaces are mapped, so a monitor always parses.
        let items: Vec<serde_json::Value> = roots.iter().map(|r| metrics_json(r, now)).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&items).context("serializing metrics as JSON")?
        );
        return Ok(());
    }
    if roots.is_empty() {
        println!("no Spaces mapped yet — run `filething init` or `clone` first.");
        return Ok(());
    }
    for root in roots {
        let m = SyncMetrics::load(&root);
        println!("Space at {}", root.display());
        if m == SyncMetrics::default() {
            println!("  (no metrics yet — has the daemon run for this Space?)");
            continue;
        }
        println!(
            "  commits: {}   pulls applied: {}   conflicts: {}",
            m.commits, m.pulls_applied, m.conflicts
        );
        println!(
            "  feed errors: {}   stale alerts: {}",
            m.feed_errors, m.stale_alerts
        );
        // Quarantine (issue #8): surface a Space the daemon is backing off on.
        if m.quarantines > 0 || m.quarantined {
            println!("  quarantines: {}", m.quarantines);
            if m.quarantined {
                let err = m
                    .last_quarantine_error
                    .as_deref()
                    .unwrap_or("unknown error");
                match m.last_quarantine {
                    Some(t) => {
                        println!(
                            "  QUARANTINED ({} ago): {err}",
                            humanize_secs(now.saturating_sub(t))
                        )
                    }
                    None => println!("  QUARANTINED: {err}"),
                }
            }
        }
        print_ago("  started", m.started_at, now);
        print_ago("  last head seen", m.last_head_seen, now);
        print_ago("  last commit", m.last_commit, now);
    }
    Ok(())
}

/// Prints a unix-seconds timestamp as its age in natural units ("16s ago",
/// "4h 23m ago", "5d 22h ago"), or "never" when absent (issue #18).
fn print_ago(label: &str, ts: Option<u64>, now: u64) {
    match ts {
        Some(t) => println!("{label}: {} ago", humanize_secs(now.saturating_sub(t))),
        None => println!("{label}: never"),
    }
}

/// Formats a duration in whole seconds as its two largest natural units:
/// `16s`, `1m 15s`, `4h 23m`, `5d 22h`. Below a minute it is a single unit; a
/// zero lower unit is dropped (`1m`, `1h`, `1d`). For humans only — the `--json`
/// output keeps the raw seconds (issue #18). Shared with `service` status, which
/// humanizes the daemon's uptime the same way (issue #19).
pub(crate) fn humanize_secs(secs: u64) -> String {
    const MIN: u64 = 60;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;
    if secs < MIN {
        format!("{secs}s")
    } else if secs < HOUR {
        let (m, s) = (secs / MIN, secs % MIN);
        if s == 0 {
            format!("{m}m")
        } else {
            format!("{m}m {s}s")
        }
    } else if secs < DAY {
        let (h, m) = (secs / HOUR, (secs % HOUR) / MIN);
        if m == 0 {
            format!("{h}h")
        } else {
            format!("{h}h {m}m")
        }
    } else {
        let (d, h) = (secs / DAY, (secs % DAY) / HOUR);
        if h == 0 {
            format!("{d}d")
        } else {
            format!("{d}d {h}h")
        }
    }
}

/// The `--json` view of one Space's metrics: every counter plus, for each
/// timestamp, both the raw unix seconds (`*_at`, stable across calls) and the
/// age in whole seconds at call time (`*_secs_ago`, what the text report
/// humanizes). Absent timestamps serialize as `null`. `has_metrics` is false
/// when no daemon has written a snapshot yet (issue #18).
fn metrics_json(root: &std::path::Path, now: u64) -> serde_json::Value {
    let m = SyncMetrics::load(root);
    let secs_ago = |ts: Option<u64>| ts.map(|t| now.saturating_sub(t));
    serde_json::json!({
        "root": root.display().to_string(),
        "has_metrics": m != SyncMetrics::default(),
        "commits": m.commits,
        "pulls_applied": m.pulls_applied,
        "conflicts": m.conflicts,
        "feed_errors": m.feed_errors,
        "stale_alerts": m.stale_alerts,
        "quarantines": m.quarantines,
        "quarantined": m.quarantined,
        "last_quarantine_error": m.last_quarantine_error,
        "started_at": m.started_at,
        "started_secs_ago": secs_ago(m.started_at),
        "last_head_seen_at": m.last_head_seen,
        "last_head_seen_secs_ago": secs_ago(m.last_head_seen),
        "last_commit_at": m.last_commit,
        "last_commit_secs_ago": secs_ago(m.last_commit),
        "last_quarantine_at": m.last_quarantine,
        "last_quarantine_secs_ago": secs_ago(m.last_quarantine),
    })
}

/// `service <install|uninstall|status>` — manage the daemon as an OS service.
pub fn service(action: ServiceAction) -> anyhow::Result<()> {
    crate::service::run(action)
}

/// Makes sure the daemon keeps running in the background after a successful
/// `init`/`clone`/`sync`, so day-to-day use never needs a separate `filething
/// service install` step (`TODO.md` Fase 6, "daemon por defecto"). ALWAYS
/// best-effort: any failure is a `tracing::warn!`, never propagated — the command
/// that called this already succeeded and must not fail because of it.
///
/// Skips entirely when `no_daemon` (the `--no-daemon` flag) is set, or when
/// `FILETHING_NO_AUTO_DAEMON` is a non-empty env var (the integration scripts set
/// this — they drive one-shot `sync` in throwaway `FILETHING_HOME`s and must not
/// install a service on the host running them). Also skips with a warning on any
/// OS other than macOS/Linux (the only ones `service.rs` supports).
///
/// `new_space` marks `init`/`clone` (a Space mapping was just added): if the
/// service is already installed, it is RESTARTED so the daemon — which resolves
/// its Space list fresh from `config.json` on every start — picks up the new
/// mapping. A plain `sync` only starts it when it is not already running.
fn ensure_background_daemon(new_space: bool, no_daemon: bool) {
    if no_daemon {
        return;
    }
    if std::env::var("FILETHING_NO_AUTO_DAEMON")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return;
    }
    if !(cfg!(target_os = "macos") || cfg!(target_os = "linux")) {
        tracing::warn!("background daemon auto-start is only supported on macOS/Linux; skipping");
        return;
    }

    if !crate::service::is_installed() {
        match crate::service::install() {
            Ok(()) => println!("daemon: running in background (service installed)"),
            Err(e) => tracing::warn!("could not install the background daemon service: {e:#}"),
        }
        return;
    }

    if new_space {
        match crate::service::restart() {
            Ok(()) => println!("daemon: restarted to pick up the new Space"),
            Err(e) => tracing::warn!("could not restart the background daemon service: {e:#}"),
        }
    } else if !crate::service::is_running() {
        match crate::service::restart() {
            Ok(()) => println!("daemon: running in background (was stopped; restarted)"),
            Err(e) => tracing::warn!("could not start the background daemon service: {e:#}"),
        }
    }
}

/// Restarts the background daemon after an `unmap` so it stops watching the
/// dropped Space (the daemon resolves its Space list fresh from `config.json` on
/// every start — see [`crate::commands::daemon`]). Best-effort, mirroring
/// [`ensure_background_daemon`]: skipped when the service is not installed or
/// `FILETHING_NO_AUTO_DAEMON` is set, and any failure is a warning, never fatal
/// — the mapping has already been removed either way.
fn restart_daemon_after_unmap() {
    if std::env::var("FILETHING_NO_AUTO_DAEMON")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return;
    }
    if !crate::service::is_installed() {
        return;
    }
    match crate::service::restart() {
        Ok(()) => println!("daemon: restarted to drop the unmapped Space"),
        Err(e) => tracing::warn!("could not restart the background daemon service: {e:#}"),
    }
}

/// Lowercase hex of a 32-byte id, for human-readable output of a `manifestRoot`.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The examples from issue #18 plus the unit boundaries: below a minute is a
    /// single unit, otherwise the two largest units, dropping a zero lower unit.
    #[test]
    fn humanize_secs_formats_natural_units() {
        assert_eq!(humanize_secs(0), "0s");
        assert_eq!(humanize_secs(16), "16s");
        assert_eq!(humanize_secs(59), "59s");
        assert_eq!(humanize_secs(60), "1m");
        assert_eq!(humanize_secs(75), "1m 15s");
        assert_eq!(humanize_secs(3600), "1h");
        assert_eq!(humanize_secs(15_780), "4h 23m"); // 4*3600 + 23*60
        assert_eq!(humanize_secs(86_400), "1d");
        assert_eq!(humanize_secs(514_483), "5d 22h"); // the issue's «514483s ago»
    }

    /// The JSON view carries raw seconds: both the absolute unix timestamp and
    /// the age, and `has_metrics` reflects whether a snapshot exists. A default
    /// (never-run) Space reports nulls and `has_metrics: false`.
    #[test]
    fn metrics_json_exposes_raw_seconds() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000u64;

        // No snapshot yet: has_metrics false, timestamps null.
        let v = metrics_json(dir.path(), now);
        assert_eq!(v["has_metrics"], serde_json::json!(false));
        assert_eq!(v["started_at"], serde_json::Value::Null);
        assert_eq!(v["started_secs_ago"], serde_json::Value::Null);

        // With a snapshot, secs_ago is the raw difference (parseable, not "5d").
        let m = SyncMetrics {
            commits: 3,
            started_at: Some(now - 514_483),
            ..Default::default()
        };
        m.save(dir.path());
        let v = metrics_json(dir.path(), now);
        assert_eq!(v["has_metrics"], serde_json::json!(true));
        assert_eq!(v["commits"], serde_json::json!(3));
        assert_eq!(v["started_at"], serde_json::json!(now - 514_483));
        assert_eq!(v["started_secs_ago"], serde_json::json!(514_483));
    }
}
