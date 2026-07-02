//! The `filething` subcommand implementations (`docs/BUILD-PLAN.md §3`,
//! `CONTEXT.md` — CLI estilo git).
//!
//! Each function ORCHESTRATES the engine; none reimplements sync logic. They load
//! the [`Config`] identity, build the [`Vault`]/[`Coordinator`] from env
//! ([`crate::env`]), open the Space's local index, drive a `SpaceContext`, and
//! print a clear result.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use ft_engine::{
    AccountId, CommitOutcome, DeviceId, GcOptions, PullOutcome, SpaceContext, SpaceId, SyncMetrics,
};

use crate::config::{normalize_abs, Config};
use crate::env;
use crate::service::ServiceAction;

/// A reasonable default Device name when `--name` is omitted: the machine
/// hostname, else a generic label.
fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "filething-device".to_string())
}

/// `login` — pair this Device with the Coordinator (`docs/BUILD-PLAN.md §3`).
///
/// Without `--code` this is a BOOTSTRAP: create the first Account + Device and
/// print the pairing code a second Device can `claim`. With `--code` it CLAIMS an
/// existing Account. Either way the learned identity (account/device id +
/// coordinator url) is saved to `config.json`.
pub async fn login(code: Option<String>, name: Option<String>) -> anyhow::Result<()> {
    let device_name = name.unwrap_or_else(default_device_name);
    let url = env::coordinator_url_from_env();
    let mut coordinator = env::connect_coordinator(&url).await?;

    let mut config = Config::load()?;

    match code {
        None => {
            let boot = coordinator
                .bootstrap(&device_name)
                .await
                .context("bootstrap (first Device of a new Account)")?;
            config.set_identity(&url, boot.account_id.as_str(), boot.device_id.as_str());
            config.save()?;
            println!("Paired this Device as the first of a new Account.");
            println!("  account: {}", boot.account_id);
            println!("  device:  {}", boot.device_id);
            println!("  coordinator: {url}");
            println!();
            println!(
                "Pairing code (run `filething login --code {0}` on another Device):",
                boot.pairing_code
            );
            println!("  {}", boot.pairing_code);
        }
        Some(code) => {
            let claim = coordinator
                .claim(&code, &device_name)
                .await
                .context("claim (joining an existing Account with a pairing code)")?;
            config.set_identity(&url, claim.account_id.as_str(), claim.device_id.as_str());
            config.save()?;
            println!("Paired this Device into the existing Account.");
            println!("  account: {}", claim.account_id);
            println!("  device:  {}", claim.device_id);
            println!("  coordinator: {url}");
        }
    }
    Ok(())
}

/// Loads the paired identity from the config, erroring with a `login` hint if the
/// Device has not been paired yet. Returns `(coordinator_url, account, device)`.
fn require_identity(config: &Config) -> anyhow::Result<(String, AccountId, DeviceId)> {
    let url = config
        .coordinator_url
        .clone()
        .unwrap_or_else(env::coordinator_url_from_env);
    let account_id = config
        .account_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not paired yet — run `filething login` first"))?;
    let device_id = config
        .device_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not paired yet — run `filething login` first"))?;
    Ok((url, AccountId::new(account_id), DeviceId::new(device_id)))
}

/// `init <dir>` — make a local folder a fresh Space and commit its first Revision
/// (`docs/BUILD-PLAN.md §3`).
pub async fn init(dir: PathBuf, name: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let (url, account_id, device_id) = require_identity(&config)?;
    let root = normalize_abs(&dir);
    std::fs::create_dir_all(&root)
        .with_context(|| format!("creating Space dir {}", root.display()))?;

    let space_name = name.unwrap_or_else(|| {
        root.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("space")
            .to_string()
    });

    let index = env::open_index(&root)?;
    let vault = env::build_vault().await?;
    let coordinator = env::connect_coordinator(&url).await?;

    let ctx = SpaceContext::init_space(
        index,
        vault,
        coordinator,
        account_id,
        device_id,
        space_name.as_bytes(),
        &root,
    )
    .await
    .context("init_space")?;
    let space_id = ctx.space_id.clone();

    // Record the mapping in the config.
    let mut config = Config::load()?;
    config.upsert_space(space_id.as_str(), &root.to_string_lossy());
    config.save()?;

    println!("Created Space {space_id}");
    println!("  name:  {space_name}");
    println!("  local: {}", root.display());
    println!(
        "  synced seq {} root {}",
        ctx.last_synced.seq,
        hex32(ctx.last_synced.root.as_bytes())
    );
    Ok(())
}

/// `clone <space_id> <dir>` — materialize an existing Space into a local folder
/// (`docs/BUILD-PLAN.md §3`).
pub async fn clone(space_id: String, dir: PathBuf, name: Option<String>) -> anyhow::Result<()> {
    let _ = name; // accepted for symmetry with init; clone takes the Space's name.
    let config = Config::load()?;
    let (url, account_id, device_id) = require_identity(&config)?;
    let root = normalize_abs(&dir);
    let space_id = SpaceId::new(space_id);

    let index = env::open_index(&root)?;
    let vault = env::build_vault().await?;
    let coordinator = env::connect_coordinator(&url).await?;

    let ctx = SpaceContext::clone_space(
        index,
        vault,
        coordinator,
        account_id,
        device_id,
        space_id.clone(),
        &root,
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

/// `status [<dir>]` — show the synced base and whether there are uncommitted
/// local changes for the Space at `dir` (or cwd) (`docs/BUILD-PLAN.md §3`).
///
/// Robust + informative: it reads the local index (the source of truth for
/// `last_synced`) and re-scans the tree to detect local changes WITHOUT a network
/// round-trip. If the Coordinator is reachable it also reports whether the remote
/// head has advanced past the synced base.
pub async fn status(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let root = resolve_root(dir)?;
    let space_id = env::space_id_at(&root)?;
    let (url, account_id, device_id) = require_identity(&config)?;

    let index = env::open_index(&root)?;
    let vault = env::build_vault().await?;

    // Mount for scanning only (no Coordinator needed to detect LOCAL changes).
    let ctx = SpaceContext::mount(
        index,
        vault,
        Box::new(ft_fsmap::LinuxFs),
        account_id,
        device_id,
        space_id.clone(),
    )
    .context("mounting Space for status")?;

    println!("Space {space_id}");
    println!("  local: {}", root.display());
    println!(
        "  last synced: seq {} root {}",
        ctx.last_synced.seq,
        hex32(ctx.last_synced.root.as_bytes())
    );

    // Local change detection: build the scanned tree's root and compare.
    let scan = ctx.scan().context("scanning the Space")?;
    let local_root = ft_manifest::build(scan.entries.clone()).root;
    let has_local_changes = ctx.last_synced.seq < 0 || local_root != ctx.last_synced.root;
    if has_local_changes {
        println!("  local changes: yes (uncommitted — run `filething sync` or the daemon)");
    } else {
        println!("  local changes: none");
    }
    println!("  tracked paths: {}", scan.entries.len());

    // Best-effort remote head check (does not fail status if the Coordinator is
    // unreachable — status must work offline).
    match env::connect_coordinator(&url).await {
        Ok(mut coordinator) => match coordinator.get_space(&space_id).await {
            Ok(space) => match space.head_revision_id {
                Some(head) => {
                    let behind = ctx.last_synced_revision_id.as_ref() != Some(&head);
                    println!(
                        "  remote head: {head}{}",
                        if behind {
                            " (behind — pull pending)"
                        } else {
                            ""
                        }
                    );
                }
                None => println!("  remote head: none yet"),
            },
            Err(e) => println!("  remote head: unavailable ({e})"),
        },
        Err(e) => println!("  remote head: unavailable ({e})"),
    }
    Ok(())
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
pub async fn sync(dir: PathBuf) -> anyhow::Result<()> {
    let config = Config::load()?;
    let root = normalize_abs(&dir);
    let space_id = env::space_id_at(&root)?;
    let (url, account_id, device_id) = require_identity(&config)?;

    let index = env::open_index(&root)?;
    let vault = env::build_vault().await?;
    let coordinator = env::connect_coordinator(&url).await?;

    let mut ctx = SpaceContext::open(index, vault, coordinator, account_id, device_id, space_id)
        .context("opening Space")?;

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

    let committed = ctx.commit_and_reconcile().await.context("commit")?;
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
    Ok(())
}

/// `daemon <dir>...` — run the foreground Daemon over the given Space dirs
/// (`docs/BUILD-PLAN.md §3`). Opens one `SpaceContext` per dir and hands them to
/// [`ft_daemon::serve`], shutting down on Ctrl-C.
pub async fn daemon(dirs: Vec<PathBuf>) -> anyhow::Result<()> {
    anyhow::ensure!(!dirs.is_empty(), "daemon needs at least one Space dir");
    let config = Config::load()?;
    let (url, account_id, device_id) = require_identity(&config)?;

    let mut spaces = Vec::with_capacity(dirs.len());
    for dir in dirs {
        let root = normalize_abs(&dir);
        let space_id = env::space_id_at(&root)?;
        let index = env::open_index(&root)?;
        let vault = env::build_vault().await?;
        let coordinator = env::connect_coordinator(&url).await?;
        let ctx = SpaceContext::open(
            index,
            vault,
            coordinator,
            account_id.clone(),
            device_id.clone(),
            space_id.clone(),
        )
        .with_context(|| format!("opening Space at {}", root.display()))?;
        tracing::info!(space = %space_id, root = %root.display(), "mounted Space for daemon");
        spaces.push(ctx);
    }

    println!(
        "filething daemon running over {} Space(s); press Ctrl-C to stop.",
        spaces.len()
    );
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Ctrl-C received; shutting down");
    };
    ft_daemon::serve(spaces, shutdown)
        .await
        .context("daemon serve")?;
    println!("filething daemon stopped.");
    Ok(())
}

/// `gc <dir>` — mark-and-sweep the Space's Vault objects, dry-run by default
/// (`docs/format.md §6.3`, `docs/adr/0007`). Requires a Coordinator (retained
/// roots + retention floor). Pass `--apply` to actually delete.
pub async fn gc(
    dir: PathBuf,
    apply: bool,
    grace_secs: Option<u64>,
    keep_all: bool,
) -> anyhow::Result<()> {
    let config = Config::load()?;
    let root = normalize_abs(&dir);
    let space_id = env::space_id_at(&root)?;
    let (url, account_id, device_id) = require_identity(&config)?;

    let index = env::open_index(&root)?;
    let vault = env::build_vault().await?;
    let coordinator = env::connect_coordinator(&url).await?;
    let mut ctx = SpaceContext::open(index, vault, coordinator, account_id, device_id, space_id)
        .context("opening Space")?;

    let grace = grace_secs
        .map(Duration::from_secs)
        .unwrap_or(ft_engine::DEFAULT_GRACE);
    let report = ctx
        .gc(GcOptions {
            apply,
            grace,
            keep_all,
        })
        .await
        .context("gc")?;

    let mode = if report.applied { "APPLIED" } else { "dry run" };
    println!(
        "GC ({mode}) — account-wide Vault, selected via {}",
        root.display()
    );
    println!("  (all your Spaces share one Vault; reachability is unioned across them)");
    if report.keep_all {
        println!("  retention: keep-all (every Revision retained; sweeps only orphans)");
    } else {
        println!("  retention: seq >= per-Space floor (min base across your Devices)");
    }
    println!(
        "  {} Space(s), {} retained revision(s)",
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
pub fn metrics(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let roots: Vec<PathBuf> = match dir {
        Some(d) => vec![normalize_abs(&d)],
        None => Config::load()?
            .spaces
            .iter()
            .map(|m| PathBuf::from(&m.local_root))
            .collect(),
    };
    if roots.is_empty() {
        println!("no Spaces mapped yet — run `filething init` or `clone` first.");
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
        print_ago("  started", m.started_at, now);
        print_ago("  last head seen", m.last_head_seen, now);
        print_ago("  last commit", m.last_commit, now);
    }
    Ok(())
}

/// Prints a unix-seconds timestamp as "<n>s ago", or "never" when absent.
fn print_ago(label: &str, ts: Option<u64>, now: u64) {
    match ts {
        Some(t) => println!("{label}: {}s ago", now.saturating_sub(t)),
        None => println!("{label}: never"),
    }
}

/// `service <install|uninstall|status>` — manage the daemon as an OS service.
pub fn service(action: ServiceAction) -> anyhow::Result<()> {
    crate::service::run(action)
}

/// Lowercase hex of a 32-byte id, for human-readable output of a `manifestRoot`.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
