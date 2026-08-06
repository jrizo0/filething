//! filething — the `filething` CLI binary (`docs/BUILD-PLAN.md §3`, `CONTEXT.md`).
//!
//! A git-style CLI that ORCHESTRATES the engine: it pairs the Device (`login`),
//! turns a folder into a Space (`init`) or materializes one (`clone`), reports
//! state (`status`/`ls`), runs a one-shot sync (`sync`), and runs the foreground
//! Daemon (`daemon`). All sync logic lives in `ft-engine`; this binary is wiring.
//!
//! Identity + Space mappings live in `config.json` ([`config::Config`]); the
//! Coordinator URL/admin key and the Vault `S3_*` credentials come from the
//! environment (the MVP self-hosted model, `infra/.env`).

mod auth;
mod commands;
mod config;
mod credentials;
mod env;
mod errors;
mod logrotate;
mod progress;
mod service;
mod signed_vault;

use std::io::IsTerminal as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::service::ServiceAction;

/// filething — keep your developer folders identical across machines.
#[derive(Debug, Parser)]
#[command(name = "filething", version, about, long_about = None)]
struct Cli {
    /// Show the internal logging that one-shot commands hide by default
    /// (equivalent to `FILETHING_LOG=info`) and the full technical detail of an
    /// error. `RUST_LOG`, then `FILETHING_LOG`, take precedence over this flag.
    /// Third-party crates are capped at `info` whatever you ask for: their debug
    /// logs print your session token and Space keys in cleartext.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Log this Device in to the Coordinator via Better Auth, then register it
    /// (`auth:ensureDevice`). Use `--signup` the first time (creates the Account);
    /// omit it to log in an existing Account — including from a SECOND Device,
    /// which is just the same user logging in elsewhere (pairing codes are gone).
    /// The password is read from `$FILETHING_PASSWORD` (for scripts) or prompted.
    Login {
        /// The account email (Better Auth identity).
        #[arg(long)]
        email: String,
        /// Create the Account instead of logging in to an existing one.
        #[arg(long)]
        signup: bool,
        /// A human name for this Device (defaults to the machine hostname). On
        /// `--signup` it also seeds the Account's display name if unset.
        #[arg(long)]
        name: Option<String>,
    },

    /// Show who this Device is logged in as: the account email (when known) and
    /// id, this Device's name and id, and the Coordinator URL. Reads the local
    /// config only — no network.
    Whoami,

    /// List the Spaces owned by the logged-in account, marking which are mapped
    /// to a local folder on THIS Device (and where). Handy before `clone` from a
    /// second Device, so the Space id no longer has to be copied by hand.
    Spaces,

    /// Make a local folder a new Space and commit its first Revision, then install
    /// (or restart) the background daemon service so the folder keeps syncing —
    /// pass `--no-daemon` to skip that.
    Init {
        /// The folder to turn into a Space.
        dir: PathBuf,
        /// A name for the Space (defaults to the folder name).
        #[arg(long)]
        name: Option<String>,
        /// Don't install/restart the background daemon service after this
        /// command (also settable via `FILETHING_NO_AUTO_DAEMON`).
        #[arg(long)]
        no_daemon: bool,
    },

    /// Materialize an existing Space into a local folder, then install (or restart)
    /// the background daemon service so it keeps syncing — pass `--no-daemon` to
    /// skip that.
    Clone {
        /// The Space id to clone (printed by `init`).
        space_id: String,
        /// The local folder to materialize it into.
        dir: PathBuf,
        /// Unused for now; the Space carries its own name. Accepted for symmetry.
        #[arg(long)]
        name: Option<String>,
        /// Don't install/restart the background daemon service after this
        /// command (also settable via `FILETHING_NO_AUTO_DAEMON`).
        #[arg(long)]
        no_daemon: bool,
    },

    /// Stop syncing a Space on this Device: KEEP the local files, remove its
    /// mapping from `config.json`, and restart the background daemon (if
    /// installed as a service) so it drops the Space. The Space and its history
    /// stay on the Coordinator and on your other Devices.
    Unmap {
        /// The mapped Space folder to unmap.
        dir: PathBuf,
    },

    /// Show a Space's synced base and whether it has uncommitted local changes.
    /// With no dir, outside a Space, reports every mapped Space (like `metrics`).
    /// The local half works offline; comparing against the remote head is
    /// best-effort and degrades to "unavailable" with no Coordinator.
    Status {
        /// The Space folder (defaults to the current directory).
        dir: Option<PathBuf>,
    },

    /// List a Space's synced paths (from the local index).
    Ls {
        /// The Space folder (defaults to the current directory).
        dir: Option<PathBuf>,
    },

    /// One-shot sync: pull the head, then commit local changes, then exit — handy
    /// for scripts and the integration gates. It does not WATCH the folder itself,
    /// but it does install (or restart) the background daemon service that does;
    /// pass `--no-daemon` for a sync that touches nothing but this Space.
    Sync {
        /// The Space folder.
        dir: PathBuf,
        /// Don't install/restart the background daemon service after this
        /// command (also settable via `FILETHING_NO_AUTO_DAEMON`).
        #[arg(long)]
        no_daemon: bool,
    },

    /// Run the foreground Daemon over one or more Space folders until Ctrl-C.
    /// With no folders, syncs every Space mapped in `config.json` — this is what
    /// the background service invokes, so a newly mapped Space just needs a
    /// restart to be picked up (`docs/BUILD-PLAN.md §3`, "daemon por defecto").
    Daemon {
        /// The Space folders to sync continuously (defaults to all mapped Spaces).
        dirs: Vec<PathBuf>,
    },

    /// Garbage-collect the account's Vault: delete ORPHANED objects that no
    /// Revision of any of your Spaces references. Dry-run by default (prints what
    /// WOULD be deleted); pass --apply to delete. Selecting a Space `dir` only
    /// picks the account/Vault — the sweep is account-wide. OPERATOR-ONLY: it needs
    /// direct `S3_*` storage credentials (a sweep has to list and delete, which
    /// presigned URLs cannot do), so on the managed data plane it fails instead of
    /// pretending to have collected anything.
    Gc {
        /// A Space folder (selects the account whose Vault to GC).
        dir: PathBuf,
        /// Actually delete swept objects (default is a dry run).
        #[arg(long)]
        apply: bool,
        /// Never sweep an object younger than this many seconds (default 86400).
        #[arg(long)]
        grace_secs: Option<u64>,
    },

    /// Show sync metrics (commits, pulls, conflicts, feed errors, staleness) for a
    /// Space, or for every mapped Space when no dir is given.
    Metrics {
        /// The Space folder (defaults to all mapped Spaces).
        dir: Option<PathBuf>,
        /// Emit the raw values as JSON (durations in whole seconds), stable for
        /// monitoring, instead of the humanized text report.
        #[arg(long)]
        json: bool,
    },

    /// Install / uninstall / status the daemon as an OS service (launchd on macOS,
    /// systemd --user on Linux).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Update filething itself to the latest release (GitHub Releases). Requires
    /// an install made by the official installer; restarts the daemon service
    /// afterwards so it runs the new binary.
    Update,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 needs ONE process-level CryptoProvider, and this binary links
    // two candidates (reqwest brings `ring`, the convex websocket stack brings
    // `aws-lc-rs`), so auto-detection panics inside the first TLS handshake —
    // on a tokio worker thread, which dies silently and leaves the websocket
    // mutation waiting forever. Pin `ring` explicitly before any TLS happens.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls CryptoProvider was already installed"))?;

    // Parse before initializing logging: the daemon subcommand logs to a rotating
    // FILE (it can run for weeks under launchd, which otherwise appends its stderr
    // to one unbounded daemon.log — GitHub #22), while every one-shot command
    // keeps logging to stderr. TLS is not touched by parsing, so this stays after
    // the CryptoProvider install and before any network work.
    let cli = Cli::parse();
    init_tracing(&cli.command, cli.verbose);

    // The verbose signal for error rendering: the `-v` flag OR an explicit log
    // filter asking for debug/trace. A plain `RUST_LOG=error` must NOT flip us
    // verbose — that user asked for LESS noise, not more (issue #11/#16).
    let verbose_errors = cli.verbose
        || log_env()
            .map(|v| {
                let v = v.to_ascii_lowercase();
                v.contains("debug") || v.contains("trace")
            })
            .unwrap_or(false);

    let verbose = cli.verbose;
    let result = match cli.command {
        Command::Login {
            email,
            signup,
            name,
        } => commands::login(email, signup, name).await,
        Command::Whoami => commands::whoami(),
        Command::Spaces => commands::spaces().await,
        Command::Init {
            dir,
            name,
            no_daemon,
        } => commands::init(dir, name, no_daemon).await,
        Command::Clone {
            space_id,
            dir,
            name,
            no_daemon,
        } => commands::clone(space_id, dir, name, no_daemon).await,
        Command::Unmap { dir } => commands::unmap(dir),
        Command::Status { dir } => commands::status(dir, verbose).await,
        Command::Ls { dir } => commands::ls(dir),
        Command::Sync { dir, no_daemon } => commands::sync(dir, no_daemon).await,
        Command::Daemon { dirs } => commands::daemon(dirs).await,
        Command::Gc {
            dir,
            apply,
            grace_secs,
        } => commands::gc(dir, apply, grace_secs).await,
        Command::Metrics { dir, json } => commands::metrics(dir, json),
        Command::Service { action } => commands::service(action),
        Command::Update => commands::update().await,
    };

    // Render a failure ourselves so a typed Coordinator error becomes a human
    // message + next step (issue #11) instead of anyhow's raw Debug chain. The
    // raw detail (and the Convex Request ID) is shown only when verbose (the
    // `-v` flag or an explicit log filter at debug/trace). We still exit non-zero
    // so scripts and the integration gates see the failure.
    if let Err(err) = result {
        // Close any open one-shot progress line so the error does not land on
        // the same terminal row (issue #16).
        progress::finish();
        errors::report(&err, verbose_errors);
        std::process::exit(exit_code(&err));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------
//
// A CLI is an API for scripts, and "every failure is 1" forces a caller to grep
// human prose to tell "not logged in" from "the network is down" from "someone
// else already holds this Space". These are the codes; treat them as a contract:
//
//   0  success
//   1  generic failure (anything not classified below — the safe default)
//   2  usage error (clap's own code for a bad command line; never returned here)
//   3  not authenticated — log in and retry
//   4  the Coordinator or its Vault could not be reached — transient, retryable
//   5  the Space head moved under us (a commit CAS conflict) — sync and retry
//   6  a safety guard REFUSED a destructive operation — needs a human decision
//   7  another process holds this Space's lock — wait for it, or stop it
//
// New codes may be added; existing ones keep their meaning.

/// Generic failure. Also the fallback for anything unclassified, so adding a
/// classification can only ever narrow an existing 1 — never break a caller.
const EXIT_FAILURE: i32 = 1;
/// Not authenticated (no session, or the Coordinator rejected it).
const EXIT_NOT_AUTHENTICATED: i32 = 3;
/// The Coordinator (or its Vault) is unreachable/unavailable: retryable.
const EXIT_UNAVAILABLE: i32 = 4;
/// The Space head moved while we worked (commit CAS conflict).
const EXIT_CONFLICT: i32 = 5;
/// A safety guard declined a destructive operation.
const EXIT_REFUSED: i32 = 6;
/// Another filething process holds this Space's lock.
const EXIT_SPACE_LOCKED: i32 = 7;

/// Classifies a failure into one of the documented exit codes.
///
/// Typed errors first — that is the part that cannot rot. The one text match is
/// for the CLI's own "not logged in" preconditions, which are plain `anyhow!`
/// messages in `commands.rs`; it is a narrow, exact-sentence match, and a reworded
/// message degrades to [`EXIT_FAILURE`] rather than misclassifying.
fn exit_code(err: &anyhow::Error) -> i32 {
    use ft_coordinator::CoordinatorError as CE;

    if let Some(ce) = errors::find_coordinator_error(err) {
        return match ce {
            CE::NotAuthenticated { .. } => EXIT_NOT_AUTHENTICATED,
            CE::Transport(..) | CE::VaultUnavailable { .. } => EXIT_UNAVAILABLE,
            CE::Conflict { .. } => EXIT_CONFLICT,
            _ => EXIT_FAILURE,
        };
    }
    if let Some(engine) = err
        .chain()
        .find_map(|c| c.downcast_ref::<ft_engine::EngineError>())
    {
        return match engine {
            ft_engine::EngineError::Refused(..) => EXIT_REFUSED,
            ft_engine::EngineError::SpaceLocked { .. } => EXIT_SPACE_LOCKED,
            _ => EXIT_FAILURE,
        };
    }
    if err
        .chain()
        .any(|c| c.downcast_ref::<env::CoordinatorUnreachable>().is_some())
    {
        return EXIT_UNAVAILABLE;
    }
    // `require_identity` / `require_credentials` in `commands.rs`.
    if err
        .chain()
        .any(|c| c.to_string().contains("run `filething login` first"))
    {
        return EXIT_NOT_AUTHENTICATED;
    }
    EXIT_FAILURE
}

/// The env var that requests a log level for THIS project's crates. Preferred over
/// `RUST_LOG` because it cannot be mistaken for a request to make the whole
/// dependency tree verbose.
const ENV_LOG: &str = "FILETHING_LOG";

/// The explicit log-filter request for this run, if any: `RUST_LOG` (kept for
/// habit and for the crates.io convention), else [`ENV_LOG`]. An empty value is
/// treated as unset.
fn log_env() -> Option<String> {
    ["RUST_LOG", ENV_LOG]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// The base log filter for this run — see [`log_filter`], which caps it.
///
/// - An explicit `RUST_LOG` / `FILETHING_LOG` wins (verbatim, so
///   `FILETHING_LOG=ft_engine=trace` works), for both the daemon and one-shot
///   commands.
/// - Otherwise the daemon keeps `info` (it can run for weeks; its log is its
///   observability), and `-v/--verbose` restores `info` for one-shot commands too.
/// - Otherwise a one-shot command defaults to `warn`, so the internal machinery
///   (`convex::*` "Starting action…", per-batch upload INFO) stops drowning the
///   command's own output (issue #16). The command's result is `println!` to
///   stdout and is unaffected; progress is rendered separately (see `progress`).
///
/// One-shot commands additionally silence `convex` entirely at that default level:
/// its websocket worker logs one raw ERROR per reconnect backoff
/// ("Convex WebSocketWorker failed: … Backing off for 15s"), which is noise next to
/// the single actionable message `crate::env` now produces for an unreachable
/// Coordinator. `-v` and an explicit filter bring it back.
fn env_filter(command: &Command, verbose: bool) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    if let Some(directives) = log_env() {
        return EnvFilter::try_new(&directives).unwrap_or_else(|_| EnvFilter::new("info"));
    }
    EnvFilter::new(default_directives(command, verbose))
}

/// The directives [`env_filter`] falls back to with no explicit request.
fn default_directives(command: &Command, verbose: bool) -> &'static str {
    if matches!(command, Command::Daemon { .. }) || verbose {
        "info"
    } else {
        "warn,convex=off"
    }
}

/// The filter the fmt layer actually runs, built from three parts:
///
/// 1. [`env_filter`] — what the user asked for;
/// 2. OR the engine's progress events, when a one-shot command is writing to
///    something that is not a terminal (see [`is_progress_event`]);
/// 3. AND a HARD cap on third-party targets (see [`third_party_cap_allows`]).
///
/// Part 3 is a security control, not a preference, which is why it is an `and` the
/// user cannot override: `RUST_LOG=debug` used to reach `convex`'s websocket
/// writer, which logs every outgoing message — and those messages carry the Account
/// escrow `dedupSecret` (`auth:ensureDevice`), a Space's `spaceKey`
/// (`spaces:create`) and the Convex JWT in CLEARTEXT. The CLI itself used to tell
/// users to re-run with `RUST_LOG=debug` for detail, so following that hint,
/// redirecting to a file and pasting it into a bug report published both halves of
/// the user's Space key material.
fn log_filter<S: 'static>(
    command: &Command,
    verbose: bool,
    plain_progress: bool,
) -> impl tracing_subscriber::layer::Filter<S> + 'static {
    use tracing_subscriber::filter::{filter_fn, FilterExt as _};
    env_filter(command, verbose)
        .or(filter_fn(move |meta: &tracing::Metadata<'_>| {
            plain_progress && is_progress_event(meta)
        }))
        .and(filter_fn(|meta: &tracing::Metadata<'_>| {
            third_party_cap_allows(meta.target(), *meta.level())
        }))
}

/// Whether a tracing event's `target` belongs to THIS project (the binary or one of
/// the `ft-*` crates, whose module paths tracing renders with underscores).
fn is_project_target(target: &str) -> bool {
    target == "filething" || target.starts_with("filething::") || target.starts_with("ft_")
}

/// The hard third-party cap: our own crates honor whatever level was requested,
/// everything else is capped at `info`.
///
/// Deny-by-default (rather than a list of `convex`/`tungstenite`/`reqwest`) because
/// the dangerous set is "every dependency that logs what it is about to send", and
/// that set grows: `convex` prints the outgoing `Authenticate`/`Mutation` frames at
/// debug, and the S3/HTTP stacks print signed URLs and auth headers. `info` and
/// above stay, so a genuinely useful third-party error is never hidden.
fn third_party_cap_allows(target: &str, level: tracing::Level) -> bool {
    is_project_target(target) || level <= tracing::Level::INFO
}

/// Whether this is one of the engine's progress events — an INFO event from
/// `ft_engine`/`ft_diff` carrying a `total` field (see `progress`).
///
/// Used to keep a NON-TTY one-shot run from printing nothing at all for minutes:
/// the rewriting single-line renderer needs a terminal, so `filething sync > log
/// 2>&1` (or CI) used to show total silence during a long transfer. Letting these
/// events through the fmt layer turns them into ordinary, already-throttled plain
/// text lines. The TTY path is untouched.
fn is_progress_event(meta: &tracing::Metadata<'_>) -> bool {
    is_progress_target(meta.target())
        && *meta.level() == tracing::Level::INFO
        && meta.fields().field("total").is_some()
}

/// Initialize tracing for this invocation.
///
/// The fmt layer honors [`env_filter`] (per-layer, so it can suppress INFO
/// without hiding it from the progress layer below). One-shot commands (and the
/// Linux daemon under systemd, which journald rotates) log to stderr. The daemon
/// logs to a size-rotated FILE it owns whenever it would otherwise be at the
/// mercy of launchd's unbounded stderr redirect: on macOS, or when
/// `FILETHING_LOG_TO_FILE` is set non-empty (a manual opt-in on any OS). If that
/// file can't be opened we warn and fall back to stderr — the daemon must still
/// run. When stderr is a terminal (a foreground `filething daemon`) we tee to
/// both so it stays visible while the file always receives the log.
///
/// On top of the fmt layer, one-shot `init`/`clone`/`sync` runs get the compact
/// [`progress`] layer — a single rewriting stderr line instead of per-batch INFO
/// logs (issue #16) — but only on a TTY, when not verbose, and with no explicit
/// `RUST_LOG` (where the user wants the raw logs, or nothing, instead).
fn init_tracing(command: &Command, verbose: bool) {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::Layer as _;

    let log_to_file = matches!(command, Command::Daemon { .. })
        && (cfg!(target_os = "macos")
            || std::env::var("FILETHING_LOG_TO_FILE")
                .map(|v| !v.is_empty())
                .unwrap_or(false));

    if log_to_file {
        match daemon_file_writer() {
            Ok(writer) => {
                // The daemon already logs at `info`, so its own progress events
                // reach the file without the non-TTY fallback.
                let filter = log_filter(command, verbose, false);
                // Foreground run (tty): tee to the file AND stderr so the file is
                // always written yet the operator still sees the log live.
                if std::io::stderr().is_terminal() {
                    use tracing_subscriber::fmt::writer::MakeWriterExt as _;
                    let fmt = tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(writer.and(std::io::stderr))
                        .with_filter(filter);
                    tracing_subscriber::registry().with(fmt).init();
                } else {
                    let fmt = tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(writer)
                        .with_filter(filter);
                    tracing_subscriber::registry().with(fmt).init();
                }
                return;
            }
            Err(e) => {
                eprintln!(
                    "filething: could not open the rotating daemon log ({e}); logging to stderr"
                );
            }
        }
    }

    // A one-shot command with no explicit log request renders progress ONE of two
    // ways: the rewriting single line when stderr is a terminal, or plain periodic
    // log lines when it is not (a file, a pipe, CI) — where the rewriting line
    // would be `\r` soup and its absence was minutes of total silence.
    let one_shot_default =
        !matches!(command, Command::Daemon { .. }) && !verbose && log_env().is_none();
    let show_progress = one_shot_default && std::io::stderr().is_terminal();
    let plain_progress = one_shot_default && !std::io::stderr().is_terminal();

    // The progress layer sees the engine's progress events regardless of the fmt
    // layer's (possibly WARN) filter, because per-layer filters are independent —
    // that is exactly what lets us hide the raw INFO logs yet still draw the
    // progress line.
    let progress_layer = show_progress.then(|| {
        progress::ProgressLayer.with_filter(tracing_subscriber::filter::filter_fn(
            |meta: &tracing::Metadata<'_>| is_progress_target(meta.target()),
        ))
    });

    let fmt = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(log_filter(command, verbose, plain_progress));

    tracing_subscriber::registry()
        .with(fmt)
        .with(progress_layer)
        .init();
}

/// Whether a tracing event's `target` (its originating crate/module path) is one
/// the compact [`progress`] layer should see. The progress events live in TWO
/// crates: `ft-engine` emits the commit/reconcile phases and the fast-forward
/// start/finish markers, while `ft-diff` emits the intermediate "applying changes"
/// ticks that advance the line during a clone/fast-forward (the engine only frames
/// that phase, it does not tick it — issue #15). Anything else (`convex::*`,
/// `reqwest`, …) stays out so the line is not disturbed by unrelated INFO.
fn is_progress_target(target: &str) -> bool {
    target.starts_with("ft_engine") || target.starts_with("ft_diff")
}

/// Build the daemon's rotating log writer at `<config_dir>/daemon.log`
/// (5 MB per file, 3 generations). Creates the config dir (`0700`) if needed.
///
/// The log file itself is created/kept `0600`: a daemon log records Space paths and
/// filenames, and any third-party debug line that ever slips past the cap in
/// [`log_filter`] would land here, so it is not something other accounts on the
/// machine should be able to read.
fn daemon_file_writer() -> std::io::Result<logrotate::SharedRotatingWriter> {
    const MAX_BYTES: u64 = 5 * 1024 * 1024;
    const KEEP: usize = 3;
    let path = config::Config::config_dir().join(service::LOG_FILE);
    if let Some(parent) = path.parent() {
        config::ensure_private_dir(parent).map_err(std::io::Error::other)?;
    }
    #[cfg(unix)]
    {
        // Create it 0600 BEFORE the rotating writer opens it, so it is never even
        // briefly world-readable; re-assert the mode for a log an older build left
        // at 0644.
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let writer = logrotate::RotatingFileWriter::new(path, MAX_BYTES, KEEP)?;
    Ok(logrotate::SharedRotatingWriter::new(writer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// clap's own invariant check: the derived command tree is internally valid.
    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// The progress-layer filter admits BOTH engine crates — including `ft_diff`,
    /// whose "applying changes" ticks are the only ones that advance the line on a
    /// clone/fast-forward (issue #15) — and rejects unrelated targets so foreign
    /// INFO never disturbs the line. Guards against the regression where the
    /// filter matched `ft_engine` only and the clone line stayed frozen.
    #[test]
    fn progress_filter_admits_both_engine_crates() {
        assert!(is_progress_target("ft_engine"));
        assert!(is_progress_target("ft_engine::pull"));
        assert!(is_progress_target("ft_diff"));
        assert!(is_progress_target("ft_diff::lib"));
        assert!(!is_progress_target("convex::client"));
        assert!(!is_progress_target("reqwest"));
        assert!(!is_progress_target("ft_core"));
    }

    /// `login --email` parses to a log-in (no signup, no device name).
    #[test]
    fn parse_login_email_only() {
        let cli = Cli::parse_from(["filething", "login", "--email", "a@b.com"]);
        match cli.command {
            Command::Login {
                email,
                signup,
                name,
            } => {
                assert_eq!(email, "a@b.com");
                assert!(!signup);
                assert!(name.is_none());
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    /// `login --email X --signup --name Y` parses all three.
    #[test]
    fn parse_login_signup_with_name() {
        let cli = Cli::parse_from([
            "filething",
            "login",
            "--email",
            "a@b.com",
            "--signup",
            "--name",
            "laptop",
        ]);
        match cli.command {
            Command::Login {
                email,
                signup,
                name,
            } => {
                assert_eq!(email, "a@b.com");
                assert!(signup);
                assert_eq!(name.as_deref(), Some("laptop"));
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    /// `login` with no `--email` is a parse error (email is required).
    #[test]
    fn login_requires_email() {
        assert!(Cli::try_parse_from(["filething", "login"]).is_err());
    }

    /// `init <dir> --name` parses the positional dir and the name flag; `--no-daemon`
    /// defaults to false.
    #[test]
    fn parse_init_dir_and_name() {
        let cli = Cli::parse_from(["filething", "init", "/home/u/proj", "--name", "proj"]);
        match cli.command {
            Command::Init {
                dir,
                name,
                no_daemon,
            } => {
                assert_eq!(dir, PathBuf::from("/home/u/proj"));
                assert_eq!(name.as_deref(), Some("proj"));
                assert!(!no_daemon);
            }
            other => panic!("expected Init, got {other:?}"),
        }
    }

    /// `clone <space_id> <dir>` parses both positionals in order.
    #[test]
    fn parse_clone_space_and_dir() {
        let cli = Cli::parse_from(["filething", "clone", "sp_123", "/home/u/clone"]);
        match cli.command {
            Command::Clone {
                space_id,
                dir,
                name,
                no_daemon,
            } => {
                assert_eq!(space_id, "sp_123");
                assert_eq!(dir, PathBuf::from("/home/u/clone"));
                assert!(name.is_none());
                assert!(!no_daemon);
            }
            other => panic!("expected Clone, got {other:?}"),
        }
    }

    /// `--no-daemon` parses on `init`, `clone`, and `sync`.
    #[test]
    fn parse_no_daemon_flag() {
        match Cli::parse_from(["filething", "init", "/p", "--no-daemon"]).command {
            Command::Init { no_daemon, .. } => assert!(no_daemon),
            other => panic!("expected Init, got {other:?}"),
        }
        match Cli::parse_from(["filething", "clone", "sp_1", "/p", "--no-daemon"]).command {
            Command::Clone { no_daemon, .. } => assert!(no_daemon),
            other => panic!("expected Clone, got {other:?}"),
        }
        match Cli::parse_from(["filething", "sync", "/p", "--no-daemon"]).command {
            Command::Sync { no_daemon, .. } => assert!(no_daemon),
            other => panic!("expected Sync, got {other:?}"),
        }
    }

    /// `status` / `ls` accept an optional dir (absent -> None = cwd).
    #[test]
    fn parse_status_and_ls_optional_dir() {
        match Cli::parse_from(["filething", "status"]).command {
            Command::Status { dir } => assert!(dir.is_none()),
            other => panic!("expected Status, got {other:?}"),
        }
        match Cli::parse_from(["filething", "ls", "/some/dir"]).command {
            Command::Ls { dir } => assert_eq!(dir, Some(PathBuf::from("/some/dir"))),
            other => panic!("expected Ls, got {other:?}"),
        }
    }

    /// `daemon` requires at least one dir and collects several.
    #[test]
    fn parse_daemon_multiple_dirs() {
        let cli = Cli::parse_from(["filething", "daemon", "/a", "/b", "/c"]);
        match cli.command {
            Command::Daemon { dirs } => {
                assert_eq!(
                    dirs,
                    vec![
                        PathBuf::from("/a"),
                        PathBuf::from("/b"),
                        PathBuf::from("/c")
                    ]
                );
            }
            other => panic!("expected Daemon, got {other:?}"),
        }
    }

    /// `daemon` with no dir is valid (defaults to every mapped Space at runtime).
    #[test]
    fn parse_daemon_no_dirs_is_valid() {
        match Cli::parse_from(["filething", "daemon"]).command {
            Command::Daemon { dirs } => assert!(dirs.is_empty()),
            other => panic!("expected Daemon, got {other:?}"),
        }
    }

    /// `gc <dir>` defaults to a dry run; flags flip apply/grace.
    #[test]
    fn parse_gc_defaults_and_flags() {
        match Cli::parse_from(["filething", "gc", "/proj"]).command {
            Command::Gc {
                dir,
                apply,
                grace_secs,
            } => {
                assert_eq!(dir, PathBuf::from("/proj"));
                assert!(!apply);
                assert!(grace_secs.is_none());
            }
            other => panic!("expected Gc, got {other:?}"),
        }
        match Cli::parse_from(["filething", "gc", "/proj", "--apply", "--grace-secs", "0"]).command
        {
            Command::Gc {
                apply, grace_secs, ..
            } => {
                assert!(apply);
                assert_eq!(grace_secs, Some(0));
            }
            other => panic!("expected Gc, got {other:?}"),
        }
    }

    /// `-v/--verbose` is a global flag: it parses both before and after the
    /// subcommand, and defaults to false.
    #[test]
    fn parse_global_verbose_flag() {
        assert!(!Cli::parse_from(["filething", "status"]).verbose);
        assert!(Cli::parse_from(["filething", "-v", "status"]).verbose);
        assert!(Cli::parse_from(["filething", "status", "--verbose"]).verbose);
    }

    /// `metrics` accepts an optional dir; `service <action>` parses the nested
    /// subcommand.
    #[test]
    fn parse_metrics_and_service() {
        match Cli::parse_from(["filething", "metrics"]).command {
            Command::Metrics { dir, json } => {
                assert!(dir.is_none());
                assert!(!json);
            }
            other => panic!("expected Metrics, got {other:?}"),
        }
        // `--json` parses (and works before the positional dir too).
        match Cli::parse_from(["filething", "metrics", "--json"]).command {
            Command::Metrics { dir, json } => {
                assert!(dir.is_none());
                assert!(json);
            }
            other => panic!("expected Metrics, got {other:?}"),
        }
        match Cli::parse_from(["filething", "service", "install"]).command {
            Command::Service { action } => assert_eq!(action, ServiceAction::Install),
            other => panic!("expected Service, got {other:?}"),
        }
        // `service` with no action is a parse error.
        assert!(Cli::try_parse_from(["filething", "service"]).is_err());
    }

    /// `whoami` / `spaces` take no arguments; `unmap` requires a dir.
    #[test]
    fn parse_whoami_spaces_and_unmap() {
        assert!(matches!(
            Cli::parse_from(["filething", "whoami"]).command,
            Command::Whoami
        ));
        assert!(matches!(
            Cli::parse_from(["filething", "spaces"]).command,
            Command::Spaces
        ));
        match Cli::parse_from(["filething", "unmap", "/home/u/proj"]).command {
            Command::Unmap { dir } => assert_eq!(dir, PathBuf::from("/home/u/proj")),
            other => panic!("expected Unmap, got {other:?}"),
        }
        // `unmap` with no dir is a parse error (the dir is required).
        assert!(Cli::try_parse_from(["filething", "unmap"]).is_err());
    }

    // ----- the third-party log cap -----

    /// REGRESSION (the CLI used to tell users to leak their own keys): `RUST_LOG` was
    /// passed through verbatim as a GLOBAL filter, so `RUST_LOG=debug` also enabled
    /// debug for `convex`, whose websocket writer logs every outgoing message —
    /// including the Account escrow `dedupSecret`, a Space's `spaceKey` and the
    /// Convex JWT in cleartext. No requested level may re-enable that.
    #[test]
    fn third_party_debug_is_never_allowed_however_loud_the_request() {
        for target in [
            "convex",
            "convex::sync::web_socket_manager",
            "convex::base_client",
            "tungstenite::protocol",
            "reqwest::connect",
            "hyper_util::client",
            "aws_sdk_s3::operation",
            "rustls::client::hs",
        ] {
            assert!(
                !third_party_cap_allows(target, tracing::Level::DEBUG),
                "{target} must not be allowed to log at debug"
            );
            assert!(
                !third_party_cap_allows(target, tracing::Level::TRACE),
                "{target} must not be allowed to log at trace"
            );
            // Its errors/warnings/info stay: capping must not hide real failures.
            for level in [
                tracing::Level::INFO,
                tracing::Level::WARN,
                tracing::Level::ERROR,
            ] {
                assert!(
                    third_party_cap_allows(target, level),
                    "{target} must still log at {level}"
                );
            }
        }
    }

    /// The cap applies to third parties only: our own crates still honor a debug or
    /// trace request, which is the whole point of asking for one.
    #[test]
    fn project_targets_still_honor_a_debug_request() {
        for target in [
            "filething",
            "filething::commands",
            "ft_engine::commit",
            "ft_diff",
            "ft_core",
            "ft_vault::s3",
        ] {
            assert!(is_project_target(target), "{target} should be ours");
            assert!(third_party_cap_allows(target, tracing::Level::TRACE));
        }
        // A crate that merely starts with our prefix letters is NOT ours.
        assert!(!is_project_target("filethingy"));
        assert!(!is_project_target("convex"));
    }

    /// With the Coordinator down, the ONLY thing a one-shot command used to print
    /// was `convex`'s internal worker ERROR, once per backoff, forever. The default
    /// filter must keep that out so `crate::env`'s single actionable message is the
    /// whole output — while `-v` and the daemon still get it.
    #[test]
    fn the_one_shot_default_silences_the_convex_worker_but_v_and_the_daemon_do_not() {
        let sync = Command::Sync {
            dir: PathBuf::from("/p"),
            no_daemon: false,
        };
        assert!(default_directives(&sync, false).contains("convex=off"));
        assert!(!default_directives(&sync, true).contains("convex=off"));
        assert!(
            !default_directives(&Command::Daemon { dirs: vec![] }, false).contains("convex=off")
        );
    }

    // ----- non-TTY progress -----

    /// A stand-in callsite, so a test can build the [`tracing::Metadata`] the
    /// filters see without installing a subscriber (which would poison tracing's
    /// process-global callsite interest cache for the other tests).
    struct TestCallsite;

    impl tracing::Callsite for TestCallsite {
        fn set_interest(&self, _: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            unreachable!("only the FieldSet identity is used")
        }
    }

    static TEST_CALLSITE: TestCallsite = TestCallsite;

    fn meta(
        target: &'static str,
        level: tracing::Level,
        fields: &'static [&'static str],
    ) -> tracing::Metadata<'static> {
        tracing::Metadata::new(
            "event",
            target,
            level,
            None,
            None,
            None,
            tracing::field::FieldSet::new(fields, tracing::callsite::Identifier(&TEST_CALLSITE)),
            tracing::metadata::Kind::EVENT,
        )
    }

    /// A long transfer printed NOTHING when stderr was not a terminal (the
    /// rewriting line needs one), so `filething sync > log 2>&1` and CI logs showed
    /// minutes of silence. The engine's already-throttled progress events are what
    /// fills that gap, and nothing else may sneak through with them.
    #[test]
    fn plain_progress_admits_the_engines_progress_events_and_nothing_else() {
        // The real callsites: `tracing::info!(total, "uploading blocks")` in
        // ft-engine and `tracing::info!(completed = n, total, "applying changes")`
        // in ft-diff.
        assert!(is_progress_event(&meta(
            "ft_engine::commit",
            tracing::Level::INFO,
            &["message", "total"]
        )));
        assert!(is_progress_event(&meta(
            "ft_diff",
            tracing::Level::INFO,
            &["message", "completed", "total"]
        )));
        // Not a progress event: no `total` field, the wrong level, a foreign crate.
        assert!(!is_progress_event(&meta(
            "ft_engine::commit",
            tracing::Level::INFO,
            &["message"]
        )));
        assert!(!is_progress_event(&meta(
            "ft_engine::commit",
            tracing::Level::DEBUG,
            &["message", "total"]
        )));
        assert!(!is_progress_event(&meta(
            "convex::base_client",
            tracing::Level::INFO,
            &["message", "total"]
        )));
    }

    // ----- exit codes -----

    /// A caller has to be able to tell the failure modes apart; before this, every
    /// failure was 1. Each documented code is reachable, and 1 stays the fallback so
    /// no existing caller regresses.
    #[test]
    fn exit_codes_classify_the_documented_failure_modes() {
        use ft_coordinator::CoordinatorError as CE;

        let cases: [(anyhow::Error, i32); 7] = [
            (
                anyhow::Error::new(CE::NotAuthenticated {
                    message: "x".into(),
                })
                .context("spaces:listMine"),
                EXIT_NOT_AUTHENTICATED,
            ),
            (
                anyhow::Error::new(CE::Transport("socket closed".into())),
                EXIT_UNAVAILABLE,
            ),
            (
                anyhow::Error::new(env::CoordinatorUnreachable {
                    url: "http://localhost:3210".into(),
                })
                .context("connecting"),
                EXIT_UNAVAILABLE,
            ),
            (
                anyhow::Error::new(CE::Conflict {
                    message: "head moved".into(),
                }),
                EXIT_CONFLICT,
            ),
            (
                anyhow::Error::new(ft_engine::EngineError::Refused("no roots".into()))
                    .context("gc"),
                EXIT_REFUSED,
            ),
            (
                anyhow::Error::new(ft_engine::EngineError::SpaceLocked {
                    root: "/p".into(),
                    holder: "pid 1".into(),
                }),
                EXIT_SPACE_LOCKED,
            ),
            (anyhow::anyhow!("something else broke"), EXIT_FAILURE),
        ];
        for (err, want) in cases {
            assert_eq!(exit_code(&err), want, "for {err:?}");
        }
    }

    /// The CLI's own "not logged in" preconditions are plain `anyhow!` messages in
    /// `commands.rs`; this pins the exact sentence the classification matches, and
    /// documents that a reworded message degrades to 1 rather than misclassifying.
    #[test]
    fn not_logged_in_precondition_maps_to_the_auth_exit_code() {
        let err = anyhow::anyhow!("not logged in yet — run `filething login` first");
        assert_eq!(exit_code(&err), EXIT_NOT_AUTHENTICATED);
        let err = anyhow::anyhow!("no Device credentials found — run `filething login` first")
            .context("sync");
        assert_eq!(exit_code(&err), EXIT_NOT_AUTHENTICATED);
        // A merely login-adjacent message is not the same claim.
        let err = anyhow::anyhow!("your password expired; visit the dashboard");
        assert_eq!(exit_code(&err), EXIT_FAILURE);
    }

    /// Every documented code must be distinct, and none may collide with clap's
    /// usage exit code (2) — a caller distinguishing "bad command line" from a
    /// runtime failure relies on that.
    #[test]
    fn exit_codes_are_distinct_and_avoid_claps_usage_code() {
        let codes = [
            EXIT_FAILURE,
            EXIT_NOT_AUTHENTICATED,
            EXIT_UNAVAILABLE,
            EXIT_CONFLICT,
            EXIT_REFUSED,
            EXIT_SPACE_LOCKED,
        ];
        for (i, a) in codes.iter().enumerate() {
            assert_ne!(*a, 2, "2 belongs to clap's usage errors");
            assert_ne!(*a, 0, "0 means success");
            for b in &codes[i + 1..] {
                assert_ne!(a, b, "duplicate exit code {a}");
            }
        }
    }

    // ----- help text that matches the code -----

    /// `sync --help` used to claim it "does not run the daemon" while the command
    /// INSTALLS and starts an OS service by default. Help text that lies is worse
    /// than none: this pins the corrected claim.
    #[test]
    fn sync_help_does_not_claim_it_leaves_the_daemon_alone() {
        let sync = Cli::command()
            .get_subcommands()
            .find(|c| c.get_name() == "sync")
            .expect("sync subcommand")
            .clone();
        let help = sync
            .get_about()
            .map(|a| a.to_string())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            !help.contains("does not run the daemon"),
            "sync installs and starts the daemon service by default: {help}"
        );
        assert!(
            help.contains("--no-daemon"),
            "sync's help must point at the opt-out: {help}"
        );
    }

    /// `update` takes no arguments; extras are a parse error.
    #[test]
    fn parse_update() {
        match Cli::parse_from(["filething", "update"]).command {
            Command::Update => {}
            other => panic!("expected Update, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["filething", "update", "extra"]).is_err());
    }
}
