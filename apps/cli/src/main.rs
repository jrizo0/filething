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
    /// Show the internal debug logging that one-shot commands hide by default
    /// (equivalent to `RUST_LOG=info`) and the full technical detail of an error.
    /// An explicit `RUST_LOG` always takes precedence over this flag.
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

    /// Make a local folder a new Space and commit its first Revision.
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

    /// Materialize an existing Space into a local folder.
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
    Status {
        /// The Space folder (defaults to the current directory).
        dir: Option<PathBuf>,
    },

    /// List a Space's synced paths (from the local index).
    Ls {
        /// The Space folder (defaults to the current directory).
        dir: Option<PathBuf>,
    },

    /// One-shot sync: pull the head, then commit local changes. Does not run the
    /// daemon — handy for scripts and the integration gates.
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
    /// picks the account/Vault — the sweep is account-wide.
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

    // The verbose signal for error rendering: the `-v` flag OR an explicit
    // `RUST_LOG` at debug/trace. A plain `RUST_LOG=error` must NOT flip us
    // verbose — that user asked for LESS noise, not more (issue #11/#16).
    let verbose_errors = cli.verbose
        || std::env::var("RUST_LOG")
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
    };

    // Render a failure ourselves so a typed Coordinator error becomes a human
    // message + next step (issue #11) instead of anyhow's raw Debug chain. The
    // raw detail (and the Convex Request ID) is shown only when verbose (the
    // `-v` flag or RUST_LOG at debug/trace). We still exit non-zero so scripts
    // and the integration gates see the failure.
    if let Err(err) = result {
        // Close any open one-shot progress line so the error does not land on
        // the same terminal row (issue #16).
        progress::finish();
        errors::report(&err, verbose_errors);
        std::process::exit(1);
    }
    Ok(())
}

/// The log filter for this run.
///
/// - An explicit `RUST_LOG` ALWAYS wins (verbatim), for both the daemon and
///   one-shot commands.
/// - Otherwise the daemon keeps `info` (it can run for weeks; its log is its
///   observability), and `-v/--verbose` restores `info` for one-shot commands
///   too — the full internal tracing (`convex::*`, `ft_*`).
/// - Otherwise a one-shot command defaults to `warn`, so the internal machinery
///   (`convex::*` "Starting action…", per-batch upload INFO) stops drowning the
///   command's own output (issue #16). The command's result is `println!` to
///   stdout and is unaffected; progress is rendered separately (see `progress`).
fn env_filter(command: &Command, verbose: bool) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    if std::env::var_os("RUST_LOG").is_some() {
        return EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    }
    if matches!(command, Command::Daemon { .. }) || verbose {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("warn")
    }
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
                let filter = env_filter(command, verbose);
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

    let show_progress = !matches!(command, Command::Daemon { .. })
        && !verbose
        && std::env::var_os("RUST_LOG").is_none()
        && std::io::stderr().is_terminal();

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
        .with_filter(env_filter(command, verbose));

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
/// (5 MB per file, 3 generations). Creates the config dir if needed.
fn daemon_file_writer() -> std::io::Result<logrotate::SharedRotatingWriter> {
    const MAX_BYTES: u64 = 5 * 1024 * 1024;
    const KEEP: usize = 3;
    let path = config::Config::config_dir().join(service::LOG_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
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
}
