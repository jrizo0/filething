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
mod service;
mod signed_vault;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::service::ServiceAction;

/// filething — keep your developer folders identical across machines.
#[derive(Debug, Parser)]
#[command(name = "filething", version, about, long_about = None)]
struct Cli {
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

    /// Show a Space's synced base and whether it has uncommitted local changes.
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

    // Logs: default to info, override with RUST_LOG. Written to stderr so command
    // output on stdout stays clean for scripting.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Login {
            email,
            signup,
            name,
        } => commands::login(email, signup, name).await,
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
        Command::Status { dir } => commands::status(dir).await,
        Command::Ls { dir } => commands::ls(dir),
        Command::Sync { dir, no_daemon } => commands::sync(dir, no_daemon).await,
        Command::Daemon { dirs } => commands::daemon(dirs).await,
        Command::Gc {
            dir,
            apply,
            grace_secs,
        } => commands::gc(dir, apply, grace_secs).await,
        Command::Metrics { dir } => commands::metrics(dir),
        Command::Service { action } => commands::service(action),
    }
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

    /// `metrics` accepts an optional dir; `service <action>` parses the nested
    /// subcommand.
    #[test]
    fn parse_metrics_and_service() {
        match Cli::parse_from(["filething", "metrics"]).command {
            Command::Metrics { dir } => assert!(dir.is_none()),
            other => panic!("expected Metrics, got {other:?}"),
        }
        match Cli::parse_from(["filething", "service", "install"]).command {
            Command::Service { action } => assert_eq!(action, ServiceAction::Install),
            other => panic!("expected Service, got {other:?}"),
        }
        // `service` with no action is a parse error.
        assert!(Cli::try_parse_from(["filething", "service"]).is_err());
    }
}
