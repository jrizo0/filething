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

mod commands;
mod config;
mod env;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// filething — keep your developer folders identical across machines.
#[derive(Debug, Parser)]
#[command(name = "filething", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Pair this Device with the Coordinator. Without --code, bootstrap a new
    /// Account (prints a pairing code); with --code, join an existing Account.
    Login {
        /// Pairing code from another Device's `login` (join an existing Account).
        #[arg(long)]
        code: Option<String>,
        /// A human name for this Device (defaults to the machine hostname).
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
    },

    /// Run the foreground Daemon over one or more Space folders until Ctrl-C.
    Daemon {
        /// The Space folders to sync continuously.
        #[arg(required = true)]
        dirs: Vec<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        Command::Login { code, name } => commands::login(code, name).await,
        Command::Init { dir, name } => commands::init(dir, name).await,
        Command::Clone {
            space_id,
            dir,
            name,
        } => commands::clone(space_id, dir, name).await,
        Command::Status { dir } => commands::status(dir).await,
        Command::Ls { dir } => commands::ls(dir),
        Command::Sync { dir } => commands::sync(dir).await,
        Command::Daemon { dirs } => commands::daemon(dirs).await,
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

    /// `login` with no flags parses to a bootstrap (no code, no name).
    #[test]
    fn parse_login_bootstrap() {
        let cli = Cli::parse_from(["filething", "login"]);
        match cli.command {
            Command::Login { code, name } => {
                assert!(code.is_none());
                assert!(name.is_none());
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    /// `login --code X --name Y` parses both flags.
    #[test]
    fn parse_login_claim_with_code_and_name() {
        let cli = Cli::parse_from([
            "filething",
            "login",
            "--code",
            "ABCD-1234",
            "--name",
            "laptop",
        ]);
        match cli.command {
            Command::Login { code, name } => {
                assert_eq!(code.as_deref(), Some("ABCD-1234"));
                assert_eq!(name.as_deref(), Some("laptop"));
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    /// `init <dir> --name` parses the positional dir and the name flag.
    #[test]
    fn parse_init_dir_and_name() {
        let cli = Cli::parse_from(["filething", "init", "/home/u/proj", "--name", "proj"]);
        match cli.command {
            Command::Init { dir, name } => {
                assert_eq!(dir, PathBuf::from("/home/u/proj"));
                assert_eq!(name.as_deref(), Some("proj"));
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
            } => {
                assert_eq!(space_id, "sp_123");
                assert_eq!(dir, PathBuf::from("/home/u/clone"));
                assert!(name.is_none());
            }
            other => panic!("expected Clone, got {other:?}"),
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

    /// `daemon` with no dir is a parse error (required = true).
    #[test]
    fn daemon_requires_a_dir() {
        let r = Cli::try_parse_from(["filething", "daemon"]);
        assert!(r.is_err(), "daemon with no dir must fail to parse");
    }
}
