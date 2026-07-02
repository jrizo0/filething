//! `service` — install / uninstall / status of the filething daemon as an OS
//! service (`TODO.md` Fase B, "daemon como servicio").
//!
//! macOS → a launchd LaunchAgent (`~/Library/LaunchAgents/com.filething.daemon.plist`).
//! Linux → a systemd **user** unit (`~/.config/systemd/user/filething.service`).
//!
//! Both run `filething daemon <root…>` over every Space mapped in `config.json`,
//! restart on crash, and log to `<config_dir>/daemon.log`. The daemon needs the
//! Convex + `S3_*` credentials in its environment; `install` captures the ones
//! currently set into a 0600 `<config_dir>/service.env` that the service loads
//! (systemd `EnvironmentFile`; launchd via a `/bin/sh` wrapper that sources it),
//! so secrets live in ONE private file, never in the unit/plist or the config.
//!
//! The content generators are pure and unit-tested; the install/uninstall/status
//! entry points shell out to `launchctl` / `systemctl --user` and degrade to
//! printing the manual command if that step fails (so a restricted environment
//! still gets the files written).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context as _};

use crate::config::Config;

/// launchd job label / systemd unit base name.
const LABEL: &str = "com.filething.daemon";
/// The systemd user unit filename.
const SYSTEMD_UNIT: &str = "filething.service";
/// The captured-env filename under the config dir (0600).
const ENV_FILE: &str = "service.env";
/// The daemon log filename under the config dir.
const LOG_FILE: &str = "daemon.log";

/// Environment variables captured into the service env file so the daemon starts
/// with the same credentials the install shell had. Missing ones are skipped.
const CAPTURED_ENV: &[&str] = &[
    "CONVEX_URL",
    "CONVEX_SELF_HOSTED_URL",
    "CONVEX_DEPLOY_KEY",
    "CONVEX_ADMIN_KEY",
    "CONVEX_SELF_HOSTED_ADMIN_KEY",
    "S3_ENDPOINT",
    "S3_REGION",
    "S3_ACCESS_KEY",
    "S3_SECRET_KEY",
    "S3_BUCKET",
    "FILETHING_HOME",
    "XDG_CONFIG_HOME",
    "RUST_LOG",
];

/// Which lifecycle action `filething service` should perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::Subcommand)]
pub enum ServiceAction {
    /// Write the unit/plist + env file and load the service.
    Install,
    /// Unload the service and remove its files (keeps the log).
    Uninstall,
    /// Report whether the service is installed / running.
    Status,
}

/// Entry point for `filething service <action>`.
pub fn run(action: ServiceAction) -> anyhow::Result<()> {
    match action {
        ServiceAction::Install => install(),
        ServiceAction::Uninstall => uninstall(),
        ServiceAction::Status => status(),
    }
}

// ---------------------------------------------------------------------------
// Pure content generators (unit-tested)
// ---------------------------------------------------------------------------

/// Single-quotes a value for a POSIX shell (used in the env file + the launchd
/// wrapper), escaping embedded single quotes as `'\''`.
fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// Escapes text for inclusion in an XML text node (the launchd plist).
fn xml_escape(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The `KEY='value'` body of the service env file. Single-quoted so it is safe
/// both for `. file` under `/bin/sh -c 'set -a; …'` (launchd) and for systemd's
/// `EnvironmentFile` (which accepts quoted values).
fn env_file_body(vars: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in vars {
        s.push_str(k);
        s.push('=');
        s.push_str(&sh_quote(v));
        s.push('\n');
    }
    s
}

/// The launchd plist body. Runs a `/bin/sh -c` wrapper that sources the env file
/// (auto-exporting via `set -a`) then execs the daemon over `roots`.
fn plist_body(exe: &str, roots: &[String], env_file: &str, log_file: &str) -> String {
    let mut cmd = format!(
        "set -a; . {}; set +a; exec {} daemon",
        sh_quote(env_file),
        sh_quote(exe)
    );
    for root in roots {
        cmd.push(' ');
        cmd.push_str(&sh_quote(root));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>{cmd}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        label = LABEL,
        cmd = xml_escape(&cmd),
        log = xml_escape(log_file),
    )
}

/// Escapes one `ExecStart=` argument for systemd: `%`→`%%` (systemd expands
/// `%`-specifiers even inside quotes), then C-style-escapes `\` and `"`, wrapped
/// in double quotes. Without the `%%` a Space path like `/x 100%backup` would be
/// silently rewritten by specifier expansion.
fn systemd_arg(s: &str) -> String {
    let escaped = s
        .replace('%', "%%")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// The systemd user-unit body. Loads the env file, runs the daemon over `roots`,
/// restarts on failure.
fn systemd_unit_body(exe: &str, roots: &[String], env_file: &str) -> String {
    let mut exec = format!("{} daemon", systemd_arg(exe));
    for root in roots {
        exec.push(' ');
        exec.push_str(&systemd_arg(root));
    }
    format!(
        "[Unit]\n\
         Description=filething continuous sync daemon\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         EnvironmentFile={env_file}\n\
         ExecStart={exec}\n\
         Restart=always\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/// Absolute path of the running `filething` binary (embedded into the service).
fn current_exe() -> anyhow::Result<String> {
    let exe = std::env::current_exe().context("resolving the filething binary path")?;
    Ok(exe.to_string_lossy().into_owned())
}

/// The Space roots to sync, from `config.json`. Errors if none are mapped yet.
fn configured_roots() -> anyhow::Result<Vec<String>> {
    let cfg = Config::load()?;
    let roots: Vec<String> = cfg.spaces.iter().map(|m| m.local_root.clone()).collect();
    if roots.is_empty() {
        bail!("no Spaces mapped yet — run `filething init` or `filething clone` first");
    }
    Ok(roots)
}

fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// Writes the captured-env file and returns its path. The file holds
/// deployment-root-equivalent secrets, so it is created **0600 from the outset**
/// (never write-then-chmod, which would leave a window where the secrets are
/// world-readable): any stale file is removed first, then created with mode 0600
/// atomically. The config dir is tightened to 0700 too.
fn write_env_file() -> anyhow::Result<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let vars: Vec<(String, String)> = CAPTURED_ENV
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    let path = Config::config_dir().join(ENV_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        // Best-effort: keep the dir owner-only (it holds secrets + config).
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    // Remove any stale file so the create below always makes a fresh 0600 file
    // (create+truncate would keep a pre-existing looser mode).
    let _ = std::fs::remove_file(&path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating {} (0600)", path.display()))?;
    file.write_all(env_file_body(&vars).as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn install() -> anyhow::Result<()> {
    let exe = current_exe()?;
    let roots = configured_roots()?;
    let env_file = write_env_file()?;
    let log_file = Config::config_dir().join(LOG_FILE);
    let env_file_s = env_file.to_string_lossy().into_owned();
    let log_file_s = log_file.to_string_lossy().into_owned();

    if cfg!(target_os = "macos") {
        let plist = home_dir()?
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"));
        write_file(&plist, &plist_body(&exe, &roots, &env_file_s, &log_file_s))?;
        println!("Wrote launchd agent: {}", plist.display());
        // Reload: unload first (ignore errors), then load.
        let plist_s = plist.to_string_lossy().into_owned();
        let _ = run_cmd("launchctl", &["unload", &plist_s]);
        match run_cmd("launchctl", &["load", "-w", &plist_s]) {
            Ok(()) => println!("Loaded and started the launchd agent."),
            Err(e) => println!(
                "Could not load the agent automatically ({e}). Load it with:\n  launchctl load -w {plist_s}"
            ),
        }
    } else if cfg!(target_os = "linux") {
        let unit = home_dir()?.join(".config/systemd/user").join(SYSTEMD_UNIT);
        write_file(&unit, &systemd_unit_body(&exe, &roots, &env_file_s))?;
        println!("Wrote systemd user unit: {}", unit.display());
        let _ = run_cmd("systemctl", &["--user", "daemon-reload"]);
        match run_cmd("systemctl", &["--user", "enable", "--now", SYSTEMD_UNIT]) {
            Ok(()) => println!("Enabled and started {SYSTEMD_UNIT} (systemctl --user)."),
            Err(e) => println!(
                "Could not enable the unit automatically ({e}). Enable it with:\n  \
                 systemctl --user enable --now {SYSTEMD_UNIT}\n(You may need `loginctl \
                 enable-linger $USER` so it runs without an active login session.)"
            ),
        }
    } else {
        bail!("`service` supports macOS (launchd) and Linux (systemd) only");
    }

    println!(
        "Syncing {} Space(s); logs at {}",
        roots.len(),
        log_file.display()
    );
    Ok(())
}

fn uninstall() -> anyhow::Result<()> {
    if cfg!(target_os = "macos") {
        let plist = home_dir()?
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"));
        let plist_s = plist.to_string_lossy().into_owned();
        let _ = run_cmd("launchctl", &["unload", &plist_s]);
        remove_if_present(&plist)?;
    } else if cfg!(target_os = "linux") {
        let _ = run_cmd("systemctl", &["--user", "disable", "--now", SYSTEMD_UNIT]);
        let unit = home_dir()?.join(".config/systemd/user").join(SYSTEMD_UNIT);
        remove_if_present(&unit)?;
        let _ = run_cmd("systemctl", &["--user", "daemon-reload"]);
    } else {
        bail!("`service` supports macOS (launchd) and Linux (systemd) only");
    }
    // Remove the captured secrets; keep the log for post-mortem.
    remove_if_present(&Config::config_dir().join(ENV_FILE))?;
    println!("Uninstalled the filething service.");
    Ok(())
}

fn status() -> anyhow::Result<()> {
    if cfg!(target_os = "macos") {
        match run_cmd_output("launchctl", &["list", LABEL]) {
            Ok(out) => {
                println!("launchd agent {LABEL}: loaded");
                print!("{out}");
            }
            Err(_) => println!("launchd agent {LABEL}: not loaded"),
        }
    } else if cfg!(target_os = "linux") {
        let active = run_cmd_output("systemctl", &["--user", "is-active", SYSTEMD_UNIT])
            .unwrap_or_else(|_| "unknown".into());
        let enabled = run_cmd_output("systemctl", &["--user", "is-enabled", SYSTEMD_UNIT])
            .unwrap_or_else(|_| "unknown".into());
        println!(
            "systemd user unit {SYSTEMD_UNIT}: active={} enabled={}",
            active.trim(),
            enabled.trim()
        );
    } else {
        bail!("`service` supports macOS (launchd) and Linux (systemd) only");
    }
    Ok(())
}

// ----- small IO / process helpers -----

fn write_file(path: &std::path::Path, body: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))
}

fn remove_if_present(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!("removing {}: {e}", path.display())),
    }
}

/// Runs a command, erroring on a non-zero exit (stderr folded into the message).
fn run_cmd(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "{program} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

/// Runs a command and returns its stdout, erroring on a non-zero exit.
fn run_cmd_output(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        bail!("{program} exited {}", out.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_escapes_single_quotes() {
        assert_eq!(sh_quote("plain"), "'plain'");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn env_file_body_is_key_quoted_value() {
        let vars = vec![
            (
                "CONVEX_URL".to_string(),
                "https://x.convex.cloud".to_string(),
            ),
            ("S3_SECRET_KEY".to_string(), "ab'cd".to_string()),
        ];
        let body = env_file_body(&vars);
        assert!(body.contains("CONVEX_URL='https://x.convex.cloud'\n"));
        // Embedded quote is escaped so both `. file` and systemd read it.
        assert!(body.contains("S3_SECRET_KEY='ab'\\''cd'\n"));
    }

    #[test]
    fn plist_embeds_wrapper_and_roots() {
        let p = plist_body(
            "/usr/local/bin/filething",
            &["/home/u/proj".to_string(), "/home/u/notes".to_string()],
            "/cfg/service.env",
            "/cfg/daemon.log",
        );
        assert!(p.contains("<string>com.filething.daemon</string>"));
        assert!(p.contains("/bin/sh"));
        // The wrapper sources the env file then execs the daemon over both roots.
        assert!(p.contains("set -a; . &apos;/cfg/service.env&apos;; set +a; exec"));
        assert!(p.contains("daemon &apos;/home/u/proj&apos; &apos;/home/u/notes&apos;"));
        assert!(p.contains("<string>/cfg/daemon.log</string>"));
    }

    #[test]
    fn systemd_arg_escapes_percent() {
        assert_eq!(systemd_arg("/home/u/proj"), "\"/home/u/proj\"");
        // A `%` in a path must be doubled or systemd expands it as a specifier.
        assert_eq!(systemd_arg("/x 100%backup"), "\"/x 100%%backup\"");
    }

    #[test]
    fn systemd_unit_has_envfile_and_execstart() {
        let u = systemd_unit_body(
            "/usr/local/bin/filething",
            &["/home/u/proj".to_string()],
            "/cfg/service.env",
        );
        assert!(u.contains("EnvironmentFile=/cfg/service.env"));
        assert!(u.contains("ExecStart=\"/usr/local/bin/filething\" daemon \"/home/u/proj\""));
        assert!(u.contains("Restart=always"));
        assert!(u.contains("WantedBy=default.target"));
    }
}
