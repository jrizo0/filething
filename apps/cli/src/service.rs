//! `service` — install / uninstall / status of the filething daemon as an OS
//! service (`TODO.md` Fase B, "daemon como servicio"; Fase 6, "daemon por
//! defecto").
//!
//! macOS → a launchd LaunchAgent (`~/Library/LaunchAgents/com.filething.daemon.plist`).
//! Linux → a systemd **user** unit (`~/.config/systemd/user/filething.service`).
//!
//! Both run `filething daemon` with NO folder arguments: the daemon resolves its
//! Space list fresh from `config.json` on every start, so a Space added later
//! (another `init`/`clone`) only needs a restart — the unit/plist never has to be
//! rewritten to add it (see [`crate::commands`]'s `ensure_background_daemon`,
//! which installs/restarts this service automatically after `init`/`clone`/
//! `sync`). Both restart on crash and log to `<config_dir>/daemon.log`. The
//! daemon needs the Convex + `S3_*` credentials in its environment; `install`
//! captures the ones currently set into a 0600 `<config_dir>/service.env` that
//! the service loads (systemd `EnvironmentFile`; launchd via a `/bin/sh` wrapper
//! that sources it), so secrets live in ONE private file, never in the
//! unit/plist or the config.
//!
//! The content generators are pure and unit-tested; the install/uninstall/status
//! entry points shell out to `launchctl` / `systemctl --user` and degrade to
//! printing the manual command if that step fails (so a restricted environment
//! still gets the files written).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context as _};

use crate::config::Config;

/// Uptime (seconds) below which a nonzero last-exit reads as a crash-loop rather
/// than a normal recent (re)start (issue #19).
const CRASH_LOOP_UPTIME_SECS: u64 = 30;
/// systemd `NRestarts` at or above which the unit is treated as crash-looping
/// regardless of the current instance's uptime/exit (issue #19).
const CRASH_LOOP_RESTARTS: u64 = 3;
/// How many trailing log lines to show when warning about a crash-loop.
const ERROR_LOG_TAIL: usize = 15;

/// launchd job label / systemd unit base name.
const LABEL: &str = "com.filething.daemon";
/// The systemd user unit filename.
const SYSTEMD_UNIT: &str = "filething.service";
/// The captured-env filename under the config dir (0600).
const ENV_FILE: &str = "service.env";
/// The daemon log filename under the config dir. The daemon process OWNS this
/// file and rotates it itself (`crate::logrotate`), so launchd no longer redirects
/// its std streams here — see [`ERR_FILE`]. Kept for the `install()` "logs at …"
/// message, which still points operators at the rotated log, and shared with
/// `crate::main`'s rotating-writer setup so the two can never drift.
pub(crate) const LOG_FILE: &str = "daemon.log";
/// Where launchd sends the daemon's raw stdout/stderr: panics, early-startup
/// errors before tracing is up, and the couple of `println!` lines. Tiny by
/// construction (the bulk of logging goes through the rotated [`LOG_FILE`]), so it
/// needs no rotation of its own (GitHub #22).
const ERR_FILE: &str = "daemon.err.log";

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
/// (auto-exporting via `set -a`) then execs `filething daemon` with no folder
/// arguments — it resolves every Space mapped in `config.json` at startup, so
/// this body never needs rewriting when a Space is added.
///
/// launchd's `Standard{Out,Error}Path` point at the small [`ERR_FILE`], NOT the
/// rotated [`LOG_FILE`]: the daemon writes its real log through the rotating
/// writer, so this file only catches panics / pre-tracing startup errors and
/// stays tiny (GitHub #22 — the old design let launchd append forever here).
/// `ThrottleInterval` keeps a persistent GLOBAL failure (broken identity/
/// credentials — per-Space failures no longer exit, GitHub #8) from relaunching
/// more than once per 30s, bounding how fast [`ERR_FILE`] can grow.
fn plist_body(exe: &str, env_file: &str, err_file: &str) -> String {
    let cmd = format!(
        "set -a; . {}; set +a; exec {} daemon",
        sh_quote(env_file),
        sh_quote(exe)
    );
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
  <key>ThrottleInterval</key>
  <integer>30</integer>
  <key>StandardOutPath</key>
  <string>{err}</string>
  <key>StandardErrorPath</key>
  <string>{err}</string>
</dict>
</plist>
"#,
        label = LABEL,
        cmd = xml_escape(&cmd),
        err = xml_escape(err_file),
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

/// The systemd user-unit body. Loads the env file, runs `filething daemon` with
/// no folder arguments (resolves every mapped Space at startup — see
/// [`plist_body`]), restarts on failure.
fn systemd_unit_body(exe: &str, env_file: &str) -> String {
    let exec = format!("{} daemon", systemd_arg(exe));
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

/// How many Spaces `config.json` currently maps, for the informational line
/// `install()` prints (the service itself takes no roots — see the module docs).
fn configured_space_count() -> usize {
    Config::load().map(|c| c.spaces.len()).unwrap_or(0)
}

fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// The OS-specific service descriptor path (the launchd plist on macOS, the
/// systemd user unit on Linux). Its existence is the source of truth for
/// "installed" — used by [`is_installed`] and by `install`/`uninstall`.
fn service_file_path() -> anyhow::Result<PathBuf> {
    if cfg!(target_os = "macos") {
        Ok(home_dir()?
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    } else if cfg!(target_os = "linux") {
        Ok(home_dir()?.join(".config/systemd/user").join(SYSTEMD_UNIT))
    } else {
        bail!("`service` supports macOS (launchd) and Linux (systemd) only")
    }
}

/// Whether the service is installed (its unit/plist file exists on disk). Used
/// by `commands::ensure_background_daemon` to decide install vs. restart/start.
pub(crate) fn is_installed() -> bool {
    service_file_path().map(|p| p.exists()).unwrap_or(false)
}

/// Whether the service is currently active. macOS: `launchctl list <label>`
/// exits 0 only while the job is loaded; since the plist sets `KeepAlive`, loaded
/// and running coincide in practice. Linux: `systemctl --user is-active` prints
/// `active` exactly while the unit is running.
pub(crate) fn is_running() -> bool {
    if cfg!(target_os = "macos") {
        run_cmd_output("launchctl", &["list", LABEL]).is_ok()
    } else if cfg!(target_os = "linux") {
        run_cmd_output("systemctl", &["--user", "is-active", SYSTEMD_UNIT])
            .map(|out| out.trim() == "active")
            .unwrap_or(false)
    } else {
        false
    }
}

/// Restarts the already-installed service in place — does not touch the
/// unit/plist or env file (use `install()` to regenerate those). Also used to
/// start it when [`is_running`] is false.
///
/// macOS has no portable single-command restart for a plist-based LaunchAgent
/// across OS versions (`kickstart` targets the modern service domain and isn't
/// always available/permitted for LaunchAgents), so this does the same
/// unload-then-load `install()` uses to (re)start it.
pub(crate) fn restart() -> anyhow::Result<()> {
    if cfg!(target_os = "macos") {
        let plist = service_file_path()?;
        let plist_s = plist.to_string_lossy().into_owned();
        let _ = run_cmd("launchctl", &["unload", &plist_s]);
        run_cmd("launchctl", &["load", "-w", &plist_s])
    } else if cfg!(target_os = "linux") {
        run_cmd("systemctl", &["--user", "restart", SYSTEMD_UNIT])
    } else {
        bail!("`service` supports macOS (launchd) and Linux (systemd) only")
    }
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

/// Writes the unit/plist + env file and loads the service. Public to
/// `crate::commands`'s `ensure_background_daemon`, which calls this the first
/// time `init`/`clone`/`sync` succeeds with no service installed yet.
pub(crate) fn install() -> anyhow::Result<()> {
    let exe = current_exe()?;
    let env_file = write_env_file()?;
    // The rotated log the daemon owns (shown to the operator below); the tiny
    // err file launchd captures raw stdout/stderr into (see `plist_body`).
    let log_file = Config::config_dir().join(LOG_FILE);
    let err_file = Config::config_dir().join(ERR_FILE);
    let env_file_s = env_file.to_string_lossy().into_owned();
    let err_file_s = err_file.to_string_lossy().into_owned();
    let path = service_file_path()?;

    if cfg!(target_os = "macos") {
        write_file(&path, &plist_body(&exe, &env_file_s, &err_file_s))?;
        println!("Wrote launchd agent: {}", path.display());
        // Reload: unload first (ignore errors), then load.
        let plist_s = path.to_string_lossy().into_owned();
        let _ = run_cmd("launchctl", &["unload", &plist_s]);
        match run_cmd("launchctl", &["load", "-w", &plist_s]) {
            Ok(()) => println!("Loaded and started the launchd agent."),
            Err(e) => println!(
                "Could not load the agent automatically ({e}). Load it with:\n  launchctl load -w {plist_s}"
            ),
        }
    } else if cfg!(target_os = "linux") {
        write_file(&path, &systemd_unit_body(&exe, &env_file_s))?;
        println!("Wrote systemd user unit: {}", path.display());
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
        "Syncing {} Space(s) mapped in config.json (it re-reads the mapping on every \
         restart, so a later `init`/`clone` just needs a restart); logs at {}",
        configured_space_count(),
        log_file.display()
    );
    Ok(())
}

fn uninstall() -> anyhow::Result<()> {
    let path = service_file_path()?;
    if cfg!(target_os = "macos") {
        let plist_s = path.to_string_lossy().into_owned();
        let _ = run_cmd("launchctl", &["unload", &plist_s]);
        remove_if_present(&path)?;
    } else if cfg!(target_os = "linux") {
        let _ = run_cmd("systemctl", &["--user", "disable", "--now", SYSTEMD_UNIT]);
        remove_if_present(&path)?;
        let _ = run_cmd("systemctl", &["--user", "daemon-reload"]);
    } else {
        bail!("`service` supports macOS (launchd) and Linux (systemd) only");
    }
    // Remove the captured secrets; keep the log for post-mortem.
    remove_if_present(&Config::config_dir().join(ENV_FILE))?;
    println!("Uninstalled the filething service.");
    Ok(())
}

/// A uniform snapshot of the daemon service, so `status` reads the same on both
/// platforms instead of dumping the raw launchctl dict (issue #19).
#[derive(Debug, Default, PartialEq, Eq)]
struct ServiceStatus {
    /// Whether a live daemon process is currently running.
    running: bool,
    /// The daemon PID, when running.
    pid: Option<u32>,
    /// Seconds the current process has been up (from `ps`), when running.
    uptime_secs: Option<u64>,
    /// The last observed exit code (launchd `LastExitStatus` / systemd
    /// `ExecMainStatus`). `0` while a run is healthy.
    last_exit_code: Option<i64>,
    /// systemd `NRestarts` (the auto-restart count). `None` on launchd, which
    /// exposes no equivalent.
    restarts: Option<u64>,
}

impl ServiceStatus {
    /// Crash-loop heuristic (issue #19): the supervisor keeps relaunching the
    /// daemon but it keeps dying. Two independent signals:
    /// - a nonzero last exit together with either "not running" or an uptime of
    ///   only seconds — the launchd trap where the agent shows a fresh PID that
    ///   is about to die again, with `LastExitStatus != 0` buried in the dump;
    /// - a high systemd restart count, which climbs across a restart loop even
    ///   when we happen to sample it mid-run (its `ExecMainStatus` reads `0`).
    fn looks_crash_looping(&self) -> bool {
        let recent_bad_exit = matches!(self.last_exit_code, Some(c) if c != 0);
        let young = matches!(self.uptime_secs, Some(s) if s < CRASH_LOOP_UPTIME_SECS);
        let many_restarts = matches!(self.restarts, Some(n) if n >= CRASH_LOOP_RESTARTS);
        many_restarts || (recent_bad_exit && (young || !self.running))
    }
}

fn status() -> anyhow::Result<()> {
    if !is_installed() {
        println!("filething daemon service: not installed");
        println!(
            "  install it with `filething service install` (or just run `filething init`/`clone`, \
             which installs it automatically)."
        );
        return Ok(());
    }

    let mut st = if cfg!(target_os = "macos") {
        // `launchctl list <label>` exits 0 (and prints the dict) only while the
        // job is loaded; a nonzero exit means "not loaded" = stopped.
        match run_cmd_output("launchctl", &["list", LABEL]) {
            Ok(out) => parse_launchctl_list(&out),
            Err(_) => ServiceStatus::default(),
        }
    } else if cfg!(target_os = "linux") {
        // `systemctl --user show` always succeeds for an installed unit and
        // prints KEY=VALUE properties; parse the few we report.
        match run_cmd_output(
            "systemctl",
            &[
                "--user",
                "show",
                SYSTEMD_UNIT,
                "-p",
                "ActiveState",
                "-p",
                "MainPID",
                "-p",
                "ExecMainStatus",
                "-p",
                "NRestarts",
            ],
        ) {
            Ok(out) => parse_systemd_show(&out),
            Err(_) => ServiceStatus::default(),
        }
    } else {
        bail!("`service` supports macOS (launchd) and Linux (systemd) only");
    };

    // Uptime uniformly from the live PID (`ps -o etime`), so both platforms
    // report it even though only systemd exposes a start timestamp of its own.
    if let Some(pid) = st.pid {
        st.uptime_secs = process_uptime_secs(pid);
    }

    render_status(&st);
    Ok(())
}

/// Prints the uniform status report (issue #19) and, on a detected crash-loop,
/// a WARNING with the log location and its last lines.
fn render_status(st: &ServiceStatus) {
    println!(
        "filething daemon service: {}",
        if st.running { "running" } else { "stopped" }
    );
    if let Some(pid) = st.pid {
        println!("  pid: {pid}");
    }
    match st.uptime_secs {
        Some(s) => println!("  uptime: {}", crate::commands::humanize_secs(s)),
        None if st.running => println!("  uptime: unknown"),
        None => {}
    }
    if let Some(code) = st.last_exit_code {
        println!("  last exit code: {code}");
    }
    if let Some(n) = st.restarts {
        println!("  restarts: {n}");
    }
    let log = log_location_hint();
    println!("  log: {log}");

    if st.looks_crash_looping() {
        let exit = st
            .last_exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "?".into());
        let up = st
            .uptime_secs
            .map(|s| format!("up {}", crate::commands::humanize_secs(s)))
            .unwrap_or_else(|| "not running".into());
        println!();
        println!("  WARNING: the daemon looks like it is crash-looping (last exit {exit}, {up}).");
        let lines = last_error_log_lines(ERROR_LOG_TAIL);
        if lines.is_empty() {
            println!("  (no recent log lines found; see {log})");
        } else {
            println!("  last log lines:");
            for l in &lines {
                println!("    {l}");
            }
        }
        println!(
            "  \u{2192} a single dead Space can do this (issue #8): check \
             `filething status` for a QUARANTINED Space and `filething unmap <dir>` it."
        );
    }
}

/// Parses `launchctl list <label>` output — a plist-ish dict of `"Key" = value;`
/// lines — into a [`ServiceStatus`]. A present `PID` means the job is running;
/// `LastExitStatus` is the last observed exit code (the value that used to be
/// buried in the raw dump, issue #19).
fn parse_launchctl_list(out: &str) -> ServiceStatus {
    let mut pid = None;
    let mut last_exit_code = None;
    for line in out.lines() {
        let line = line.trim().trim_end_matches(';');
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().trim_matches('"');
        let val = v.trim().trim_matches('"');
        match key {
            "PID" => pid = val.parse::<u32>().ok(),
            "LastExitStatus" => last_exit_code = val.parse::<i64>().ok(),
            _ => {}
        }
    }
    ServiceStatus {
        running: pid.is_some(),
        pid,
        uptime_secs: None,
        last_exit_code,
        restarts: None,
    }
}

/// Parses `systemctl --user show` KEY=VALUE properties into a [`ServiceStatus`]:
/// `ActiveState` (running ⟺ `active`), `MainPID` (0 ⇒ not running),
/// `ExecMainStatus` (last exit code), `NRestarts` (auto-restart count).
fn parse_systemd_show(out: &str) -> ServiceStatus {
    let map: HashMap<&str, &str> = out
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let running = map.get("ActiveState").is_some_and(|s| *s == "active");
    let pid = map
        .get("MainPID")
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|p| *p != 0);
    let last_exit_code = map
        .get("ExecMainStatus")
        .and_then(|s| s.parse::<i64>().ok());
    let restarts = map.get("NRestarts").and_then(|s| s.parse::<u64>().ok());
    ServiceStatus {
        running,
        pid,
        uptime_secs: None,
        last_exit_code,
        restarts,
    }
}

/// Elapsed seconds for `pid` via `ps -o etime=` (portable across macOS/Linux),
/// or `None` if the process is gone or `ps` is unavailable.
fn process_uptime_secs(pid: u32) -> Option<u64> {
    let out = run_cmd_output("ps", &["-o", "etime=", "-p", &pid.to_string()]).ok()?;
    parse_etime(out.trim())
}

/// Parses a `ps -o etime` field (`[[dd-]hh:]mm:ss`) into whole seconds.
fn parse_etime(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, s),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let (h, m, sec): (u64, u64, u64) = match parts.as_slice() {
        [h, m, s] => (h.parse().ok()?, m.parse().ok()?, s.parse().ok()?),
        [m, s] => (0, m.parse().ok()?, s.parse().ok()?),
        _ => return None,
    };
    Some(days * 86_400 + h * 3_600 + m * 60 + sec)
}

/// Where the daemon's log lives, for the `log:` line. macOS always logs to the
/// rotated file (`daemon.log`); Linux logs to journald unless the file-log
/// opt-in wrote `daemon.log` (`FILETHING_LOG_TO_FILE`), in which case that file
/// is shown. The macOS `daemon.err.log` (panics/startup) is read by
/// [`last_error_log_lines`] but not named here to keep the line short.
fn log_location_hint() -> String {
    let daemon_log = Config::config_dir().join(LOG_FILE);
    if cfg!(target_os = "macos") || daemon_log.exists() {
        daemon_log.display().to_string()
    } else {
        format!("journalctl --user -u {SYSTEMD_UNIT}")
    }
}

/// The last `n` log lines to show under a crash-loop warning. macOS prefers the
/// tiny `daemon.err.log` (where panics/pre-tracing fatal errors land), falling
/// back to the rotated `daemon.log`. Linux tails `daemon.log` when present, else
/// asks journald.
fn last_error_log_lines(n: usize) -> Vec<String> {
    let dir = Config::config_dir();
    if cfg!(target_os = "macos") {
        let err = tail_file(&dir.join(ERR_FILE), n);
        if !err.is_empty() {
            return err;
        }
        return tail_file(&dir.join(LOG_FILE), n);
    }
    let daemon_log = dir.join(LOG_FILE);
    if daemon_log.exists() {
        return tail_file(&daemon_log, n);
    }
    match run_cmd_output(
        "journalctl",
        &[
            "--user",
            "-u",
            SYSTEMD_UNIT,
            "-n",
            &n.to_string(),
            "--no-pager",
        ],
    ) {
        Ok(out) => out.lines().map(str::to_string).collect(),
        Err(_) => Vec::new(),
    }
}

/// Reads the last `n` lines of a text file, or an empty vec if it cannot be read.
fn tail_file(path: &Path, n: usize) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(n);
            lines[start..].iter().map(|l| l.to_string()).collect()
        }
        Err(_) => Vec::new(),
    }
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
    fn plist_embeds_wrapper_and_no_roots() {
        let p = plist_body(
            "/usr/local/bin/filething",
            "/cfg/service.env",
            "/cfg/daemon.err.log",
        );
        assert!(p.contains("<string>com.filething.daemon</string>"));
        assert!(p.contains("/bin/sh"));
        // The wrapper sources the env file then execs the daemon with NO folder
        // args — it resolves every mapped Space itself at startup.
        assert!(p.contains(
            "set -a; . &apos;/cfg/service.env&apos;; set +a; exec &apos;/usr/local/bin/filething&apos; daemon"
        ));
        // launchd captures raw std streams into the tiny err file; the rotated
        // daemon.log is owned by the process and must NOT appear in the plist
        // (GitHub #22).
        assert!(p.contains("<string>/cfg/daemon.err.log</string>"));
        assert!(!p.contains("<string>/cfg/daemon.log</string>"));
    }

    #[test]
    fn systemd_arg_escapes_percent() {
        assert_eq!(systemd_arg("/home/u/proj"), "\"/home/u/proj\"");
        // A `%` in a path must be doubled or systemd expands it as a specifier.
        assert_eq!(systemd_arg("/x 100%backup"), "\"/x 100%%backup\"");
    }

    #[test]
    fn systemd_unit_has_envfile_and_execstart_with_no_roots() {
        let u = systemd_unit_body("/usr/local/bin/filething", "/cfg/service.env");
        assert!(u.contains("EnvironmentFile=/cfg/service.env"));
        // No folder args — the daemon resolves every mapped Space itself.
        assert!(u.contains("ExecStart=\"/usr/local/bin/filething\" daemon\n"));
        assert!(u.contains("Restart=always"));
        assert!(u.contains("WantedBy=default.target"));
    }

    // ----- status parsing / crash-loop detection (issue #19) -----

    #[test]
    fn parse_launchctl_list_reads_pid_and_last_exit() {
        // A loaded, healthy job: PID present, LastExitStatus 0.
        let running = r#"{
	"StandardOutPath" = "/cfg/daemon.err.log";
	"LimitLoadToSessionType" = "Aqua";
	"Label" = "com.filething.daemon";
	"OnDemand" = false;
	"LastExitStatus" = 0;
	"PID" = 4242;
	"Program" = "/bin/sh";
};"#;
        let st = parse_launchctl_list(running);
        assert!(st.running);
        assert_eq!(st.pid, Some(4242));
        assert_eq!(st.last_exit_code, Some(0));
        assert_eq!(st.restarts, None);

        // The issue's crash-loop trap: a relaunched PID but LastExitStatus 256.
        let looping = "{\n\t\"LastExitStatus\" = 256;\n\t\"PID\" = 9001;\n};";
        let st = parse_launchctl_list(looping);
        assert_eq!(st.pid, Some(9001));
        assert_eq!(st.last_exit_code, Some(256));
        assert!(st.running); // has a PID *right now*…
    }

    #[test]
    fn parse_launchctl_list_not_running_when_no_pid() {
        let stopped = "{\n\t\"LastExitStatus\" = 0;\n\t\"OnDemand\" = false;\n};";
        let st = parse_launchctl_list(stopped);
        assert!(!st.running);
        assert_eq!(st.pid, None);
    }

    #[test]
    fn parse_systemd_show_reads_state_pid_exit_restarts() {
        let active = "ActiveState=active\nMainPID=1234\nExecMainStatus=0\nNRestarts=0\n";
        let st = parse_systemd_show(active);
        assert!(st.running);
        assert_eq!(st.pid, Some(1234));
        assert_eq!(st.last_exit_code, Some(0));
        assert_eq!(st.restarts, Some(0));

        // Failed unit mid-restart-loop: no MainPID, nonzero exit, restarts climbing.
        let failed = "ActiveState=failed\nMainPID=0\nExecMainStatus=1\nNRestarts=7\n";
        let st = parse_systemd_show(failed);
        assert!(!st.running);
        assert_eq!(st.pid, None); // MainPID 0 → not running
        assert_eq!(st.last_exit_code, Some(1));
        assert_eq!(st.restarts, Some(7));
    }

    #[test]
    fn parse_etime_handles_all_field_widths() {
        assert_eq!(parse_etime("03"), None); // ss alone is not a valid etime
        assert_eq!(parse_etime("00:03"), Some(3)); // mm:ss
        assert_eq!(parse_etime("01:02"), Some(62));
        assert_eq!(parse_etime("01:00:00"), Some(3600)); // hh:mm:ss
        assert_eq!(parse_etime("2-03:00:00"), Some(2 * 86_400 + 3 * 3600)); // dd-hh:mm:ss
        assert_eq!(parse_etime(""), None);
        assert_eq!(parse_etime("garbage"), None);
    }

    #[test]
    fn crash_loop_detection() {
        // Healthy: long uptime, clean exit → not a loop.
        let healthy = ServiceStatus {
            running: true,
            pid: Some(1),
            uptime_secs: Some(3600),
            last_exit_code: Some(0),
            restarts: Some(0),
        };
        assert!(!healthy.looks_crash_looping());

        // launchd trap: a fresh PID (running), up only 3s, last exit 256.
        let launchd_loop = ServiceStatus {
            running: true,
            pid: Some(2),
            uptime_secs: Some(3),
            last_exit_code: Some(256),
            restarts: None,
        };
        assert!(launchd_loop.looks_crash_looping());

        // A healthy-but-recent (re)start with a clean exit must NOT false-positive.
        let just_started = ServiceStatus {
            running: true,
            pid: Some(3),
            uptime_secs: Some(2),
            last_exit_code: Some(0),
            restarts: None,
        };
        assert!(!just_started.looks_crash_looping());

        // systemd: sampled mid-run (ExecMainStatus 0) but NRestarts high.
        let systemd_loop = ServiceStatus {
            running: true,
            pid: Some(4),
            uptime_secs: Some(4),
            last_exit_code: Some(0),
            restarts: Some(9),
        };
        assert!(systemd_loop.looks_crash_looping());

        // Stopped after a bad exit is also a loop signal (nothing running now).
        let down_bad = ServiceStatus {
            running: false,
            pid: None,
            uptime_secs: None,
            last_exit_code: Some(1),
            restarts: Some(0),
        };
        assert!(down_bad.looks_crash_looping());
    }
}
