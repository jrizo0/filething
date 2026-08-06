//! The `filething` subcommand implementations (`docs/BUILD-PLAN.md §3`,
//! `CONTEXT.md` — CLI estilo git).
//!
//! Each function ORCHESTRATES the engine; none reimplements sync logic. They load
//! the [`Config`] identity, build the [`Vault`]/[`Coordinator`] from env
//! ([`crate::env`]), open the Space's local index, drive a `SpaceContext`, and
//! print a clear result.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use convex::ConvexClient;
use ft_core::SpaceCrypto;
use ft_engine::{
    AccountId, CommitOutcome, DeviceId, EngineError, GcOptions, GcReport, PullOutcome,
    SpaceContext, SpaceId, SyncMetrics,
};
use futures::future::LocalBoxFuture;

use crate::config::{normalize_abs, Config};
use crate::credentials::{self, Credentials};
use crate::service::ServiceAction;
use crate::{auth, env};

/// Pre-approves every confirmation prompt in this run — the scriptable twin of a
/// `--yes`/`--force` flag, following the same pattern as `--no-daemon` and its
/// `FILETHING_NO_AUTO_DAEMON` twin. Set to yes per [`env::env_flag_enabled`], so
/// `=0`/`false`/`no`/`off` deny instead of approving.
const ENV_ASSUME_YES: &str = "FILETHING_YES";

/// A reasonable default Device name when `--name` is omitted: this machine's real
/// hostname.
///
/// `auth:ensureDevice` keys Devices BY NAME, so a name that is not per-machine
/// silently MERGES two machines into one Device record — which makes the retention
/// floor (`min(baseSeqInUse)`) describe the wrong Device and makes both machines
/// write colliding conflict-copy names (`§10`, they embed the Device name).
/// `$HOSTNAME` cannot carry that weight on its own: it is a SHELL variable, not
/// part of the environment on macOS or under launchd/systemd, so relying on it
/// named nearly every Device the same constant. It is still honored when
/// explicitly exported (a container/CI that names the box that way); otherwise the
/// name comes from `gethostname(2)`.
fn default_device_name() -> String {
    let from_env = std::env::var("HOSTNAME")
        .ok()
        .and_then(|h| clean_hostname(&h));
    let from_os = machine_hostname();
    device_name_from(from_env.as_deref(), from_os.as_deref())
}

/// The pure resolver behind [`default_device_name`]. The last resort is UNIQUE
/// rather than a shared constant: a duplicate Device record is recoverable, two
/// machines merged into one is not.
fn device_name_from(env_hostname: Option<&str>, machine_hostname: Option<&str>) -> String {
    if let Some(h) = env_hostname {
        return h.to_string();
    }
    if let Some(h) = machine_hostname {
        return h.to_string();
    }
    format!(
        "filething-device-{}",
        hex::encode(&credentials::generate_secret()[..4])
    )
}

/// This machine's hostname via `gethostname(2)` — the value `$HOSTNAME` fails to
/// expose outside an interactive shell. `None` if the call fails or yields nothing
/// usable.
fn machine_hostname() -> Option<String> {
    // Declared here instead of taking a `libc`/`hostname` dependency, mirroring how
    // `ft_engine`'s per-Space lock declares `flock(2)`: filething ships for macOS
    // and Linux only, both expose `gethostname` from the libc every Rust binary
    // already links, and the signature is identical on the two.
    extern "C" {
        fn gethostname(name: *mut std::os::raw::c_char, len: usize) -> std::os::raw::c_int;
    }
    // POSIX guarantees HOST_NAME_MAX >= 255; the extra byte is for the NUL.
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a live, writable allocation of exactly `buf.len()` bytes and
    // `gethostname` writes at most that many into it.
    if unsafe { gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    // Truncation is not reported as an error on every platform, so a name that
    // filled the buffer with no NUL is treated as untrustworthy rather than cut.
    let nul = buf.iter().position(|b| *b == 0)?;
    clean_hostname(&String::from_utf8_lossy(&buf[..nul]))
}

/// Normalizes a hostname for use as a Device name: trims surrounding whitespace
/// and the trailing dot of a fully-qualified name. `None` when nothing is left.
fn clean_hostname(raw: &str) -> Option<String> {
    let h = raw.trim().trim_end_matches('.');
    (!h.is_empty()).then(|| h.to_string())
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
///
/// Logging in as a DIFFERENT Account than the one already stored is a REBIND and is
/// confirmed first — see [`confirm_account_rebind`].
pub async fn login(email: String, signup: bool, name: Option<String>) -> anyhow::Result<()> {
    let url = env::coordinator_url_from_env();
    let base = auth::auth_base_url(&url)?;
    let device_name = name.clone().unwrap_or_else(default_device_name);

    // (0) Rebind check, BEFORE the password prompt so a mistyped email costs the
    // user nothing. The by-id counterpart runs after `ensureDevice` below.
    let config = Config::load()?;
    let mut rebind_confirmed = false;
    if let Some(from) = config.email.clone().filter(|e| rebinds_account(e, &email)) {
        confirm_account_rebind(&config, &from, &email)?;
        rebind_confirmed = true;
    }

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

    // The same rebind caught by ID instead of email: the SAME email in a
    // re-deployed Coordinator is a DIFFERENT Account document, and the Spaces
    // mapped here break identically. Skipped if the email check already asked.
    if !rebind_confirmed {
        if let Some(from) = config
            .account_id
            .clone()
            .filter(|a| rebinds_account(a, ensured.account_id.as_str()))
        {
            confirm_account_rebind(&config, &from, ensured.account_id.as_str())?;
        }
    }

    // (4) Persist: identity in config.json, secrets in credentials.json (0600).
    //
    // RE-LOADED first: the snapshot taken in (0) predates the password prompt (a
    // human typing, unbounded) and the network round-trips above, so saving it
    // would write back the config as it was minutes ago and silently undo any
    // `init`/`clone`/`unmap` run meanwhile in another terminal. Only the identity
    // fields set below belong to this command; everything else must come from the
    // file as it is NOW. The rebind check keeps using the (0) snapshot on purpose:
    // it must run before the password prompt.
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

/// Whether `login` would REBIND this Device: it already recorded `stored` and the
/// incoming identity differs. Compared case-insensitively after trimming, so the
/// same email typed with different case is not a rebind. Used for both the email
/// and the Account id.
fn rebinds_account(stored: &str, incoming: &str) -> bool {
    !stored.trim().eq_ignore_ascii_case(incoming.trim())
}

/// Explains what rebinding this Device to another Account does to the Spaces mapped
/// on it, then asks. Returns `Ok(())` only if the user (or [`ENV_ASSUME_YES`])
/// approved; otherwise it is an error, so the stored identity is left untouched.
///
/// The mappings are the reason this matters: they point at Spaces the NEW Account
/// does not own, and the Coordinator deliberately cannot distinguish "no such Space"
/// from "someone else's Space", so every one of them starts failing with the same
/// opaque "not found or no access" until it is unmapped.
fn confirm_account_rebind(config: &Config, from: &str, to: &str) -> anyhow::Result<()> {
    println!("This Device is already logged in as {from}.");
    if config.spaces.is_empty() {
        println!("Logging in as {to} replaces that identity (no Space is mapped here).");
    } else {
        println!(
            "Logging in as {to} replaces that identity, but the {} Space(s) mapped here belong to \
             {from}. {to} cannot read them, so each will start failing with \"Space not found or \
             no access\" until you `filething unmap` it:",
            config.spaces.len()
        );
        for m in &config.spaces {
            println!("  {}", m.local_root);
        }
        println!(
            "(To keep both accounts on this machine, give each one its own FILETHING_HOME instead.)"
        );
    }
    if !confirm(&format!("Log in as {to} and rebind this Device?"))? {
        anyhow::bail!(
            "aborted: this Device is still logged in as {from} and nothing changed. Re-run with \
             {ENV_ASSUME_YES}=1 to confirm non-interactively."
        );
    }
    Ok(())
}

/// Reads the login password from `$FILETHING_PASSWORD` (scripts/CI) or, failing
/// that, an interactive prompt on stderr.
///
/// The interactive read is HIDDEN whenever stdin is a terminal (see [`EchoGuard`]):
/// this password unlocks the server-escrowed `space_key`/`dedup_secret`, i.e. it is
/// the encryption boundary (`§4.4`, `§4.5`, `docs/adr/0015`), so it must not survive
/// in scrollback or in a `script`/tmux capture. A PIPED stdin (`echo pw |
/// filething login`, CI) is read verbatim exactly as before — there is no terminal
/// to configure and nothing on screen to hide.
fn read_password() -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("FILETHING_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    use std::io::Write as _;
    eprint!("Password: ");
    std::io::stderr().flush().ok();
    let hidden = EchoGuard::suppress();
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    // Restore echo BEFORE printing anything else, and close the prompt line
    // ourselves: with echo off the terminal never echoed the user's Enter.
    let was_hidden = hidden.is_some();
    drop(hidden);
    if was_hidden {
        eprintln!();
    }
    read.context("reading the password from stdin")?;
    let p = line.trim_end_matches(['\n', '\r']).to_string();
    anyhow::ensure!(
        !p.is_empty(),
        "no password provided (set FILETHING_PASSWORD or type one at the prompt)"
    );
    Ok(p)
}

/// What an interactive password read can do about terminal echo.
#[derive(Debug, PartialEq, Eq)]
enum EchoPlan {
    /// Echo is off for the read: the password never reaches the screen.
    Hidden,
    /// stdin is not a terminal (a pipe, a file, CI): nothing to hide, read as-is.
    PipedStdin,
    /// stdin IS a terminal but echo could not be turned off: read anyway (refusing
    /// would leave the user unable to log in at all) and WARN, because what they
    /// type will be visible.
    EchoUnavailable,
}

/// Pure decision behind [`EchoGuard::suppress`].
fn echo_plan(stdin_is_terminal: bool, echo_turned_off: bool) -> EchoPlan {
    match (stdin_is_terminal, echo_turned_off) {
        (false, _) => EchoPlan::PipedStdin,
        (true, true) => EchoPlan::Hidden,
        (true, false) => EchoPlan::EchoUnavailable,
    }
}

/// Terminal echo turned OFF for as long as this guard lives, restored on drop —
/// including on the error paths, so a failed read never leaves the terminal mute.
///
/// Echo is toggled with `stty`, the same shell-out style [`crate::service`] uses
/// for `launchctl`/`systemctl`/`ps`, rather than a hand-rolled `termios` FFI whose
/// `struct` layout differs between macOS and Linux — the two platforms filething
/// ships for, both of which have `stty` in the base system.
///
/// `Drop` alone is NOT enough, though: SIGINT (Ctrl-C at the prompt, the obvious
/// way to back out of typing a password) kills the process outright, so no
/// destructor runs and the user's SHELL inherits a terminal with echo off —
/// invisible typing until they blindly run `stty sane`. So the guard also owns a
/// SIGINT disposition for as long as the prompt is up (see [`SigintRestore`]).
struct EchoGuard {
    /// Live only while echo is actually off; restores the previous disposition on
    /// drop, before this guard turns echo back on.
    _sigint: SigintRestore,
}

impl EchoGuard {
    /// Turns echo off, or returns `None` when there is no terminal to configure
    /// (piped stdin) or `stty` could not do it (warned about, since the password
    /// is then visible as typed).
    fn suppress() -> Option<Self> {
        let is_terminal = std::io::stdin().is_terminal();
        // Snapshot the terminal BEFORE `stty -echo`, so the SIGINT handler has
        // something to put back; it is a no-op when there is no terminal.
        let sigint = SigintRestore::arm();
        match echo_plan(is_terminal, is_terminal && set_terminal_echo(false)) {
            EchoPlan::Hidden => Some(Self { _sigint: sigint }),
            EchoPlan::PipedStdin => None,
            EchoPlan::EchoUnavailable => {
                eprintln!(
                    "\nwarning: could not turn off terminal echo (`stty` unavailable) — what you \
                     type WILL be visible. Set FILETHING_PASSWORD instead if that matters."
                );
                eprint!("Password: ");
                None
            }
        }
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        set_terminal_echo(true);
    }
}

/// `SIGINT` handled, for as long as this value lives, by putting the terminal back
/// the way it was and then dying the way the shell expects (128 + SIGINT = 130).
///
/// It exists ONLY for the hidden password prompt: with echo off, the default SIGINT
/// disposition (terminate immediately, no destructors) is what leaves the user's
/// shell mute. Everywhere else filething keeps the default disposition, so this is
/// armed for the prompt and disarmed right after.
///
/// The handler restores with `tcsetattr(3)` rather than the `stty` shell-out used
/// elsewhere: a signal handler may only call async-signal-safe functions, and
/// fork/exec-ing a child from one is not that. The `termios` layout still is not
/// hard-coded — it is captured verbatim by `tcgetattr` into an oversized opaque
/// buffer and handed straight back — so the macOS/Linux difference stays the
/// libc's problem.
struct SigintRestore {
    /// The disposition replaced by [`SigintRestore::arm`], or `None` when nothing
    /// was installed (no terminal, or `tcgetattr` failed).
    previous: Option<usize>,
}

/// POSIX bits used by the SIGINT path. Declared here instead of taking a `libc`
/// dependency, exactly like [`machine_hostname`]'s `gethostname`: filething ships
/// for macOS and Linux only and both agree on these.
mod sigint_ffi {
    use std::os::raw::{c_int, c_void};

    pub const SIGINT: c_int = 2;
    pub const SIG_DFL: usize = 0;
    pub const SIG_ERR: usize = usize::MAX;
    pub const TCSANOW: c_int = 0;
    pub const STDIN_FILENO: c_int = 0;

    extern "C" {
        pub fn tcgetattr(fd: c_int, termios_p: *mut c_void) -> c_int;
        pub fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const c_void) -> c_int;
        /// `sighandler_t` is a function pointer; it is passed and returned here as
        /// the pointer-sized integer it is so `SIG_DFL`/`SIG_ERR` stay writable.
        pub fn signal(signum: c_int, handler: usize) -> usize;
        pub fn raise(sig: c_int) -> c_int;
    }
}

/// The terminal state captured before echo was turned off, for the signal handler
/// to hand back. Oversized on purpose: `struct termios` is ~72 bytes at most on the
/// supported platforms and its contents are never inspected here.
static mut SAVED_TERMIOS: [u64; 32] = [0; 32];
/// Whether [`SAVED_TERMIOS`] holds a real capture the handler may restore.
static TERMIOS_SAVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Puts the terminal back as it was and re-raises `SIGINT` with the default
/// disposition, so the process dies from the signal and the shell reports the
/// conventional 130 instead of a normal exit.
extern "C" fn restore_terminal_on_sigint(sig: std::os::raw::c_int) {
    use std::sync::atomic::Ordering;
    if TERMIOS_SAVED.load(Ordering::SeqCst) {
        // SAFETY: async-signal-safe call; the pointer is a live static of at least
        // `sizeof(struct termios)` bytes filled by `tcgetattr` in `arm()`, and the
        // handler is only installed after that capture succeeded.
        unsafe {
            sigint_ffi::tcsetattr(
                sigint_ffi::STDIN_FILENO,
                sigint_ffi::TCSANOW,
                std::ptr::addr_of!(SAVED_TERMIOS).cast(),
            );
        }
    }
    // SAFETY: `signal`/`raise` are async-signal-safe.
    unsafe {
        sigint_ffi::signal(sig, sigint_ffi::SIG_DFL);
        sigint_ffi::raise(sig);
    }
}

impl SigintRestore {
    /// Captures the current terminal state and installs the handler. A no-op (and
    /// harmless) when stdin is not a terminal or the capture fails: the prompt then
    /// has nothing to restore anyway.
    fn arm() -> Self {
        use std::sync::atomic::Ordering;
        // SAFETY: `tcgetattr` writes at most `sizeof(struct termios)` bytes, far
        // less than the buffer; nothing else touches it while the prompt is up
        // (the CLI reads the password on one thread, before any daemon starts).
        let captured = unsafe {
            sigint_ffi::tcgetattr(
                sigint_ffi::STDIN_FILENO,
                std::ptr::addr_of_mut!(SAVED_TERMIOS).cast(),
            ) == 0
        };
        TERMIOS_SAVED.store(captured, Ordering::SeqCst);
        if !captured {
            return Self { previous: None };
        }
        // SAFETY: installing a disposition for one signal; the handler is `extern
        // "C"` and async-signal-safe.
        let handler = restore_terminal_on_sigint as *const () as usize;
        let previous = unsafe { sigint_ffi::signal(sigint_ffi::SIGINT, handler) };
        Self {
            previous: (previous != sigint_ffi::SIG_ERR).then_some(previous),
        }
    }
}

impl Drop for SigintRestore {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if let Some(previous) = self.previous.take() {
            // SAFETY: same call as in `arm`, putting back what it replaced.
            unsafe { sigint_ffi::signal(sigint_ffi::SIGINT, previous) };
        }
        TERMIOS_SAVED.store(false, Ordering::SeqCst);
    }
}

/// Turns the controlling terminal's echo on/off via `stty`, which reads the
/// terminal from its INHERITED stdin — the same one we are about to read the
/// password from. Returns whether it worked.
fn set_terminal_echo(on: bool) -> bool {
    std::process::Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Asks a yes/no question on stderr and reads the answer from stdin, for the
/// commands that would otherwise do something destructive or surprising in
/// silence.
///
/// `true` only on an explicit `y`/`yes`. A NON-TTY stdin (a script, CI, the
/// daemon) has nobody to answer, so it never blocks: it returns `false` and the
/// caller must refuse, naming [`ENV_ASSUME_YES`] as the non-interactive
/// pre-approval.
fn confirm(question: &str) -> anyhow::Result<bool> {
    if assume_yes() {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    use std::io::Write as _;
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading the confirmation from stdin")?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Whether [`ENV_ASSUME_YES`] pre-approved this run's confirmations. `=0`/`false`/
/// `no`/`off` mean NO — see [`env::env_flag_enabled`].
fn assume_yes() -> bool {
    env::env_flag_enabled(ENV_ASSUME_YES)
}

/// Loads the paired identity from the config, erroring with a `login` hint if the
/// Device has not logged in yet. Returns `(coordinator_url, account, device)`.
///
/// The STORED Coordinator URL WINS over the environment once `login` has run, and
/// that is deliberate: the account/device ids in the config are documents of THAT
/// deployment and mean nothing in another one, so following a stray `CONVEX_URL`
/// here would turn every command into "Space not found or no access". A `CONVEX_URL`
/// / `CONVEX_SELF_HOSTED_URL` explicitly set to something ELSE used to be ignored in
/// complete silence, which is the surprising half — so it is reported, with the two
/// ways out.
fn require_identity(config: &Config) -> anyhow::Result<(String, AccountId, DeviceId)> {
    let url = config
        .coordinator_url
        .clone()
        .unwrap_or_else(env::coordinator_url_from_env);
    if let Some(warning) = coordinator_url_mismatch(
        config.coordinator_url.as_deref(),
        explicit_env_coordinator_url().as_deref(),
    ) {
        eprintln!("{warning}");
    }
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

/// The Coordinator URL as EXPLICITLY set in the environment. The two names are
/// repeated from [`env::coordinator_url_from_env`] on purpose: that helper folds in
/// the baked-in build default and the localhost fallback, and only a URL the user
/// really set is worth warning about.
fn explicit_env_coordinator_url() -> Option<String> {
    ["CONVEX_URL", "CONVEX_SELF_HOSTED_URL"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
}

/// The warning for a stored-vs-environment Coordinator URL disagreement, or `None`
/// when they agree (a trailing slash is not a disagreement) or nothing is set.
fn coordinator_url_mismatch(stored: Option<&str>, env_url: Option<&str>) -> Option<String> {
    let (stored, env_url) = (stored?, env_url?);
    if stored.trim_end_matches('/') == env_url.trim_end_matches('/') {
        return None;
    }
    Some(format!(
        "warning: CONVEX_URL points at {env_url}, but this Device is logged in against {stored}, \
         which WINS — the stored account/device ids only exist there. Run `filething login` to \
         move this Device to {env_url}, or unset the variable."
    ))
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

/// Why `root` may NOT become (or contain) a Space, or `None` when it is free.
///
/// Nesting is refused in BOTH directions, because two engines over one file tree
/// fight: each sees the other's writes as local edits and each materializes into
/// the other's root, so both Spaces end up with a mixture of the two trees plus
/// conflict copies. Refused cases:
///
/// - an ANCESTOR of `root` is a Space root (`root` would live inside it);
/// - a DESCENDANT of `root` is a mapped Space root (it would live inside `root`).
///
/// Ancestors are also probed on disk, so a Space whose mapping this config lost
/// still counts (an unreadable index is NOT evidence of a Space — a guard must not
/// make `init` fail because of an unrelated folder). Descendants come from the
/// config alone: walking the whole subtree looking for a stray control dir would
/// re-scan the tree just to answer a guard.
fn nested_space_conflict(root: &Path, config: &Config) -> Option<String> {
    for ancestor in root.ancestors().skip(1) {
        let id = config
            .spaces
            .iter()
            .find(|m| Path::new(&m.local_root) == ancestor)
            .map(|m| m.space_id.clone())
            .or_else(|| {
                env::existing_space_id_at(ancestor)
                    .unwrap_or(None)
                    .map(|id| id.as_str().to_string())
            });
        if let Some(id) = id {
            return Some(format!(
                "{} is INSIDE {}, which is already a filething Space ({id}) — nesting Spaces makes \
                 two engines sync the same files and overwrite each other. Pick a folder outside \
                 it, or run `filething unmap {}` first.",
                root.display(),
                ancestor.display(),
                ancestor.display()
            ));
        }
    }
    for m in &config.spaces {
        let mapped = Path::new(&m.local_root);
        if mapped != root && mapped.starts_with(root) {
            return Some(format!(
                "{} CONTAINS {}, which is already a filething Space ({}) — nesting Spaces makes \
                 two engines sync the same files and overwrite each other. Pick a folder that does \
                 not contain it, or run `filething unmap {}` first.",
                root.display(),
                mapped.display(),
                m.space_id,
                mapped.display()
            ));
        }
    }
    None
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
    if let Some(conflict) = nested_space_conflict(&root, &config) {
        anyhow::bail!("{conflict}");
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
    if let Some(conflict) = nested_space_conflict(&root, &config) {
        anyhow::bail!("{conflict}");
    }
    // A non-empty target is ABSORBED into the Space, which must be asked for — see
    // [`confirm_absorption`]. Listed before `open_index` below, which creates the
    // control dir this check ignores anyway.
    let absorbed = absorbable_entries(&root)?;
    if !absorbed.is_empty() {
        confirm_absorption(&root, &absorbed, &space_id)?;
    }

    let index = env::open_index(&root)?;
    let (mut coordinator, vault) = env::connect_and_vault(&url, Some(&creds)).await?;

    // Cache the Space's escrow key locally (0600) before materializing, so later
    // commands open it offline. `clone_space` uses it + dedup_secret to decrypt
    // `alg=1` Blocks; a legacy Space has no key (materializes cleartext).
    env::ensure_space_key_cached(&mut coordinator, &space_id, &root).await?;

    let mut ctx = SpaceContext::clone_space(
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
    if !absorbed.is_empty() {
        print_absorption_conflicts(&mut ctx)?;
    }
    ensure_background_daemon(true, no_daemon);
    Ok(())
}

/// The names directly inside `root` that a `clone` would ABSORB into the Space.
///
/// Ignores filething's own control dir and the platform junk the engine's scan
/// discards anyway (its `JUNK_NAMES` — repeated by name because the const is
/// private): a folder holding only a Finder `.DS_Store` is empty as far as the
/// Space is concerned, and refusing there would be a pure false alarm on macOS.
/// A folder that does not exist yet is empty, not an error — `clone` creates it.
fn absorbable_entries(root: &Path) -> anyhow::Result<Vec<String>> {
    const IGNORED: [&str; 4] = [env::CONTROL_DIR, ".DS_Store", "Thumbs.db", "desktop.ini"];
    let read = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", root.display())),
    };
    let mut names = Vec::new();
    for entry in read {
        let entry = entry.with_context(|| format!("reading {}", root.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !IGNORED.contains(&name.as_str()) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Explains what cloning into a NON-EMPTY folder does, then asks.
///
/// Absorption is not a small side effect: the first pull reconciles the head
/// against an EMPTY base, so every pre-existing path counts as a local change to
/// upload — and the daemon this command auto-installs commits on startup, which
/// replicates the whole folder to every other Device of the Account. Colliding
/// paths lose the real path to the Space's version and survive as conflict copies
/// (`§10`). `filething clone sp_x ~/Documents`, a plausible typo for
/// `~/Documents/notes`, does all of that to the user's whole Documents folder,
/// which is why this is the one place the command stops and asks.
///
/// A `--force` flag should short-circuit this check once `main.rs` parses one (see
/// the handoff note); [`ENV_ASSUME_YES`] is the pre-approval scripts have today.
fn confirm_absorption(root: &Path, absorbed: &[String], space_id: &SpaceId) -> anyhow::Result<()> {
    const SHOW: usize = 20;
    println!(
        "{} is not empty: it holds {} existing entr{}.",
        root.display(),
        absorbed.len(),
        if absorbed.len() == 1 { "y" } else { "ies" }
    );
    for name in absorbed.iter().take(SHOW) {
        println!("    {name}");
    }
    if absorbed.len() > SHOW {
        println!("    … and {} more", absorbed.len() - SHOW);
    }
    println!(
        "Cloning {space_id} here ABSORBS them into the Space: they will be uploaded and \
         replicated to every other Device of this account, and anything whose path also exists in \
         the Space is renamed to a conflict copy (the Space's version wins the real path)."
    );
    if !confirm("Absorb this folder into the Space?")? {
        anyhow::bail!(
            "aborted: nothing was cloned. Clone into a fresh (empty) folder, or re-run with \
             {ENV_ASSUME_YES}=1 to absorb {} on purpose.",
            root.display()
        );
    }
    Ok(())
}

/// Names the conflict copies an absorbing clone left behind.
///
/// `clone_space` drops the [`PullOutcome`] of its materializing pull (unlike
/// `sync`, which prints its own), so a reconcile that renamed the user's files was
/// invisible. Re-scanning is the cheapest way to recover the list here, and the
/// index cache written by that same pull keeps it from re-reading file content.
fn print_absorption_conflicts(ctx: &mut SpaceContext) -> anyhow::Result<()> {
    const SHOW: usize = 20;
    let scan = ctx
        .scan()
        .context("re-scanning the Space to list its conflict copies")?;
    let mut copies: Vec<&str> = scan
        .entries
        .iter()
        .map(|(_, entry)| entry.p.as_str())
        .filter(|p| {
            let name = p.rsplit('/').next().unwrap_or(p);
            ft_engine::is_conflict_copy_name(name)
        })
        .collect();
    copies.sort_unstable();
    if copies.is_empty() {
        println!("  absorbed this folder's existing files (no path collided with the Space)");
        return Ok(());
    }
    println!(
        "  {} absorbed path(s) collided and were kept as conflict copies (the Space's version won \
         the real path):",
        copies.len()
    );
    for p in copies.iter().take(SHOW) {
        println!("    conflict copy: {p}");
    }
    if copies.len() > SHOW {
        println!("    … and {} more", copies.len() - SHOW);
    }
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

    // Sampled ONCE per run — each probe shells out to launchctl/systemctl — and
    // shared by every Space reported below (they are all served by the one service).
    let installed = crate::service::is_installed();
    let running = installed && crate::service::is_running();

    for (i, root) in roots.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let watch = DaemonWatch {
            installed,
            running,
            mapped: config
                .spaces
                .iter()
                .any(|m| Path::new(&m.local_root) == root.as_path()),
        };
        let res = status_one(
            root,
            &account_id,
            &device_id,
            creds.as_ref(),
            client.clone(),
            &watch,
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

/// Whether anything is actually SYNCING a given Space in the background, as seen
/// from outside: the OS service's install/run state plus whether this Space is one
/// of the folders the daemon resolves from `config.json` at startup.
struct DaemonWatch {
    /// The unit/plist exists (see `crate::service::is_installed`).
    installed: bool,
    /// A live daemon process is running.
    running: bool,
    /// This Space is mapped in `config.json`, so a running daemon covers it.
    mapped: bool,
}

impl DaemonWatch {
    /// The `daemon:` line for [`status_one`]. `status` used to describe a perfectly
    /// healthy Space while NOTHING was syncing it — which reads as "you are backed
    /// up" — so every state other than "watching" says so plainly and names the
    /// command that explains it.
    fn line(&self) -> &'static str {
        match (self.installed, self.running, self.mapped) {
            (true, true, true) => "watching this Space (background service running)",
            (true, true, false) => {
                "running, but NOT watching this Space — this folder is not mapped in config.json \
                 (`filething clone`/`init` maps it; `filething sync` syncs it by hand)"
            }
            (true, false, _) => {
                "installed but NOT running — nothing is syncing this Space (`filething service \
                 status` says why)"
            }
            (false, _, _) => {
                "NOT installed — nothing syncs this Space in the background (`filething service \
                 install`, or run `filething sync` yourself)"
            }
        }
    }
}

/// The `encryption:` line for [`status_one`]. `init` prints the Space's state at
/// creation and nothing showed it afterwards, so a legacy CLEARTEXT Space was
/// indistinguishable from an `alg=1` one. The cached per-Space escrow key (`§4.5`)
/// is the local evidence of `alg=1` — the same evidence `env::load_space_crypto`
/// treats as authoritative.
fn encryption_line(space_key_cached: bool) -> &'static str {
    if space_key_cached {
        "on (alg=1)"
    } else {
        "off (cleartext alg=0 — no escrow key cached here; `filething sync` recovers one if the \
         Space has it)"
    }
}

/// Reports one Space for [`status`]: the local synced base + change detection
/// (offline), then the best-effort remote verdict. Errors only on a genuinely
/// broken Space (not a Space folder, unreadable index/tree); an unreachable
/// Coordinator is NOT an error here — it degrades to "remote: unavailable".
#[allow(clippy::too_many_arguments)]
async fn status_one(
    root: &Path,
    account_id: &AccountId,
    device_id: &DeviceId,
    creds: Option<&Credentials>,
    client: Option<ConvexClient>,
    watch: &DaemonWatch,
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
    println!(
        "  encryption: {}",
        encryption_line(credentials::read_space_key(root)?.is_some())
    );

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

    // Everything above can look perfectly healthy while NOTHING is syncing this
    // Space, so say which it is.
    println!("  daemon: {}", watch.line());

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
                // Roots differ but the remote is NOT strictly ahead. With a
                // committed base at an equal-or-higher seq this is a genuine
                // DIVERGENCE (both sides advanced to different roots), not "behind"
                // — saying "behind" here would lie about what a pull can do.
                Some(head_seq) if local_seq >= 0 => {
                    println!("  remote: diverged (remote at seq {head_seq})")
                }
                // No committed base yet (local_seq < 0): the remote holds the only
                // revision, so we really are behind it.
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
    .map_err(|e| open_space_error(&root, e))?;
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
///
/// `--apply` is destructive and irreversible, so on a TTY it shows the plan and
/// asks first ([`ENV_ASSUME_YES`] pre-approves it for scripts). A run that CANNOT
/// collect anything fails instead of exiting 0, so "gc said nothing" is never
/// mistaken for "gc ran".
pub async fn gc(dir: PathBuf, apply: bool, grace_secs: Option<u64>) -> anyhow::Result<()> {
    // In the managed deployment this Device holds no direct storage credentials
    // (S3_*); its data plane is the presigned SignedVault, which cannot `list`
    // or `delete` across the bucket, so gc is operator-side only there. Detect
    // that mode UP FRONT — before requiring a login, opening the index, or
    // spending ~5s minting `vault:sign` URLs only to fail on the first `list()`
    // with a duplicated operator-only error (issue #21).
    //
    // This is an ERROR, not a friendly note with exit 0: nothing was collected, and
    // a zero exit told every caller (a user, a cron job, a monitoring script) that a
    // GC had run when none had.
    if !env::direct_s3_configured() {
        anyhow::bail!(
            "gc did NOT run: it needs direct S3_* storage credentials this Device does not have \
             (its data plane is the one signed by the Coordinator, and presigned URLs cannot \
             list or delete across the bucket).\n  \u{2192} In the managed deployment garbage \
             collection runs on the operator side and you don't need to run it. To run it \
             yourself, set S3_ENDPOINT / S3_REGION / S3_ACCESS_KEY / S3_SECRET_KEY / S3_BUCKET."
        );
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
        .map_err(|e| open_space_error(&root, e))?;

    let grace = grace_secs
        .map(Duration::from_secs)
        .unwrap_or(ft_engine::DEFAULT_GRACE);
    // The clock-skew allowance keeps its safe default. The max-sweep fraction — the
    // guard that refuses an `--apply` whose delete set is implausibly large — is
    // overridable, because the engine's refusal tells the operator to raise it and
    // a CLI with no way to do that would be a dead end (see [`sweep_fraction_override`]).
    let opts = |apply: bool| -> anyhow::Result<GcOptions> {
        let mut opts = GcOptions {
            apply,
            grace,
            ..Default::default()
        };
        if let Some(fraction) = sweep_fraction_override()? {
            opts.max_sweep_fraction = fraction;
        }
        Ok(opts)
    };

    // `--apply` deletes irreversibly, so a human at a terminal sees the PLAN and
    // approves it before anything goes: a dry run first, then the real sweep. A
    // script (no TTY) or an explicit pre-approval sweeps in one pass — there is
    // nobody to ask, and the plan is still printed with the result.
    if apply && !assume_yes() && std::io::stdin().is_terminal() {
        let plan = ctx.gc(opts(false)?).await.map_err(gc_error)?;
        print_gc_report(&plan, &root);
        if plan.sweepable.is_empty() {
            println!("nothing to sweep — no objects were deleted.");
            return Ok(());
        }
        if !confirm(&format!(
            "Delete {} object(s) from the Vault? This cannot be undone.",
            plan.sweepable.len()
        ))? {
            anyhow::bail!(
                "aborted: nothing was deleted. Re-run with {ENV_ASSUME_YES}=1 to skip this \
                 confirmation (e.g. from a script)."
            );
        }
    }

    let report = ctx.gc(opts(apply)?).await.map_err(gc_error)?;
    print_gc_report(&report, &root);
    Ok(())
}

/// Prints one [`GcReport`] — the plan in a dry run, the plan plus what it deleted
/// after an `--apply`.
fn print_gc_report(report: &GcReport, root: &Path) {
    const SHOW: usize = 20;
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
}

/// Renders a `gc` failure.
///
/// An [`EngineError::Refused`] is a SAFETY GUARD declining (no reachability roots,
/// a Space the login does not own, a delete set too large, a head that moved
/// mid-sweep). Its message already states what was refused, why, and what to do, so
/// it is surfaced VERBATIM rather than under a `gc:` context that would read like a
/// plumbing failure — and, being an `Err`, it can never be mistaken for a
/// successful empty sweep.
fn gc_error(err: EngineError) -> anyhow::Error {
    match err {
        EngineError::Refused(message) => anyhow::anyhow!("{message}"),
        other => anyhow::Error::new(other).context("gc"),
    }
}

/// The `max_sweep_fraction` override from `$FILETHING_GC_MAX_SWEEP_FRACTION` — the
/// scriptable twin of a `--max-sweep-fraction` flag (see the handoff note), needed
/// because the engine's proportion guard tells the operator to raise the threshold
/// and only `1.0` disables it. A value that does not parse is an ERROR rather than a
/// silent fall back to the default, and a NaN is rejected outright: the engine maps
/// NaN back to the default, so accepting one would look like an override that did
/// nothing.
fn sweep_fraction_override() -> anyhow::Result<Option<f64>> {
    const ENV: &str = "FILETHING_GC_MAX_SWEEP_FRACTION";
    let Some(raw) = std::env::var(ENV).ok().filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let fraction: f64 = raw
        .trim()
        .parse()
        .with_context(|| format!("{ENV} must be a fraction between 0 and 1, got {raw:?}"))?;
    anyhow::ensure!(
        fraction.is_finite() && (0.0..=1.0).contains(&fraction),
        "{ENV} must be a fraction between 0 and 1 (1 disables the guard), got {raw:?}"
    );
    Ok(Some(fraction))
}

/// Renders a failure to open a Space for a ONE-SHOT command.
///
/// [`EngineError::SpaceLocked`] is not a bug: another process (almost always the
/// background daemon) holds this Space's `flock(2)`, and the engine fails fast
/// instead of racing it into a Revision built from a half-applied tree. Its own
/// message says who holds the lock, so all this adds is what to do about it — under
/// no `opening Space` context, which would make a normal, expected refusal read like
/// a broken index.
fn open_space_error(root: &Path, err: EngineError) -> anyhow::Error {
    match err {
        EngineError::SpaceLocked { .. } => anyhow::anyhow!(
            "{err}\n  \u{2192} the background daemon usually holds it, and it is already syncing \
             this Space — `filething status {}` shows where it is at. To run one-shot commands \
             here instead, stop the service (`filething service uninstall`).",
            root.display()
        ),
        other => anyhow::Error::new(other).context("opening Space"),
    }
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

/// `update` — self-update this binary to the latest GitHub Release.
///
/// Uses axoupdater against the install receipt the shell installer wrote
/// (`~/.config/filething/filething-receipt.json`), so it only works for
/// installer-based installs — a `cargo install`/source build has no receipt and
/// gets a pointer to the installer instead. The receipt's recorded version is
/// overridden with this binary's own so a stale receipt can't mask an update.
/// After a successful swap the daemon service (if installed) is restarted so
/// the background sync runs the new binary, not the deleted old one.
pub async fn update() -> anyhow::Result<()> {
    let mut updater = axoupdater::AxoUpdater::new_for("filething");
    updater.load_receipt().context(
        "no install receipt found — `filething update` only works when filething was \
         installed with the official installer. Re-run the installer from \
         https://github.com/jrizo0/filething/releases to update (or reinstall)",
    )?;
    updater.set_current_version(
        env!("CARGO_PKG_VERSION")
            .parse()
            .context("parsing this binary's own version")?,
    )?;

    match updater.run().await.context("running the self-update")? {
        Some(result) => {
            println!(
                "filething updated: {} -> {} (installed at {})",
                env!("CARGO_PKG_VERSION"),
                result.new_version,
                result.install_prefix
            );
            // The launchd/systemd service keeps the OLD binary running (the
            // daemon process survives the file swap); restart it onto the new
            // one. Best-effort, like ensure_background_daemon: the update
            // itself already succeeded.
            if crate::service::is_installed() {
                match crate::service::restart() {
                    Ok(()) => println!("daemon: restarted on the new binary"),
                    Err(e) => {
                        tracing::warn!("could not restart the daemon service: {e:#}");
                        println!(
                            "daemon: could not restart automatically; run \
                             `filething service install` to restart it on the new binary"
                        );
                    }
                }
            }
        }
        None => println!(
            "filething {} is already the latest version",
            env!("CARGO_PKG_VERSION")
        ),
    }
    Ok(())
}

/// Makes sure the daemon keeps running in the background after a successful
/// `init`/`clone`/`sync`, so day-to-day use never needs a separate `filething
/// service install` step (`TODO.md` Fase 6, "daemon por defecto"). ALWAYS
/// best-effort: no failure is ever propagated — the command that called this
/// already succeeded and must not fail because of it. What it does NOT do is stay
/// quiet: whether the background sync is really running is the user's business, so
/// the outcome is VERIFIED and reported (see [`report_daemon_state`] /
/// [`report_daemon_failure`]), with the technical detail left to `tracing::warn!`.
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
            Ok(()) => report_daemon_state("installed"),
            Err(e) => report_daemon_failure("install", &e),
        }
        return;
    }

    if new_space {
        match crate::service::restart() {
            Ok(()) => report_daemon_state("restarted to pick up the new Space"),
            Err(e) => report_daemon_failure("restart", &e),
        }
    } else if !crate::service::is_running() {
        match crate::service::restart() {
            Ok(()) => report_daemon_state("was stopped; restarted"),
            Err(e) => report_daemon_failure("start", &e),
        }
    }
}

/// Reports the daemon state after [`ensure_background_daemon`] acted — VERIFIED,
/// not assumed.
///
/// `launchctl load` / `systemctl enable --now` exiting 0 only means the supervisor
/// accepted the job; the daemon can still fail to come up (a bad env file, a unit
/// that will not start, no `loginctl enable-linger`). Claiming "running in
/// background" without checking told the user their files were syncing when
/// nothing was.
fn report_daemon_state(what: &str) {
    if service_came_up() {
        println!("daemon: running in background ({what})");
        return;
    }
    println!(
        "daemon: WARNING — the service was {what} but is NOT running, so nothing is syncing in \
         the background yet."
    );
    println!(
        "  \u{2192} run `filething service status` to see why (it reports the last exit code and \
         the tail of the daemon log), or `filething sync <dir>` meanwhile."
    );
}

/// Reports that a service lifecycle step failed, on stdout as well as in the log:
/// this is the difference between "your folders keep syncing by themselves" and
/// "they do not", so it must not depend on the log level in effect.
fn report_daemon_failure(action: &str, err: &anyhow::Error) {
    tracing::warn!("could not {action} the background daemon service: {err:#}");
    println!("daemon: could not {action} the background service ({err})");
    println!(
        "  \u{2192} nothing is syncing in the background; run `filething service install` to \
         retry, or `filething sync <dir>` by hand."
    );
}

/// Whether the service actually came up, polling briefly because both supervisors
/// load asynchronously — `launchctl load` returns before the job is spawned, and a
/// systemd unit reaches `active` a moment after `enable --now`. Blocking is fine
/// here: this is the last step of a one-shot command that has nothing left to do.
fn service_came_up() -> bool {
    const TRIES: usize = 6;
    const WAIT: Duration = Duration::from_millis(250);
    for attempt in 0..TRIES {
        if crate::service::is_running() {
            return true;
        }
        if attempt + 1 < TRIES {
            std::thread::sleep(WAIT);
        }
    }
    false
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

    /// The SIGINT disposition is armed only for the duration of the password
    /// prompt: whatever it replaced must be back once the guard is dropped, or
    /// Ctrl-C would keep re-raising through this handler for the rest of the run.
    /// (Under `cargo test` stdin is not a terminal, so `arm` also has to be a
    /// harmless no-op.)
    #[test]
    fn sigint_restore_puts_the_previous_disposition_back() {
        // SAFETY: single-signal disposition calls; no other test touches SIGINT.
        unsafe {
            sigint_ffi::signal(sigint_ffi::SIGINT, sigint_ffi::SIG_DFL);
            let guard = SigintRestore::arm();
            drop(guard);
            let after = sigint_ffi::signal(sigint_ffi::SIGINT, sigint_ffi::SIG_DFL);
            assert_eq!(after, sigint_ffi::SIG_DFL, "SIGINT was left hooked");
        }
        assert!(
            !TERMIOS_SAVED.load(std::sync::atomic::Ordering::SeqCst),
            "the saved terminal state must not outlive the prompt"
        );
    }

    /// `auth:ensureDevice` keys Devices by NAME, so the default must be this
    /// machine's real hostname — `$HOSTNAME` is not exported on macOS or under
    /// launchd/systemd, and falling back to one shared constant merged every
    /// machine into a single Device record.
    #[test]
    fn default_device_name_uses_the_real_hostname_not_a_shared_constant() {
        let host = machine_hostname().expect("gethostname(2) works on macOS and Linux");
        assert!(!host.is_empty());
        assert_ne!(host, "filething-device");
        // With no exported $HOSTNAME (the normal case) the OS hostname is used…
        assert_eq!(device_name_from(None, Some(&host)), host);
        // …and an explicitly exported one still wins over it.
        assert_eq!(device_name_from(Some("box-7"), Some(&host)), "box-7");
    }

    /// If NO hostname can be had at all, the generated name must still be unique
    /// per machine: a duplicate Device record is recoverable, two machines silently
    /// sharing one is not.
    #[test]
    fn device_name_fallback_is_unique_instead_of_a_shared_constant() {
        let a = device_name_from(None, None);
        let b = device_name_from(None, None);
        assert_ne!(a, "filething-device");
        assert!(a.starts_with("filething-device-"), "unexpected name: {a}");
        assert_ne!(a, b, "the fallback name must not be a shared constant");
    }

    /// A hostname is trimmed and loses the trailing dot of an FQDN; nothing usable
    /// left is `None` (so the caller falls through instead of naming the Device "").
    #[test]
    fn clean_hostname_rejects_blank_and_trims_fqdn_dot() {
        assert_eq!(
            clean_hostname("  mac.local \n").as_deref(),
            Some("mac.local")
        );
        assert_eq!(
            clean_hostname("host.example.com.").as_deref(),
            Some("host.example.com")
        );
        assert_eq!(clean_hostname("   "), None);
        assert_eq!(clean_hostname(""), None);
    }

    /// The password gates the escrowed `space_key`/`dedup_secret`, so an
    /// interactive read must be HIDDEN — while the piped-stdin path (CI, `echo pw |
    /// filething login`) keeps reading verbatim, and a terminal where echo cannot be
    /// turned off is warned about rather than silently echoing.
    #[test]
    fn echo_plan_hides_an_interactive_password_and_keeps_the_piped_path() {
        assert_eq!(echo_plan(true, true), EchoPlan::Hidden);
        assert_eq!(echo_plan(false, false), EchoPlan::PipedStdin);
        assert_eq!(echo_plan(true, false), EchoPlan::EchoUnavailable);
    }

    /// The clone guard's notion of "not empty": anything the user put there counts,
    /// filething's own control dir and platform junk do not (refusing on a Finder
    /// `.DS_Store` would be a pure false alarm), and a folder that does not exist
    /// yet is empty rather than an error.
    #[test]
    fn absorbable_entries_ignores_the_control_dir_and_platform_junk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(absorbable_entries(&root.join("not-created-yet"))
            .unwrap()
            .is_empty());
        assert!(absorbable_entries(root).unwrap().is_empty());

        std::fs::create_dir_all(root.join(env::CONTROL_DIR)).unwrap();
        std::fs::write(root.join(".DS_Store"), b"junk").unwrap();
        assert!(
            absorbable_entries(root).unwrap().is_empty(),
            "the control dir and platform junk are not the user's files"
        );

        std::fs::write(root.join("taxes.pdf"), b"mine").unwrap();
        std::fs::create_dir_all(root.join("notes")).unwrap();
        assert_eq!(
            absorbable_entries(root).unwrap(),
            vec!["notes".to_string(), "taxes.pdf".to_string()]
        );
    }

    /// A Space may be created neither INSIDE an existing Space nor AROUND one: two
    /// engines over the same files overwrite each other.
    #[test]
    fn nested_space_conflict_refuses_both_an_ancestor_and_a_descendant_space() {
        let dir = tempfile::tempdir().unwrap();
        let outer = dir.path().join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).unwrap();

        let mut config = Config::default();
        assert!(nested_space_conflict(&inner, &config).is_none());

        // An ancestor is already a Space: refuse, and say which one.
        config.upsert_space("sp_outer", &outer.to_string_lossy());
        let msg = nested_space_conflict(&inner, &config).expect("nesting must be refused");
        assert!(msg.contains("INSIDE"), "unexpected message: {msg}");
        assert!(msg.contains("sp_outer"), "unexpected message: {msg}");

        // The other direction: the target CONTAINS a mapped Space.
        let mut config = Config::default();
        config.upsert_space("sp_inner", &inner.to_string_lossy());
        let msg = nested_space_conflict(&outer, &config).expect("nesting must be refused");
        assert!(msg.contains("CONTAINS"), "unexpected message: {msg}");
        assert!(msg.contains("sp_inner"), "unexpected message: {msg}");

        // The Space's OWN root is not nested inside itself.
        let mut config = Config::default();
        config.upsert_space("sp_inner", &inner.to_string_lossy());
        assert!(nested_space_conflict(&inner, &config).is_none());
    }

    /// `status` must never imply a Space is being synced when nothing watches it:
    /// only the fully-healthy combination reads as "watching".
    #[test]
    fn daemon_watch_line_only_claims_watching_when_something_actually_is() {
        let watching = DaemonWatch {
            installed: true,
            running: true,
            mapped: true,
        };
        assert!(watching.line().starts_with("watching this Space"));

        for (installed, running, mapped) in [
            (true, true, false),
            (true, false, true),
            (false, false, true),
            (false, false, false),
        ] {
            let w = DaemonWatch {
                installed,
                running,
                mapped,
            };
            assert!(
                w.line().contains("NOT"),
                "({installed},{running},{mapped}) must not read as healthy: {}",
                w.line()
            );
        }
    }

    /// The encryption state is reported, and the two cases are distinguishable — a
    /// legacy cleartext Space used to look exactly like an `alg=1` one.
    #[test]
    fn encryption_line_distinguishes_alg1_from_a_legacy_cleartext_space() {
        assert!(encryption_line(true).contains("alg=1"));
        assert!(encryption_line(false).contains("cleartext"));
        assert_ne!(encryption_line(true), encryption_line(false));
    }

    /// A second `login` as a different Account is a REBIND (orphaning the mappings
    /// of the old one); the same identity re-typed, in any case, is not.
    #[test]
    fn rebinds_account_only_when_the_identity_actually_changes() {
        assert!(rebinds_account("a@example.com", "b@example.com"));
        assert!(rebinds_account("acc_1", "acc_2"));
        assert!(!rebinds_account("a@example.com", "a@example.com"));
        assert!(!rebinds_account("A@Example.com", " a@example.com "));
    }

    /// An explicitly-set `CONVEX_URL` that disagrees with the stored one is
    /// REPORTED (it used to be ignored in silence); agreement — trailing slash and
    /// all — stays quiet, and so does having no config yet.
    #[test]
    fn coordinator_url_mismatch_is_reported_instead_of_silently_ignored() {
        let m = coordinator_url_mismatch(
            Some("https://stored.convex.cloud"),
            Some("http://localhost:3210"),
        )
        .expect("a disagreement must be reported");
        assert!(m.contains("localhost:3210"), "unexpected warning: {m}");
        assert!(m.contains("stored.convex.cloud"), "unexpected warning: {m}");
        assert!(
            m.contains("WINS"),
            "the warning must say which one is used: {m}"
        );

        assert!(coordinator_url_mismatch(
            Some("https://x.convex.cloud/"),
            Some("https://x.convex.cloud")
        )
        .is_none());
        assert!(coordinator_url_mismatch(None, Some("https://x.convex.cloud")).is_none());
        assert!(coordinator_url_mismatch(Some("https://x.convex.cloud"), None).is_none());
    }

    /// A gc REFUSAL is a safety guard declining, so its own explanation must reach
    /// the user intact — not buried under a `gc:` context that reads like plumbing —
    /// and it must stay an error, never a report that looks like an empty sweep.
    #[test]
    fn gc_error_surfaces_a_refusal_verbatim() {
        let refused = gc_error(EngineError::Refused(
            "gc: the logged-in Account owns NO Spaces, so the sweep would delete the entire bucket"
                .to_string(),
        ));
        assert_eq!(
            refused.to_string(),
            "gc: the logged-in Account owns NO Spaces, so the sweep would delete the entire bucket"
        );
        // Anything else keeps its context so the cause chain still reads.
        let other = gc_error(EngineError::MetaBlob("bad cbor".to_string()));
        assert_eq!(other.to_string(), "gc");
        assert!(other.chain().any(|c| c.to_string().contains("bad cbor")));
    }

    /// The sweep-fraction override parses a real fraction and REJECTS anything else
    /// instead of silently keeping the default — including a NaN, which the engine
    /// maps back to the default and which would therefore look like an override
    /// that did nothing. (Mutates its own env var, like `config`'s tests.)
    #[test]
    fn sweep_fraction_override_rejects_anything_that_is_not_a_fraction() {
        const ENV: &str = "FILETHING_GC_MAX_SWEEP_FRACTION";
        let saved = std::env::var(ENV).ok();
        std::env::remove_var(ENV);
        assert_eq!(sweep_fraction_override().unwrap(), None);

        std::env::set_var(ENV, "0.9");
        assert_eq!(sweep_fraction_override().unwrap(), Some(0.9));
        std::env::set_var(ENV, "1");
        assert_eq!(sweep_fraction_override().unwrap(), Some(1.0));
        for bad in ["nan", "-0.1", "1.5", "half", "0.5x"] {
            std::env::set_var(ENV, bad);
            assert!(
                sweep_fraction_override().is_err(),
                "{bad:?} must be rejected, not silently ignored"
            );
        }

        match saved {
            Some(v) => std::env::set_var(ENV, v),
            None => std::env::remove_var(ENV),
        }
    }

    /// A Space held by another process is an expected refusal with its own clear
    /// message plus what to do; anything else keeps the `opening Space` context.
    #[test]
    fn open_space_error_explains_a_locked_space() {
        let locked = open_space_error(
            Path::new("/home/u/proj"),
            EngineError::SpaceLocked {
                root: "/home/u/proj".to_string(),
                holder: "pid 4242".to_string(),
            },
        );
        let msg = locked.to_string();
        assert!(msg.contains("pid 4242"), "unexpected message: {msg}");
        assert!(msg.contains("daemon"), "unexpected message: {msg}");
        assert!(
            !msg.starts_with("opening Space"),
            "unexpected message: {msg}"
        );

        let other = open_space_error(
            Path::new("/home/u/proj"),
            EngineError::SpaceState("no row".to_string()),
        );
        assert_eq!(other.to_string(), "opening Space");
    }

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
