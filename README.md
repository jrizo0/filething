# filething

Sync your developer folders across your own machines, with client-side encryption and no vendor lock-in.

## What is filething

filething is a command-line tool that keeps a folder ("Space") identical across your machines — think a developer-focused, self-hostable sync tool rather than a general file-sharing product. Files are chunked and encrypted client-side before upload; the server never sees plaintext or storage credentials. Divergent edits are reconciled per file against the common base: text files whose changes don't overlap (appends, edits in separate line regions) are auto-merged by content, and anything that does overlap — or any binary file — is kept as a conflict copy instead of "last write wins." There is no GUI: everything is driven from the `filething` binary and an optional background daemon.

## Install

```
curl -fsSL https://github.com/jrizo0/filething/releases/latest/download/filething-installer.sh | sh
```

Supported platforms: macOS (Apple Silicon and Intel) and Linux (x86_64 and arm64). Windows is not supported yet.

To upgrade later, run `filething update` — it replaces the binary with the latest GitHub release and restarts the daemon service. (It only works for installs made by the script above; a `cargo build` checkout upgrades with `git pull` + rebuild.)

From source (requires [Rust](https://www.rust-lang.org/tools/install)):

```
cargo build --release -p filething
```

## Quickstart

On your first machine, create an account and turn a folder into a Space:

```
filething login --signup --email you@example.com --name my-laptop
filething init ~/projects/notes --name notes
```

`init` prints the Space id. On another machine, log in to the same account and clone the Space:

```
filething login --email you@example.com --name my-desktop
filething clone <space_id> ~/notes
```

> Signup on the managed deployment is closed by default: the operator opens it (`FILETHING_ALLOW_SIGNUP=1`) long enough to create an account, then closes it again. There is no per-invite gate yet — the flag is on or off for everyone. Self-hosting (see below) has no such restriction.

The password is read from `$FILETHING_PASSWORD` (useful in scripts) or prompted for interactively.

After a successful `init`, `clone` or `sync`, filething installs and starts the background
daemon as an OS service automatically (launchd on macOS, systemd --user on Linux), so your
Spaces keep syncing without any extra step. Opt out with `--no-daemon` on the command, or
`FILETHING_NO_AUTO_DAEMON=1` in the environment. You can still drive things manually:

```
filething sync ~/notes            # one-shot: pull, then commit local changes
filething daemon                  # continuous sync of every mapped Space, in the foreground
filething service status          # check the background service (install/uninstall also available)
```

Check on things with:

```
filething status ~/notes          # synced base + whether there are uncommitted local changes
filething ls ~/notes              # list the Space's synced paths
filething metrics                 # sync counters (commits, pulls, conflicts, staleness) for every mapped Space
```

## Commands

| Command | What it does |
|---|---|
| `login` | Authenticate this Device (Better Auth) and register it with the account. `--signup` creates the account; a second Device just logs in to the existing one. |
| `whoami` | Show who this Device is logged in as, its own name and id, and the Coordinator URL. Local config only, no network. |
| `spaces` | List the account's Spaces, marking which are mapped to a folder on this Device — so a Space id never has to be copied by hand. |
| `init <dir>` | Turn a local folder into a new Space and commit its first Revision. |
| `clone <space_id> <dir>` | Materialize an existing Space into a local folder. |
| `unmap <dir>` | Stop syncing a Space on this Device, keeping the local files. The Space and its history stay on the Coordinator and your other Devices. |
| `status [dir]` | Show a Space's synced base and whether it has uncommitted local changes. |
| `ls [dir]` | List a Space's synced paths, from the local index. |
| `sync <dir>` | One-shot: pull the head, then commit local changes. |
| `daemon [dir]...` | Run the foreground daemon; with no dirs, over every mapped Space (what the OS service runs). |
| `gc <dir>` | Garbage-collect the account's Vault (dry-run by default; pass `--apply` to delete). |
| `metrics [dir]` | Show sync metrics for a Space, or every mapped Space. |
| `service <install\|uninstall\|status>` | Manage the daemon as an OS service (launchd on macOS, systemd --user on Linux). |
| `update` | Upgrade filething itself to the latest GitHub release and restart the daemon service. Requires an install made by the installer script. |

Run `filething <command> --help` for the full flag list.

## How it works

A Space is synced as content-addressed blocks: files are split with FastCDC (content-defined chunking), and each block is addressed by the hash of its stored (encrypted) bytes. Deduplication is keyed by a per-account secret over the plaintext hash, so identical content dedupes across your Devices without leaking content hashes across accounts. Convex is the control plane — it only stores small pointers and metadata (the Space head, the Revision chain), never file bytes. Cloudflare R2 (or any S3-compatible store) is the data plane: the client asks Convex for a short-lived (15-minute) presigned URL per object and talks to storage directly, so it never holds storage credentials. Client-side encryption (`alg=1`, XChaCha20-Poly1305) is on by default for new Spaces. When two Devices edit the same file offline, reconciliation is a three-way merge against the last common version (`§10`): for text files whose edits don't overlap, the two sides are fused into one file automatically; when the edits touch the same lines, or the file is binary, both versions are kept (the remote wins the real path and your local edit is preserved as a conflict copy) — never "last write wins," never silent data loss. Each Space respects a `.filethingignore` file for excluded paths.

See `docs/format.md` for the normative block/manifest format and `docs/adr/` for the individual design decisions.

## Self-hosting

The entire stack is self-hostable: Convex can run self-hosted, and the data plane works with any S3-compatible store. `infra/docker-compose.yml` brings up a local Convex + MinIO stack for development. If you set the `S3_*` environment variables directly, the CLI talks to storage with those credentials instead of asking Convex for presigned URLs — useful for self-hosted and operator setups. See `docs/PRODUCTION-SETUP.md` for a full runbook (including moving to Convex Cloud + Cloudflare R2).

## Status / roadmap

filething is an MVP undergoing hardening. It currently supports a single user syncing across their own Devices — there is no sharing between accounts yet — and there is no Windows build. See `TODO.md` for the current state and what's left.

## License

MIT
