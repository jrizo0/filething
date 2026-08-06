# filething — local infra

Local stand-in for production. Two services, each behind the same abstraction
the production system uses, so switching to managed infra is a config change
only (see [Going to managed infra](#going-to-managed-infra-r2--convex-cloud)).

- **Vault** — MinIO (S3-compatible). The data plane that holds `Block`s
  (`blocks/`, `manifest/`, `blocklist/` under one bucket).
- **Coordinator** — Convex backend self-hosted. The control plane: `Space head`,
  the `Revision` chain, auth (Better Auth, on the `:3211` HTTP-actions proxy) and
  the change feed. It never sees file bytes.
- **Convex dashboard** (optional) — web UI for the local Coordinator.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose`, not `docker-compose`).
- No `mc` / `aws` needed on the host — the bucket script runs `mc` in a container.

## Bring it up

```bash
infra/scripts/up.sh                  # generates infra/.env + compose up -d + bucket + print env
```

`up.sh` creates `infra/.env` from `.env.example` **with generated credentials**
(do not `cp` the template yourself — see [Credentials](#credentials)), starts the
containers, waits for MinIO to go healthy, creates the Vault bucket (idempotent),
then prints the endpoints. To create the bucket manually:

```bash
infra/scripts/create-bucket.sh
```

Tear down (keep data):

```bash
docker compose --project-directory infra --env-file infra/.env down
```

Tear down and wipe volumes:

```bash
docker compose --project-directory infra --env-file infra/.env down -v
```

## Credentials

Every credential in this stack is **generated on first `up.sh`**, never shipped:

| Variable                                        | Where it comes from                            |
| ----------------------------------------------- | ---------------------------------------------- |
| `MINIO_ROOT_USER` / `S3_ACCESS_KEY`             | `up.sh` (random hex)                           |
| `MINIO_ROOT_PASSWORD` / `S3_SECRET_KEY`         | `up.sh` (random hex) — same pair as the root user |
| `CONVEX_INSTANCE_SECRET`                        | `up.sh` (`openssl rand -hex 32`)               |
| `CONVEX_SELF_HOSTED_ADMIN_KEY`                  | the backend, after first boot (see below)      |

`.env.example` ships `REPLACE_ME` in each of those slots and `up.sh` **refuses to
start** while one is still there, so there is no configuration in which this stack
boots with a credential an attacker could know. It used to ship
`minioadmin`/`minioadmin` and a 64-zero instance secret — and the instance secret
is what the admin key derives from, i.e. that combination handed over the whole
deployment to anyone who could reach a port.

An `infra/.env` created **before** this change still holds the old shipped
defaults, so `up.sh` also refuses to boot on `minioadmin` or an all-zero
`CONVEX_INSTANCE_SECRET`. To rotate: `rm infra/.env && infra/scripts/up.sh`, then
regenerate the admin key from the backend. Rotating the instance secret may need
the Convex volume recreated (`docker compose --project-directory infra down -v`),
because the backend ties its persisted instance to that secret. To boot on the old
values anyway — deliberately, on a host you trust:
`FT_ALLOW_WEAK_CREDS=1 infra/scripts/up.sh`.

`infra/.env` is gitignored and written mode `600`. Never paste its values into a
tracked file (`diary/2026-06-25.md` leaked a real admin key exactly that way; CI
now runs gitleaks over the tree on every push).

## Ports

| Service            | Host port | Purpose                                   |
| ------------------ | --------- | ----------------------------------------- |
| MinIO API          | `9000`    | S3 endpoint the Rust `ft-vault` talks to  |
| MinIO console      | `9001`    | Web UI for the Vault                      |
| Convex backend API | `3210`    | `CONVEX_URL` — `ft-coordinator` + CLI     |
| Convex site proxy  | `3211`    | Convex HTTP actions                       |
| Convex dashboard   | `6791`    | Web UI for the Coordinator                |

All host ports are overridable via `infra/.env` (`*_PORT` vars).

**Every one of them binds to `127.0.0.1` only** (`FT_BIND_ADDR`, default
`127.0.0.1`). MinIO's console, the Convex backend and the Convex dashboard are
admin surfaces; publishing them on `0.0.0.0` — which is what this compose used to
do — exposes them to the whole network. Reach them from another machine through
an SSH tunnel (`docs/MAC-SETUP.md` §3):

```bash
ssh -N -L 9000:localhost:9000 -L 3210:localhost:3210 -L 3211:localhost:3211 user@host
```

If you really want them on the network, set `FT_BIND_ADDR=0.0.0.0` in
`infra/.env` — and firewall the host first.

## What it exports to the rest of the system

`infra/scripts/print-env.sh` prints (and, with `--exports`, emits as shell
`export`s) the values the Rust client reads:

```bash
eval "$(infra/scripts/print-env.sh --exports)"
```

| Variable        | Used by                | Local value              |
| --------------- | ---------------------- | ------------------------ |
| `S3_ENDPOINT`   | `ft-vault` (S3 backend)| `http://localhost:9000`  |
| `S3_REGION`     | `ft-vault`             | `us-east-1`              |
| `S3_ACCESS_KEY` | `ft-vault`             | generated (`infra/.env`) |
| `S3_SECRET_KEY` | `ft-vault`             | generated (`infra/.env`) |
| `S3_BUCKET`     | `ft-vault`             | `filething`              |
| `CONVEX_URL`    | `ft-coordinator`       | `http://localhost:3210`  |

The human-readable report hides the secret key (it ends up in terminal scrollback
and in gate logs); `--exports` still emits it, since that output is meant to be
`eval`'d, not read.

The MinIO S3 backend uses **path-style** addressing (`endpoint/bucket/key`),
which both MinIO and R2 support.

## Deploying the Coordinator schema (first boot)

The backend boots empty. To push `packages/backend/convex/schema.ts` to the
local Coordinator, point the Convex CLI at the self-hosted backend:

```bash
# Generate a self-hosted admin key from the running backend, then:
export CONVEX_SELF_HOSTED_URL=http://localhost:3210
export CONVEX_SELF_HOSTED_ADMIN_KEY=<key from the backend>
bun run --cwd packages/backend deploy   # or: dev (watch mode)
```

Put that key in `infra/.env` (it replaces the `REPLACE_ME-after-first-boot`
placeholder) so the scripts pick it up. It is a **root** credential: it derives
from `CONVEX_INSTANCE_SECRET` and grants full control of the deployment, so
rotating it means rotating the instance secret.

`bun run codegen` works offline for type generation once a deployment is
configured; with no deployment set it errors by design (no login is forced).

## Going to managed infra (R2 + Convex cloud)

No code changes — only config:

- **Vault → Cloudflare R2.** Point `S3_ENDPOINT` at the R2 S3 endpoint
  (`https://<account>.r2.cloudflarestorage.com`), set `S3_ACCESS_KEY` /
  `S3_SECRET_KEY` to an R2 API token, keep path-style. `ft-vault`'s S3 backend
  is unchanged.
- **Coordinator → Convex cloud.** Replace `CONVEX_URL` with the cloud
  deployment URL and deploy with `bunx convex deploy` (cloud) instead of the
  self-hosted env vars. The schema and functions are identical.

The MinIO and Convex-backend containers exist only for local dev; in managed
mode you simply do not run them.
