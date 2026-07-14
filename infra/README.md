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
cp infra/.env.example infra/.env     # edit if you want non-default creds
infra/scripts/up.sh                  # compose up -d + create bucket + print env
```

`up.sh` starts the containers, waits for MinIO to go healthy, creates the Vault
bucket (idempotent), then prints the endpoints. To create the bucket manually:

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

## Ports

| Service            | Host port | Purpose                                   |
| ------------------ | --------- | ----------------------------------------- |
| MinIO API          | `9000`    | S3 endpoint the Rust `ft-vault` talks to  |
| MinIO console      | `9001`    | Web UI for the Vault                      |
| Convex backend API | `3210`    | `CONVEX_URL` — `ft-coordinator` + CLI     |
| Convex site proxy  | `3211`    | Convex HTTP actions                       |
| Convex dashboard   | `6791`    | Web UI for the Coordinator                |

All host ports are overridable via `infra/.env` (`*_PORT` vars).

## What it exports to the rest of the system

`infra/scripts/print-env.sh` prints (and, with `--exports`, emits as shell
`export`s) the values the Rust client reads:

```bash
eval "$(infra/scripts/print-env.sh --exports)"
```

| Variable        | Used by                | Local value (default)   |
| --------------- | ---------------------- | ----------------------- |
| `S3_ENDPOINT`   | `ft-vault` (S3 backend)| `http://localhost:9000` |
| `S3_REGION`     | `ft-vault`             | `us-east-1`             |
| `S3_ACCESS_KEY` | `ft-vault`             | `minioadmin`            |
| `S3_SECRET_KEY` | `ft-vault`             | `minioadmin`            |
| `S3_BUCKET`     | `ft-vault`             | `filething`             |
| `CONVEX_URL`    | `ft-coordinator`       | `http://localhost:3210` |

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
