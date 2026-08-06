#!/usr/bin/env bash
# Bring up the filething local infra (Vault + Coordinator) and create the bucket.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${INFRA_DIR}/.env"

# openssl is the fast path; /dev/urandom + od is the fallback for a host without
# it (od is POSIX, xxd is not).
rand_hex() {
  local bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "${bytes}"
  else
    od -An -tx1 -N "${bytes}" /dev/urandom | tr -d ' \n'
  fi
}

# infra/.env used to be a verbatim `cp` of .env.example, which shipped
# minioadmin/minioadmin and a 64-zero INSTANCE_SECRET — so every stack that
# booted "out of the box" was ownable by anyone who could reach a port, and this
# compose has been run on a public VPS (diary/2026-06-25.md). Generate instead.
if [[ ! -f "${ENV_FILE}" ]]; then
  echo ">> infra/.env not found — creating it from infra/.env.example with generated credentials"
  MINIO_USER="ft$(rand_hex 8)"     # MinIO requires >= 3 chars; hex keeps it shell-safe
  MINIO_PASS="$(rand_hex 24)"      # MinIO requires >= 8 chars
  INSTANCE_SECRET="$(rand_hex 32)" # the backend requires EXACTLY 64 hex chars
  export MINIO_USER MINIO_PASS INSTANCE_SECRET

  # umask 077: this file holds the Vault's root credentials and the secret the
  # Coordinator's admin key derives from.
  (
    umask 077
    awk '
      /^MINIO_ROOT_USER=REPLACE_ME$/        { print "MINIO_ROOT_USER=" ENVIRON["MINIO_USER"]; next }
      /^S3_ACCESS_KEY=REPLACE_ME$/          { print "S3_ACCESS_KEY=" ENVIRON["MINIO_USER"]; next }
      /^MINIO_ROOT_PASSWORD=REPLACE_ME$/    { print "MINIO_ROOT_PASSWORD=" ENVIRON["MINIO_PASS"]; next }
      /^S3_SECRET_KEY=REPLACE_ME$/          { print "S3_SECRET_KEY=" ENVIRON["MINIO_PASS"]; next }
      /^CONVEX_INSTANCE_SECRET=REPLACE_ME$/ { print "CONVEX_INSTANCE_SECRET=" ENVIRON["INSTANCE_SECRET"]; next }
      { print }
    ' "${INFRA_DIR}/.env.example" >"${ENV_FILE}"
  )
  echo "   generated: MinIO root credentials (= S3 key pair) + CONVEX_INSTANCE_SECRET, mode 600"
fi

# Refuse to boot on a leftover placeholder rather than let compose interpolate it.
# CONVEX_SELF_HOSTED_ADMIN_KEY is exempt: the backend mints it FROM the instance
# secret on first boot, so it cannot be generated here (see infra/README.md).
# Only real assignments count — the header comments talk ABOUT REPLACE_ME.
LEFTOVER="$(grep -nE '^[A-Za-z_][A-Za-z0-9_]*=.*REPLACE_ME' "${ENV_FILE}" | grep -v 'CONVEX_SELF_HOSTED_ADMIN_KEY' || true)"
if [[ -n "${LEFTOVER}" ]]; then
  echo "ERROR: ${ENV_FILE} still has placeholder credentials:" >&2
  echo "${LEFTOVER}" >&2
  echo "  Fill them in, or delete infra/.env and re-run this script to generate them." >&2
  exit 1
fi

# An infra/.env created BEFORE this hardening still holds the defaults this repo
# used to ship (minioadmin / 64 zeros) — that is the population actually at risk,
# so generating for new users is not enough.
WEAK="$(grep -nE '^(MINIO_ROOT_USER|MINIO_ROOT_PASSWORD|S3_ACCESS_KEY|S3_SECRET_KEY)=minioadmin$|^CONVEX_INSTANCE_SECRET=0+$' "${ENV_FILE}" || true)"
if [[ -n "${WEAK}" && "${FT_ALLOW_WEAK_CREDS:-}" != "1" ]]; then
  echo "ERROR: ${ENV_FILE} uses credentials this repo used to ship as defaults:" >&2
  echo "${WEAK}" >&2
  cat >&2 <<EOF
  They are public knowledge, and CONVEX_INSTANCE_SECRET is what the Coordinator's
  admin key derives from. Rotate them:

    rm ${ENV_FILE} && infra/scripts/up.sh

  Rotating CONVEX_INSTANCE_SECRET invalidates the current admin key (regenerate it
  from the backend and put it back in infra/.env) and may need the Convex volume
  recreated (\`docker compose --project-directory infra down -v\`), since the
  backend ties its persisted instance to that secret.

  To boot anyway, deliberately: FT_ALLOW_WEAK_CREDS=1 infra/scripts/up.sh
EOF
  exit 1
fi

echo ">> Starting containers (docker compose up -d)..."
docker compose --project-directory "${INFRA_DIR}" --env-file "${ENV_FILE}" up -d

echo ">> Waiting for MinIO to become healthy..."
for _ in $(seq 1 30); do
  status="$(docker inspect -f '{{.State.Health.Status}}' filething-minio-1 2>/dev/null || echo starting)"
  [[ "${status}" == "healthy" ]] && break
  sleep 2
done

# Create the Vault bucket.
"${SCRIPT_DIR}/create-bucket.sh"

echo
"${SCRIPT_DIR}/print-env.sh"
