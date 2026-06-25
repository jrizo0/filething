#!/usr/bin/env bash
# Print the URLs and credentials the rest of filething needs to talk to the
# local infra. Copy/paste the export block into your shell, or `eval` this:
#     eval "$(infra/scripts/print-env.sh --exports)"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${INFRA_DIR}/.env"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

# Defaults mirror infra/.env.example.
S3_ENDPOINT="${S3_ENDPOINT:-http://localhost:9000}"
S3_REGION="${S3_REGION:-us-east-1}"
S3_ACCESS_KEY="${S3_ACCESS_KEY:-minioadmin}"
S3_SECRET_KEY="${S3_SECRET_KEY:-minioadmin}"
S3_BUCKET="${S3_BUCKET:-filething}"
CONVEX_URL="${CONVEX_URL:-http://localhost:3210}"
MINIO_CONSOLE_PORT="${MINIO_CONSOLE_PORT:-9001}"
CONVEX_DASHBOARD_PORT="${CONVEX_DASHBOARD_PORT:-6791}"

if [[ "${1:-}" == "--exports" ]]; then
  cat <<EOF
export S3_ENDPOINT="${S3_ENDPOINT}"
export S3_REGION="${S3_REGION}"
export S3_ACCESS_KEY="${S3_ACCESS_KEY}"
export S3_SECRET_KEY="${S3_SECRET_KEY}"
export S3_BUCKET="${S3_BUCKET}"
export CONVEX_URL="${CONVEX_URL}"
EOF
  exit 0
fi

cat <<EOF
filething local infra — endpoints & credentials
================================================

Vault (MinIO, S3 data plane)
  S3 endpoint   : ${S3_ENDPOINT}   (path-style)
  Region        : ${S3_REGION}
  Access key    : ${S3_ACCESS_KEY}
  Secret key    : ${S3_SECRET_KEY}
  Bucket        : ${S3_BUCKET}
  Web console   : http://localhost:${MINIO_CONSOLE_PORT}

Coordinator (Convex backend, control plane)
  Convex URL    : ${CONVEX_URL}
  Dashboard     : http://localhost:${CONVEX_DASHBOARD_PORT}

Export these for the Rust client (ft-vault / ft-coordinator):
  eval "\$(infra/scripts/print-env.sh --exports)"
EOF
