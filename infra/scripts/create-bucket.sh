#!/usr/bin/env bash
# Create the filething Vault bucket in the local MinIO.
#
# Runs the MinIO client (`mc`) inside a throwaway container on the compose
# network, so you need no `mc`/`aws` installed on the host. Idempotent:
# re-running it is safe (bucket already existing is not an error).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${INFRA_DIR}/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: ${ENV_FILE} not found — run infra/scripts/up.sh first (it generates it)." >&2
  exit 1
fi
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

# No minioadmin fallback: guessing at the credentials only ever produced a
# working bucket back when minioadmin WAS the credential.
: "${MINIO_ROOT_USER:?not set in ${ENV_FILE} — delete it and re-run infra/scripts/up.sh}"
: "${MINIO_ROOT_PASSWORD:?not set in ${ENV_FILE} — delete it and re-run infra/scripts/up.sh}"
S3_BUCKET="${S3_BUCKET:-filething}"

echo ">> Ensuring MinIO bucket '${S3_BUCKET}' exists..."

# Use the compose project network so 'minio' resolves by service name.
docker run --rm \
  --network filething_default \
  --entrypoint sh \
  minio/mc:latest -c "
    set -e
    mc alias set local http://minio:9000 '${MINIO_ROOT_USER}' '${MINIO_ROOT_PASSWORD}' >/dev/null
    mc mb --ignore-existing local/${S3_BUCKET}
    mc anonymous set none local/${S3_BUCKET} >/dev/null 2>&1 || true
    echo '   bucket ready: ${S3_BUCKET}'
  "

echo ">> Done."
