#!/usr/bin/env bash
# Bring up the filething local infra (Vault + Coordinator) and create the bucket.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${INFRA_DIR}/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo ">> infra/.env not found — creating it from infra/.env.example"
  cp "${INFRA_DIR}/.env.example" "${ENV_FILE}"
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
