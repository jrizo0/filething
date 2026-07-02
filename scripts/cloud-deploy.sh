#!/usr/bin/env bash
# filething — despliega el Coordinator (schema + funciones Convex) a Convex Cloud.
# Lee las credenciales de infra/.env.cloud (NO commiteado). Idempotente y seguro de
# reejecutar: vuelve a publicar el mismo schema/funciones sin efectos secundarios.
# No hardcodea secretos. Guía completa: docs/PRODUCTION-SETUP.md
set -euo pipefail

# Raíz del repo relativa a este script (funciona desde cualquier cwd y en worktrees).
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO/infra/.env.cloud"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: no existe $ENV_FILE" >&2
  echo "  Copia la plantilla y rellénala (guía: docs/PRODUCTION-SETUP.md):" >&2
  echo "    cp infra/.env.cloud.example infra/.env.cloud" >&2
  exit 1
fi

# Carga las credenciales de la nube al entorno (S3_* y CONVEX_*).
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# Verifica las dos variables imprescindibles para el deploy del Coordinator.
: "${CONVEX_URL:?falta CONVEX_URL en infra/.env.cloud (URL del deployment Convex Cloud, https://<name>.convex.cloud)}"
: "${CONVEX_DEPLOY_KEY:?falta CONVEX_DEPLOY_KEY en infra/.env.cloud (dashboard: Project Settings > Deploy Keys > Generate Production Deploy Key)}"

echo ">> Desplegando packages/backend a Convex Cloud"
echo "   CONVEX_URL = $CONVEX_URL"

# `convex deploy` toma el deployment del propio deploy key; lo exportamos y usamos
# -y (no interactivo). Se ejecuta desde packages/backend, en un subshell para no
# alterar el cwd del que invoca.
export CONVEX_DEPLOY_KEY
( cd "$REPO/packages/backend" && bunx convex deploy -y )

echo ">> OK: Coordinator desplegado. Valida con: scripts/cloud-smoke.sh"
