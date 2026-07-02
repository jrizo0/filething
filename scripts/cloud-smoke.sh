#!/usr/bin/env bash
# filething — smoke test de la infra GESTIONADA (Convex Cloud + Cloudflare R2).
# Ejercita el bucle vertical entre dos "Devices" (dos FILETHING_HOME + dos carpetas)
# contra la nube, SIN Docker/MinIO/mc (no existen contra R2/Convex Cloud). Valida:
#   login (pairing) -> init(+archivo) -> clone -> edición -> sync round-trip.
# Prerrequisitos: infra/.env.cloud relleno (guía: docs/PRODUCTION-SETUP.md) y el
# backend ya desplegado con scripts/cloud-deploy.sh.
set -euo pipefail

# Raíz del repo relativa a este script (funciona desde cualquier cwd y en worktrees).
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO/infra/.env.cloud"
BIN="$REPO/target/release/filething"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ft-cloud-smoke.XXXXXX")"
A_HOME="$WORK/devA-home"; B_HOME="$WORK/devB-home"
A_DIR="$WORK/dirA";       B_DIR="$WORK/dirB"

FAILED=0
ok()  { echo "  ✓ $*"; }
bad() { echo "  ✗ $*"; FAILED=1; }
hr()  { echo; echo "==================== $* ===================="; }
cleanup() { command rm -rf "$WORK"; }
trap cleanup EXIT

# Dos Devices = dos FILETHING_HOME distintos sobre el mismo binario.
a() { FILETHING_HOME="$A_HOME" "$BIN" "$@"; }
b() { FILETHING_HOME="$B_HOME" "$BIN" "$@"; }

# --- entorno: credenciales de la nube ---
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: no existe $ENV_FILE — cópialo de infra/.env.cloud.example y rellénalo" >&2
  echo "  (guía: docs/PRODUCTION-SETUP.md)" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

hr "BUILD — binario release (target/release/filething)"
( cd "$REPO" && cargo build --release -p filething )
[ -x "$BIN" ] || { echo "ERROR: no se construyó $BIN" >&2; exit 1; }

mkdir -p "$A_HOME" "$B_HOME" "$A_DIR" "$B_DIR"

hr "PASO 1 — login A (bootstrap) + login B (claim por código)"
OUT_A=$(a login --name device-a-cloud); echo "$OUT_A"
# Anclado a "--code XXXX" (mismo criterio que scripts/demo-gates.sh): un grep suelto
# de [A-Z0-9]{6,} podría capturar dígitos del account id impreso arriba.
CODE=$(echo "$OUT_A" | sed -n 's/.*--code \([A-Z0-9]\{1,\}\).*/\1/p' | head -1)
if [ -n "$CODE" ]; then ok "A generó pairing code ($CODE)"; else bad "A no imprimió pairing code"; echo "SMOKE FAIL"; exit 1; fi
b login --code "$CODE" --name device-b-cloud; echo
ok "B se emparejó con el código"

hr "PASO 2 — A init (con archivo) + B clone => el archivo aparece en B"
mkdir -p "$A_DIR/src"
echo "hola desde la nube" > "$A_DIR/hello.txt"
echo "fn main() {}" > "$A_DIR/src/main.rs"
OUT_INIT=$(a init "$A_DIR" --name smoke-cloud); echo "$OUT_INIT"
SPACE=$(echo "$OUT_INIT" | grep -oE '[a-z0-9]{30,}' | head -1)
if [ -n "$SPACE" ]; then ok "init creó el Space ($SPACE)"; else bad "init no devolvió space_id"; echo "SMOKE FAIL"; exit 1; fi
b clone "$SPACE" "$B_DIR"; echo
# Que B == A tras el clone valida commit + change feed + round-trip por R2 contra la nube.
if diff -r "$A_DIR" "$B_DIR" -x .filething >/dev/null; then
  ok "B == A tras clone (commit + change feed + round-trip R2 OK)"
else
  bad "B != A tras clone"
fi

hr "PASO 3 — A edita + sync, B sync => B ve la edición"
echo "línea añadida en A" >> "$A_DIR/hello.txt"
a sync "$A_DIR" >/dev/null
b sync "$B_DIR" >/dev/null
if diff "$A_DIR/hello.txt" "$B_DIR/hello.txt" >/dev/null; then
  ok "B recibió la edición de hello.txt"
else
  bad "B no refleja la edición de hello.txt"
fi

hr "PASO 4 (sanity) — filething gc --keep-all (dry-run)"
# gc es dry-run por defecto; --keep-all no borra nada. Best-effort: si el binario aún
# no trae el subcomando `gc` (se está añadiendo), esto NO tumba el smoke.
if a gc "$A_DIR" --keep-all; then
  ok "gc (dry-run, --keep-all) ejecutó"
else
  echo "  (aviso) 'filething gc' no disponible o falló — sanity omitido (no cuenta como fallo)"
fi

hr "RESULTADO"
if [ "$FAILED" -eq 0 ]; then
  echo "SMOKE OK: login + init + clone + edit/sync contra Convex Cloud + Cloudflare R2."
  exit 0
else
  echo "SMOKE FAIL: revisa los ✗ de arriba."
  exit 1
fi
