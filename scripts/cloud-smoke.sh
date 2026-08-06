#!/usr/bin/env bash
# filething — smoke test de la infra GESTIONADA (Convex Cloud + Cloudflare R2).
# Ejercita el bucle vertical entre dos "Devices" (dos FILETHING_HOME + dos carpetas)
# contra la nube, SIN Docker/MinIO/mc (no existen contra R2/Convex Cloud). Valida:
#   login (Better Auth: signup+login) -> init(+archivo) -> clone -> edición -> sync round-trip.
# Prerrequisitos: infra/.env.cloud relleno (guía: docs/PRODUCTION-SETUP.md) y el
# backend ya desplegado con scripts/cloud-deploy.sh.
set -euo pipefail

# Este smoke corre sync one-shot contra FILETHING_HOME's de usar y tirar; no debe
# instalar ningún servicio de daemon en la máquina que lo ejecuta (Fase 6).
export FILETHING_NO_AUTO_DAEMON=1

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
# Signup (Better Auth) está deshabilitado por defecto en el deployment (backend
# hardening, Fase 3 Fix B: convex/betterAuth.ts disableSignUp) — solo se abre
# con FILETHING_ALLOW_SIGNUP=1. Este smoke hace signup real (PASO 1), así que lo
# abrimos aquí y lo devolvemos a como estaba al terminar (éxito o fallo).
#
# El estado abierto es un cambio de SEGURIDAD real sobre un deployment vivo, así
# que el cierre no puede depender de que el camino feliz llegue al final:
#   - el flag se arma ANTES de mutar (un `env set` que aplica y devuelve != 0
#     dejaba el signup abierto sin que el trap lo supiera — es la fuga real que
#     tenía este script),
#   - el restore comprueba su propio código de salida y grita si falló,
#   - hay traps de señal explícitos: bash *suele* correr el de EXIT al recibir
#     INT/TERM/HUP, pero eso no lo garantiza POSIX y además así el script sale
#     con el 128+n convencional.
# Contra SIGKILL o un corte de luz no hay red: de ahí el chequeo manual que
# sugiere el mensaje de error.
ALLOW_SIGNUP_TOUCHED=0
ORIG_ALLOW_SIGNUP=""
CLEANED=0
cleanup() {
  [ "$CLEANED" -eq 1 ] && return 0   # los traps de señal salen -> el de EXIT reentra
  CLEANED=1
  if [ "$ALLOW_SIGNUP_TOUCHED" -eq 1 ]; then
    local restored=0 now
    if [ -n "$ORIG_ALLOW_SIGNUP" ]; then
      ( cd "$REPO/packages/backend" && bunx convex env set FILETHING_ALLOW_SIGNUP "$ORIG_ALLOW_SIGNUP" ) >/dev/null 2>&1 && restored=1
    else
      ( cd "$REPO/packages/backend" && bunx convex env remove FILETHING_ALLOW_SIGNUP ) >/dev/null 2>&1 && restored=1
    fi
    # Releer confirma el cierre, pero un `env get` de una variable ausente ya
    # devuelve vacío: solo escalamos si podemos LEER un valor distinto del
    # original. Quien manda es el código de salida del propio restore.
    now="$(cd "$REPO/packages/backend" && bunx convex env get FILETHING_ALLOW_SIGNUP 2>/dev/null || true)"
    if [ "$restored" -ne 1 ] || { [ -n "$now" ] && [ "$now" != "$ORIG_ALLOW_SIGNUP" ]; }; then
      echo >&2
      echo "!!! ATENCIÓN: no pude devolver FILETHING_ALLOW_SIGNUP a '${ORIG_ALLOW_SIGNUP:-<sin definir>}'" >&2
      echo "!!! (ahora lee '${now:-<vacío>}'). El SIGNUP PÚBLICO puede seguir ABIERTO." >&2
      echo "!!! Ciérralo A MANO ya:" >&2
      echo "!!!   cd packages/backend && bunx convex env remove FILETHING_ALLOW_SIGNUP" >&2
      command rm -rf "${WORK:?}"
      exit 1
    fi
  fi
  command rm -rf "${WORK:?}"
}
# Un handler de señal que solo limpia y RETORNA dejaría al script seguir donde
# iba, así que los de señal salen; el de EXIT cubre el camino normal y `set -e`.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 129' HUP

# Dos Devices = dos FILETHING_HOME distintos sobre el mismo binario. Los Devices
# corren SIN S3_* (env -u): igual que un usuario final, el plano de datos va por
# URLs prefirmadas que emite el Coordinator (vault:sign, ADR 0016). Solo el paso
# de gc (operador) usa las credenciales S3 directas (a_ops).
NO_S3=(env -u S3_ENDPOINT -u S3_REGION -u S3_ACCESS_KEY -u S3_SECRET_KEY -u S3_BUCKET)
a() { "${NO_S3[@]}" FILETHING_HOME="$A_HOME" "$BIN" "$@"; }
b() { "${NO_S3[@]}" FILETHING_HOME="$B_HOME" "$BIN" "$@"; }
a_ops() { FILETHING_HOME="$A_HOME" "$BIN" "$@"; }

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
: "${CONVEX_DEPLOY_KEY:?falta CONVEX_DEPLOY_KEY en $ENV_FILE (hace falta para abrir/cerrar signup)}"
export CONVEX_DEPLOY_KEY

# Una deploy key `prod:` apunta al deployment de PRODUCCIÓN, y este script no es
# read-only sobre él: abre el signup público y crea una cuenta. Eso no puede
# pasar por descuido (un `scripts/cloud-smoke.sh` a ciegas), así que exige un
# consentimiento explícito. Contra un deployment de dev/preview corre sin más.
if [[ "$CONVEX_DEPLOY_KEY" == prod:* && "${FILETHING_SMOKE_ALLOW_PROD:-}" != "1" ]]; then
  cat >&2 <<'EOF'
ERROR: CONVEX_DEPLOY_KEY apunta a un deployment de PRODUCCIÓN.

Este smoke NO es read-only sobre el deployment: abre el signup público
(FILETHING_ALLOW_SIGNUP=1) mientras corre y crea una cuenta real. Contra
producción eso es un cambio de seguridad temporal en un sistema vivo.

Opciones:
  1) (recomendado) córrelo contra un deployment de dev/preview: genera una
     deploy key de ese deployment y ponla en infra/.env.cloud.
  2) si de verdad quieres tocar producción, hazlo explícito:
       FILETHING_SMOKE_ALLOW_PROD=1 scripts/cloud-smoke.sh
     y confirma después que el signup quedó cerrado:
       cd packages/backend && bunx convex env get FILETHING_ALLOW_SIGNUP
EOF
  exit 1
fi

hr "PRECHEQUEO — habilitando signup temporalmente (FILETHING_ALLOW_SIGNUP)"
ORIG_ALLOW_SIGNUP="$(cd "$REPO/packages/backend" && bunx convex env get FILETHING_ALLOW_SIGNUP 2>/dev/null || true)"
# El flag se arma ANTES de mutar: un `env set` que falla a medias (o que aplica y
# devuelve != 0) dejaba el signup abierto sin que el trap lo supiera.
ALLOW_SIGNUP_TOUCHED=1
if ! ( cd "$REPO/packages/backend" && bunx convex env set FILETHING_ALLOW_SIGNUP 1 ); then
  echo "ERROR: no se pudo fijar FILETHING_ALLOW_SIGNUP=1 en el deployment (revisa CONVEX_DEPLOY_KEY)." >&2
  exit 1
fi
ok "signup habilitado para esta corrida (se revierte al terminar, incluso con Ctrl-C)"

hr "BUILD — binario release (target/release/filething)"
( cd "$REPO" && cargo build --release -p filething )
[ -x "$BIN" ] || { echo "ERROR: no se construyó $BIN" >&2; exit 1; }

mkdir -p "$A_HOME" "$B_HOME" "$A_DIR" "$B_DIR"

hr "PASO 1 — login A (signup) + login B (mismo usuario, otro Device)"
# Auth real (Better Auth): email único por corrida + password por env var. El
# segundo Device es el MISMO usuario logueando en otro FILETHING_HOME (pairing
# eliminado). CONVEX_SITE_URL se deriva de CONVEX_URL (*.convex.cloud →
# *.convex.site) si no se fija en el .env.
FT_EMAIL="${FILETHING_TEST_EMAIL:-smoke-$(date +%s)-$$@example.com}"
export FILETHING_PASSWORD="${FILETHING_PASSWORD:?define FILETHING_PASSWORD en $ENV_FILE}"
if a login --signup --email "$FT_EMAIL" --name device-a-cloud; then ok "A creó la cuenta ($FT_EMAIL)"; else bad "login --signup de A"; echo "SMOKE FAIL"; exit 1; fi
if b login --email "$FT_EMAIL" --name device-b-cloud; then ok "B se logueó (mismo usuario, Device nuevo)"; else bad "login de B"; echo "SMOKE FAIL"; exit 1; fi

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

hr "PASO 4 (sanity) — filething gc (dry-run, con S3_* directas: gc es de operador)"
# gc es dry-run por defecto (no borra nada). Best-effort: no tumba el smoke si falla.
# gc necesita list/delete del bucket — imposible con URLs prefirmadas — así que corre
# con las credenciales S3 directas del .env.cloud (a_ops), no como usuario final.
if a_ops gc "$A_DIR"; then
  ok "gc (dry-run) ejecutó"
else
  echo "  (aviso) 'filething gc' falló — sanity omitido (no cuenta como fallo)"
fi

hr "RESULTADO"
if [ "$FAILED" -eq 0 ]; then
  echo "SMOKE OK: login + init + clone + edit/sync contra Convex Cloud + Cloudflare R2."
  exit 0
else
  echo "SMOKE FAIL: revisa los ✗ de arriba."
  exit 1
fi
