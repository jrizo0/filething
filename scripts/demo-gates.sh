#!/usr/bin/env bash
# filething — demo de los criterios de exito a-d via la CLI real contra la infra viva.
# Dos "Devices" = dos FILETHING_HOME + dos carpetas en esta misma maquina Linux.
set -uo pipefail

# Raíz del repo relativa a este script: funciona igual en el checkout original y
# en un worktree (así el gate corre el binario y el backend de ESTE árbol).
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/debug/filething"
WORK=/tmp/ft-demo
A_HOME="$WORK/devA-home"; B_HOME="$WORK/devB-home"
A_DIR="$WORK/dirA";       B_DIR="$WORK/dirB"

# --- entorno: coordinator + vault ---
# En un worktree, infra/.env (gitignored) no existe; usa FT_ENV_FILE para apuntar
# al .env del checkout que tiene las credenciales de la infra local compartida.
ENV_FILE="${FT_ENV_FILE:-$REPO/infra/.env}"
set -a; source "$ENV_FILE"; set +a
export CONVEX_SELF_HOSTED_URL="${CONVEX_SELF_HOSTED_URL:-http://localhost:3210}"
# El cliente usa S3_* y CONVEX_SELF_HOSTED_*; ya vienen de infra/.env.

mc() { docker run --rm --network filething_default --entrypoint sh minio/mc:latest -c "mc alias set L http://minio:9000 ${S3_ACCESS_KEY} ${S3_SECRET_KEY} >/dev/null 2>&1; $1"; }
count_blocks() { mc "mc ls --recursive L/${S3_BUCKET}/blocks 2>/dev/null | wc -l" | tr -d '[:space:]'; }
a() { FILETHING_HOME="$A_HOME" "$BIN" "$@"; }
b() { FILETHING_HOME="$B_HOME" "$BIN" "$@"; }
hr() { echo; echo "==================== $* ===================="; }
fail() { echo "GATE FAIL: $*"; exit 1; }

# Un único cleanup para todo el script (los daemons de los gates e/f también
# viven aquí — un segundo `trap ... EXIT` más abajo pisaría este). Revierte
# FILETHING_ALLOW_SIGNUP (ver PRECHEQUEO) y mata cualquier daemon lanzado.
DA_PID=""; DB_PID=""
ALLOW_SIGNUP_TOUCHED=0
ORIG_ALLOW_SIGNUP=""
cleanup() {
    [ -n "$DA_PID" ] && kill "$DA_PID" >/dev/null 2>&1
    [ -n "$DB_PID" ] && kill "$DB_PID" >/dev/null 2>&1
    if [ "$ALLOW_SIGNUP_TOUCHED" -eq 1 ]; then
        if [ -n "$ORIG_ALLOW_SIGNUP" ]; then
            ( cd "$REPO/packages/backend" && bunx convex env set FILETHING_ALLOW_SIGNUP "$ORIG_ALLOW_SIGNUP" ) >/dev/null 2>&1
        else
            ( cd "$REPO/packages/backend" && bunx convex env remove FILETHING_ALLOW_SIGNUP ) >/dev/null 2>&1
        fi
    fi
}
trap cleanup EXIT

rm -rf "$WORK"; mkdir -p "$A_HOME" "$B_HOME" "$A_DIR" "$B_DIR"

# Auth real (Better Auth): un email único por corrida (para poder repetir el gate
# sin colisionar con cuentas previas) y una password por env var. El segundo
# Device es el MISMO usuario logueando en otro FILETHING_HOME (ya no hay pairing).
FT_EMAIL="${FILETHING_TEST_EMAIL:-demo-$(date +%s)-$$@example.com}"
export FILETHING_PASSWORD="${FILETHING_PASSWORD:-test-password-12345}"

hr "PRECHEQUEO — habilitando signup temporalmente (FILETHING_ALLOW_SIGNUP)"
# Signup (Better Auth) está deshabilitado por defecto en el backend (Fase 3 Fix
# B: convex/betterAuth.ts disableSignUp) — este gate hace signup real (abajo),
# así que lo abrimos en el backend self-hosted de ESTE arbol y lo revertimos
# al terminar (via el trap `cleanup`, éxito o fallo).
ORIG_ALLOW_SIGNUP="$(cd "$REPO/packages/backend" && bunx convex env get FILETHING_ALLOW_SIGNUP 2>/dev/null || true)"
( cd "$REPO/packages/backend" && bunx convex env set FILETHING_ALLOW_SIGNUP 1 ) || fail "no se pudo fijar FILETHING_ALLOW_SIGNUP=1 (revisa CONVEX_SELF_HOSTED_ADMIN_KEY en $ENV_FILE)"
ALLOW_SIGNUP_TOUCHED=1

hr "SETUP — login A (signup) + login B (mismo usuario, otro Device)"
a login --signup --email "$FT_EMAIL" --name device-a || fail "login --signup de A"
b login --email "$FT_EMAIL" --name device-b || fail "login de B (mismo usuario)"
echo ">> cuenta = $FT_EMAIL (A=device-a, B=device-b)"

hr "GATE 2 (a) — edito en A, init, clone en B => aparece en B"
mkdir -p "$A_DIR/src"
echo "fn main() { println!(\"hola\"); }" > "$A_DIR/src/main.rs"
echo "# demo" > "$A_DIR/README.md"
OUT_INIT=$(a init "$A_DIR" --name demo); echo "$OUT_INIT"
SPACE=$(echo "$OUT_INIT" | grep -oE '[a-z0-9]{30,}' | head -1)
[ -n "$SPACE" ] || fail "no space_id de init"
echo ">> space_id = $SPACE"
b clone "$SPACE" "$B_DIR"; echo
diff -r "$A_DIR" "$B_DIR" -x .filething && echo "OK (a): dirB == dirA" || fail "(a) dirB != dirA"

hr "GATE 5 (d) — 1 linea en archivo grande => solo suben bloques nuevos"
# archivo grande (~1.5 MiB) -> varios bloques
head -c 1500000 /dev/urandom | base64 > "$A_DIR/big.txt"
a sync "$A_DIR" >/dev/null
N1=$(count_blocks); echo ">> bloques tras subir big.txt: $N1"
# editar 1 linea en el medio (no cambia el tamano apreciablemente)
python3 - "$A_DIR/big.txt" <<'PY'
import sys
p=sys.argv[1]; L=open(p).read().splitlines()
i=len(L)//2; L[i]="EDITED-LINE"
open(p,"w").write("\n".join(L)+"\n")
PY
a sync "$A_DIR" >/dev/null
N2=$(count_blocks); echo ">> bloques tras editar 1 linea: $N2"
DELTA=$((N2 - N1)); echo ">> bloques nuevos por el cambio = $DELTA"
[ "$DELTA" -ge 1 ] && [ "$DELTA" -le 4 ] && echo "OK (d): delta de $DELTA bloques (no re-subio el archivo entero)" || fail "(d) delta=$DELTA (esperado 1-4)"
b sync "$B_DIR" >/dev/null
diff "$A_DIR/big.txt" "$B_DIR/big.txt" && echo "OK (d): B recibio el delta" || fail "(d) B no refleja el delta"

hr "GATE 3 (b) — bidireccional sin eco ni conflictos falsos"
echo "edit en B" > "$B_DIR/from_b.txt"
b sync "$B_DIR" >/dev/null
a sync "$A_DIR" >/dev/null
[ -f "$A_DIR/from_b.txt" ] && echo "OK (b): A recibio from_b.txt (B->A)" || fail "(b) A no recibio el archivo de B"
# y un cambio simultaneo en archivos DISTINTOS no debe generar conflicto
echo "a2" >> "$A_DIR/README.md"; echo "b2" > "$B_DIR/notes.txt"
a sync "$A_DIR" >/dev/null; b sync "$B_DIR" >/dev/null; a sync "$A_DIR" >/dev/null; b sync "$B_DIR" >/dev/null
CONF=$(find "$A_DIR" "$B_DIR" -name '*conflicto*' | wc -l)
[ "$CONF" -eq 0 ] && echo "OK (b): cambios en archivos distintos => 0 conflictos falsos" || fail "(b) hubo $CONF conflictos falsos"

hr "GATE 4 (c) — corte de red: editar offline en AMBOS el MISMO archivo => reconcilia sin perder datos"
# sincroniza un archivo comun primero
echo "base" > "$A_DIR/shared.txt"; a sync "$A_DIR" >/dev/null; b sync "$B_DIR" >/dev/null
echo ">> cortando red (docker stop convex-backend)"
docker stop filething-convex-backend-1 >/dev/null
# editar offline en ambos el MISMO archivo, a contenidos distintos
echo "version de A (offline)" > "$A_DIR/shared.txt"
echo "version de B (offline)" > "$B_DIR/shared.txt"
echo ">> reconectando (docker start convex-backend)"
docker start filething-convex-backend-1 >/dev/null
for i in $(seq 1 30); do curl -sf http://localhost:3210/version >/dev/null 2>&1 && break; sleep 2; done
a sync "$A_DIR"; echo "---"; b sync "$B_DIR"   # B debe reconciliar: copia de conflicto
echo ">> archivos shared* en B:"; ls "$B_DIR" | grep -E 'shared'
# ambas versiones deben existir en B (sin perdida)
HAVE_A=$(grep -rl "version de A (offline)" "$B_DIR" | wc -l)
HAVE_B=$(grep -rl "version de B (offline)" "$B_DIR" | wc -l)
[ "$HAVE_A" -ge 1 ] && [ "$HAVE_B" -ge 1 ] && echo "OK (c): B conserva AMBAS versiones (sin perdida de datos)" || fail "(c) se perdio una version (A=$HAVE_A B=$HAVE_B)"

hr "GATE (g) — GC: dry-run no borra; huerfano inyectado se barre; lo alcanzable sobrevive"
a sync "$A_DIR" >/dev/null   # asegura A al dia antes de barrer
# (g.1) dry-run (grace 0) NO debe borrar nada — es solo un reporte.
N0=$(count_blocks)
a gc "$A_DIR" --grace-secs 0 >/dev/null
N0b=$(count_blocks)
[ "$N0b" -eq "$N0" ] && echo "OK (g.1): dry-run no borro nada (bloques $N0 == $N0b)" || fail "(g.1) el dry-run borro objetos ($N0 -> $N0b)"
# (g.2) inyecta un objeto huerfano bajo blocks/ y confirma que --apply lo borra.
ORPHAN="blocks/zz/orphan-$(date +%s)"
mc "echo huerfano | mc pipe L/${S3_BUCKET}/${ORPHAN}"
mc "mc ls L/${S3_BUCKET}/${ORPHAN} 2>/dev/null | wc -l" | grep -q 1 || fail "(g.2) no se inyecto el huerfano"
echo ">> huerfano inyectado: $ORPHAN"
a gc "$A_DIR" --grace-secs 0 --apply
LEFT=$(mc "mc ls L/${S3_BUCKET}/${ORPHAN} 2>/dev/null | wc -l" | tr -d '[:space:]')
[ "$LEFT" -eq 0 ] && echo "OK (g.2): --apply borro el huerfano inyectado" || fail "(g.2) el huerfano sobrevivio al --apply"
# (g.3) SEGURIDAD: lo alcanzable no se borro — un clone fresco reconstruye big.txt.
B_DIR2="$WORK/dirB2"; mkdir -p "$B_DIR2"
b clone "$SPACE" "$B_DIR2" >/dev/null
diff "$A_DIR/big.txt" "$B_DIR2/big.txt" >/dev/null && echo "OK (g.3): clone fresco reconstruye big.txt tras el GC (bloques alcanzables intactos)" || fail "(g.3) el GC borro bloques alcanzables (clone no reconstruye big.txt)"

hr "RESULTADO"
echo "Gates a, b, c, d, g: PASARON via la CLI real contra Convex+MinIO."

# ---------------------------------------------------------------------------
# Gates (e) y (f) — daemons de verdad (no `sync` puntual), Space/HOMEs propios
# para no pisar el estado de los gates a-d.
# ---------------------------------------------------------------------------

DWORK=/tmp/ft-demo-daemons
DA_HOME="$DWORK/devA-home"; DB_HOME="$DWORK/devB-home"
DA_DIR="$DWORK/dirA";       DB_DIR="$DWORK/dirB"
DA_LOG="$DWORK/daemon-a.log"; DB_LOG="$DWORK/daemon-b.log"
# DA_PID/DB_PID ya declarados arriba (los usa el `cleanup` de todo el script).

da() { FILETHING_HOME="$DA_HOME" "$BIN" "$@"; }
db() { FILETHING_HOME="$DB_HOME" "$BIN" "$@"; }

# Sondea hasta ~$2 segundos (por defecto 30) a que el comando $1 sea verdadero.
wait_for() {
    local desc="$1"; local timeout="${2:-30}"; local check="$3"
    local waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if eval "$check"; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo ">> TIMEOUT esperando: $desc (despues de ${timeout}s)"
    return 1
}

command rm -rf "$DWORK"; mkdir -p "$DA_HOME" "$DB_HOME" "$DA_DIR" "$DB_DIR"

hr "SETUP (e/f) — login A + login B (mismo usuario, otros Devices), init+clone"
# Reusa la cuenta creada en el primer SETUP (mismo email); solo son dos Devices
# nuevos (otros FILETHING_HOME) del mismo usuario.
da login --email "$FT_EMAIL" --name device-a-daemon || fail "(e/f) login de A"
db login --email "$FT_EMAIL" --name device-b-daemon || fail "(e/f) login de B"

echo "seed inicial" > "$DA_DIR/seed.txt"
OUT_DINIT=$(da init "$DA_DIR" --name demo-daemons); echo "$OUT_DINIT"
DSPACE=$(echo "$OUT_DINIT" | grep -oE '[a-z0-9]{30,}' | head -1)
[ -n "$DSPACE" ] || fail "(e/f) no space_id de init"
echo ">> space_id = $DSPACE"
db clone "$DSPACE" "$DB_DIR"; echo
[ -f "$DB_DIR/seed.txt" ] || fail "(e/f) B no clono el seed inicial"

hr "GATE (e) — segunda edicion: coalesce del watcher NO debe tragarse la 2a modificacion"
# OJO: lanzar el daemon directo con `env` (no via las funciones da()/db()) para
# que "$!" sea el PID real del binario. Backgrounding una FUNCION de shell deja
# "$!" apuntando al subshell de la funcion, no al binario que ejecuta adentro
# (una fork extra) — eso huerfana el proceso real al matar solo "$!".
env FILETHING_HOME="$DA_HOME" "$BIN" daemon "$DA_DIR" >"$DA_LOG" 2>&1 &
DA_PID=$!
env FILETHING_HOME="$DB_HOME" "$BIN" daemon "$DB_DIR" >"$DB_LOG" 2>&1 &
DB_PID=$!
echo ">> daemon A pid=$DA_PID  daemon B pid=$DB_PID"
sleep 2  # deja que ambos daemons terminen su startup_sync antes de tocar el FS

echo "version 1" > "$DA_DIR/coalesce.txt"
wait_for "(e) B recibe la creacion de coalesce.txt" 30 \
    '[ -f "'"$DB_DIR"'/coalesce.txt" ] && grep -qx "version 1" "'"$DB_DIR"'/coalesce.txt" 2>/dev/null' \
    || fail "(e) B nunca recibio la creacion de coalesce.txt"
echo "OK (e): B recibio la 1a version de coalesce.txt"

echo "version 2" > "$DA_DIR/coalesce.txt"
wait_for "(e) B recibe la 1a edicion" 30 \
    'grep -qx "version 2" "'"$DB_DIR"'/coalesce.txt" 2>/dev/null' \
    || fail "(e) B nunca recibio la 1a edicion de coalesce.txt"
echo "OK (e): B recibio la 1a edicion (version 2)"

echo "version 3" > "$DA_DIR/coalesce.txt"
wait_for "(e) B recibe la 2a edicion (el bug viejo del coalesce fallaba aqui)" 30 \
    'grep -qx "version 3" "'"$DB_DIR"'/coalesce.txt" 2>/dev/null' \
    || fail "(e) B nunca recibio la 2a edicion de coalesce.txt (bug de coalesce del watcher)"
echo "OK (e): B recibio la 2a edicion (version 3) — el coalesce NO se tildo"

hr "GATE (f) — arranque offline: apagar B, borrar+crear en B, prender B => A ve ambos cambios via startup_sync"
kill "$DB_PID" >/dev/null 2>&1
wait "$DB_PID" 2>/dev/null
DB_PID=""
echo ">> daemon B apagado"

# Un archivo YA sincronizado (seed.txt, presente desde el clone) se borra en B;
# uno nuevo se crea en B. Ambos cambios se hacen con el daemon de B APAGADO.
command rm -f "$DB_DIR/seed.txt"
echo "nuevo mientras B estaba offline" > "$DB_DIR/offline_new.txt"

env FILETHING_HOME="$DB_HOME" "$BIN" daemon "$DB_DIR" >>"$DB_LOG" 2>&1 &
DB_PID=$!
echo ">> daemon B reiniciado pid=$DB_PID"

wait_for "(f) A ve el archivo nuevo creado offline en B" 30 \
    'grep -qx "nuevo mientras B estaba offline" "'"$DA_DIR"'/offline_new.txt" 2>/dev/null' \
    || fail "(f) A nunca recibio offline_new.txt (startup_sync no comprometio el cambio offline)"
echo "OK (f): A recibio offline_new.txt"

wait_for "(f) A refleja el borrado offline de seed.txt" 30 \
    '[ ! -f "'"$DA_DIR"'/seed.txt" ]' \
    || fail "(f) A todavia tiene seed.txt (startup_sync no comprometio el borrado offline)"
echo "OK (f): A ya no tiene seed.txt (borrado offline propagado)"

# El `trap cleanup EXIT` de arriba mata A/B y revierte FILETHING_ALLOW_SIGNUP
# al salir del script — no hace falta repetirlo aquí.

hr "RESULTADO FINAL"
echo "Gates a, b, c, d, e, f: PASARON via la CLI real contra Convex+MinIO."