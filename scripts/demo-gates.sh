#!/usr/bin/env bash
# filething — demo de los criterios de exito a-d via la CLI real contra la infra viva.
# Dos "Devices" = dos FILETHING_HOME + dos carpetas en esta misma maquina Linux.
set -uo pipefail

REPO=/home/jrizo/repos/filething
BIN="$REPO/target/debug/filething"
WORK=/tmp/ft-demo
A_HOME="$WORK/devA-home"; B_HOME="$WORK/devB-home"
A_DIR="$WORK/dirA";       B_DIR="$WORK/dirB"

# --- entorno: coordinator + vault de infra/.env ---
set -a; source "$REPO/infra/.env"; set +a
export CONVEX_SELF_HOSTED_URL="${CONVEX_SELF_HOSTED_URL:-http://localhost:3210}"
# El cliente usa S3_* y CONVEX_SELF_HOSTED_*; ya vienen de infra/.env.

mc() { docker run --rm --network filething_default --entrypoint sh minio/mc:latest -c "mc alias set L http://minio:9000 ${S3_ACCESS_KEY} ${S3_SECRET_KEY} >/dev/null 2>&1; $1"; }
count_blocks() { mc "mc ls --recursive L/${S3_BUCKET}/blocks 2>/dev/null | wc -l" | tr -d '[:space:]'; }
a() { FILETHING_HOME="$A_HOME" "$BIN" "$@"; }
b() { FILETHING_HOME="$B_HOME" "$BIN" "$@"; }
hr() { echo; echo "==================== $* ===================="; }
fail() { echo "GATE FAIL: $*"; exit 1; }

rm -rf "$WORK"; mkdir -p "$A_HOME" "$B_HOME" "$A_DIR" "$B_DIR"

hr "SETUP — login A (bootstrap) + login B (claim por codigo)"
OUT_A=$(a login --name device-a); echo "$OUT_A"
CODE=$(echo "$OUT_A" | grep -oE '[A-Z0-9]{6,10}' | head -1)
[ -n "$CODE" ] || fail "no pairing code de A"
echo ">> pairing code = $CODE"
b login --code "$CODE" --name device-b; echo

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

hr "RESULTADO"
echo "Gates a, b, c, d: PASARON via la CLI real contra Convex+MinIO."