#!/usr/bin/env bash
# Runbook e2e Mac <-> VPS: corre TODOS los flujos de sync conocidos, sin intervención.
#
# Se corre EN LA MAC. Requisitos (una vez, ver docs/MAC-SETUP.md):
#   - ssh a `vpsjr` sin password
#   - ~/filething-test-env.sh en la Mac (env S3/Convex/FILETHING_HOME)
#   - Devices logueados (Better Auth, mismo usuario) y Space clonado en ~/space-demo
#     de ambos lados (ya no hay pairing codes; ver docs/MAC-SETUP.md §5)
#   - infra (MinIO+Convex) arriba en el VPS; túnel opcional (si no hay, lo levanta).
#     El túnel reenvía 9000/3210/3211 — el 3211 (Better Auth) lo necesita el daemon
#     para re-mintear su JWT (~15 min).
#
# Uso:    bash scripts/runbook-e2e-mac-vps.sh
# Salida: PASS/FAIL por gate + resumen final; logs en ~/ft-e2e-<TS>/
# Exit:   0 si todo pasó, 1 si algún gate falló, 2 si falló el setup (preflight)
#
# Qué cubre cada gate (mapa a los fixes de cd4e066 y 464496c):
#   g01 crear Mac->VPS            g08 exclusión .DS_Store   (fix #4, ADR 0011)
#   g02 crear VPS->Mac            g09 arranque offline      (fix #2, startup_sync)
#   g03 2a edición mismo archivo  g10 túnel cortado         (fix #3, backstop pull)
#        (fix #1, coalesce)       g11 conflicto offline     (copias de conflicto)
#   g04 ráfaga 30 archivos        g12 borrado recursivo del dir de prueba
#   g05 blob binario 3MB          g13 sync one-shot al día
#   g06 borrados bidireccionales  g14 roots idénticos + status sin "behind"
#   g07 subdirs + rename + bit x       (fix de 464496c)
set -u

TS=$(date +%Y%m%d-%H%M%S)
RUN_DIR=$HOME/ft-e2e-$TS
mkdir -p "$RUN_DIR"
LOG=$RUN_DIR/runbook.log

BIN=/Users/jrizo/filething/target/release/filething
MAC_SPACE=$HOME/space-demo
E2E=e2e-$TS                       # subdir de prueba dentro del Space
VPS=vpsjr
CM=$HOME/.ssh/ft-e2e-cm           # ControlMaster: ssh's repetidos rápidos
SSH="ssh -o ControlMaster=auto -o ControlPath=$CM -o ControlPersist=300 $VPS"
VPS_ENV='cd ~/repos/filething; set -a; . infra/.env; set +a; export FILETHING_HOME=$HOME/.filething-vps'
TUNNEL_PAT='-L 9000:localhost:9000'   # patrón pkill del ssh del túnel (y solo de él)

say()  { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
RESULTS=()
RC=0
ok()   { RESULTS+=("PASS  $1"); say "PASS  $1"; }
ko()   { RESULTS+=("FAIL  $1 — $2"); say "FAIL  $1 — $2"; RC=1; }
info() { RESULTS+=("INFO  $1 — $2"); say "INFO  $1 — $2"; }
die()  { say "FATAL: $*"; exit 2; }

# wait_until <timeout_s> <cmd...> — repite el predicado cada 1s hasta timeout
wait_until() {
  local timeout=$1 t=0; shift
  while (( t < timeout )); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1; t=$((t+1))
  done
  return 1
}

# ---- predicados (Mac local, VPS vía ssh) ------------------------------------
mac_has()  { [ -f "$MAC_SPACE/$1" ] && grep -qxF "$2" "$MAC_SPACE/$1"; }
mac_gone() { [ ! -e "$MAC_SPACE/$1" ]; }
vps_has()  { $SSH "cat ~/space-demo/$1 2>/dev/null" | grep -qxF "$2"; }
vps_gone() { ! $SSH "test -e ~/space-demo/$1"; }
vps_exec() { $SSH "test -x ~/space-demo/$1"; }
vps_count(){ [ "$($SSH "find ~/space-demo/$1 -type f 2>/dev/null | wc -l" | tr -d '[:space:]')" = "$2" ]; }
mac_daemon_alive() { kill -0 "$MAC_PID" 2>/dev/null; }
vps_daemon_alive() { $SSH "kill -0 $VPS_PID" 2>/dev/null; }
tunnel_up() { curl -s --max-time 3 http://localhost:3210/version >/dev/null 2>&1; }
tunnel_down() { ! tunnel_up; }

ensure_tunnel() {
  tunnel_up && return 0
  say "  túnel caído; levantando uno propio"
  ssh -f -N -o ExitOnForwardFailure=yes \
    -L 9000:localhost:9000 -L 3210:localhost:3210 -L 3211:localhost:3211 "$VPS" 2>>"$LOG" || true
  wait_until 15 tunnel_up
}

# ---- daemons -----------------------------------------------------------------
MAC_PID=""
VPS_PID=""

start_mac_daemon() {
  "$BIN" daemon "$MAC_SPACE" >>"$RUN_DIR/daemon-mac.log" 2>&1 &
  MAC_PID=$!
  sleep 3   # deja terminar startup_sync (pull + commit inicial)
  mac_daemon_alive || die "el daemon de la Mac murió al arrancar (ver $RUN_DIR/daemon-mac.log)"
}
stop_mac_daemon() {   # SIGINT = único shutdown limpio que maneja el binario
  [ -n "$MAC_PID" ] && kill -INT "$MAC_PID" 2>/dev/null
  [ -n "$MAC_PID" ] && wait "$MAC_PID" 2>/dev/null
  MAC_PID=""
}
start_vps_daemon() {
  VPS_PID=$($SSH "set -e; $VPS_ENV; nohup target/debug/filething daemon ~/space-demo >> ~/ft-daemon-vps-$TS.log 2>&1 < /dev/null & echo \$!")
  sleep 3
  vps_daemon_alive || die "el daemon del VPS murió al arrancar (ver ~/ft-daemon-vps-$TS.log en el VPS)"
}
stop_vps_daemon() {
  [ -n "$VPS_PID" ] && $SSH "kill -INT $VPS_PID 2>/dev/null; sleep 1" || true
  VPS_PID=""
}

cleanup() {
  say "cleanup: deteniendo daemons y cerrando ssh multiplexado"
  [ -n "$MAC_PID" ] && kill -INT "$MAC_PID" 2>/dev/null
  $SSH "pkill -INT -f 'filething daemon'" 2>/dev/null
  $SSH "tail -80 ~/ft-daemon-vps-$TS.log" >"$RUN_DIR/daemon-vps.log" 2>/dev/null
  ssh -o ControlPath="$CM" -O exit "$VPS" 2>/dev/null
  true
}
trap cleanup EXIT

# ==== preflight =================================================================
say "== preflight (logs en $RUN_DIR) =="
[ -x "$BIN" ] || die "no existe $BIN (cargo build --release -p filething)"
[ -f "$HOME/filething-test-env.sh" ] || die "falta ~/filething-test-env.sh"
# shellcheck disable=SC1090
source "$HOME/filething-test-env.sh"
ensure_tunnel || die "no pude levantar el túnel a $VPS"
[ "$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' http://localhost:9000/minio/health/live)" = "200" ] \
  || die "MinIO no responde vía túnel"
$SSH true || die "ssh a $VPS no funciona"
[ -d "$MAC_SPACE" ] || die "no existe $MAC_SPACE (clone pendiente)"
$SSH "test -d ~/space-demo" || die "no existe ~/space-demo en el VPS"
# cero daemons zombis antes de empezar
pkill -INT -f "filething daemon" 2>/dev/null && sleep 1 || true
$SSH "pkill -INT -f 'filething daemon' && sleep 1" 2>/dev/null || true
say "  binario Mac: $("$BIN" --version)   commit: $(cd /Users/jrizo/filething && git log -1 --format=%h)"
say "  binario VPS: $($SSH "~/repos/filething/target/debug/filething --version")   commit: $($SSH 'cd ~/repos/filething && git log -1 --format=%h')"

start_vps_daemon
start_mac_daemon
say "  daemons arriba (mac pid $MAC_PID, vps pid $VPS_PID)"
mkdir -p "$MAC_SPACE/$E2E"

# ==== g01: crear Mac -> VPS =====================================================
printf 'uno v1 %s\n' "$TS" >"$MAC_SPACE/$E2E/uno.txt"
if wait_until 30 vps_has "$E2E/uno.txt" "uno v1 $TS"; then
  ok "g01 crear Mac->VPS"
else ko "g01 crear Mac->VPS" "uno.txt no llegó al VPS en 30s"; fi

# ==== g02: crear VPS -> Mac =====================================================
$SSH "printf 'dos v1 %s\n' '$TS' > ~/space-demo/$E2E/dos.txt"
if wait_until 30 mac_has "$E2E/dos.txt" "dos v1 $TS"; then
  ok "g02 crear VPS->Mac"
else ko "g02 crear VPS->Mac" "dos.txt no llegó a la Mac en 30s"; fi

# ==== g03: SEGUNDA edición del mismo archivo (fix #1: coalesce) ================
printf 'uno v2 %s\n' "$TS" >"$MAC_SPACE/$E2E/uno.txt"
wait_until 30 vps_has "$E2E/uno.txt" "uno v2 $TS" || ko "g03a 1a edición Mac->VPS" "v2 no llegó"
printf 'uno v3 %s\n' "$TS" >"$MAC_SPACE/$E2E/uno.txt"
if wait_until 30 vps_has "$E2E/uno.txt" "uno v3 $TS"; then
  ok "g03 2a edición mismo archivo Mac->VPS (fix coalesce)"
else ko "g03 2a edición mismo archivo Mac->VPS (fix coalesce)" "v3 nunca llegó — REGRESIÓN del bug #1"; fi
# y en la otra dirección
$SSH "printf 'dos v2 %s\n' '$TS' > ~/space-demo/$E2E/dos.txt"
wait_until 30 mac_has "$E2E/dos.txt" "dos v2 $TS" || ko "g03b 1a edición VPS->Mac" "v2 no llegó"
$SSH "printf 'dos v3 %s\n' '$TS' > ~/space-demo/$E2E/dos.txt"
if wait_until 30 mac_has "$E2E/dos.txt" "dos v3 $TS"; then
  ok "g03 2a edición mismo archivo VPS->Mac (fix coalesce)"
else ko "g03 2a edición mismo archivo VPS->Mac (fix coalesce)" "v3 nunca llegó — REGRESIÓN del bug #1"; fi

# ==== g04: ráfaga de 30 archivos ================================================
mkdir -p "$MAC_SPACE/$E2E/burst"
for i in $(seq 1 30); do printf 'burst %s #%s\n' "$TS" "$i" >"$MAC_SPACE/$E2E/burst/f$i.txt"; done
if wait_until 45 vps_count "$E2E/burst" 30; then
  ok "g04 ráfaga de 30 archivos Mac->VPS"
else ko "g04 ráfaga de 30 archivos Mac->VPS" "llegaron $($SSH "find ~/space-demo/$E2E/burst -type f 2>/dev/null | wc -l" | tr -d ' ') de 30 en 45s"; fi

# ==== g05: blob binario 3MB (bloques content-addressed) ========================
dd if=/dev/urandom of="$MAC_SPACE/$E2E/blob.bin" bs=1m count=3 2>/dev/null
BLOB_HASH=$(shasum -a 256 "$MAC_SPACE/$E2E/blob.bin" | awk '{print $1}')
vps_blob_ok() { [ "$($SSH "sha256sum ~/space-demo/$E2E/blob.bin 2>/dev/null" | awk '{print $1}')" = "$BLOB_HASH" ]; }
if wait_until 45 vps_blob_ok; then
  ok "g05 blob binario 3MB Mac->VPS (sha256 idéntico)"
else ko "g05 blob binario 3MB Mac->VPS" "hash distinto o no llegó en 45s"; fi

# ==== g06: borrados en ambas direcciones =======================================
rm "$MAC_SPACE/$E2E/uno.txt"
if wait_until 30 vps_gone "$E2E/uno.txt"; then
  ok "g06 borrado Mac->VPS"
else ko "g06 borrado Mac->VPS" "uno.txt sigue en el VPS tras 30s"; fi
$SSH "rm ~/space-demo/$E2E/dos.txt"
if wait_until 30 mac_gone "$E2E/dos.txt"; then
  ok "g06 borrado VPS->Mac"
else ko "g06 borrado VPS->Mac" "dos.txt sigue en la Mac tras 30s"; fi

# ==== g07: subdirs anidados + rename + bit ejecutable ==========================
mkdir -p "$MAC_SPACE/$E2E/dir/sub"
printf 'tres %s\n' "$TS" >"$MAC_SPACE/$E2E/dir/sub/tres.txt"
if wait_until 30 vps_has "$E2E/dir/sub/tres.txt" "tres $TS"; then
  ok "g07 archivo en subdir anidado Mac->VPS"
else ko "g07 archivo en subdir anidado Mac->VPS" "no llegó en 30s"; fi
mv "$MAC_SPACE/$E2E/dir/sub/tres.txt" "$MAC_SPACE/$E2E/dir/sub/tres-renamed.txt"
rename_ok() { vps_gone "$E2E/dir/sub/tres.txt" && vps_has "$E2E/dir/sub/tres-renamed.txt" "tres $TS"; }
if wait_until 30 rename_ok; then
  ok "g07 rename (delete+create) Mac->VPS"
else ko "g07 rename Mac->VPS" "viejo presente o nuevo ausente tras 30s"; fi
printf '#!/bin/sh\necho hola %s\n' "$TS" >"$MAC_SPACE/$E2E/run.sh"
vps_runsh() { $SSH "test -f ~/space-demo/$E2E/run.sh"; }
wait_until 30 vps_runsh || ko "g07c crear run.sh" "no llegó"
chmod +x "$MAC_SPACE/$E2E/run.sh"
if wait_until 35 vps_exec "$E2E/run.sh"; then
  ok "g07 chmod +x (cambio solo de metadata) Mac->VPS"
else ko "g07 chmod +x Mac->VPS" "el bit x no se propagó en 35s"; fi
# symlink: informativo (la política Preserve/LocalOnly decide si viaja)
ln -s ../saludo.txt "$MAC_SPACE/$E2E/lnk" 2>/dev/null || true
vps_link_ok() { [ "$($SSH "readlink ~/space-demo/$E2E/lnk 2>/dev/null")" = "../saludo.txt" ]; }
if wait_until 20 vps_link_ok; then
  info "g07 symlink Mac->VPS" "se propagó con target intacto (política Preserve)"
else
  info "g07 symlink Mac->VPS" "NO se propagó en 20s (¿política LocalOnly? no cuenta como fallo)"
fi

# ==== g08: exclusión de basura (.DS_Store, fix #4) =============================
printf 'basura finder\n' >"$MAC_SPACE/$E2E/.DS_Store"
sleep 1
printf 'normal %s\n' "$TS" >"$MAC_SPACE/$E2E/normal.txt"
if wait_until 30 vps_has "$E2E/normal.txt" "normal $TS"; then
  if vps_gone "$E2E/.DS_Store"; then
    ok "g08 .DS_Store NO viaja pero el archivo normal sí (fix junk)"
  else ko "g08 exclusión .DS_Store" "el .DS_Store apareció en el VPS — REGRESIÓN del fix #4"; fi
else ko "g08 exclusión .DS_Store" "normal.txt no llegó (no se pudo probar el orden)"; fi

# ==== g09: arranque offline (fix #2: commit inicial en startup_sync) ===========
stop_mac_daemon
printf 'nacido offline %s\n' "$TS" >"$MAC_SPACE/$E2E/offline-new.txt"
rm "$MAC_SPACE/$E2E/normal.txt"
start_mac_daemon
offline_ok() { vps_has "$E2E/offline-new.txt" "nacido offline $TS" && vps_gone "$E2E/normal.txt"; }
if wait_until 30 offline_ok; then
  ok "g09 cambios hechos con el daemon apagado propagan al arrancar (fix startup_sync)"
else ko "g09 arranque offline (fix startup_sync)" "creación o borrado offline no llegaron — REGRESIÓN del bug #2"; fi

# ==== g10: túnel cortado + recuperación por backstop pull (fix #3) =============
# Regla: NADA escribe en la Mac durante el corte (un commit fallido mata al daemon
# por diseño actual). El VPS commitea local; la Mac debe recuperarlo al volver el
# túnel vía el pull de respaldo de 30s aunque el feed haya muerto en silencio.
say "  g10: cortando el túnel ~8s (se restaura solo: loop del usuario o fallback propio)"
( end=$((SECONDS+8)); while (( SECONDS < end )); do
    pkill -f -- "$TUNNEL_PAT" 2>/dev/null; sleep 1
  done ) &
KILLER=$!
sleep 2
tunnel_down || say "  WARN g10: el túnel no cayó tras pkill (¿patrón cambió?)"
$SSH "printf 'sobreviví al corte %s\n' '$TS' > ~/space-demo/$E2E/feed.txt"
wait "$KILLER" 2>/dev/null
ensure_tunnel || ko "g10 túnel" "el túnel no volvió tras el corte"
if ! mac_daemon_alive; then
  ko "g10 backstop pull (fix #3)" "el daemon de la Mac MURIÓ durante el corte (ver daemon-mac.log)"
  start_mac_daemon
elif wait_until 50 mac_has "$E2E/feed.txt" "sobreviví al corte $TS"; then
  ok "g10 corte de túnel: daemon vivo y el cambio llegó ≤50s (fix backstop pull)"
else
  ko "g10 backstop pull (fix #3)" "daemon vivo pero feed.txt no llegó en 50s — REGRESIÓN del bug #3"
fi

# ==== g11: conflicto por divergencia offline ====================================
# Base sincronizada -> Mac offline -> ambos editan el MISMO archivo -> Mac arranca:
# el remoto gana en el path original y lo local queda en "* (conflicto mac N)*".
printf 'pelea base %s\n' "$TS" >"$MAC_SPACE/$E2E/pelea.txt"
wait_until 30 vps_has "$E2E/pelea.txt" "pelea base $TS" || ko "g11a base del conflicto" "no sincronizó la base"
stop_mac_daemon
printf 'version mac %s\n' "$TS" >"$MAC_SPACE/$E2E/pelea.txt"
$SSH "printf 'version vps %s\n' '$TS' > ~/space-demo/$E2E/pelea.txt"
sleep 5   # deja al daemon del VPS commitear su versión
start_mac_daemon
mac_conflict_ok() {
  mac_has "$E2E/pelea.txt" "version vps $TS" || return 1
  local f; f=$(find "$MAC_SPACE/$E2E" -name '*conflicto*' -type f 2>/dev/null | head -1)
  [ -n "$f" ] && grep -qxF "version mac $TS" "$f"
}
vps_conflict_ok() {
  vps_has "$E2E/pelea.txt" "version vps $TS" || return 1
  local f_remote
  f_remote=$($SSH "find ~/space-demo/$E2E -name '*conflicto*' -type f 2>/dev/null | head -1")
  [ -n "$f_remote" ] || return 1
  $SSH "cat '$f_remote'" | grep -qxF "version mac $TS"
}
if wait_until 40 mac_conflict_ok; then
  ok "g11 conflicto: remoto gana en el path, lo local queda en copia (conflicto ...) en la Mac"
else ko "g11 conflicto (lado Mac)" "sin copia de conflicto o versión equivocada tras 40s — ninguna versión debe perderse"; fi
if wait_until 40 vps_conflict_ok; then
  ok "g11 conflicto: la copia de conflicto también llegó al VPS"
else ko "g11 conflicto (lado VPS)" "la copia de conflicto no llegó al VPS en 40s"; fi

# ==== g12: borrado recursivo del dir de prueba =================================
# El manifest solo registra archivos (los directorios son implícitos en las rutas),
# así que el receptor borra los archivos pero no puede saber que debe borrar las
# carpetas vacías — limitación conocida del MVP. El gate exige CERO archivos.
rm -rf "${MAC_SPACE:?}/$E2E"
vps_no_files() { [ "$($SSH "find ~/space-demo/$E2E -type f 2>/dev/null | wc -l" | tr -d '[:space:]')" = "0" ]; }
if wait_until 40 vps_no_files; then
  ok "g12 borrado recursivo Mac->VPS (0 archivos restantes)"
  vps_gone "$E2E" || info "g12 dirs vacíos" "el árbol de carpetas vacío queda en el VPS (limitación MVP: el manifest no registra directorios)"
else ko "g12 borrado recursivo" "quedan archivos en e2e-$TS en el VPS tras 40s"; fi

# daemons vivos hasta el final (nadie murió en silencio)
mac_daemon_alive || ko "g12b daemon Mac" "murió en algún punto de la corrida"
vps_daemon_alive || ko "g12b daemon VPS" "murió en algún punto de la corrida"
stop_mac_daemon
stop_vps_daemon

# ==== g13: sync one-shot reporta al día ========================================
MAC_SYNC=$("$BIN" sync "$MAC_SPACE" 2>&1)
VPS_SYNC=$($SSH "set -e; $VPS_ENV; target/debug/filething sync ~/space-demo" 2>&1)
if grep -q 'pull: up to date' <<<"$MAC_SYNC" && grep -q 'commit: no local changes' <<<"$MAC_SYNC" \
   && grep -q 'pull: up to date' <<<"$VPS_SYNC" && grep -q 'commit: no local changes' <<<"$VPS_SYNC"; then
  ok "g13 sync one-shot: ambos lados al día, nada pendiente"
else ko "g13 sync one-shot" "mac: [$MAC_SYNC] vps: [$VPS_SYNC]"; fi

# ==== g14: roots idénticos + status limpio (fix 464496c) + listado idéntico ====
MAC_STATUS=$("$BIN" status "$MAC_SPACE" 2>&1)
VPS_STATUS=$($SSH "set -e; $VPS_ENV; target/debug/filething status ~/space-demo" 2>&1)
MAC_ROOT=$(sed -n 's/.*last synced: seq [0-9]* root //p' <<<"$MAC_STATUS")
VPS_ROOT=$(sed -n 's/.*last synced: seq [0-9]* root //p' <<<"$VPS_STATUS")
if [ -n "$MAC_ROOT" ] && [ "$MAC_ROOT" = "$VPS_ROOT" ]; then
  ok "g14 root hash idéntico en ambos lados ($MAC_ROOT)"
else ko "g14 root hash" "mac=$MAC_ROOT vps=$VPS_ROOT"; fi
if ! grep -q 'behind' <<<"$MAC_STATUS" && ! grep -q 'behind' <<<"$VPS_STATUS"; then
  ok "g14 status sin falso \"behind\" en ningún lado (fix 464496c)"
else ko "g14 status" "aparece \"behind\" estando al día — REGRESIÓN del fix de status"; fi
MAC_LS=$(cd "$MAC_SPACE" && find . -type f ! -name '.DS_Store' | sort)
VPS_LS=$($SSH "cd ~/space-demo && find . -type f ! -name '.DS_Store' | sort")
if [ "$MAC_LS" = "$VPS_LS" ]; then
  ok "g14 listado de archivos idéntico en ambos lados"
else
  ko "g14 listado" "difieren; mac=[$(tr '\n' ' ' <<<"$MAC_LS")] vps=[$(tr '\n' ' ' <<<"$VPS_LS")]"
fi

# ==== resumen ===================================================================
say ""
say "== RESUMEN ($TS) =="
for r in "${RESULTS[@]}"; do say "  $r"; done
N_FAIL=$(printf '%s\n' "${RESULTS[@]}" | grep -c '^FAIL') || true
say ""
if [ "$RC" -eq 0 ]; then
  say "TODO VERDE — logs en $RUN_DIR"
else
  say "$N_FAIL GATE(S) FALLARON — revisa $RUN_DIR/runbook.log, daemon-mac.log y daemon-vps.log"
fi
exit "$RC"
