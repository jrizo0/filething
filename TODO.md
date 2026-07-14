# filething — TODO (MVP)

Checklist maestro de TODO lo que queda por hacer para el MVP. Fuente de verdad viva:
se va marcando a medida que avanza. Detalle técnico de cada ítem en `docs/BUILD-PLAN.md`
y la spec normativa en `docs/format.md`.

Leyenda: `[ ]` pendiente · `[~]` en progreso · `[x]` hecho · `[R]` reservado (post-MVP, NO construir)

---

## Fase 0 — Cimientos y scaffold
- [x] Instalar toolchain Rust (rustup stable + clippy + rustfmt)
- [x] Crear rama de trabajo `mvp-implementation`
- [x] Bajar imágenes Docker (MinIO + Convex backend)
- [x] Escribir `docs/BUILD-PLAN.md` (contrato de interfaces) y este `TODO.md`
- [x] Scaffold del workspace Cargo (root `Cargo.toml` + 14 crates stub que compilan)
- [x] Scaffold del workspace Bun (`package.json`) + `packages/backend` stub
- [x] Config: `rustfmt.toml`, `clippy.toml`, `.gitignore`, CI básico (fmt/clippy/test, tsc/convex)
- [x] `infra/docker-compose.yml` (MinIO + Convex backend + dashboard) + scripts (crear bucket, env)
- [x] **ft-core** — tipos y constantes compartidos (FUNDACIÓN, 21 tests, clippy/fmt OK)
- [x] **ft-hash** — BLAKE3-256, hex+fan-out, KDF/gear table (FUNDACIÓN, 19 tests, clippy/fmt OK)

## Fase 1 — Componentes en paralelo (cada uno con TDD)
Ola 1 (deps = fundación) — ✅ workspace verde (build/test/clippy/fmt):
- [x] **ft-chunker** — FastCDC 16/64/256 KiB, normalized chunking nivel 2 (§3) — 14 tests
- [x] **ft-block** — codec del objeto Block, header 64B, `cid=BLAKE3(payload)` MVP (§4) — 16 tests
- [x] **ft-manifest** — B-tree CBOR canónico, paginación determinista 256/256 (§5) — 20 tests
- [x] **ft-fsmap** — paths canónicos, NFC solo en key, casefold, symlinks, adaptadores OS (§5.2) — 13 tests
- [x] **ft-index** — SQLite local, schema exacto (§9) — 26 tests
- [x] **ft-vault** — trait Vault + backend S3 (MinIO/R2) + backend fs (§6.1) — 6 tests
- [x] **ft-coordinator** — cliente Rust de Convex: head CAS, change feed (§6.2/§7/§8) — 33 tests
- [x] **ft-watcher** — file watcher + supresión de eco (§9) — 5 tests
- [x] **packages/backend** — Convex TS: schema §6.2, mutations §7 (commit+CAS), queries §8, pairing — tsc OK
Ola 2 (deps = Ola 1) — ✅:
- [x] **ft-diff** — diff de árboles por poda de hash + aplicar bloques (§8) — 15 tests
- [x] **ft-conflict** — resolución de conflictos a 3 vías por archivo (§10) — 27 tests

## Fase 1.5 — Revisión adversarial por componente
- [x] Auditoría adversarial de 7 áreas de riesgo (read-only): chunker ✅, manifest ✅, block+hash ✅, diff ❌, conflict ❌, fsmap ❌, coordinator/backend ❌
- [x] Corregir hallazgos reales (workflow de fixes en 2 etapas):
  - [x] coordinator: `seq`/`baseSeqInUse` enviados como Float64 — **change feed validado en vivo contra Convex real**
  - [x] diff: borrar destino antes de materializar (symlink↔file); integridad de `blocklist/<cid>`; Modified por identidad completa
  - [x] conflict: identidad por tipo (File→pcid+x, Symlink→lt, Derived→t); fix de `conflict_copy_name`
  - [x] block: `decode`/`verify` exigen magic FTB1
- [x] Re-verificar workspace completo: 235 tests + 1 live OK, clippy/fmt limpios
- Limitaciones conocidas aceptadas para MVP (registradas, no bloquean el demo Linux+ASCII):
  - [R] `ft-fsmap` casefold = `to_lowercase` (no casefold Unicode completo): colisiones exóticas (µ/μ, ς/σ) no se detectan; ASCII sí. Mejorar con `caseless` o validación en FS case-insensitive = post-MVP.
  - Nota: `ft-manifest` ordena claves length-first; para keys de texto ≤23 chars es **idéntico** a RFC 8949 §4.2.1 (no es bug). Páginas-hoja podrían crecer si las FileEntry son grandes-pero-bajo-`ENTRY_INLINE_MAX` (edge, no MVP).
  - Engine debe: garantizar que no lleguen keys casefold duplicadas a `manifest::build` (resolver conflicto antes); fijar `pcid` de symlink determinista (p.ej. `pcid_of(lt)`).

## Fase 2 — Integración (secuencial, por gates)
- [~] **ft-engine** — protocolo de commit §7 (orden estricto + CAS), reconciliación, re-scan §9
  - [x] E1: `SpaceContext` + scan + commit §7 + `init_space` — 11 tests, **commit live contra Convex+vault OK**
  - [x] E2: pull/apply/reconcile §10 + clone + watch loop + supresión de eco — 18 tests + **`two_devices_end_to_end` live OK**
- [x] **ft-daemon** — daemon foreground multi-Space (`serve` concurrente, shutdown por watch, Ctrl-C). Socket local → reservado (status lee estado local sin daemon vivo)
- [x] **apps/cli** — binario `filething`: `login`(código)/`init`/`clone`/`status`/`ls`/`sync`/`daemon` — 15 tests + flujo CLI 2-devices live OK
Gates (validados a nivel engine; falta correrlos vía CLI real para el demo):
- [x] Gate 0 — archivo → chunk → Vault → reconstrucción idéntica (ft-diff round-trip + engine)
- [x] Gate 1 — manifest + commit §7 + CAS del head en Convex (live `commit_against_live_backend`)
- [x] Gate 2 — criterio **(a)**: A → B (live `two_devices_end_to_end`: clone + pull)
- [x] Gate 3 — criterio **(b)**: bidireccional sin eco ni conflictos falsos (live two-device)
- [x] Gate 4 — criterio **(c)**: corte de red (`docker stop` Convex) + edición offline en ambos + reconexión → reconcilia con copia de conflicto, **sin pérdida** (demo CLI live)
- [x] Gate 5 — criterio **(d)**: 1 línea en archivo grande → **delta = 1 bloque** (36→37 en MinIO; demo CLI live)
- [x] **a–d corridos vía la CLI real** (`filething login/init/clone/sync`) contra Convex+MinIO — `scripts/demo-gates.sh`. **TODOS PASAN.**

## Fase 3 — Revisión adversarial final — ✅
- [x] Determinismo del chunker y del Manifest (auditoría `holds` + tests); content-addressing (cid==pcid, integridad)
- [x] Atomicidad del CAS (live `commit_against_live_backend`) + crash-safety del commit (orden §7 verificado en `commit.rs`: todo al Vault → luego CAS; nunca head colgante)
- [x] Reconciliación tras corte de red (Gate 4 live: copia de conflicto, sin pérdida)

## Documentación (ADRs)
- [x] `docs/adr/0001-derived-path-policy.md` (política de artefactos por gestor)
- [x] 9 ADRs del apéndice de `format.md` (0002–0010, escritos):
  - [x] 0002 `cid = BLAKE3(nonce‖payload)` excluye la data key envuelta
  - [x] 0003 data key/nonce DETERMINISTAS por `pcid` (invierte el "aleatoria" de la memoria)
  - [x] 0004 data key envuelta en sidecar `keys/<cid>` (no en el header)
  - [x] 0005 B-tree de Manifest con paginación determinista (256/256, bottom-up)
  - [x] 0006 colisión NFC = conflicto; NFC solo en la key
  - [x] 0007 safety de GC: grace-period + `retentionFloorSeq`
  - [x] 0008 `dedup` de Convex es caché, no fuente de verdad
  - [x] 0009 FastCDC 16/64/256 KiB (no el de backup)
  - [x] 0010 primitivas: BLAKE3-256, hex fan-out, CBOR canónico, XChaCha20-Poly1305

## Cierre
- [x] Actualizar `HANDOFF.md` y `memories/filething-project.md` con el estado real del código
- [x] `DEMO.md` — correr la demo (2 Devices) + `scripts/demo-gates.sh` + migrar a R2/Convex cloud
- [x] Commit de la rama `mvp-implementation` (2 commits pusheados a origin, 2026-07-01)
- [x] Disco del VPS liberado (~80 GB libres al 2026-07-01); dashboard de Convex se recrea con `docker compose up -d` cuando haga falta
- [ ] Arreglar el healthcheck de Convex en `infra/docker-compose.yml` (el contenedor aparece "unhealthy" pero el servicio responde 200 — el comando de chequeo falla por timeout)
- [ ] Mergear `mvp-implementation` → `main` (tras validar la prueba real Mac↔VPS con los fixes)

---

## Hallazgos de prueba manual Mac↔VPS (2026-06-25) — DIAGNOSTICADOS Y ARREGLADOS (2026-07-01)
Diagnóstico por 3 vías: forense de las 13 Revisions en Convex, reproducción local con 2 devices
y red estable, y lectura del código. Detalle completo en `diary/2026-07-01.md`. Conclusión
central: **los commits nunca fallaron** (todo lo editado/borrado llegó a Convex); lo que se
rompía era el lado que *recibe* y dos huecos de resiliencia del daemon.

- [x] **Modificación no se propaga (C2)** → era un bug real y reproducible: el buffer de
  coalescing de `ft-watcher` nunca expiraba — la 2ª edición del mismo archivo jamás se
  reenviaba en la vida del daemon. FIX: ventana real de 50 ms (`CoalesceBuffer`) + 6 tests.
  (En la prueba del 25, además, la Mac no aplicó la Revision seq 8 pese a estar commiteada —
  ver el fix del pull de respaldo.)
- [x] **Borrado VPS→Mac no se propaga (C4)** → NO reproduce con red estable (el borrado sí se
  commiteó: seq 9, justo al inicio del corte). Era artefacto del corte, agravado por dos huecos
  reales, ambos arreglados: (1) el daemon no hacía commit inicial al arrancar (`startup_sync()`
  en `run.rs`: cambios offline se commitean al montar); (2) el feed podía morir en silencio sin
  recuperación (pull de respaldo cada 30 s, `FALLBACK_PULL_INTERVAL`).
- [x] **Latencia de borrados (C1)** → el commit fue inmediato (seq 7); la demora era del lado
  que aplica (feed dormido). El pull de respaldo acota el peor caso a ~30 s; con feed sano la
  propagación medida es ~2 s.
- [x] **Extra**: el `.DS_Store` de la Mac se sincronizó al Space → `.DS_Store`/`Thumbs.db`/
  `desktop.ini` ya no se sincronizan nunca (built-in, ADR 0011); un Space que ya los tenga se
  auto-limpia en el siguiente commit.
- [ ] Re-correr la prueba manual Mac↔VPS con los fixes (guía `docs/MAC-SETUP.md`, ya
  actualizada con túnel auto-reconectable y daemon detached con log en append).

---

## Roadmap a producción — Convex Cloud + R2 (agregado 2026-07-01)
Objetivo: salir de la infra de juguete (Docker en el VPS) a la infra gestionada real, y dejar
el producto usable en producción. Orden pensado para que cada fase sea usable por sí sola.

### Fase A — Infra gestionada (uso propio, multi-red real) — CÓDIGO/CONFIG LISTO (2026-07-02)
La migración de datos es barata: los Blocks son content-addressed (re-subir o `aws s3 sync`
al bucket nuevo) y el Coordinator se re-crea (re-init de Spaces si no se migran los docs).
Runbook completo: `docs/PRODUCTION-SETUP.md`. ADR: `docs/adr/0013`.
- [x] **Auth cloud-neutral en el cliente**: `apps/cli/src/env.rs` lee `CONVEX_URL` +
  `CONVEX_DEPLOY_KEY`/`CONVEX_ADMIN_KEY` (fallback a `CONVEX_SELF_HOSTED_*`); si no hay
  credencial, conecta sin auth (funciones Convex públicas por defecto). Deploy key vía la ruta
  `set_admin_auth` (`#[doc(hidden)]`) → **verificar en vivo** con `scripts/cloud-smoke.sh`.
- [x] **Convex Cloud**: `scripts/cloud-deploy.sh` (deploy no interactivo con `CONVEX_DEPLOY_KEY`).
- [x] **Cloudflare R2**: config-only (`ft-vault` ya habla R2; `S3_REGION=auto`, path-style).
  Plantilla `infra/.env.cloud.example`.
- [x] **Secretos fuera del repo**: `infra/.env.cloud` (gitignored, en `.gitignore`).
- [~] **Provisionar cuentas + validar en vivo** (2026-07-04): R2 (`filething-prod`) y Convex
  Cloud (`knowing-giraffe-699`, prod) provisionados; `cloud-deploy.sh` + `cloud-smoke.sh` en
  verde (login Better Auth + init/clone 2 devices + round-trip R2 con descifrado `alg=1` + gc
  dry-run). **Queda**: re-correr la prueba Mac↔VPS contra la nube (sin túnel SSH — Mac y VPS
  hablan directo por HTTPS); requiere la Mac del usuario.

### Fase B — Endurecer para usuarios reales (desbloquea cobrar)
En orden de prioridad; los [R] de abajo guardan los huecos ya cableados en el formato.
Entró en la tanda del 2026-07-02: daemon-servicio + observabilidad + GC/retención.
Entró en la tanda del 2026-07-03 ("Fase 3"): auth real + cifrado en runtime.
- [x] **Auth real** (Better Auth, ADR 0014 — 2026-07-03): email+password headless (login por
  navegador diferido); componente `@convex-dev/better-auth` en el backend; `ctx.auth` +
  ownership en TODAS las funciones Convex; `filething login --email` (token de sesión por
  device en `credentials.json` 0600, JWT vía `set_auth`/`set_auth_callback`); pairing codes
  eliminados (pairing = login del mismo usuario); deploy key relegada a fallback de ops.
  Validado e2e contra el stack local (2 devices, aislamiento cross-account).
- [x] **Cifrado en runtime** (`alg=1`, ADR 0015 — 2026-07-03): XChaCha20-Poly1305 con data
  key/nonce deterministas (ADR 0003), sidecars `keys/<aa>/<cid>` (ADR 0004), escrow v1 de
  `dedupSecret`/`spaceKey` en Convex, GC barre sidecars junto a sus Blocks. Manifests siguen
  `alg=0` (zero-knowledge diferido). Vault mixto OK; spaces pre-Fase 3 siguen en claro.
  Validado e2e: blocks en MinIO sin plaintext + clone/descifrado cross-device. Validado en
  vivo contra Convex Cloud + R2 (2026-07-04, `cloud-smoke.sh` en verde con
  `BETTER_AUTH_SECRET`/`SITE_URL` en el deployment — runbook §4.3).
- [x] **Vault firmado** (URLs prefirmadas, ADR 0016 — 2026-07-04, "Fase 4"): el Device ya no
  necesita `S3_*` — action `vault:sign` ("use node", batcheada ≤256, TTL 15 min) con
  `ctx.auth` + validación estricta de keys + ownership para `keys/<space_id>/…`; cliente
  `SignedVault` (`apps/cli/src/signed_vault.rs`) ejecuta las URLs con reqwest directo a R2.
  Precedencia en `build_vault`: `S3_*` en el entorno → acceso directo (ops/self-hosted/gates);
  si no → firmado. `gc` sigue siendo de operador (list/delete no se prefirman). El smoke corre
  los devices SIN `S3_*`. **Reservado**: batching desde el engine (hoy 1 action-call por
  operación) y layout de keys con prefijo por Account.
- [x] **Daemon como servicio** (`filething service install/uninstall/status`): launchd en
  macOS, systemd `--user` en Linux; env file 0600 con las credenciales + logs en
  `<config_dir>/daemon.log`, reinicio al fallar. `apps/cli/src/service.rs` (generadores puros
  testeados; carga/descarga vía launchctl/systemctl).
- [x] **Binarios por SO** (Fase 5, 2026-07-04): `dist` (cargo-dist 0.32) con installer shell
  (`curl | sh` desde GitHub Releases) para Mac arm64/x86_64 + Linux musl x86_64/arm64
  (estático, sin glibc del host); stack TLS migrado a rustls (fuera OpenSSL) para el
  cross-build musl; el workflow de release hornea `FILETHING_DEFAULT_CONVEX_URL`
  (`.github/workflows/release-build-setup.yml` → `apps/cli/src/env.rs`) — sin ella el
  binario cae a localhost como en dev. Repo público + licencia MIT. **Reservado**:
  firma/notarización macOS (solo hace falta para Homebrew cask/GUI; `curl` no pone el
  atributo de cuarentena de Gatekeeper), dominio propio para el installer (redirect).
- [x] **Performance del vault firmado + daemon por defecto** (Fase 6, 2026-07-04, ADR 0017;
  motivado por la primera corrida real en Mac: un init de ~100 archivos tardó ~3.5 min en
  silencio): `Vault::warm` (hint batch, default no-op) + `SignedVault` con firmas por lote
  (≤256/action) y caché de URLs (TTL 900s−60 de margen); concurrencia `buffer_unordered` en
  `commit.rs` (16) y `ft-diff::apply` (8); progreso visible por `tracing::info` en
  subidas/bajadas. `init`/`clone`/`sync` instalan/arrancan/reinician el daemon-servicio en
  background por defecto (`--no-daemon` / `FILETHING_NO_AUTO_DAEMON=1` para opt-out; los
  scripts de gates/smoke lo setean); `filething daemon` sin dirs = todos los Spaces mapeados
  (lo que invoca el unit del servicio; con 0 Spaces queda idle, sin crash-loop). **Reservado**:
  warm de bloques tras leer una blocklist externalizada (`bk_ref` solo pre-firma la blocklist).
- [~] **GC/retención** (`filething gc`, dry-run por defecto): mark-and-sweep **account-wide de
  huérfanos** (retiene TODO el historial; borra solo objetos que ninguna Revision referencia) +
  grace-period + guard de concurrencia. Validado en vivo (demo-gates gate g). ADR 0012. La
  **poda de historial** (retention floor) queda diferida: necesita telemetría por-(Device,Space)
  para un floor sound (el escalar `baseSeqInUse` actual no basta). Andamiaje reservado.
- [x] **Observabilidad mínima**: `SyncMetrics` (commits, pulls, conflictos, errores del feed,
  alertas de staleness) persistida en `<root>/.filething/metrics.json`; `filething metrics`;
  watchdog que alerta si el head queda >5 min sin confirmarse; heartbeat por `tracing`.
- [ ] Validación de nombres Windows (antes de soportar Windows) y packing de bloques chicos
  (costo/latencia en R2) — según demanda.
- [ ] **Billing (Polar) + dashboard (Next.js)**: cuando haya usuarios que cobrar (Seats por
  device, storage gestionado como add-on medido).

---

## Reservado — NO construir en el MVP (huecos ya cableados en el formato)
- [R] ~~Cifrado en runtime~~ → construido en Fase 3 (2026-07-03, ADR 0015)
- [R] Zero-knowledge (cifrar páginas de Manifest, `reach/*` para GC)
- [R] Serve mode / self-hosted vault + Grants firmados — **parcialmente construido en Fase 4**
  (2026-07-04, ADR 0016): el plano de datos gestionado ya va por URLs prefirmadas del
  Coordinator; siguen reservados el serve mode P2P y los Grants offline firmados del formato
- [R] GC / retención (grace-period y retention floor ya reservados en schema)
- [R] ~~Better Auth~~ → construido en Fase 3 (email+password headless, ADR 0014); OAuth
  navegador + device-authorization para devices headless siguen reservados
- [R] Billing (Polar), dashboard y marketing (Next.js)
- [R] Packing de bloques chicos; binarios per-SO; validación de nombres Windows
- [R] Move-detection / tombstones explícitos (rename = delete+add en MVP)
