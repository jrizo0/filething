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

### Fase A — Infra gestionada (uso propio, multi-red real)
La migración de datos es barata: los Blocks son content-addressed (re-subir o `aws s3 sync`
al bucket nuevo) y el Coordinator se re-crea (re-init de Spaces si no se migran los docs).
- [ ] **Convex Cloud**: crear proyecto/deployment, `npx convex deploy` de `packages/backend`,
  apuntar `CONVEX_SELF_HOSTED_URL` → URL del deployment. ⚠️ No es 100% config: el cliente Rust
  hoy se autentica con el **admin key self-hosted**; en cloud eso no existe para clientes — para
  uso personal se puede usar un deploy key (aceptable solo mientras todos los devices sean tuyos),
  y para terceros exige la Fase B (auth real). Verificar también que el change feed (WebSocket)
  funciona igual contra cloud.
- [ ] **Cloudflare R2**: crear bucket + API token con scope al bucket; apuntar
  `S3_ENDPOINT`/`S3_ACCESS_KEY`/`S3_SECRET_KEY`/`S3_BUCKET`. El backend S3 de `ft-vault` ya
  habla R2 (mismo protocolo); sin egress fees. Validar `scripts/demo-gates.sh` completo (a–f)
  contra R2 + Convex Cloud antes de dar por buena la migración.
- [ ] **Secretos fuera del repo**: env/secret manager para las credenciales R2 y Convex
  (hoy viven en `infra/.env` local, que no se commitea — mantenerlo así).
- [ ] Sin túnel SSH: con infra gestionada, Mac y VPS hablan directo a Convex/R2 por HTTPS —
  desaparece la fragilidad del túnel que contaminó la prueba del 25.
- [ ] Re-correr la prueba Mac↔VPS contra la infra gestionada (el escenario real de uso).

### Fase B — Endurecer para usuarios reales (desbloquea cobrar)
En orden de prioridad; los [R] de abajo guardan los huecos ya cableados en el formato:
- [ ] **Auth real** (Better Auth): login por navegador + tokens por device emitidos en el
  pairing; el cliente deja de necesitar cualquier key privilegiada. Prerrequisito para todo lo demás.
- [ ] **Cifrado en runtime** (`alg=1`, huecos ya reservados): antes de guardar bytes de
  terceros en R2. Data key determinista por cuenta (ADR 0003), sidecars `keys/<cid>`.
- [ ] **Daemon como servicio** (launchd en macOS, systemd en Linux) con logs rotados —
  hoy es foreground/nohup y el log se pierde al relanzar con `>`.
- [ ] **Binarios por SO** (cargo-dist o similar) + firma/notarización en macOS.
- [ ] **GC/retención** (grace-period + `retentionFloorSeq`, schema ya lo reserva): sin esto el
  Vault solo crece.
- [ ] **Observabilidad mínima**: métricas de sync (commits, pulls, conflictos, errores del
  feed) y alerta si un daemon queda >N min sin ver el head.
- [ ] Validación de nombres Windows (antes de soportar Windows) y packing de bloques chicos
  (costo/latencia en R2) — según demanda.
- [ ] **Billing (Polar) + dashboard (Next.js)**: cuando haya usuarios que cobrar (Seats por
  device, storage gestionado como add-on medido).

---

## Reservado — NO construir en el MVP (huecos ya cableados en el formato)
- [R] Cifrado en runtime (`alg=1`, sidecars `keys/*`, derivación+cifrado AEAD)
- [R] Zero-knowledge (cifrar páginas de Manifest, `reach/*` para GC)
- [R] Serve mode / self-hosted vault + Grants firmados
- [R] GC / retención (grace-period y retention floor ya reservados en schema)
- [R] Better Auth / OAuth navegador completo (MVP = pairing por código)
- [R] Billing (Polar), dashboard y marketing (Next.js)
- [R] Packing de bloques chicos; binarios per-SO; validación de nombres Windows
- [R] Move-detection / tombstones explícitos (rename = delete+add en MVP)
