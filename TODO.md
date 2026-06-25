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
- [ ] (cuando el usuario lo pida) commit de la rama `mvp-implementation`
- [ ] (opcional) liberar más disco / recrear el dashboard de Convex (`docker compose up -d`)

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
