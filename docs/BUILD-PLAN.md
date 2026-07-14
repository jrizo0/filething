# filething — Plan de construcción del MVP (contrato de interfaces)

Documento de orquestación. Define el mapa de crates, el grafo de dependencias, la
API pública (las "costuras") de cada componente y qué sección de `docs/format.md`
gobierna a cada uno. **Cada agente construye su crate contra este contrato y contra
`docs/format.md`** — así los componentes encajan sin colisionar.

`docs/format.md` v1.0 es la biblia normativa. Este doc NO la repite; la indexa.

> **Estado (2026-07):** este es el contrato ORIGINAL del build del MVP (2026-06-25). El MVP se
> construyó y validó, y las Fases 2–3 **superaron** dos decisiones de la §0: el auth pasó de
> pairing por código a **Better Auth real** (email+password por Device, `login --email`, ADR
> 0014) y el cifrado pasó de OFF a **`alg=1` en runtime** (XChaCha20-Poly1305 + escrow v1 en
> Convex, ADR 0015). El grafo de crates y las costuras (§1–§3) siguen vigentes **salvo lo de
> auth**: las mutations de pairing (`mintCode`/`claimCode`, tabla `pairing_codes`) se retiraron
> y la identidad la lleva Better Auth (`ctx.auth` + ownership). Estado vivo: `TODO.md`, `DEMO.md`
> y `docs/PRODUCTION-SETUP.md`.

---

## 0. Decisiones de este build (cerradas con el fundador, 2026-06-25)

- **Infra de prueba = local en Docker:** almacén S3 = **MinIO**; Coordinator = **Convex self-hosted** (imagen `ghcr.io/get-convex/convex-backend`). Todo corre en este VPS Linux. El código del `Vault` y del `Coordinator` queda detrás de una abstracción para apuntar a Cloudflare R2 / Convex cloud cambiando solo configuración.
- **Demo = 2 Devices simulados** como dos procesos con dos carpetas en este mismo Linux. El adaptador de FS de macOS se **codifica completo pero no se prueba en runtime** (no hay Mac).
- **Auth = pairing mínimo por código de dispositivo.** Better Auth / OAuth navegador = hueco reservado (post-MVP). — *SUPERADO en Fase 3: Better Auth real, `login --email` (ADR 0014); OAuth navegador sigue reservado.*
- **Cifrado = OFF** (`alg=0`, `nonce`=ceros, `cid == pcid`) pero con TODOS los huecos del formato reservados. `cid` y `pcid` son tipos SEPARADOS desde el día 1. — *SUPERADO en Fase 3: `alg=1` en runtime (ADR 0015); manifests siguen `alg=0`.*
- **Gestor JS = Bun** (workspaces), no pnpm.

---

## 1. Layout del monorepo

```
filething/
├── Cargo.toml                  # workspace Rust (lista todos los members)
├── rustfmt.toml, clippy.toml   # estilo
├── package.json                # workspace Bun (packages/*)
├── crates/
│   ├── ft-core/        # tipos y constantes compartidos (FUNDACIÓN)
│   ├── ft-hash/        # BLAKE3-256, hex+fan-out, KDF (FUNDACIÓN)
│   ├── ft-chunker/     # FastCDC 16/64/256 KiB
│   ├── ft-block/       # codec del objeto Block (header 64B)
│   ├── ft-manifest/    # B-tree de Manifest (CBOR canónico)
│   ├── ft-fsmap/       # mapeo de FS canónico + adaptadores OS
│   ├── ft-index/       # índice local SQLite
│   ├── ft-vault/       # trait Vault + backend S3 (MinIO/R2) + backend fs (tests)
│   ├── ft-coordinator/ # cliente Rust de Convex (head CAS, change feed)
│   ├── ft-watcher/     # file watcher + supresión de eco
│   ├── ft-diff/        # diff de árboles por poda de hash + aplicar bloques
│   ├── ft-conflict/    # resolución de conflictos a 3 vías por archivo
│   ├── ft-engine/      # INTEGRADOR: protocolo de commit, reconciliación, re-scan
│   └── ft-daemon/      # daemon foreground + socket local CLI↔daemon
├── apps/
│   └── cli/            # binario `filething` (clap): login/init/clone/status/ls/daemon
├── packages/
│   └── backend/        # Convex TS: schema §6.2, mutations §7, queries §8, auth (Better Auth)
├── infra/
│   ├── docker-compose.yml   # MinIO + Convex backend + dashboard
│   └── scripts/             # crear bucket, desplegar funciones, env de ejemplo
└── docs/
    ├── format.md       # spec normativa (existe)
    ├── BUILD-PLAN.md   # este doc
    └── adr/            # 9 ADRs de decisiones load-bearing
```

## 2. Grafo de dependencias (orden de construcción)

```
ft-core  (sin deps de filething)
  └─ ft-hash
       ├─ ft-chunker
       ├─ ft-block
       └─ ft-manifest
ft-core ─ ft-fsmap
ft-core ─ ft-index
ft-core ─ ft-vault
ft-core ─ ft-coordinator
ft-core ─ ft-watcher (+ ft-index)
ft-diff      → ft-manifest, ft-vault, ft-block, ft-fsmap
ft-conflict  → ft-core, ft-index, ft-manifest
ft-engine    → (todos los anteriores)        [INTEGRADOR]
ft-daemon    → ft-engine
apps/cli     → ft-engine, ft-daemon
packages/backend  (TS, independiente del Rust)
```

**Fundación (Fase 0, antes del fan-out):** `ft-core` + `ft-hash`. Todos compilan contra
ellos, así que sus tipos/firmas deben estar estables antes de paralelizar.

**Fan-out paralelo (Fase 1):** chunker, block, manifest, fsmap, index, vault,
coordinator, watcher, diff, conflict, y `packages/backend`. Son directorios DISJUNTOS
→ los agentes no se pisan (no hace falta worktree). Cada agente solo escribe en su crate.

**Integración (Fase 2):** ft-engine + ft-daemon + apps/cli, secuencial por gates.

---

## 3. Contrato por crate (responsabilidad · API · §format · tests clave · NO hacer)

### ft-core — tipos y constantes compartidos · §2, §4, §5
- **Newtypes:** `Cid([u8;32])`, `Pcid([u8;32])` (SEPARADOS aunque iguales en MVP),
  `CanonicalPath(String)`, `CasefoldKey(String)`.
- **Enums/structs:** `FileType { File=0, Symlink=1, Derived=2 }`; `FileEntry`
  (campos `p,t,x,sz,pcid,bk,bk_ref,lt,wu` de §5.1, con `serde` derive); tipos de
  página `LeafPage`/`IndexPage`/`ChildRef` (§5.3); `BlockHeader` (§4.3).
- **Constantes:** `CHUNK_MIN=16384, CHUNK_AVG=65536, CHUNK_MAX=262144`;
  `LEAF_FANOUT=256, INDEX_FANOUT=256, ENTRY_INLINE_MAX=262144`;
  `BLOCK_HEADER_LEN=64`, `MAGIC_BLOCK=*b"FTB1"`, `MAGIC_MANIFEST=*b"FTM1"`;
  `HEADER_VERSION=1`, `ALG_CLEARTEXT=0`, `ALG_AEAD=1`.
- **KDF context strings (§2.1):** las 5 constantes `&str`.
- **Errores:** enum raíz con `thiserror`.
- **NO:** lógica de hashing/IO/serialización de wire (eso es de cada crate consumidor).

### ft-hash — primitivas · §2, §4.2, §4.4
- `pub fn cid_of(stored_payload_with_nonce: &[u8]) -> Cid` = `BLAKE3-256(nonce || payload)`.
- `pub fn pcid_of(cleartext: &[u8]) -> Pcid`.
- `pub fn hex_lower(b: &[u8;32]) -> String`; `pub fn fanout_key(prefix: &str, hex: &str) -> String` → `"<prefix>/<aa>/<hex>"`.
- KDF (`blake3::derive_key`): `gear_table(chunk_secret) -> [u64;256]` (XOF a 256·8 B);
  `data_key(dedup_secret, pcid) -> [u8;32]`; `nonce(dedup_secret, pcid) -> [u8;24]`.
- **Tests:** vectores fijos de BLAKE3; determinismo de gear table; hex roundtrip.
- **NO:** cifrar nada (reservado); el cifrado solo deriva claves, OFF en MVP.

### ft-chunker — FastCDC · §3
- `pub struct Chunker { gear: [u64;256] }`; `pub fn chunk(&self, data: &[u8]) -> Vec<Span{offset,len}>`.
- Normalized chunking **nivel 2** (dos máscaras), min/avg/max de ft-core, gear de ft-hash.
- **Tests CLAVE:** (1) determinismo total; (2) **delta intra-archivo**: editar 1 byte
  en medio de un archivo de ~200 KiB cambia 1–2 spans, el resto idénticos; (3) min/max
  respetados; (4) mismo input + mismo secret en "dos máquinas" → mismos cortes.
- **NO:** chunking fijo; no usar el avg ~1 MiB de backup.

### ft-block — codec del objeto Block · §4.1–4.3, §4.5(reservar)
- `pub fn encode(payload: &[u8]) -> Vec<u8>` (header 64B `alg=0`, nonce ceros, payload_len LE).
- `pub fn decode(obj: &[u8]) -> Result<(BlockHeader, &[u8])>`.
- `pub fn cid_for(obj: &[u8]) -> Cid` = `BLAKE3(nonce||payload)`; `pub fn verify(obj, expected: &Cid)`.
- Reservar (no implementar) la rama `alg=1` y el sidecar `keys/*`.
- **Tests:** roundtrip; en MVP `cid == pcid`; header bien formado; verify falla si se corrompe un byte.

### ft-manifest — B-tree de Manifest · §5
- `pub fn build(entries: Vec<FileEntry>) -> ManifestBuild { root: Cid, pages: Vec<(Cid, Vec<u8>)>, blocklists: Vec<(Cid, Vec<u8>)> }`.
  Orden total por `casefold(NFC(p))` (usa ft-fsmap o recibe la key ya calculada),
  hojas de ≤256 entries, index de ≤256 hijos, bottom-up función pura, externaliza `bk`
  a `blocklist/<cid>` si CBOR de la FileEntry > `ENTRY_INLINE_MAX`. CBOR canónico (RFC 8949 §4.2.1).
- Lectura: `pub fn decode_page(bytes) -> Page`; helper para recorrer el árbol contra un `Vault`.
- **Tests CLAVE:** **mismo set de archivos → mismo `root` en cualquier máquina** (determinismo);
  reuso estructural (cambiar 5 archivos reescribe O(log n) páginas, el resto comparte `page_cid`);
  paginación con >256 entries; externalización de `bk` enorme.
- **NO:** meter el Manifest en Convex; no orden por hash (el orden de `bk` ES el contenido).

### ft-fsmap — mapeo de FS canónico · §5.2 + decisiones de FS
- `pub fn canonicalize(rel_path) -> CanonicalPath` (forward slash, relativo, UTF-8; NFC **solo** para derivar la key).
- `pub fn casefold_key(p: &CanonicalPath) -> CasefoldKey` = `casefold(NFC(p))`.
- `pub fn classify(meta) -> FileType`; política de symlink (relativo dentro del Space se preserva;
  absoluto / que escapa → local-only); detección de Derived path (node_modules, target, .next, venv).
- **Adaptador OS (trait `OsFs`):** leer/escribir bytes, bit ejecutable, crear symlink, leer mtime real.
  Impl **Linux** (probado) + impl **macOS** (codificado, no probado). Detección de colisión
  casefold/NFC → señal de conflicto (no sobre-escribir).
- **Tests:** NFC NO toca el contenido ni el `lt` de symlink; colisión de mayúsculas y de NFC detectada;
  symlink que escapa el Space rechazado; bit ejecutable preservado.

### ft-index — índice local SQLite · §9
- Tablas EXACTAS de §9: `space_state`, `local_entry`, `local_block`, `dedup_local` (+ índices).
- API tipada: upsert/get de entries por path; lookup dedup por `pcid`; query de colisión por `casefold_key`;
  set de bloques locales presentes; estado por Space (`last_synced_seq/root`, secrets, `local_root_path`).
- `rusqlite` (bundled). **Tests:** roundtrip de cada tabla; dedup por pcid; colisión por casefold.
- **NO:** poner lógica de sync aquí; es solo persistencia.

### ft-vault — almacén content-addressed · §6.1, F9
- `#[async_trait] pub trait Vault { async fn head(&self,key)->Result<bool>; async fn get(&self,key)->Result<Bytes>; async fn put(&self,key,bytes)->Result<()>; }`.
- Backend **S3** (apunta a MinIO local / R2): usa `aws-sdk-s3` con endpoint+creds configurables, path-style.
- Backend **fs** (carpeta local) para tests sin Docker.
- Keys: `blocks/<aa>/<cid>`, `manifest/<aa>/<cid>`, `blocklist/<aa>/<cid>` (reservar `keys/*`, `reach/*`).
- PUT idempotente (content-addressed); `head` antes de `put` para ahorrar ancho de banda.
- **Tests:** roundtrip put/get/head contra backend fs; (integración) contra MinIO.

### ft-coordinator — cliente Rust del Coordinator · §6.2, §7(cliente), §8
- Envuelve el crate `convex`. `connect(url) -> Coordinator`.
- Mutations: `create_space`, `register_device`, `mint_pairing_code`/`claim_pairing_code`,
  `commit_revision(space, expected_base, manifest_root, author)` → `Result<RevisionId, ConflictError>` (CAS §7).
- Queries/subscripción: `subscribe_head(space) -> Stream<HeadUpdate{seq, manifest_root, parent}>` (change feed §8);
  `revision_by_seq`. Tipos `Cid` ↔ `v.bytes()`.
- **Tests:** serialización de args; (integración) contra Convex local.
- **NO:** subir bytes ni Manifest a Convex; solo punteros/hashes de 32B.

### ft-watcher — watcher + supresión de eco · §9
- `notify` crate; emite eventos de cambio coalescidos (debounce). Tras aplicar un archivo bajado
  del feed, registra `(mtime real, pcid)`; un evento que coincide con ese estado se reconoce como
  propio y NO se re-emite.
- API: `Watcher::new(root, callback)`; `mark_applied(path, mtime, pcid)`.
- **Tests:** la supresión de eco descarta el evento auto-generado; un cambio real sí pasa.

### ft-diff — diff de árboles + aplicar · §8
- `pub fn diff(root_a: Cid, root_b: Cid, vault) -> Vec<Change{Added|Modified|Deleted, FileEntry}>` por poda de hash
  (páginas con mismo `page_cid` → poda; merge-join en hojas que difieren).
- `pub async fn apply(changes, vault, fsmap, index)`: `bk_faltantes = bk_nuevos − local`; baja solo esos
  `blocks/<cid>`, **verifica integridad** (`BLAKE3(nonce||payload)` vs cid), concatena, escribe vía adaptador OS.
- **Tests:** un commit que tocó 5 archivos baja O(log n) páginas; delete inferido por ausencia; verificación de wire.

### ft-conflict — conflictos a 3 vías por archivo · §10
- `pub fn resolve(base: Option<FileEntry>, local: Option<FileEntry>, remote: Option<FileEntry>) -> Resolution`
  decidiendo "cambió" por **`pcid`** (nunca mtime): cambió en un lado → fast-forward;
  en ambos → copia de conflicto (`nombre (conflicto <deviceId> <seq>).ext`); delete-vs-edit → gana edición;
  colisión casefold/NFC → conflicto.
- **Tests:** los 4 casos; nombre de copia de conflicto determinista.

### ft-engine — INTEGRADOR · §7, §8, §10, re-scan §9
- Protocolo de commit §7 EXACTO: chunk+hash → dedup (index + HEAD vault) → build manifest →
  subir TODOS los bloques+páginas al Vault (verificado) → CAS atómico del head en Convex →
  si `ConflictError`: pull + reconciliar (§10) + reconstruir + reintentar.
- Re-scan completo al arrancar/reconectar contra el índice local.
- Lazo del feed: head nuevo → diff → aplicar (con supresión de eco) → actualizar índice.
- **Tests:** los gates de integración (ver §4) viven aquí o en `apps/cli`.

### ft-daemon — daemon foreground + socket · CONTEXT (Daemon), §MVP
- Daemon multi-Space en **foreground** (MVP). Socket local (Unix socket) para que la CLI hable con él.
- Protocolo de comandos: status, list spaces, trigger sync. Supervisión por Space.

### apps/cli — binario `filething` · CONTEXT (CLI estilo git)
- `clap`. Comandos: `login --email` (Better Auth desde Fase 3; ya no pairing por código), `init <dir>` (carpeta→Space, registra en daemon),
  `clone <space> <dir>`, `status`, `ls`, `daemon` (corre el daemon en foreground).
- Habla con el daemon por el socket local.

### packages/backend — Convex (TS) · §6.2, §7, §8
- `schema.ts` EXACTO de §6.2: `spaces, revisions, devices, dedup` con sus índices.
- Mutations: `commitRevision` con **lectura del head DENTRO de la txn + CAS** (§7),
  `createSpace`, `registerDevice`, pairing (`mintCode`/`claimCode`).
- Queries: `headBySpace` (reactiva = change feed), `revisionBySeq`.
- Bun + `convex`. Codegen para que el cliente Rust conozca las firmas.
- **NO:** almacenar Manifest ni bytes; respetar 1 MiB/doc, 16 MiB/txn, 1s CPU.

---

## 4. Gates de integración (Fase 2, secuencial — validan el criterio de éxito)

- **Gate 0** (1 máquina, sin Coordinator): escribo archivo → chunk → bloques al Vault → recargo → reconstruyo bytes idénticos.
- **Gate 1:** + manifest + commit §7: construir manifest, subir páginas, CAS del head en Convex. Un Device commitea una Revision.
- **Gate 2** (criterio **a**): segundo "Device" (proceso, carpeta+índice aparte) se suscribe, hace pull, aplica, reconstruye el árbol. *Edito en A → aparece en B.*
- **Gate 3** (criterio **b**): bidireccional + supresión de eco + conflictos. *Sin loop de eco ni conflictos falsos.*
- **Gate 4** (criterio **c**): corto Coordinator/Vault, edito offline en ambos, reconecto → reconcilia sin perder datos (copias de conflicto donde toca).
- **Gate 5** (criterio **d**): cambio 1 línea de un archivo grande → suben SOLO los bloques cambiados (assert sobre el conteo de PUTs).

## 5. Convenciones (TODOS los agentes)

- **Lenguaje ubicuo** de `CONTEXT.md` en tipos, módulos y nombres: Space, Block, Manifest, Revision,
  Space head, Coordinator, Vault, Grant, Derived path, Cid, Pcid, FileEntry.
- `Cid` y `Pcid` SEPARADOS desde el día 1 (aunque `cid==pcid` en MVP).
- Determinismo es sagrado: chunker, CBOR canónico, paginación del Manifest. Tests de "misma entrada → mismo hash en cualquier máquina".
- Errores con `thiserror` por crate; `anyhow` solo en el binario.
- Cifrado OFF: `alg=0`, nonce=ceros, sin escribir `keys/*`; pero reservar los campos del header y computar `cid = BLAKE3(nonce||payload)`.
- TDD en los componentes críticos (chunker, block, manifest, commit). `cargo fmt` + `cargo clippy -D warnings` limpios.
