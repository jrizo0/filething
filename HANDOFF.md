# filething — Handoff: implementar el MVP con un equipo grande de agentes

**Fecha:** 2026-06-24
**Próxima sesión:** construir el MVP de filething orquestando muchos agentes en paralelo (Workflow / multi-agente). El diseño ya está cerrado; ahora toca **codear**.

---

## 1. Qué es filething (orientación en 30s)

CLI dev-focused de sync de carpetas, "Dropbox para developers", en Rust. Modelo mental git: `login` (1 vez por equipo), `init` (carpeta → Space), `clone <space> <ruta>`, `status`. Dos planos que nunca se mezclan:
- **Coordinator** (Convex): control plane. Identidad, pairing, Manifests, change feed en tiempo real. Docs diminutos. Nunca ve bytes ni llaves.
- **Vault** (R2 gestionado o VPS self-hosted en serve mode): data plane. Bloques content-addressed e inmutables.

Negocio: cobrar por **conectar** (Seat = device pagado), no por bytes. Storage gestionado = add-on medido.

---

## 2. Referencias canónicas — LEER ESTO PRIMERO (no duplicar; está todo ahí)

| Qué | Dónde |
|---|---|
| **Formato Block/Manifest v1.0 (la biblia para construir el MVP)** | `/Users/jrizo/filething/docs/format.md` |
| Glosario de lenguaje ubicuo (usar estos términos en el código) | `/Users/jrizo/filething/CONTEXT.md` |
| Todas las decisiones (arquitectura, negocio, cripto, conflictos, stack, scope MVP) | memoria del proyecto: `/Users/jrizo/.claude/projects/-Users-jrizo-filething/memory/filething-project.md` |
| Documento de diseño visual | https://claude.ai/code/artifact/75e8cf92-cc81-4bda-883f-0d17eb532e60 |
| Formato de ADR / CONTEXT (para escribir los ADRs pendientes) | `/Users/jrizo/filething/.claude/skills/domain-modeling/{ADR-FORMAT.md,CONTEXT-FORMAT.md}` |

`docs/format.md` es self-contained: layouts exactos, primitivas, schema de Convex (§6.2), protocolo de commit (§7), índice local SQLite (§9), y un checklist de los 14 requisitos. **El equipo construye contra ese doc.**

---

## 3. Estado actual

- **Diseño 100% cerrado.** Se cerraron 5 decisiones grandes en entrevista (binarios por SO, daemon, historial/GC, precios, MVP) + se auditaron 10 hallazgos de un revisor externo (8 reales resueltos, 1 falso, 1 parcial) + se aterrizó el formato Block/Manifest. Todo en la memoria.
- **Repo casi vacío:** solo existen `CONTEXT.md` (raíz) y `docs/format.md`. **No hay código todavía.** El working dir **aún no es un repo git** — hay que `git init` (y crear rama antes de commitear, ver guardrails).
- Stack fijado: **Rust+Cargo** (CLI/motor), **Convex** (coordinator, TS), **Cloudflare R2** (bytes), **Next.js** (web, post-MVP), **Better Auth**, **Polar** (billing, post-MVP), **monorepo pnpm + Turborepo**.

---

## 4. El MVP — qué construir (recap; detalle en `docs/format.md §11` y memoria)

**"Magia completa, todo lo demás recortado":** el bucle vertical delgado entre **una Mac + un VPS Linux**, con un Space de juguete de **archivos normales** (no node_modules real).

**DENTRO:** motor de bloques FastCDC + índice local + re-chunkeo solo de lo tocado; Vault R2 con orden de commit estricto; Coordinator Convex con Manifest paginado por hash; change feed bidireccional (cliente Rust de Convex); supresión de eco; conflictos = ambas versiones; login por código; daemon en **foreground**; **mapeo de FS canónico desde el día 1**; **cifrado OFF pero con todos los huecos reservados** (`alg=0`, cleartext).

**FUERA (huecos reservados, no construir):** cifrado en runtime, self-hosted vault/`serve`, servicio instalado, billing, dashboard, GC/retención, escala, binarios per-SO, Windows.

**Criterio de éxito (demo):** (a) edito en Mac A → aparece solo en B; (b) bidireccional sin loop de eco ni conflictos falsos; (c) corto la red, edito offline en ambos, reconecto → reconcilia sin perder datos; (d) cambio 1 línea de un archivo grande → solo suben los bloques cambiados.

---

## 5. Cómo abordarlo con un equipo GRANDE de agentes

Ultracode está activo: usa el **Workflow tool** para orquestar. Sugerencia de fases (una Workflow por fase, revisando entre fases):

**Fase 0 — Scaffold (1-2 agentes):** `git init`; monorepo `apps/cli` (Rust), `packages/backend` (Convex TS), `packages/shared`; pnpm workspaces + Turbo + Cargo workspace; CI básico (fmt/clippy/tsc). Esto debe ir **antes** de paralelizar (los demás dependen de la estructura).

**Fase 1 — Componentes en paralelo, cada uno construido contra `docs/format.md` con TDD + revisión adversarial.** La mayoría son independientes y se integran después. Usa `isolation: 'worktree'` para agentes que tocan archivos en paralelo:
- Chunker **FastCDC** (params 16/64/256 KiB, normalized chunking nivel 2, gear table desde el chunk secret) — Rust. *Test clave: determinismo y delta intra-archivo.*
- Hashing/encoding (**BLAKE3-256**, naming hex-lower con fan-out de 2 chars) — Rust.
- Codec del objeto **Block** (header de 64 B, `alg=0`, `cid = BLAKE3(nonce‖payload)`) — Rust.
- Builder/serializer del **Manifest B-tree** (CBOR canónico, paginación determinista LEAF/INDEX_FANOUT=256, FileEntry) — Rust. *Test clave: mismo set de archivos → mismo `manifestRoot` en cualquier máquina.*
- **Mapeo de FS canónico** (NFC solo en la key, casefold, bit ejecutable, symlinks, colisiones = conflicto) — Rust.
- **Índice local SQLite** (schema §9) — Rust.
- **Vault client** (R2 S3: PUT/GET/HEAD content-addressed) — Rust.
- **Convex** schema + mutations (spaces, revisions con padre, head CAS, queries del change feed) — TS (§6.2/§7).
- **Watcher** + supresión de eco (mtime real + pcid) — Rust.
- **Diff** de árboles por poda de hash + aplicar bloques faltantes — Rust.
- **Resolución de conflictos** a 3 vías por archivo (delete-vs-edit → gana edición) — Rust.

**Fase 2 — Integración secuencial (gates):** paso 0 = chunker+index+block codec+vault en **una sola máquina** → + manifest+commit (orden estricto + CAS) → + coordinator+change feed → "media magia" dos procesos misma máquina → **Mac + VPS Linux + corte de red real**. Validar cada gate contra el criterio de éxito.

**Fase 3 — Revisión adversarial final** de correctitud (determinismo del chunker, content-addressing, atomicidad del CAS, crash-safety del commit, reconciliación tras corte de red).

En paralelo (opcional, barato): la "fake demo" (video/mock estilo Dropbox) para validar mensaje.

---

## 6. NO ROMPAS ESTO (decisiones load-bearing — el formato es lo más caro de cambiar)

- **MVP = cifrado OFF** (`alg=0`, bloques en claro) PERO reservando exactamente los huecos de `docs/format.md` (header 64 B, sidecar de llaves, etc.). En MVP `nonce`=ceros y `cid == pcid`, pero **trata `cid` y `pcid` como campos separados desde el día 1**.
- **data key DETERMINISTA por-cuenta** (KDF(dedup_secret_de_cuenta, pcid)), **NO aleatoria** — una data key aleatoria rompe el dedup cross-device. Ver `format.md §4.4` (corrige el texto viejo "aleatoria").
- **Orden de commit:** TODOS los bloques + páginas de Manifest al Vault **primero**, luego CAS atómico sobre el head en Convex. Crash-safe; nunca un head colgante.
- **Convex se queda diminuto:** el Manifest es un B-tree en el **Vault**, NO en Convex. Respetar 1 MiB/doc, 16 MiB/txn, 1s CPU/mutation.
- **Paths canónicos:** forward slash, relativos al root, NFC **solo en la key** (no en el contenido ni en el target de symlink). Colisión de mayúsculas o de NFC = **conflicto**, nunca sobre-escribir.
- **Space = una raíz, uno-a-uno** con una carpeta local por Device; se sincroniza el Space entero (sin sync parcial de subcarpetas en v1).
- **Detección de conflictos CAUSAL, nunca por reloj.** `mtime` solo acelera el re-scan. delete-vs-edit → gana la edición.
- **FastCDC 16/64/256 KiB** (afinado para código, no el ~1 MiB de backup).
- Lenguaje ubicuo: usar los términos de `CONTEXT.md` en código y nombres (Space, Block, Manifest, Revision, Space head, Coordinator, Vault, Grant, Derived path, etc.).

---

## 7. Pendientes (registrar / no-MVP)

- **Escribir 9 ADRs** de las decisiones load-bearing nuevas (apéndice de `docs/format.md`), usando `ADR-FORMAT.md`, en `docs/adr/`. La #1 a documentar: data key determinista-por-cuenta (no aleatoria). También crear `docs/adr/0001-derived-path-policy.md` (política de artefactos por gestor).
- Post-MVP (huecos ya reservados): cifrado en runtime, serve mode / self-hosted vault, GC con grace-period + retention floor, billing (Polar), dashboard (Next.js), escala, binarios per-SO, validación de nombres Windows, packing de bloques chicos. Elegir servidor S3 self-hosted más adelante (RustFS Apache-2.0 candidato; MinIO/Garage AGPL descartados).

---

## 8. Entorno y notas

- Working dir: `/Users/jrizo/filething` (macOS, zsh; **aún no es git** → inicializar; crear rama antes de commitear; commits/push solo si el usuario lo pide).
- Cuenta del fundador: su email está en la memoria del proyecto (redactado aquí por ser PII).
- No hay secretos/keys en el contexto que redactar. Cuando se configuren R2/Convex/Better Auth/Polar, mantener credenciales fuera del repo (env / secret manager).
- El usuario prefiere comunicación **concisa, en español llano, sin jerga sin explicar** (ver memoria `communication-style`).

---

## 9. Suggested skills (invocar en la próxima sesión)

- **`domain-modeling`** — escribir los 9 ADRs (`ADR-FORMAT.md`) y mantener `CONTEXT.md` como fuente de verdad del lenguaje ubicuo a medida que aparezcan términos nuevos en el código.
- **`ubiquitous-language`** — hacer cumplir el glosario en el naming del código.
- **`to-issues`** (y/o `to-prd`) — descomponer el MVP en issues paralelizables para repartir entre el equipo de agentes (mapea bien a los componentes de la §5).
- **`implement`** — conducir la implementación de cada componente.
- **`tdd`** — el motor de bloques exige tests (determinismo del chunker, content-addressing, orden de commit, reconciliación). Empezar por aquí en los componentes críticos.
- **`codebase-design`** — estructurar el monorepo polyglot (Rust + Convex TS) limpio.
- **`review`** / **`qa`** — verificación adversarial de cada componente contra `docs/format.md`.
- **`git-guardrails-claude-code`** — seguridad de ramas/commits (repo nuevo).
- **`setup-pre-commit`** — fmt/clippy/tsc como hooks desde el principio.

> Para el "equipo grande de agentes": usa el **Workflow tool** (ultracode está activo). Patrón sugerido por fase: scaffold → fan-out de componentes (worktrees aislados) con TDD → integración por gates → revisión adversarial. Mantente en el loop entre fases.
