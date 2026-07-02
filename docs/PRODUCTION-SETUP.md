# filething — pasar a producción (Convex Cloud + Cloudflare R2)

Runbook para mover filething de la infra local de juguete (Docker: Convex self-hosted +
MinIO) a la **infra gestionada real**: **Convex Cloud** (Coordinator) y **Cloudflare R2**
(Vault). Uso **personal**: todos los Devices son tuyos.

El código del cliente NO cambia — solo el entorno (`infra/.env.cloud`). La migración de datos
es barata: los `Block` son content-addressed y el Coordinator se re-crea (re-`init` de los
Spaces si no migras los documentos). Detalle de contexto en `DEMO.md` y `TODO.md`
(sección "Roadmap a producción").

---

## Qué necesito de ti

Antes de tocar nada, necesito que crees estas cuentas y me pases estos valores. Todo cabe en
el free tier ($0/mes para un solo usuario — ver "Coste estimado").

- [ ] **Cuenta de Cloudflare** con **R2 habilitado** (pide un método de pago aunque el free
      tier sea gratis). De R2 saldrán, tras crear un **bucket** y un **token de API S3**:
  - [ ] `S3_ENDPOINT`  → `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`
  - [ ] `S3_ACCESS_KEY` → *Access Key ID* del token
  - [ ] `S3_SECRET_KEY` → *Secret Access Key* del token (se muestra **una sola vez**)
  - [ ] `S3_BUCKET`    → el nombre del bucket que creaste
- [ ] **Cuenta de Convex** (Convex Cloud). De ella saldrán, tras crear el proyecto y desplegar:
  - [ ] `CONVEX_URL`        → `https://<name>.convex.cloud` (URL del deployment de producción)
  - [ ] `CONVEX_DEPLOY_KEY` → *Production Deploy Key* del proyecto (secreto tipo root)

Con esos seis valores relleno `infra/.env.cloud`, despliego el backend y corro el smoke test.

Herramientas locales que hacen falta (ya instaladas en este repo): Rust (stable), Bun, `git`,
`curl`. No hace falta Docker/MinIO/`mc` en modo gestionado.

---

## Paso 1 — Cloudflare R2

### 1.1 Habilitar R2 (una vez)
1. Entra al dashboard de Cloudflare.
2. En la barra lateral: **Storage & databases > R2 > Overview**.
3. Completa el checkout de R2. Cloudflare pide un **método de pago aunque uses el free tier**
   (no se cobra mientras te mantengas dentro de los límites; ver "Coste estimado").

### 1.2 Crear el bucket
1. En **R2 > Overview** pulsa **Create bucket**.
2. **Nombre**: minúsculas `a-z`, dígitos `0-9` y guiones (no al inicio ni al final), 3–63
   caracteres. Ej.: `filething-prod`. → este es tu `S3_BUCKET`.
3. **Location**: deja **Automatic**.
4. **Jurisdiction**: para uso personal **no elijas ninguna jurisdicción** (deja la opción por
   defecto / "none").
5. Crea el bucket.

### 1.3 Crear el token de API S3
1. En **R2 > Overview**, entra a **API Tokens** (botón/enlace "Manage" o "API"; en el
   dashboard actual busca "API Tokens" dentro de R2).
2. **Create Account API token**.
3. **Permissions** = **Object Read & Write**.
4. **Specify bucket(s)** = **Apply to specific buckets only** → selecciona el bucket del 1.2.
5. **TTL** = opcional (por defecto sin expiración; para uso personal puedes dejarlo así).
6. **Create**. Cloudflare te muestra, **una sola vez**:
   - **Access Key ID**       → `S3_ACCESS_KEY`
   - **Secret Access Key**   → `S3_SECRET_KEY`  ← **cópiala YA**, no se vuelve a mostrar.
   - **S3 API endpoint**     → `https://<ACCOUNT_ID>.r2.cloudflarestorage.com` → `S3_ENDPOINT`
   (El `<ACCOUNT_ID>` también está en la barra lateral del dashboard.)

### 1.4 Mapeo de valores
| Valor de Cloudflare               | Variable en `infra/.env.cloud` |
| --------------------------------- | ------------------------------ |
| S3 API endpoint                   | `S3_ENDPOINT`                  |
| (fijo)                            | `S3_REGION=auto`               |
| Access Key ID                     | `S3_ACCESS_KEY`                |
| Secret Access Key                 | `S3_SECRET_KEY`                |
| Nombre del bucket                 | `S3_BUCKET`                    |

> `S3_REGION` es **siempre** `auto` para R2 con clientes AWS-SDK. filething ya fuerza
> path-style addressing, que R2 soporta.

---

## Paso 2 — Convex Cloud

Se trabaja desde `packages/backend` (donde vive el schema + las funciones del Coordinator).

### 2.1 Login
```bash
cd packages/backend
bunx convex login      # abre el navegador para autenticarte
```

### 2.2 Crear el proyecto y el deployment de producción
La primera vez, un `deploy` (o `dev`) crea el proyecto y su deployment. Genera la **deploy key
de producción** desde el dashboard y úsala para desplegar de forma no interactiva:
1. Dashboard de Convex → tu proyecto → **Project Settings > Deploy Keys**.
2. **Generate Production Deploy Key** → cópiala. → este es tu `CONVEX_DEPLOY_KEY`.

> Si aún no tienes proyecto, puedes crearlo con `bunx convex dev` una vez (te guía por el
> navegador) y luego generar la deploy key de producción como arriba.

### 2.3 Obtener la URL del deployment
El deploy (Paso 4) imprime la URL del deployment de producción, con formato
`https://<name>.convex.cloud`. También aparece en el dashboard del proyecto. → este es tu
`CONVEX_URL`.

### 2.4 Mapeo de valores
| Valor de Convex                        | Variable en `infra/.env.cloud` |
| -------------------------------------- | ------------------------------ |
| URL del deployment (`…convex.cloud`)   | `CONVEX_URL`                   |
| Production Deploy Key                  | `CONVEX_DEPLOY_KEY`            |

---

## Paso 3 — Configurar filething

1. Copia la plantilla y rellénala con los seis valores de los Pasos 1 y 2:
   ```bash
   cp infra/.env.cloud.example infra/.env.cloud
   # edita infra/.env.cloud
   ```
   > ⚠️ La `CONVEX_DEPLOY_KEY` tiene formato `prod:<nombre>|<secreto>`. El `|` rompe el
   > `source` de bash si el valor NO va entrecomillado, y `source` deja la variable
   > **vacía** (los scripts abortarán con "falta CONVEX_DEPLOY_KEY"). Enciérrala en
   > **comillas simples**: `CONVEX_DEPLOY_KEY='prod:…|…'` (la plantilla ya trae las
   > comillas — solo pega tu key dentro).

2. **Verifica que `infra/.env.cloud` está gitignoreado** (ya lo está en este repo — el
   `.gitignore` incluye `.env.cloud`):
   ```bash
   git check-ignore infra/.env.cloud     # debe imprimir la ruta => está ignorado
   ```
   El `infra/.env.cloud` real **nunca** se commitea (contiene el deploy key y las claves R2);
   las plantillas `*.example` sí se commitean.

3. Carga las variables en tu shell cuando vayas a usar la CLI a mano:
   ```bash
   set -a; source infra/.env.cloud; set +a
   ```
   Los scripts de los pasos siguientes ya hacen este `source` por ti.

---

## Paso 4 — Desplegar y validar

### 4.1 Desplegar el Coordinator a Convex Cloud
```bash
scripts/cloud-deploy.sh
```
Lee `infra/.env.cloud`, verifica `CONVEX_URL` + `CONVEX_DEPLOY_KEY` y corre
`bunx convex deploy -y` desde `packages/backend`. Es idempotente: reejecutarlo vuelve a
publicar el mismo schema/funciones. **Éxito** = el deploy termina sin error e imprime la URL
`https://<name>.convex.cloud` (confírmala contra tu `CONVEX_URL`).

### 4.2 Smoke test end-to-end contra la nube
```bash
scripts/cloud-smoke.sh
```
Construye el binario release y simula **dos Devices** (dos `FILETHING_HOME`) contra Convex
Cloud + R2: `login` (pairing) → `init` con un archivo → `clone` en el segundo Device →
edición + `sync`. Imprime `✓`/`✗` por chequeo. **Éxito** = todos los chequeos en `✓` y
`SMOKE OK` al final. Que el `clone` traiga el archivo valida el commit, el change feed
(WebSocket) y el round-trip por R2 contra la infra gestionada.

### 4.3 Caveat del deploy key (VERIFICAR EN VIVO)
El cliente Rust usa la ruta `set_admin_auth(<deploy_key>)` del crate `convex`, que autentica
sobre `wss://<name>.convex.cloud/api/sync`. Esa ruta **acepta** un deploy key, pero la API es
`#[doc(hidden)]` / no documentada: **hay que verificarla empíricamente**. El smoke test del
4.2 es esa verificación.

- **Si el smoke pasa con `CONVEX_DEPLOY_KEY`**: listo, esa es la ruta buena para uso personal.
- **Si falla en el `login`/conexión por culpa del deploy key**: las funciones de Convex son
  **públicas por defecto** y el backend de filething **no tiene checks de `ctx.auth`**, así que
  el cliente puede funcionar **sin credencial**. `connect_coordinator` (`apps/cli/src/env.rs`)
  ya contempla ese caso: si no hay `CONVEX_DEPLOY_KEY` / `CONVEX_ADMIN_KEY` /
  `CONVEX_SELF_HOSTED_ADMIN_KEY`, conecta **sin** `set_admin_auth` y solo emite un warning. Para
  probar esta ruta, comenta `CONVEX_DEPLOY_KEY` en `infra/.env.cloud` y repite el smoke.
  (Aceptable solo para uso personal, porque el backend no valida identidad — ver Riesgos.)

---

## Coste estimado

**~$0/mes** para un solo usuario con pocos GB. Ambos servicios tienen free tier recurrente:

- **Cloudflare R2** (free tier mensual): 10 GB de almacenamiento, 1M ops Clase A, 10M ops
  Clase B, y **egress GRATIS**. (Pide método de pago en el checkout aunque no se cobre.)
- **Convex Cloud (Starter)**: 1M llamadas a funciones/mes, 0.5 GB de DB, 1 GB de file storage,
  1 GB de egress.

Los costes empiezan si te pasas de esos límites (p.ej. >10 GB en R2, o >1M llamadas de función
al mes en Convex). Para uso personal de unos pocos GB no deberías acercarte.

---

## Riesgos conocidos

- **Deploy key por la ruta `#[doc(hidden)]`**: filething autentica al cliente con el deploy key
  vía `set_admin_auth` sobre una API no documentada del crate `convex`. Puede romperse en una
  actualización del crate; verifica siempre con el smoke test (4.2/4.3).
- **El deploy key es un secreto ROOT**: da control total del deployment (puede impersonar a
  cualquier usuario). Guárdalo como tal; `infra/.env.cloud` debe estar gitignoreado (Paso 3).
- **Backend sin auth**: las funciones de Convex son públicas y el backend no valida `ctx.auth`.
  Es **aceptable solo mientras todos los Devices sean tuyos**. Antes de terceros hace falta auth
  real (Better Auth) — ver `TODO.md`, Fase B.
- **Sin cifrado en runtime**: los bytes se guardan en R2 en claro (`alg=0`). Solo para uso
  personal; el cifrado (`alg=1`) es un hueco reservado del formato, aún no construido.
- **GC = solo huérfanos (por ahora)**: `filething gc <dir>` hace mark-and-sweep account-wide
  con grace-period, **dry-run por defecto** (`--apply` para borrar). Retiene TODO el historial
  y solo borra objetos que ninguna Revision referencia (basura de commits abortados). La poda
  de historial (retention floor) está **diferida**: un floor sound por-Space necesita telemetría
  por-(device,space) que el escalar `baseSeqInUse` actual no da (ver `docs/adr/0012`). Revisa
  siempre el dry-run antes de `--apply`.
