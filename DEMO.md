# filething — cómo correr el MVP

CLI de sync de carpetas tipo "Dropbox para developers", en Rust. Este MVP corre el bucle
vertical completo entre **dos Devices** (aquí simulados como dos procesos en la misma
máquina Linux) contra un **Coordinator** (Convex) y un **Vault** (S3/MinIO).

Cifrado OFF en el MVP (`alg=0`, `cid==pcid`) con todos los huecos del formato reservados
(ver `docs/format.md`). Detalle de la arquitectura en `docs/BUILD-PLAN.md`; estado en `TODO.md`.

## 0. Requisitos
- Rust (stable), Bun, Docker. (En este repo ya están instalados.)

## 1. Levantar la infra local (Vault + Coordinator)
```bash
bash infra/scripts/up.sh          # MinIO (:9000) + Convex self-hosted (:3210) + bucket
# Genera infra/.env desde infra/.env.example. Si Convex es nuevo, genera el admin key:
#   docker exec filething-convex-backend-1 ./generate_admin_key.sh
# y pégalo en infra/.env -> CONVEX_SELF_HOSTED_ADMIN_KEY="..."
```
Desplegar las funciones del Coordinator (una vez, o tras cambiarlas):
```bash
cd packages/backend && set -a; source ../../infra/.env; set +a
export CONVEX_SELF_HOSTED_URL CONVEX_SELF_HOSTED_ADMIN_KEY
bunx convex deploy -y
```

## 2. Construir la CLI
```bash
cargo build --release -p filething   # binario en target/release/filething
```

## 3. El comando
```
filething login [--code <CODE>] [--name <NAME>]   # emparejar Device (sin --code = primer Device, imprime un código)
filething init  <dir> [--name <NAME>]             # carpeta -> Space nuevo (primer commit)
filething clone <space_id> <dir>                  # traer un Space existente a una carpeta
filething status [<dir>]                          # base sincronizada + cambios locales
filething ls     [<dir>]                          # listar rutas del Space
filething sync   <dir>                            # one-shot: pull + commit (para scripts)
filething daemon <dir>...                         # sync continuo en foreground (Ctrl-C para parar)
```
Config/identidad por Device en `$FILETHING_HOME` (o `~/.config/filething/config.json`).
El índice local de cada Space vive en `<dir>/.filething/index.db`. Credenciales del
Vault/Coordinator se leen del entorno (`S3_*`, `CONVEX_SELF_HOSTED_*`).

## 4. Demo de los criterios de éxito (a–d), automatizado
```bash
bash scripts/demo-gates.sh
```
Simula dos Devices (dos `FILETHING_HOME`) y valida, contra la infra viva:
- **(a)** edito en A → `init`; B hace `clone` → aparece en B.
- **(b)** bidireccional sin loop de eco ni conflictos falsos.
- **(c)** corte de red (`docker stop` Convex) + edición offline en **ambos** del mismo archivo
  + reconexión → reconcilia con **copia de conflicto**, sin perder datos.
- **(d)** cambio de 1 línea en un archivo grande → **solo suben los bloques cambiados**
  (verificado contando objetos `blocks/` en MinIO: 36 → 37).

## 5. Demo continua (dos daemons)
```bash
FILETHING_HOME=/tmp/devA filething login --name a            # copia el código
FILETHING_HOME=/tmp/devB filething login --code <CODE> --name b
mkdir -p /tmp/A /tmp/B; echo hola > /tmp/A/saludo.txt
FILETHING_HOME=/tmp/devA filething init  /tmp/A --name demo  # imprime <space_id>
FILETHING_HOME=/tmp/devB filething clone <space_id> /tmp/B
# en dos terminales:
FILETHING_HOME=/tmp/devA filething daemon /tmp/A
FILETHING_HOME=/tmp/devB filething daemon /tmp/B
# edita archivos en /tmp/A o /tmp/B y míralos aparecer en el otro.
```

## 6. Pasar a la nube (R2 + Convex cloud) — solo configuración
El código no cambia; solo el entorno:
- **Vault → Cloudflare R2:** apunta `S3_ENDPOINT`/`S3_ACCESS_KEY`/`S3_SECRET_KEY`/`S3_BUCKET`
  a tu bucket R2 (la API es S3-compatible; `ft-vault` ya usa path-style configurable).
- **Coordinator → Convex cloud:** `npx convex deploy` a tu deployment cloud y apunta
  `CONVEX_SELF_HOSTED_URL`/auth a esa URL (o usa el flujo de Convex cloud).

## Qué NO está en el MVP (huecos reservados en el formato, no construidos)
Cifrado en runtime, zero-knowledge, serve mode / self-hosted vault, GC/retención,
Better Auth/OAuth navegador (MVP = pairing por código), billing, dashboard, packing de
bloques chicos, binarios per-SO, Windows. Ver `TODO.md` (sección Reservado) y `docs/format.md §11`.
