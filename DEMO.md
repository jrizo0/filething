# filething — cómo correr el MVP

CLI de sync de carpetas tipo "Dropbox para developers", en Rust. Este MVP corre el bucle
vertical completo entre **dos Devices** (aquí simulados como dos procesos en la misma
máquina Linux) contra un **Coordinator** (Convex) y un **Vault** (S3/MinIO).

Cifrado en runtime activo desde Fase 3: `alg=1` (XChaCha20-Poly1305) es el default para
Spaces nuevas, con escrow de claves en Convex (`docs/adr/0015`). Spaces creadas antes de
Fase 3 siguen en `alg=0` (`cid==pcid`); el Vault mixto está permitido indefinidamente
(`docs/format.md §11`). Detalle de la arquitectura en `docs/BUILD-PLAN.md`; estado en `TODO.md`.

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
filething login --email <EMAIL> [--signup] [--name <NAME>]  # login (Better Auth); --signup = crear cuenta
filething init  <dir> [--name <NAME>]             # carpeta -> Space nuevo (primer commit)
filething clone <space_id> <dir>                  # traer un Space existente a una carpeta
filething status [<dir>]                          # base sincronizada + cambios locales
filething ls     [<dir>]                          # listar rutas del Space
filething sync   <dir>                            # one-shot: pull + commit (para scripts)
filething daemon [<dir>...]                       # sync continuo en foreground; sin dirs = todos los Spaces
```
Desde Fase 6, `init`/`clone`/`sync` dejan el daemon corriendo en background como servicio
del SO automáticamente (opt-out: `--no-daemon` o `FILETHING_NO_AUTO_DAEMON=1` — los scripts
de gates/smoke lo setean para no instalar servicios en la máquina que los corre).
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
FILETHING_HOME=/tmp/devA filething login --email demo@example.com --signup --name a
FILETHING_HOME=/tmp/devB filething login --email demo@example.com --name b   # misma cuenta, otro Device
mkdir -p /tmp/A /tmp/B; echo hola > /tmp/A/saludo.txt
FILETHING_HOME=/tmp/devA filething init  /tmp/A --name demo  # imprime <space_id>
FILETHING_HOME=/tmp/devB filething clone <space_id> /tmp/B
# en dos terminales:
FILETHING_HOME=/tmp/devA filething daemon /tmp/A
FILETHING_HOME=/tmp/devB filething daemon /tmp/B
# edita archivos en /tmp/A o /tmp/B y míralos aparecer en el otro.
```

## 6. Pasar a la nube (R2 + Convex Cloud)
**Runbook paso a paso: `docs/PRODUCTION-SETUP.md`** (crear el bucket R2 + token, el proyecto
Convex Cloud + deploy key, rellenar `infra/.env.cloud`, y `scripts/cloud-deploy.sh` +
`scripts/cloud-smoke.sh`). Resumen:
- **Vault → Cloudflare R2:** apunta `S3_ENDPOINT`/`S3_REGION=auto`/`S3_ACCESS_KEY`/
  `S3_SECRET_KEY`/`S3_BUCKET` a tu bucket R2 (S3-compatible; `ft-vault` ya usa path-style).
- **Coordinator → Convex Cloud:** `scripts/cloud-deploy.sh` (deploy con `CONVEX_DEPLOY_KEY`);
  apunta `CONVEX_URL` a `https://<name>.convex.cloud`. El cliente usa el deploy key vía
  `set_admin_auth`, o conecta sin credencial (funciones públicas) — ver el runbook.

## 7. Comandos de operación (Fase 2)
- `filething gc <dir> [--apply] [--keep-all] [--grace-secs N]` — recolector de basura del
  Vault (account-wide, dry-run por defecto). Ver `docs/adr/0012`.
- `filething metrics [dir]` — métricas de sync del daemon (lee `.filething/metrics.json`).
- `filething service <install|uninstall|status>` — daemon como servicio del SO.

## Qué NO está en el MVP (huecos reservados en el formato, no construidos)
zero-knowledge, serve mode / self-hosted vault, poda de historial / retention floor (existe
`filething gc`: orphan-sweep account-wide, dry-run por defecto — retiene TODO el historial;
ver `docs/adr/0012`), OAuth navegador, billing, dashboard, packing de bloques chicos, Windows.
Ver `TODO.md` (sección Reservado) y `docs/format.md §11`. (Los binarios per-SO SÍ existen
desde Fase 5: installer shell desde GitHub Releases, ver `README.md`.)
