# filething — probar Mac + VPS (guía de setup para la Mac)

Objetivo: correr el sync real entre **tu Mac** (un Device) y **tu VPS Linux** (otro Device),
con la infra (Vault MinIO + Coordinator Convex) hospedada en el VPS por Docker.

> Estado (2026-07): el runbook e2e Mac↔VPS quedó validado (`scripts/runbook-e2e-mac-vps.sh`,
> 21/21 gates verdes) y la **Fase 3** añadió auth real (Better Auth) + cifrado en runtime
> (`alg=1`). El adaptador de FS de macOS ya corrió en runtime. Puntos aún sensibles: la
> normalización de nombres en APFS/HFS+ y el túnel — ahora hace falta **también el puerto 3211**
> (Better Auth). Ver "Qué vigilar" al final.

Topología:

```
   Mac (Device "mac")                 VPS Linux
   ┌─────────────────┐                ┌──────────────────────────────┐
   │ filething (CLI)  │  túnel SSH     │ filething (CLI, Device "vps") │
   │  → localhost:3210│ ─────────────▶ │ Docker: Convex :3210          │
   │  → localhost:9000│ ─────────────▶ │ Docker: MinIO  :9000 (bucket) │
   └─────────────────┘                └──────────────────────────────┘
```

El túnel SSH es la vía recomendada: la Mac sigue hablando a `localhost` (igual que la demo),
evita abrir puertos del VPS a internet, y esquiva un bug latente (Convex anuncia
`CONVEX_CLOUD_ORIGIN=http://localhost:3210` a sus clientes; con túnel ese `localhost` resuelve
al VPS y no rompe nada).

---

## 0. En el VPS (una vez): dejar la infra arriba

Ya está corriendo, pero para asegurar:

```bash
cd ~/repos/filething
bash infra/scripts/up.sh        # MinIO + Convex + bucket 'filething'
bash scripts/demo-gates.sh      # confirma gates a–d (opcional, ~20s)
```

Anota el admin key del Coordinator (lo necesitas en la Mac):

```bash
grep CONVEX_SELF_HOSTED_ADMIN_KEY ~/repos/filething/infra/.env
```

> El `unhealthy` de `docker ps` en el contenedor de Convex es un **falso negativo**
> (la imagen no trae `curl`); el backend funciona. No te frenes por eso.

---

## 1. En la Mac: prerequisitos

```bash
xcode-select --install                       # compilador/linker (si no lo tienes)
curl https://sh.rustup.rs -sSf | sh          # Rust stable vía rustup
source "$HOME/.cargo/env"
brew install git                              # si no lo tienes
```

## 2. Bajar el código y compilar

```bash
git clone https://github.com/jrizo0/filething.git
cd filething                                  # rama main (Fase 3 ya está mergeada)
cargo build --release -p filething           # primera vez tarda varios minutos
```

El binario queda en `target/release/filething`. Para comodidad:

```bash
export PATH="$PWD/target/release:$PATH"       # o: alias filething=$PWD/target/release/filething
filething --help
```

**Si el build falla** → ese es el primer hallazgo real del adaptador macOS. Copia el error.

## 3. Abrir el túnel SSH (déjalo en una terminal aparte)

Reemplaza `usuario@IP-DEL-VPS` por tu acceso real. Reenvía **tres** puertos: 9000 (MinIO),
3210 (Convex API) y **3211 (HTTP actions de Convex = Better Auth)** — sin el 3211 fallan el
`login` y el re-mint del JWT del daemon. Con auto-reconexión (aprendido en la prueba del
2026-06-25: un parpadeo de red mata el túnel y sin este loop se queda muerto):

```bash
while true; do
  ssh -N -o ServerAliveInterval=20 -o ServerAliveCountMax=3 \
    -L 9000:localhost:9000 -L 3210:localhost:3210 -L 3211:localhost:3211 usuario@IP-DEL-VPS
  echo "túnel caído; reintentando en 3s…"; sleep 3
done
```

Verifica desde otra terminal de la Mac que el túnel sirve:

```bash
curl -s http://localhost:3210/version && echo "  <- Convex OK"
curl -s -o /dev/null -w "Convex HTTP actions (3211) HTTP %{http_code}\n" http://localhost:3211/
# ↑ cualquier código HTTP (incluido 404) confirma que el túnel llega al 3211
curl -s -o /dev/null -w "MinIO HTTP %{http_code}\n" http://localhost:9000/minio/health/live
```

## 4. Exportar el entorno en la Mac

Pega esto (con el admin key real del paso 0):

```bash
export S3_ENDPOINT="http://localhost:9000"
export S3_REGION="us-east-1"
export S3_ACCESS_KEY="minioadmin"
export S3_SECRET_KEY="minioadmin"
export S3_BUCKET="filething"
export CONVEX_SELF_HOSTED_URL="http://localhost:3210"
export CONVEX_SELF_HOSTED_ADMIN_KEY="<pega aquí el valor de infra/.env del VPS>"
export FILETHING_HOME="$HOME/.filething-mac"   # identidad del Device en la Mac
```

## 5. Crear la cuenta y loguear los dos Devices (Better Auth)

Desde la Fase 3 **no hay pairing codes**: ambos Devices hacen `login` del **mismo usuario**
(email+password, ADR 0014). El signup viene cerrado por defecto; se abre un momento solo para
crear la cuenta y se vuelve a cerrar.

**En el VPS** (Device "vps"; usa un FILETHING_HOME propio para no chocar con la demo):

```bash
cd ~/repos/filething
set -a; source infra/.env; set +a
export FILETHING_HOME="$HOME/.filething-vps"
export FILETHING_PASSWORD='una-clave'                  # o te la pedirá por prompt
# abre el signup solo para crear la cuenta, y ciérralo enseguida:
( cd packages/backend && bunx convex env set FILETHING_ALLOW_SIGNUP 1 )
target/release/filething login --signup --email tu@email --name vps
( cd packages/backend && bunx convex env remove FILETHING_ALLOW_SIGNUP )
```

**En la Mac** (Device "mac", con el túnel —incluido el 3211— y el env arriba). Mismo usuario,
**sin** `--signup`:

```bash
export FILETHING_PASSWORD='una-clave'
filething login --email tu@email --name mac
```

**En el VPS**: crea un Space desde una carpeta de juguete:

```bash
mkdir -p ~/space-demo && echo "hola desde el vps" > ~/space-demo/saludo.txt
target/release/filething init ~/space-demo --name demo   # imprime <space_id>
```

**En la Mac**: clónalo a una carpeta local:

```bash
mkdir -p ~/space-demo
filething clone <space_id> ~/space-demo
ls ~/space-demo            # debe aparecer saludo.txt
```

## 6. Sync continuo (la "magia") — un daemon en cada lado

```bash
# VPS (detached: sobrevive cortes de SSH; log con >> para no perder historia al relanzar):
nohup target/debug/filething daemon ~/space-demo >> ~/ft-daemon-vps.log 2>&1 & disown
# Mac (otra terminal, túnel arriba):
filething daemon ~/space-demo
```

> Lanza **un solo** daemon por lado: si relanzas tras un corte, primero
> `pkill -f "filething daemon"` — en la prueba del 25 quedaron dos daemons vivos en el VPS.

Ahora edita archivos en `~/space-demo` en cualquiera de los dos y míralos aparecer en el otro.
Para la prueba de conflicto: corta el túnel SSH, edita el **mismo** archivo en ambos, reconecta
→ debe crear una "copia de conflicto" sin perder ninguna versión.

Sin daemon, para scripts: `filething sync ~/space-demo` (pull + commit one-shot).

---

## Qué vigilar (riesgos específicos de esta primera corrida en Mac)

- **Build en macOS**: nunca se compiló aquí. Si falla, es el hallazgo #1.
- **Normalización de nombres (APFS/HFS+)**: el spec usa NFC solo en la key; macOS hace su
  propia normalización de nombres de archivo. Archivos con tildes/ñ o nombres que difieren
  solo en mayúsculas son los candidatos a comportarse distinto. **Para la primera prueba usa
  nombres ASCII simples** (`saludo.txt`, `src/main.rs`) y deja los casos raros para después.
- **Casefold conocido**: `ft-fsmap` usa `to_lowercase` (no casefold Unicode completo) — colisiones
  exóticas (µ/μ) no se detectan; ASCII sí. Limitación aceptada del MVP.
- **El túnel debe seguir vivo** (puertos 9000, 3210 **y 3211**) mientras corras la CLI/daemon
  en la Mac. El 3211 es Better Auth: sin él fallan el `login` y el re-mint del JWT del daemon
  (cada ~15 min). Si cierras el túnel, los comandos de la Mac fallarán al conectar a `localhost`.
- **bit ejecutable y symlinks**: el adaptador los maneja, pero es la primera vez en macOS;
  si pruebas symlinks o scripts `+x`, revísalos explícitamente.

## Alternativa al túnel (exponer puertos) — NO recomendada para esto

Apuntar el env de la Mac a `http://IP-DEL-VPS:3210` y `:9000` directamente requiere abrir esos
puertos en el firewall del VPS y deja MinIO/Convex con credenciales por defecto (`minioadmin`)
accesibles desde internet. Además toparías con el `CONVEX_CLOUD_ORIGIN=localhost` que el backend
anuncia. Usa el túnel SSH salvo que tengas una razón fuerte.
