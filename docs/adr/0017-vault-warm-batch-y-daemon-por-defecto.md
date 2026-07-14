# Vault `warm` (firmas por lote + concurrencia) y daemon por defecto

Fase 6, motivada por la primera corrida real en Mac (2026-07-04): un `init` de una carpeta
mediana tardó ~3.5 minutos EN SILENCIO — el usuario asumió un cuelgue y mató el proceso.
Dos causas, ambas anotadas como "reservado" en el ADR 0016: cada operación del
`SignedVault` pagaba una action `vault:sign` individual (~0.5 s), y el motor subía/bajaba
objeto por objeto en serie. Tercera causa (UX): el commit no imprimía progreso.

Decisión, en tres piezas:

- **`Vault::warm(ops)`** (`crates/ft-vault/src/lib.rs`): el caller ANUNCIA las operaciones
  que está por hacer (`WarmOp { key, method: Head|Get|Put }`). Es un hint puro con default
  no-op: la corrección jamás depende de haberlo llamado, y los backends sin costo de setup
  (S3 directo, FsVault) lo ignoran. `SignedVault` lo implementa pidiendo hasta 256 firmas
  por action (`vault:sign` ya era batcheada, ADR 0016) y cacheando las URLs (TTL 900 s con
  margen de 60): un commit/pull entero pasa de ~4 round-trips por objeto a 1–2 actions en
  total + los HTTP directos a R2.
- **Concurrencia en el motor**: `commit.rs` (bloques, sidecars, manifest) y el camino de
  lectura (`pull.rs`/`ft-diff::apply`) operan con `buffer_unordered` (16 subidas / 8
  materializaciones en vuelo). La concurrencia es DENTRO de cada paso del protocolo §7/§8
  — el orden entre pasos (todo el Vault cierra antes del CAS) no cambia. Las escrituras al
  índice local (rusqlite) quedan fuera de los futures concurrentes.
- **Daemon por defecto**: `init`/`clone`/`sync` dejan el daemon corriendo en background
  (instalan/arrancan/reinician el servicio del SO, `service.rs`) salvo `--no-daemon` o
  `FILETHING_NO_AUTO_DAEMON=1` (que usan los scripts de smoke/gates). `filething daemon`
  sin dirs ahora cubre TODOS los Spaces mapeados y queda idle con cero Spaces (sin
  crash-loop); el unit del servicio invoca esa forma, así que un Space nuevo solo requiere
  el restart que `init`/`clone` ya disparan. Siempre best-effort: un fallo del servicio
  avisa pero nunca rompe el comando padre.

Progreso visible: el motor emite `tracing::info!` con totales y avance cada N objetos;
el CLI ya muestra INFO en stderr, así que nunca más un commit largo parece un cuelgue.

## Considered Options

- **Batching explícito en la firma del motor** (pasar lotes por el trait en vez de un
  hint): rechazada — obliga a todos los backends a entender lotes y rompe la simetría
  head/get/put; el hint mantiene el trait mínimo y el backend decide.
- **URLs firmadas de larga vida** (TTL horas, sin caché): rechazada — agranda la ventana
  de replay de una URL filtrada sin quitar la action por operación en corridas largas.
- **Daemon embebido (fork) en vez del servicio del SO**: rechazada — el servicio ya
  existe, sobrevive reboots y tiene logs/restart gestionados; un fork huérfano no.
