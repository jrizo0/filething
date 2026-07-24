# `init` optimizado para latencia por objeto

Una corrida real del 2026-07-24 sobre 303 archivos (445.8 MB, 98.9 % PDFs)
produjo 3,946 Blocks y tardó 11m04s. El proceso mantuvo ~0 % CPU y 16 conexiones
HTTPS: después de los Blocks pasó varios minutos subiendo 3,946 sidecars sin
progreso visible. La causa dominante no era cómputo sino la multiplicación de
HEAD/PUT y firmas por objeto.

Decisión:

- El primer commit (`last_synced_seq < 0`) hace PUT directo de Blocks y sidecars.
  Los Block PUT son content-addressed e idempotentes; el namespace
  `keys/<space_id>/` de un Space recién creado está vacío. Commits posteriores
  conservan HEAD-before-PUT porque GC puede invalidar el cache local.
- Blocks mantienen 16 uploads en vuelo para no saturar el uplink. Sidecars,
  objetos de ~100 B limitados por latencia, usan 64 y emiten su propia fase de
  progreso.
- `SignedVault::warm` conserva lotes de hasta 256 operaciones, pero procesa hasta
  4 lotes Convex simultáneos. El límite acota presión sobre el Coordinator y
  elimina la cadena estrictamente secuencial de decenas de round-trips.
- Binarios conocidos de al menos 1 MiB usan el perfil FastCDC grande descrito en
  ADR 0009, reduciendo Blocks, sidecars, firmas y requests juntos.

La interfaz pública del CLI, el layout de keys y el protocolo de CAS no cambian.
Toda optimización queda detrás de `SpaceContext::commit`, `Chunker` y el adapter
`SignedVault`.

## Considered Options

- **Aumentar solo la concurrencia de Blocks:** rechazado como solución completa;
  no elimina HEADs seguros de omitir, sidecars ni firmas, y puede saturar el
  uplink sin mejorar throughput.
- **Eliminar HEAD en todos los commits:** rechazado; después de un GC el índice
  local puede afirmar presencia de un Block que ya no existe.
- **Chunks grandes globales:** rechazado; degrada el delta intra-archivo de
  código. La selección adaptativa conserva el perfil pequeño por defecto.
- **Packing de Blocks/sidecars:** reservado; reduciría todavía más objetos, pero
  agrega indirección al formato, descarga y GC.
