# Descarga concurrente en el pull

Motivado por el issue #10: un archivo de 20 MB subía en ~4.6 s pero el pull tardaba
~183 s (~110 KB/s efectivos). La subida ya era concurrente desde la Fase 6 (ADR 0017:
`commit.rs` con `buffer_unordered(16)`), pero el camino de lectura seguía descargando en
serie por dos vías: bloque por bloque DENTRO de un archivo en `ft_diff::materialize`, y
—en un reconcile— archivo por archivo, porque `reconcile` (`crates/ft-engine/src/pull.rs`)
materializaba cada ganador remoto de forma secuencial vía `materialize_and_record`,
mientras que el `fast_forward` ya iba concurrente a través de `ft_diff::apply`.

Decisión, en tres piezas:

- **Descarga de bloques concurrente DENTRO de un archivo** (`ft_diff::materialize`): los
  GET de los bloques de un mismo archivo salen con `buffered(16)` —la misma cota que usa
  el commit para las subidas—. Se usa `buffered` (no `buffer_unordered`) porque PRESERVA
  el orden de los bloques sin lógica extra: la concatenación sigue siendo en orden y la
  escritura a disco sigue siendo `tmp` + `rename` atómico, hecha una sola vez tras haber
  verificado TODOS los bloques. La concurrencia es puramente de red; nada del contrato de
  atomicidad ni de verificación cambia.
- **Fan-out de ganadores en el reconcile** (`pull.rs::reconcile`): la función se
  reestructura en tres fases. Fase A (secuencial) recorre la unión de claves
  `base ∪ local ∪ remote`, resuelve cada una con `ft_conflict::resolve` y ejecuta lo que
  DEBE quedar ordenado o es local: las conflict copies (`write_conflict_copy`, que lee los
  bytes locales en la ruta del ganador ANTES de que ningún ganador la pise) y las
  eliminaciones remotas; los ganadores remotos a materializar se COLECTAN en un `Vec`.
  Fase B (concurrente) materializa esos ganadores con `buffer_unordered(8)` —cada uno
  escribe una ruta canónica DISTINTA (las claves de la unión son únicas y los nombres de
  conflict copy derivan de rutas distintas, nunca iguales a una ruta ganadora), lo que se
  ASEGURA con una comprobación previa que falla como error duro ante una ruta duplicada, en
  vez de dejar que dos futures corran sobre el mismo `.ft-tmp`—. El stream se DRENA de forma
  secuencial: a medida que cada `materialize` termina, su ganador se registra en el índice
  (rusqlite) y se marca como eco en la misma tarea que drena —FUERA de los futures
  concurrentes, como manda el ADR 0017—. Drenar en vez de `try_collect` + registrar al final
  preserva la ATOMICIDAD por ruta del reconcile secuencial original: un fallo a mitad de
  lote aborta con todos los ganadores ya completados plenamente consistentes (materializados
  + indexados + marcados), nunca escritos-pero-sin-registrar. Ante un error se aborta el
  reconcile sin avanzar la base (el caller solo la avanza con `Ok`); un reintento re-resuelve
  contra la misma base y se auto-sana (una ruta ya materializada resuelve a no-op).
- **Cota de vuelo combinada**: 8 cambios en paralelo × 16 bloques por archivo = 128 GET
  máximos teóricos en vuelo. Aceptado: son HTTP directos a R2 con URLs prefirmadas
  (ADR 0016) servidos por el pool de conexiones de `reqwest`; el escenario real es o un
  archivo grande (1 cambio × 16) o muchos pequeños (8 cambios × pocos bloques), y la cota
  combinada nunca se alcanza de forma sostenida.

Progreso visible: `materialize` y `reconcile` emiten `tracing::info!` con totales, avance
cada 25 objetos y un total final con `elapsed_ms`, igual que `commit.rs` — un pull largo
ya no parece un cuelgue.

## Considered Options

- **Semáforo global de descargas compartido entre crates**: rechazada — añade complejidad
  cruzando `ft-engine` y `ft-diff` para imponer un techo que en la práctica no se alcanza
  (los lotes reales son un archivo grande o muchos pequeños). Las dos cotas locales
  (16 bloques, 8 archivos) ya acotan el vuelo sin estado compartido.
- **`buffer_unordered` + reordenar los bloques por índice**: rechazada para la descarga
  intra-archivo — `buffered` ya preserva el orden sin ninguna lógica de reordenamiento, y
  el orden es obligatorio para concatenar y verificar antes del `rename`.
- **Streaming a disco bloque por bloque**: rechazada — rompería la escritura atómica
  `tmp` + `rename` y la verificación previa de TODOS los bloques (un fallo a media
  descarga dejaría un archivo parcial en la ruta final).
