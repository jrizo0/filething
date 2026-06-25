# La tabla dedup de Convex es una caché, no la fuente de verdad

La tabla `dedup` de Convex (`pcid -> cid`, scope Account) es solo una caché de aceleración cross-Device, no la fuente de verdad del dedup: el dedup real vive en el índice local del Device (`dedup_local`) más un `HEAD blocks/<cid>` al Vault antes de subir. Una tabla dedup obligatoria crecería con el número de Blocks distintos de la Account, lo que contradice el principio Convex-first (nada en Convex puede escalar con bytes o archivos). Como la data key y el nonce son deterministas por contenido (ADR 0003), un Device puede recalcular el `cid` desde el `pcid` y verificar existencia con un `HEAD` sin necesitar la tabla; por eso la caché puede tener TTL o estar incompleta sin afectar la correctitud.

## Consequences

- El dedup nunca depende de Convex: si la tabla está vacía, desactualizada o se purga, el Device cae a `dedup_local` y al `HEAD` al Vault, y el resultado es el mismo (recalcula `cid` desde `pcid`, ver ADR 0003).
- La caché solo gana latencia/ancho de banda en el caso cross-Device (un Device descubre un `cid` ya subido por otro sin hacer el `HEAD`).
- Mantiene el invariante Convex-first: ningún documento de Convex escala con el contenido del Space.
