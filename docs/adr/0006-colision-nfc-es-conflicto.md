# NFC solo en la key del Manifest; colisión NFC es conflicto

La normalización Unicode NFC se aplica SOLO a la key `p` del Manifest (para ordenar, comparar y detectar colisiones), NUNCA al contenido del archivo ni al target (`lt`) de un symlink, que se preservan byte-exactos. Dos paths byte-distintos en disco pero NFC-equivalentes (común entre macOS y Linux con formas precompuesta/descompuesta) que colapsan a la misma key NFC son un CONFLICTO (se emite copia de conflicto), idéntico al trato de la colisión de solo-mayúsculas (§5.2); nunca se sobre-escribe. Aplicar NFC al contenido corrompería archivos y symlinks byte-exactos, y colapsar dos paths en silencio perdería datos.

## Consequences

- Al construir una página hoja del Manifest (ADR-0005), si dos FileEntries normalizan a la misma key se emite copia de conflicto en vez de sobre-escribir.
