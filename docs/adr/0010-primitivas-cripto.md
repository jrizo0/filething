# Primitivas criptográficas

Fijamos las primitivas caras de cambiar (entran en cada `cid`, `pcid` y `page_cid`): el hash de direccionamiento e integridad es **BLAKE3-256**, que sirve además en modo `derive_key` para la gear table de FastCDC, la data key y el nonce, de modo que hay **una sola primitiva de hashing** (rápida, paraleliza sobre archivos grandes, sin length-extension, 256 bits de margen). Nombres de objeto e IDs van en **hex minúsculas con fan-out de 2 chars** (`blocks/<aa>/<hex>`), seguro como key de R2/S3 sin `+`/`/`/`=`; las páginas de Manifest se serializan en **CBOR canónico** (RFC 8949 §4.2.1, determinista byte-a-byte = requisito duro del content-addressing, con bytestrings nativos para hashes). El AEAD reservado (OFF en MVP) es **XChaCha20-Poly1305** (nonce de 192 bits, rápido en software puro Mac/ARM/x86) y el wrap de la data key usa el mismo XChaCha20-Poly1305 con la **Space key** como KEK.

## Considered Options

**JSON descartado** para las páginas: no es determinista (mismo árbol lógico podría producir distinto hash en otro Device) y no tiene bytestrings (forzaría base64 para los hashes). Los ejemplos JSON de la spec son solo ilustrativos.

Ver ADR-0002 (el `cid` excluye la data key) y ADR-0003 (data key y nonce deterministas) para el uso de BLAKE3 en modo `derive_key`; ADR-0004 (wrap en sidecar) para el envelope con la Space key; ADR-0005 (paginación determinista del Manifest) para por qué la serialización debe ser byte-a-byte; y ADR-0009 (FastCDC 16/64/256) para la gear table sembrada vía BLAKE3.
