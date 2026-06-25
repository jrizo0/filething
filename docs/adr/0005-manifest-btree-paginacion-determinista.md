# Manifest: B-tree content-addressed con paginación determinista

El Manifest es un B-tree de páginas content-addressed en el Vault (`manifest/<aa>/<page_cid>`), no un documento de Convex que solo guarda el `manifestRoot`; la paginación es DETERMINISTA: orden total por `casefold(NFC(p))`, hoja con hasta `LEAF_FANOUT=256` FileEntries, index con hasta `INDEX_FANOUT=256` hijos, construcción bottom-up como función pura, y el `bk` de una FileEntry que pase de `ENTRY_INLINE_MAX=256KiB` de CBOR se externaliza a `blocklist/<cid>`. Se hace así porque el content-addressing exige que dos Devices produzcan EXACTAMENTE el mismo `manifestRoot` para el mismo set lógico de archivos; un split por bytes sería ambiguo y rompería el CAS con conflictos fantasma, por eso el split es por conteo de entries, no por bytes.

## Consequences

- Reuso estructural entre Revisions: una Revision que toca pocos archivos reescribe solo las hojas afectadas y la cadena de index hasta la raíz (O(log n) páginas); el resto se comparte por `page_cid`.
- El B-tree determinista también abarata el diff (poda por igualdad de `page_cid`) y el GC (enumerar alcanzables, ADR 0007).
- El orden `casefold(NFC(p))` es el mismo que define colisión-como-conflicto (ADR 0006).
- Mantener Convex-first: el `dedup` de Convex sigue siendo caché (ADR 0008) y los `cid` referenciados desde las FileEntries excluyen la data key (ADR 0002).
