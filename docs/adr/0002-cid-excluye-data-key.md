# El cid excluye la data key envuelta

El `cid` de un Block se computa como `BLAKE3-256(nonce || payload)` —sobre el nonce y el payload del objeto, nunca sobre el objeto entero ni incluyendo la data key envuelta— porque así rotar la Space key (re-envolver las data keys en el sidecar `keys/<cid>`) no cambia el `cid` y no obliga a renombrar objetos. Por eso la data key envuelta vive en sidecar (ver ADR 0004), fuera de los bytes hasheados.

## Consequences

- La verificación de integridad del wire recomputa `BLAKE3-256(nonce || payload)` sobre lo extraído del objeto y lo compara con el `cid` esperado; nunca hashea el objeto entero, porque eso fallaría tras una rotación (cambia el sidecar, no el objeto).
- En MVP el `nonce` son ceros, así que `cid = BLAKE3-256(payload) = pcid`. Con cifrado on, el header se autentica como AAD del AEAD para que no sea maleable.
