# La data key envuelta vive en un sidecar, no en el header del Block

La data key envuelta de un Block vive en un objeto sidecar `keys/<aa>/<cid>` (CBOR canónico: `wrap_alg`, `wrap_nonce` de 24B, `wrapped_data_key` de 48B = 32B ct + 16B tag), MUTABLE bajo rotación, y NO en el header fijo de 64B del Block (inmutable). El header solo reserva `alg`/`nonce`/`flags` —lo que es función del contenido y entra al `cid` vía el nonce (ver 0002)—; el wrap cambia al rotar la Space key y debe quedar fuera de los bytes hasheados para que rotar re-envuelva sin renombrar Blocks. Ver §4.5 de `docs/format.md`.

## Consequences

- Con cifrado ON hay ~2× objetos en el Vault (Block + sidecar). Aceptable y aislado al futuro.
- En el MVP no se escribe ningún `keys/*` (cifrado OFF, `alg=0`): el sidecar es solo un hueco reservado.
