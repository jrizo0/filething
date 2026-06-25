# Data key y nonce deterministas por contenido

La data key y el nonce de cada Block son deterministas por contenido dentro de la Account: `data_key = KDF(CTX_BLOCK_KEY, dedup_secret, info=pcid)` y `nonce = KDF(CTX_BLOCK_NONCE, dedup_secret, info=pcid)`, donde el `dedup_secret` son 256 bits aleatorios por-Account. Esto invierte la decisión previa de "data key aleatoria por bloque", que rompía el dedup cross-Device bajo cifrado: dos Devices cifrarían el mismo claro a objetos distintos. Con derivación determinista, mismo claro + misma Account producen el mismo `nonce`, el mismo `cid` y por tanto dedup real (ver ADR 0002 sobre por qué el `cid` excluye la data key envuelta, y §4.4); otra Account tiene otro `dedup_secret`, así que no hay dedup ni leak cross-account: no es cifrado convergente.

## Considered Options

- **Data key aleatoria por bloque** (decisión previa, rechazada): rompe el dedup cross-Device bajo cifrado.
- **Determinista por-Account vía `dedup_secret`** (elegida): habilita dedup intra-Account sin filtrar igualdad de contenido entre Accounts.
