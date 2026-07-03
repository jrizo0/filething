# Escrow v1: dedup_secret y Space keys generadas en el cliente y custodiadas en Convex

Para activar el cifrado en runtime (`alg=1`, formato ya fijado en ADRs 0002/0003/0004/0010)
hacía falta resolver el hueco que `docs/format.md` §2 deja como "decisión del proyecto": cómo
se custodia y recupera el material de claves. Decisión Fase 3: **escrow server-side en
Convex**. El `dedup_secret` (32B por Account) y la `space_key` (32B por Space, KEK del wrap
de data keys) se **generan en el cliente** (CSPRNG) la primera vez —al crear la cuenta y al
crear cada Space— y se suben a Convex (`accounts.dedupSecret`, `spaces.spaceKey`), de donde
cualquier device **autenticado** de la misma cuenta las recupera tras el login (ADR 0014).
El cliente las cachea localmente con permisos 0600.

Modelo de amenaza cubierto: los bytes de los usuarios quedan cifrados **en el Vault (R2)** —
un compromiso del bucket o del proveedor de storage no expone contenido. Convex (el
Coordinator) sí ve las claves: es exactamente el nivel "escrow, recuperable vía login" que el
formato declara como default del proyecto. Zero-knowledge (cifrar Manifest, que Convex no
pueda leer claves) sigue explícitamente diferido (`TODO.md` Reservado).

Reglas operativas:

- Cuentas/Spaces creados antes de la Fase 3 no tienen claves: sus Blocks siguen `alg=0` y el
  Vault mixto está permitido indefinidamente (format.md §11). Con claves presentes, los
  commits nuevos escriben `alg=1` + sidecar `keys/<space_id>/<aa>/<cid>` (la clave del sidecar
  está scoped por Space: el `blocks/<cid>` se deduplica entre Spaces de la Account pero cada
  sidecar se envuelve con la Space key de su Space, así que cada Space guarda el suyo; ver
  format.md §4.5).
- El GC trata el sidecar `keys/<space_id>/<cid>` como adjunto al Block `blocks/<cid>`: vive y
  muere con él (mismo mark-and-sweep, ADR 0012), marcando el sidecar de cada Space desde los
  Manifests de ESE Space.
- Rotación de Space key = re-wrap de sidecars (mutables por diseño, ADR 0004); fuera del
  alcance de esta fase.

## Considered Options

- **Generación server-side en Convex** (rechazada): funciona, pero deja al cliente sin
  camino evolutivo hacia zero-knowledge y mete material de claves en el log de mutations.
- **Passphrase-derived keys (sin escrow)** (rechazada por ahora): pierde la recuperación vía
  login y complica multi-device; es la ruta natural cuando llegue zero-knowledge.
