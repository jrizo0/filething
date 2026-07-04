# Vault firmado: URLs S3 prefirmadas emitidas por el Coordinator

Hasta la Fase 3 el plano de datos exigía que **cada Device** tuviera las credenciales S3
directas (`S3_ACCESS_KEY`/`S3_SECRET_KEY` de la cuenta R2) en variables de entorno — viable
para uso personal, indistribuible para usuarios finales. Decisión Fase 4: **el Coordinator
firma, el Device ejecuta**. El backend Convex expone una action autenticada
(`vault:sign`, `packages/backend/convex/vault.ts`, `"use node"`) que valida y firma lotes de
operaciones HEAD/GET/PUT como URLs S3 prefirmadas (900 s) contra R2, usando credenciales que
viven **solo en el deployment** (`convex env set S3_*`). En el cliente, `SignedVault`
(`apps/cli/src/signed_vault.rs`) implementa el trait `Vault` pidiendo la firma por operación y
ejecutándola con reqwest directo contra R2 — los bytes nunca pasan por Convex.

Selección de backend en `env::build_vault` (precedencia): `S3_*` completo en el entorno →
`S3Vault` directo (ops / self-hosted / gates locales, TODO lo anterior sigue funcionando);
si no → `SignedVault` sobre la MISMA conexión autenticada del login (ADR 0014). El usuario
final ya no ve credenciales de storage jamás.

Reglas y límites:

- **`list`/`delete` no se firman.** Las URLs prefirmadas no pueden listar un prefijo, y el
  sweep del GC es account-wide: `gc` queda como comando de **operador** con `S3_*` directas
  (`SignedVault::list/delete` fallan con mensaje explícito). Mover el GC server-side queda
  reservado.
- **Validación estricta de keys** en la action: solo los cinco prefijos content-addressed del
  formato (`blocks/ | manifest/ | blocklist/ | meta/` con `<aa>/<cid64>` coherentes, y
  `keys/<space_id>/<aa>/<cid64>`); cualquier otra forma se rechaza. Para `keys/…` se verifica
  además ownership del Space (`requireOwnedSpace`) — es el único prefijo cuyo scope es
  verificable server-side.
- **Modelo de amenaza v1**: los prefijos planos (`blocks/…`) son firmables por cualquier
  cuenta autenticada, pero sus keys son HMAC del contenido con el `dedup_secret` por-Account
  (ADR 0003) — inadivinables sin él — y el contenido va cifrado `alg=1` (ADR 0015). Signup
  además está cerrado por defecto en el deployment. Endurecimiento reservado: layout de keys
  con prefijo por Account, que haría el scope verificable también para blocks.
- **Latencia v1**: una llamada `vault:sign` por operación (la action ya acepta lotes de hasta
  256; el motor hoy opera secuencialmente, ver `commit.rs`). Batching desde el engine queda
  como optimización reservada.

## Considered Options

- **Proxear los bytes por Convex** (rechazada): las HTTP actions tienen límites de payload y
  el ancho de banda por Convex cuesta; los Blocks deben ir directo a R2.
- **Tokens R2 con scope por usuario** (rechazada): R2 solo scopa tokens por bucket, no por
  prefijo — exigiría bucket-por-usuario y provisioning vía API de Cloudflare.
- **Componente `@convex-dev/r2`** (rechazada): firma PUT/GET y acepta keys custom, pero
  impone su tabla de metadata y API por-objeto; nuestro layout content-addressed y la
  validación de formato exigen la action propia (son ~100 líneas con el SDK de AWS).
- **Trae-tu-propio-bucket** (rechazada como default): válido como modo self-hosted (sigue
  existiendo vía `S3_*`), pero no puede ser el onboarding de un usuario final.
