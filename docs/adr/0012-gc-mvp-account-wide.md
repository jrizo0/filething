# GC MVP: mark-and-sweep account-wide, dry-run por defecto

El GC (post-MVP en el plan original) se implementó para la Fase 2 (`ft-engine/src/gc.rs`,
`filething gc`). Decisiones load-bearing:

1. **Alcance por CUENTA, no por Space.** El Vault es un único bucket y el dedup es
   account-scoped (`CONTEXT.md`, tabla `dedup`): los Blocks se comparten entre las Spaces de
   la cuenta. Por eso el mark une la alcanzabilidad sobre **todas** las Spaces de la cuenta
   (`spaces:listByAccount` → por cada una, `revisions:listFromSeq` + su `metaBlobCid`). Barrer
   desde la vista de una sola Space borraría Blocks vivos de otra. Corolario: el barredor
   asume **un bucket = una cuenta** (el modelo self-hosted / uso personal que se envía). Un
   Vault gestionado multi-tenant que comparta bucket entre cuentas necesitaría claves
   prefijadas por cuenta o un barrido server-side, antes de poder correr GC ahí.

2. **Dos redes de seguridad (ADR 0007), ambas activas.** (a) *Retention floor* =
   `min(baseSeqInUse)` sobre los Devices de la cuenta (`spaces:refreshRetentionFloor`,
   recalculado antes de barrer); nunca se barre lo alcanzable desde Revisions con
   `seq >= floor`. `baseSeqInUse` solo avanza y se publica al avanzar (daemon y `gc`), así que
   el floor es una cota inferior de la base real de cada Device → solo puede sobre-retener. (b)
   *Grace-period*: nunca se barre un objeto más joven que la ventana (24h por defecto), lo que
   protege un commit en vuelo (Vault-primero, head-después, §7). `mtime` ausente/futuro ⇒ se
   trata como "demasiado joven" (nunca barrer ante la duda).

3. **Dry-run por defecto; `--apply` para borrar.** `--keep-all` retiene todas las Revisions
   (solo barre huérfanos, sin podar historial). Si una Space tiene head pero `listFromSeq`
   devuelve cero raíces retenidas, el GC **se niega** a correr (anomalía de backend) en vez de
   tratar todo como basura. El mark falla si un objeto alcanzable no se puede leer (nunca se
   barre con un mark incompleto).

## Consequences

Validado en vivo (`scripts/demo-gates.sh` gate g, contra Convex+MinIO): dry-run no borra;
un huérfano inyectado se barre con `--apply`; un clone fresco reconstruye el archivo grande
tras el GC (los Blocks alcanzables sobreviven). El `list`/`delete` se añadió al trait `Vault`
(ambos backends). Podar documentos de Revisions viejos (por debajo del floor) queda fuera:
hoy solo se barren objetos del Vault; una Revision sub-floor puede quedar con su Manifest ya
barrido (degrada a re-scan, aceptable — ADR 0007).
