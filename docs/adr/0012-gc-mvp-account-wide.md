# GC MVP: orphan-sweep account-wide, dry-run por defecto; poda de historial diferida

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

2. **Solo barrido de HUÉRFANOS (retiene TODO el historial).** El GC recorre TODAS las
   Revisions de cada Space (`listFromSeq(0)`) y borra únicamente objetos que **ninguna**
   Revision referencia — típicamente basura de un commit que subió bloques al Vault pero nunca
   avanzó el head (crash/abort entre el PUT y el CAS, §7). Como nunca quita algo referenciado,
   nunca deja sin base de sync a un Device.

3. **La poda de historial (retention floor) queda DIFERIDA.** Un floor sound por-Space
   (`min(baseSeqInUse)`) requiere telemetría por-(Device,Space): el `baseSeqInUse` actual es un
   **escalar por-Device** y el `seq` es **por-Space**, así que publicar el seq de una Space en
   ese escalar puede subir el floor de OTRA Space por encima de la base real de un Device ahí y
   borrarle su base (bug de pérdida de datos encontrado en revisión adversarial). Se conservan
   `revisions:listFromSeq(minSeq)` y `spaces:refreshRetentionFloor` (sin uso hoy) como andamiaje
   para el trabajo futuro: telemetría por-(Device,Space) + floor conservador (=0 salvo que TODOS
   los Devices de la cuenta hayan reportado una base para esa Space).

4. **Redes de seguridad.** (a) *Grace-period*: nunca se barre un objeto más joven que la
   ventana (24h por defecto), protegiendo un commit en vuelo (Vault-primero, head-después, §7);
   `mtime` ausente/futuro ⇒ "demasiado joven". (b) *Guard de concurrencia*: el snapshot de
   alcanzabilidad precede al listado, así que antes de borrar (`--apply`) se re-leen los heads
   de todas las Spaces; si alguno cambió (commit concurrente) o apareció/desapareció una Space,
   se ABORTA sin borrar. (c) *Anomalía*: se niega a correr si una Space tiene head pero cero
   Revisions listadas. (d) El mark falla si un objeto alcanzable no se puede leer (nunca barre
   con un mark incompleto). Además, el commit **siempre hace HEAD-before-PUT** (`commit.rs`, no
   confía en el caché local `local_block`), así que un Block que este GC (o el de otro Device)
   borró se re-sube en el siguiente commit — el caché de presencia local nunca puede contradecir
   destructivamente al Vault.

## Consequences

Validado en vivo (`scripts/demo-gates.sh` gate g, contra Convex+MinIO): dry-run no borra; un
huérfano inyectado se barre con `--apply`; un clone fresco reconstruye el archivo grande tras
el GC (los Blocks alcanzables sobreviven). El `list`/`delete` se añadió al trait `Vault` (ambos
backends). Coste: como no se poda historial, el Vault no reclama el espacio de contenido borrado/
superado hasta que exista la poda sound (diferida); el GC de hoy limpia solo huérfanos. El
HEAD-before-PUT añade un HEAD por Block conocido en cada commit (aceptable: commits a ritmo
humano).
