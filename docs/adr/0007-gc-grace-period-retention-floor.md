# Safety de GC reservada desde el día 1: grace-period y retention floor

Aunque el GC es post-MVP, el formato y el schema reservan ya dos protecciones contra borrar objetos de un commit en vuelo, porque el orden "Vault primero, head después" (ADR 0005, §7 del formato) deja objetos subidos pero aún no alcanzables y un mark-and-sweep ingenuo en esa ventana corromperia el commit y degradaria diff/conflicto. (1) **Grace-period por antigüedad**: el sweep nunca borra un objeto con `LastModified < GC_GRACE` (p.ej. 24h). (2) **Retention floor**: `spaces.retentionFloorSeq = min(devices.baseSeqInUse)`; el GC nunca barre objetos alcanzables desde Revisions con `seq >= retentionFloorSeq`, para que un Device offline con base vieja aún pueda diffear y detectar conflictos contra esa base.

## Consequences

Un Device offline más allá del floor pierde su base retenida y degrada explícitamente a full re-scan (correcto, caro). La política de retención (cuántas Revisions guardar) y el barredor físico quedan fuera del MVP; lo caro (enumerar alcanzables + estas dos protecciones) ya está reservado en el schema.
