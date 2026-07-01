# Basura de plataforma siempre excluida (built-in), no solo vía `.filethingignore`

El scanner (`scan.rs`) NUNCA mete en el Manifest tres archivos de basura generados por el SO — `.DS_Store` (Finder de macOS), `Thumbs.db` y `desktop.ini` (Explorer de Windows) — con una lista built-in (`JUNK_NAMES`) independiente del `.filethingignore` del usuario. El match es por **nombre exacto de la entrada**, case-sensitive tal cual esos tres nombres, en **cualquier** directorio del Space (no glob, no extensión: `DS_Store`, `.DS_Store.bak`, `mythumbs.db`, `Desktop.ini` SÍ se sincronizan). La exclusión vive **solo en el lado scanner (outbound)**: la lista se aplica en el `walk`, además/antes del `.filethingignore`, y esos archivos no llegan al Manifest ni al índice local. El motivo del trade-off: es basura de plataforma sin datos del usuario que contamina el Space entre máquinas (observado en la prueba Mac↔VPS, donde el `.DS_Store` del Finder llegó al VPS); Dropbox/iCloud la excluyen siempre y esto lo debe garantizar el motor, no cada usuario re-descubriéndolo.

## Considered Options

- **Solo `.filethingignore` del usuario** (rechazada): la basura de plataforma es universal, no una elección por-Space; delegarla al usuario significa que cada persona la re-descubre después de haberla ya propagado. El `.filethingignore` sigue existiendo para exclusiones elegidas; la lista built-in es política automática del motor (como los Derived paths del ADR 0001, no como el Ignore file).
- **Ignore bidireccional en apply/diff** (rechazada): filtrar también al materializar/diffear añade complejidad y es innecesario para converger. Con el filtro solo en el scanner el sistema ya converge (ver Consequences).
- **Match por glob/extensión** (rechazada): abre la puerta a borrar archivos legítimos del usuario (`mythumbs.db`); nombre exacto es predecible y conservador — filething nunca descarta datos que el usuario no eligió excluir.

## Consequences

- **Auto-limpieza (consecuencia aceptada):** un Space que YA tiene un `.DS_Store` commiteado verá, en el próximo commit de cualquier Device con este fix, la ELIMINACIÓN del `.DS_Store` remoto: el scan deja de verlo ⇒ su fila de índice se borra ⇒ el diff lo reporta como borrado (un delete es una ausencia, §8). El archivo local en disco NO se toca; solo desaparece del Manifest. Así el Space se limpia solo sin acción manual y sin ignore bidireccional.
- **Limitación conocida (watcher):** `ft-watcher` seguirá emitiendo eventos por estos archivos (crear/modificar `.DS_Store` dispara el watcher), y el motor hará scans no-op (el walk los ignora ⇒ el `manifestRoot` no cambia ⇒ nada que commitear). Ineficiencia aceptada por ahora; optimizable después filtrando también en el motor al recibir eventos del watcher (fuera del alcance de este ADR).
- El `.filethingignore` del usuario sigue funcionando igual; la lista built-in se aplica además de él, no en su lugar.
- La constante compartida (`JUNK_NAMES`) vive en `scan.rs`, no en `ft-core`, porque el único consumidor hoy es el scanner.
