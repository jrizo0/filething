# Directorios como entradas de primera clase en el Manifest (`t=3`)

Motivado por el issue #20: un directorio VACÍO nunca se sincronizaba. Hasta ahora el
scanner trataba los directorios planos como implícitos —solo viajaban los archivos y sus
paths reconstruían el árbol al materializar—, así que una carpeta sin archivos dentro no
producía ninguna FileEntry y jamás aparecía en el otro Device. Carpetas vacías con
significado (un `build/` esperado, un `.keep`less scaffold, un punto de montaje) se perdían
en silencio.

Decisión: **trackear TODOS los directorios planos como FileEntries de primera clase**, un
nuevo tipo `FileType::Dir` (`t=3`). Una entrada Dir solo tiene `p` y `t` significativos:
`sz=0`, `pcid` en cero, `x=false`, `bk` vacío, sin `bk_ref` ni `lt`. No se trackean modo ni
permisos del directorio. El root del Space NUNCA es una entrada. Los directorios *derived*
(`node_modules/`, `target/`, …) siguen siendo `t=2` y no se descienden; el chequeo derived
gana antes que el de directorio, así que un derived nunca se reclasifica como Dir.

Piezas:

- **Scanner** (`ft-engine/scan.rs`): el walk emite una `WalkItem` por cada directorio plano
  y SIGUE descendiendo (a diferencia de un derived, que emite una y no se desciende).
  `ft-fsmap::classify` devuelve `FileType::Dir` para metadata de directorio. No se introduce
  ningún filtro nuevo: la política del proyecto es "sincronizar todo" (se mantiene el salteo
  de `.filething/`, junk de plataforma y `.filethingignore`).
- **Materialize** (`ft-diff`): `t=3` hace `create_dir_all` (idempotente). Si el path lo
  ocupa un archivo/symlink (transición file->dir) se elimina primero; un dir ya presente se
  deja intacto. La transición inversa dir->file elimina el directorio VACÍO antes de escribir
  el archivo (un dir no vacío aborta con error, nunca se fuerza).
- **Borrado seguro** (`ft-diff::apply`, `ft-engine::pull`): un `Change::Deleted` de un Dir
  usa `remove_dir` —NUNCA `remove_dir_all`—. `apply` particiona el batch: Fase A concurrente
  (adds/mods + borrados de no-directorios) y Fase B secuencial (borrados de Dir, del más
  profundo al menos profundo) para que un padre solo se elimine tras sus hijos ya borrados.
  `NotFound` es no-op; un directorio que todavía tiene contenido local no sincronizado se
  MANTIENE en silencio (`ENOTEMPTY`), y el siguiente commit lo re-agrega.
- **Conflictos** (`ft-conflict`, `ft-engine::pull`): la identidad de contenido de un Dir es
  su tipo solo (dos entradas Dir en un path son equivalentes), igual que derived. Un loser
  Dir en una copia de conflicto se materializa creando el directorio con el nombre renombrado.
- **Compat de formato**: NO se sube la versión de página (`PAGE_VERSION` intacto). Un
  Manifest viejo sin entradas Dir decodifica y difiea sin problema (la ausencia es válida);
  `ft_manifest::build` es función pura de las entradas y maneja Dir (`bk` vacío) sin
  externalizar.

## Impacto de migración

- **Un re-commit por Space al actualizar**: el primer scan tras el upgrade emite las
  entradas Dir de todo el árbol, así que el `manifestRoot` de cada Space cambia una vez. Ese
  commit toca solo páginas del Manifest (no sube Blocks nuevos: los directorios no llevan
  bytes) y, al agregar entradas, corta el dedup de páginas contra Revisiones previas para ese
  árbol —costo único y acotado.
- **Binarios viejos NO pueden decodificar `t=3`**: `FileType::from_u8(3)` en una versión
  previa devolvía `InvalidFileType(3)`. Un Device con binario anterior que intente leer un
  Manifest escrito por uno nuevo FALLA al decodificar la entrada Dir. **Limitación conocida:**
  Devices de versiones mezcladas deben actualizarse; no hay downgrade tras el primer commit
  con directorios. (Se documenta como limitación aceptada, no se añade un flag de
  compatibilidad: el modelo de uso es personal/self-hosted con Devices bajo el control del
  mismo usuario.)

## Considered Options

- **Trackear solo directorios VACÍOS** (emitir una entrada Dir únicamente cuando la carpeta
  no tiene hijos): rechazada. El conjunto de entradas se vuelve inestable —al agregar el
  primer archivo la entrada Dir desaparece, y al borrar el último reaparece—, lo que hace
  oscilar el `manifestRoot`, complica el diff (un directorio "reaparece" como Added sin que
  el usuario tocara nada) y puede resucitar cadenas de directorios ya borradas. Trackear
  TODOS los directorios da un conjunto de entradas uniforme y estable: un directorio existe
  en el Manifest exactamente cuando existe en disco.
- **`remove_dir_all` al borrar un directorio**: rechazada. Borraría contenido local aún no
  sincronizado bajo un path que el remoto eliminó —pérdida de datos—. `remove_dir` + mantener
  en `ENOTEMPTY` preserva siempre los datos locales; el árbol converge cuando el contenido
  también se borra o se sincroniza.
