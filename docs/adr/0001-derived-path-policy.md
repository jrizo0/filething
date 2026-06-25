# Política de Derived path por tipo de artefacto, no por SO

Un **Derived path** (`node_modules/`, `target/`, `.next/`, `venv/`) se trata según el tipo de artefacto detectado por su lockfile, no según el SO: por defecto el motor NO mueve sus bytes, sincroniza fuente+lockfile, marca el path en el Manifest como `FileEntry` `t=2` (derived) con `bk` vacío (ver §5.1 de format.md) y deja la ruta lista para regenerar, SOLO sugiriendo —nunca auto-ejecutando— el comando de install/build en el Device destino. La razón del trade-off central: regenerar significa ejecutar código arbitrario (el script de install), así que NUNCA se dispara automático; en serve mode/VPS jamás sin opt-in explícito.

## Considered Options

- **Rutas por SO por defecto** (rechazada): se rompe justo en pnpm/Yarn-PnP, el gestor del propio stack, donde `node_modules` es un grafo de symlinks/hardlinks a un store global fuera del Space y copiarlo por-SO da symlinks rotos.
- **Híbrido por gestor detectado** (elegida): la estrategia depende del lockfile, no del SO.

## Consequences

- **pnpm / Yarn-PnP**: NO sincronizar `node_modules` (grafo de symlinks a store global fuera del Space); se sincroniza fuente+lock y se reconstruye local.
- **venv**: SIEMPRE regenerar (guarda rutas absolutas, no es portable).
- **`node_modules` plano** (npm/yarn clásico): variante por SO solo como opt-in consciente.
- **`target/` de Rust y `.next/`**: no sincronizar por defecto; por-SO solo opt-in.
- **`.git`**: viaja normal, es portable (solo los hooks no lo son).
- El GC nunca razona sobre Blocks de derived, porque `t=2` nunca tiene `bk`.
- El otro Device no trata el path como borrado ni espera contenido; la regeneración la dispara la fuente sincronizada (p.ej. `package-lock.json` es una `FileEntry` `t=0` normal).
- Distinto del Ignore file (`.filethingignore`), que es exclusión elegida por el usuario; esto es política automática del motor.
