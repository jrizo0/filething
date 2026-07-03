# Auth real: Better Auth con email+password, tokens por device, ctx.auth en todo el backend

La Fase 3 sustituye el atajo de la Fase 2 (deploy key vía `set_admin_auth`, funciones Convex
públicas sin ningún check — ver ADR 0013) por auth real: **Better Auth** montado como
componente Convex (`@convex-dev/better-auth`) con **email+password headless** (sin navegador
por ahora), y **checks de `ctx.auth` + scoping por cuenta en todas las funciones** del
backend. El cliente Rust hace signup/login por HTTP contra los endpoints de Better Auth,
guarda su token de sesión localmente (0600) y adjunta el JWT por la ruta pública
`set_auth`/`set_auth_callback` del crate `convex` (0.10 ya la trae; se abandona la ruta
`#[doc(hidden)]` `set_admin_auth` para el flujo de usuario).

Decisiones:

1. **Account ↔ usuario Better Auth**: `accounts.subject` pasa a ser el subject del JWT.
   Toda función resuelve la cuenta desde `ctx.auth.getUserIdentity()` (helper
   `requireAccount`) y valida que cualquier `deviceId`/`spaceId` recibido pertenezca a esa
   cuenta. Desaparecen los args `accountId` confiados (`spaces:listByAccount` →
   `spaces:listMine`).
2. **Pairing = login**: se retiran los pairing codes de 8 chars no criptográficos
   (`bootstrap`/`claim` y la tabla `pairing_codes`). Vincular un device nuevo = hacer login
   con el mismo usuario en esa máquina; cada device recibe su propio token de sesión en ese
   momento ("tokens por device emitidos en el pairing"). Un flujo de device-authorization
   (código corto para devices headless sin teclear password) queda como mejora futura vía el
   plugin correspondiente de Better Auth.
3. **La deploy key queda solo para ops** (deploy del backend, emergencias). El flujo normal
   del CLI ya no necesita ninguna key privilegiada. El fallback sin credencial de
   `connect_coordinator` deja de funcionar contra un backend con checks (deseado).

## Considered Options

- **Seguir con deploy key + funciones públicas** (rechazada): aceptable solo mientras todos
  los devices son del dueño; bloquea guardar bytes de terceros y cobrar (TODO.md Fase B).
- **Auth propio (JWT firmados a mano en una action)** (rechazada): reinventa sesiones,
  hashing de passwords y refresh; el stack ya fijó Better Auth (HANDOFF).
- **OAuth por navegador desde el arranque** (diferida): exige frontend web (fuera de alcance
  de esta fase); email+password headless da la misma propiedad de seguridad para el CLI.

## Consequences

- Las funciones Convex dejan de ser utilizables sin sesión: los scripts/smokes deben crear
  usuario + login antes de operar. `cloud-smoke.sh` y los demo-gates se actualizan.
- El backend self-hosted necesita las env vars de Better Auth (`BETTER_AUTH_SECRET`,
  `SITE_URL`) y las HTTP actions (puerto 3211 self-hosted / `.convex.site` en Cloud).
- El token de sesión local sustituye a `account_id`/`device_id` como credencial de facto;
  se guarda con permisos 0600 junto al config del CLI.
