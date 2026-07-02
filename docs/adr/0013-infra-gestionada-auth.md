# Infra gestionada (Convex Cloud + R2): auth de uso personal, cifrado y auth real diferidos

La Fase 2 mueve filething de la infra local (Convex self-hosted + MinIO) a infra gestionada
(Convex Cloud + Cloudflare R2), **para uso propio** (todos los Devices son del dueño). Runbook
en `docs/PRODUCTION-SETUP.md`. Decisiones:

1. **Auth del cliente = deploy key de Convex Cloud, o sin credencial.** El cliente Rust no
   tiene un flujo de login de usuario; hoy adjunta `set_admin_auth(<key>)`. En Cloud no existe
   el admin key self-hosted, así que se usa un **deploy key** de producción por esa misma ruta
   (`apps/cli/src/env.rs`: `CONVEX_DEPLOY_KEY`/`CONVEX_ADMIN_KEY`, con fallback a
   `CONVEX_SELF_HOSTED_ADMIN_KEY`). La ruta `set_admin_auth` sobre `wss://…/api/sync` acepta el
   deploy key pero es `#[doc(hidden)]` → **se verifica en vivo** con el smoke test. Además, las
   funciones Convex son públicas por defecto y el backend no tiene checks de `ctx.auth`, así que
   `connect_coordinator` también conecta **sin credencial** (solo warning). Aceptable **solo**
   mientras todos los Devices sean del dueño.

2. **R2 = solo configuración.** `ft-vault` ya habla S3 con path-style forzado; R2 quiere
   `S3_REGION=auto` y el endpoint `https://<account>.r2.cloudflarestorage.com`. Sin cambios de
   código. Secretos en `infra/.env.cloud` (gitignored; `.env.cloud` en `.gitignore`), nunca en
   el repo.

3. **Diferido a Fase B (no bloquea uso propio):** auth real (Better Auth: login navegador +
   tokens por Device en el pairing) y cifrado en runtime (`alg=1`) — prerequisitos para
   guardar bytes de terceros. Hasta entonces los Blocks se guardan en claro (`alg=0`).

4. **Endurecimiento que SÍ entró en esta tanda:** daemon como servicio (`filething service`,
   launchd/systemd con env file 0600 + logs), observabilidad mínima (`SyncMetrics` en
   `.filething/metrics.json` + `filething metrics` + watchdog de head-staleness), y GC/retención
   (ADR 0012).

## Consequences

El deploy key es un secreto root (control total del deployment, puede impersonar usuarios);
se guarda como tal. La migración de datos es barata: los Blocks son content-addressed
(re-subir / `aws s3 sync`) y el Coordinator se re-crea (re-`init` de Spaces). Riesgo residual:
si el crate `convex` cambia la ruta `set_admin_auth`, hay que revalidar; el fallback sin
credencial mitiga. La validación real Mac↔VPS contra la nube depende de que el usuario
provisione las cuentas (no hay credenciales en este entorno).
