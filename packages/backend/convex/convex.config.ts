// Convex app definition — mounts the Better Auth component (@convex-dev/better-auth).
//
// The component owns its own namespaced tables (users, sessions, accounts, jwks,
// ...) inside the Convex deployment; our app schema (schema.ts) is unaffected.
// Better Auth is the real identity layer that replaced the MVP pairing codes:
// the client signs up / logs in over HTTP against the routes mounted in http.ts,
// obtains a Convex-audience JWT, and presents it over the websocket so every
// function can read ctx.auth (see convex/auth.ts requireAccount).

import { defineApp } from "convex/server";
import betterAuth from "@convex-dev/better-auth/convex.config";

const app = defineApp();
app.use(betterAuth);

export default app;
