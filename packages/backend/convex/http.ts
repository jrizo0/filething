// HTTP routes — mounts Better Auth's endpoints on the Coordinator's HTTP-actions
// origin (self-hosted: port 3211). This is the surface the Rust CLI hits for
// sign-up / sign-in and for exchanging its session token for a Convex JWT
// (/api/auth/convex/token). See betterAuth.ts for the full flow.
//
// cors: true so a future browser client can call these cross-origin; it also
// whitelists the Authorization header the bearer/convex-token path needs.

import { httpRouter } from "convex/server";
import { authComponent, createAuth } from "./betterAuth";

const http = httpRouter();

authComponent.registerRoutes(http, createAuth, { cors: true });

export default http;
