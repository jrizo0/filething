// Better Auth wiring — the identity layer for the Coordinator.
//
// This is intentionally HEADLESS: filething's client is a Rust CLI, not a
// browser. It talks to the HTTP routes mounted in http.ts:
//   POST /api/auth/sign-up/email   { name, email, password } -> { token, user }
//   POST /api/auth/sign-in/email   { email, password }        -> { token, user }
//   GET  /api/auth/convex/token    (Authorization: Bearer <session token>)
//                                                             -> { token: <JWT> }
// The session `token` (from sign-up/sign-in, ~7d) is the long-lived credential;
// the CLI exchanges it at /api/auth/convex/token for a short-lived (~15 min)
// Convex-audience RS256 JWT and presents THAT over the websocket (set_auth), so
// every Convex function can trust ctx.auth (see auth.ts requireAccount).
//
// We enable only the `convex` plugin (JWT issuance + JWKS + the "convex"
// audience the auth.config.ts provider validates). We deliberately do NOT add
// crossDomain — that plugin exists to shuttle cookies across browser origins,
// which a CLI does not need. The convex() plugin already bundles Better Auth's
// bearer read-path, so `Authorization: Bearer <session token>` resolves the
// session with no cookie.
//
// Env vars (set on the deployment, never in code):
//   BETTER_AUTH_SECRET — signing secret (openssl rand -base64 32).
//   CONVEX_SITE_URL    — injected by Convex; the HTTP-actions origin, and the
//                        JWT issuer + JWKS host (self-hosted: http://localhost:3211).
//   SITE_URL           — optional app origin for trustedOrigins/baseURL.

import { createClient, type GenericCtx } from "@convex-dev/better-auth";
import { convex } from "@convex-dev/better-auth/plugins";
import { betterAuth } from "better-auth/minimal";
import { components } from "./_generated/api";
import type { DataModel } from "./_generated/dataModel";
import authConfig from "./auth.config";

// The component client: adapter (DB) + registerRoutes (HTTP) + helpers.
export const authComponent = createClient<DataModel>(components.betterAuth);

// Built per-request from the Convex ctx so Better Auth reads/writes its tables
// through the component adapter within the same transaction.
export const createAuth = (ctx: GenericCtx<DataModel>) => {
  const siteUrl = process.env.SITE_URL;
  return betterAuth({
    // The HTTP-actions origin serving /api/auth/*; also the JWT issuer.
    baseURL: process.env.CONVEX_SITE_URL,
    // No Origin header from the CLI => CSRF check is a no-op; keep the app origin
    // trusted anyway for any future browser client.
    trustedOrigins: siteUrl ? [siteUrl] : [],
    database: authComponent.adapter(ctx),
    emailAndPassword: {
      enabled: true,
      // Headless CLI: no email-delivery loop in the MVP. autoSignIn (default on)
      // means sign-up returns a usable session token immediately.
      requireEmailVerification: false,
    },
    plugins: [convex({ authConfig })],
  });
};
