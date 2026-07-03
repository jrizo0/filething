// Convex auth providers — registers Better Auth's Convex JWT issuer so that
// ctx.auth.getUserIdentity() validates the tokens the client presents.
//
// getAuthConfigProvider() emits a `customJwt` provider with:
//   - applicationID "convex" (the JWT audience the convex() plugin signs),
//   - issuer = process.env.CONVEX_SITE_URL (self-hosted: http://localhost:3211),
//   - algorithm RS256, and jwks = <CONVEX_SITE_URL>/api/auth/convex/jwks.
// Convex fetches that JWKS URL from its own HTTP-actions origin to verify tokens.
// The convex() plugin in betterAuth.ts requires EXACTLY this one provider.

import { getAuthConfigProvider } from "@convex-dev/better-auth/auth-config";
import type { AuthConfig } from "convex/server";

export default {
  providers: [getAuthConfigProvider()],
} satisfies AuthConfig;
