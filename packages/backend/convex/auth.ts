// auth — identity resolution and the authorization helpers every Coordinator
// function shares.
//
// Real auth now lives in Better Auth (see betterAuth.ts / http.ts). The client
// presents a Convex-audience JWT over the websocket; here we turn that identity
// into a filething Account and enforce ownership. The MVP pairing codes
// (bootstrap/claim, table pairing_codes) are gone: pairing a second Device is
// just the same user logging in elsewhere and calling ensureDevice again.
//
// Contract (mirrored in the Rust client):
//   mutation auth:ensureDevice({ deviceName, dedupSecret? })
//     -> { accountId, deviceId, dedupSecret }   // get-or-create Account + Device
//
// The Coordinator never sees file bytes nor a Space's plaintext (format.md §1, §6);
// dedupSecret / spaceKey are opaque escrow blobs it only hands back to the same
// authenticated Account.

import { v, ConvexError } from "convex/values";
import { internalQuery, mutation } from "./_generated/server";
import type { QueryCtx } from "./_generated/server";
import type { Doc, Id } from "./_generated/dataModel";

// UTF-8 encode a string into a fresh, standalone ArrayBuffer (the type
// v.bytes() stores). Copy into a new ArrayBuffer so the value is unambiguously a
// plain ArrayBuffer that owns exactly its bytes.
function utf8ToArrayBuffer(s: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(s);
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

// Per-Account / per-Space escrow secrets are fixed 32-byte keys.
const ESCROW_KEY_BYTES = 32;

// Resolve the caller's authenticated Account, or throw. Every public function
// funnels through this: no valid JWT (ctx.auth) => "unauthenticated"; a valid
// identity with no matching Account yet => "no_account" (call ensureDevice first).
// The Account is keyed by `subject` = the JWT `sub` claim (Better Auth user id).
export async function requireAccount(ctx: QueryCtx): Promise<Doc<"accounts">> {
  const identity = await ctx.auth.getUserIdentity();
  if (identity === null) {
    throw new ConvexError({
      code: "unauthenticated",
      message: "no authenticated identity on the request",
    });
  }
  const account = await ctx.db
    .query("accounts")
    .withIndex("by_subject", (q) => q.eq("subject", identity.subject))
    .unique();
  if (account === null) {
    throw new ConvexError({
      code: "no_account",
      message: "authenticated but no Account yet; call auth:ensureDevice first",
    });
  }
  return account;
}

// Load a Space and assert the caller's Account owns it, or throw. Centralises
// the ownership check shared by spaces:* and revisions:*.
export async function requireOwnedSpace(
  ctx: QueryCtx,
  account: Doc<"accounts">,
  spaceId: Id<"spaces">,
): Promise<Doc<"spaces">> {
  const space = await ctx.db.get(spaceId);
  if (space === null) {
    throw new ConvexError({ code: "space_not_found", message: "no such Space" });
  }
  if (space.accountId !== account._id) {
    throw new ConvexError({
      code: "forbidden",
      message: "Space belongs to another Account",
    });
  }
  return space;
}

// Load a Device and assert the caller's Account owns it, or throw.
export async function requireOwnedDevice(
  ctx: QueryCtx,
  account: Doc<"accounts">,
  deviceId: Id<"devices">,
): Promise<Doc<"devices">> {
  const device = await ctx.db.get(deviceId);
  if (device === null) {
    throw new ConvexError({ code: "device_not_found", message: "no such Device" });
  }
  if (device.accountId !== account._id) {
    throw new ConvexError({
      code: "forbidden",
      message: "Device belongs to another Account",
    });
  }
  return device;
}

// callerAccount / assertOwnedSpaces — internalQuery wrappers around
// requireAccount / requireOwnedSpace for "use node" actions (vault.ts). Node
// actions run outside the V8 runtime and have no ctx.db, so they cannot call
// those helpers directly; they go through ctx.runQuery instead.

// Resolve the caller's Account from ctx.auth (same rules as requireAccount)
// and hand back just the id — the only thing an action needs to scope its work.
export const callerAccount = internalQuery({
  args: {},
  returns: v.object({ accountId: v.id("accounts") }),
  handler: async (ctx) => {
    const account = await requireAccount(ctx);
    return { accountId: account._id };
  },
});

// Assert that every one of `spaceIds` (raw strings pulled out of Vault keys,
// see vault.ts) both is a real Space id and is owned by `accountId`. Mirrors
// requireOwnedSpace's checks, but takes the ids as a batch of untrusted
// strings rather than a single v.id("spaces") arg: a string that fails to
// normalize is exactly as forbidden as one that normalizes to someone else's
// Space, so both throw the same "forbidden" — we don't leak which case it was.
export const assertOwnedSpaces = internalQuery({
  args: {
    accountId: v.id("accounts"),
    spaceIds: v.array(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    for (const raw of args.spaceIds) {
      const spaceId = ctx.db.normalizeId("spaces", raw);
      const space = spaceId === null ? null : await ctx.db.get(spaceId);
      if (space === null || space.accountId !== args.accountId) {
        throw new ConvexError({
          code: "forbidden",
          message: "not an owned Space",
        });
      }
    }
    return null;
  },
});

// Pick a human-ish display name for a freshly created Account from the identity,
// falling back to the device name. Stored as v.bytes() (ciphertext-ready).
function displayNameFor(
  identity: { email?: string; name?: string },
  deviceName: string,
): string {
  return identity.email ?? identity.name ?? deviceName;
}

// ensureDevice — the authenticated entry point every client calls at startup.
// Resolves identity -> get-or-create Account (by JWT subject) -> get-or-create
// Device (by Account + deviceName) and returns the escrow dedupSecret so a
// second Device of the same user gets the same value. Idempotent: calling it
// again for a known (Account, deviceName) returns the existing rows.
//
// `dedupSecret` (32 bytes) is generated by the CLIENT on first use and stored
// once. It is REQUIRED when the Account is created; ignored (the stored value
// wins) once set. It back-fills an Account that predates escrow.
export const ensureDevice = mutation({
  args: {
    deviceName: v.string(),
    dedupSecret: v.optional(v.bytes()),
  },
  returns: v.object({
    accountId: v.id("accounts"),
    deviceId: v.id("devices"),
    dedupSecret: v.bytes(),
  }),
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (identity === null) {
      throw new ConvexError({
        code: "unauthenticated",
        message: "no authenticated identity on the request",
      });
    }

    if (
      args.dedupSecret !== undefined &&
      args.dedupSecret.byteLength !== ESCROW_KEY_BYTES
    ) {
      throw new ConvexError({
        code: "bad_dedup_secret",
        message: `dedupSecret must be exactly ${ESCROW_KEY_BYTES} bytes`,
      });
    }

    const now = Date.now();

    // Get-or-create the Account keyed by the JWT subject.
    let account = await ctx.db
      .query("accounts")
      .withIndex("by_subject", (q) => q.eq("subject", identity.subject))
      .unique();

    let accountId: Id<"accounts">;
    let dedupSecret: ArrayBuffer;

    if (account === null) {
      // First Device for this identity: the client MUST supply the escrow secret.
      if (args.dedupSecret === undefined) {
        throw new ConvexError({
          code: "dedup_secret_required",
          message: "first ensureDevice for an Account must include dedupSecret",
        });
      }
      dedupSecret = args.dedupSecret;
      accountId = await ctx.db.insert("accounts", {
        subject: identity.subject,
        name: utf8ToArrayBuffer(
          displayNameFor(identity, args.deviceName),
        ),
        dedupSecret,
        createdAt: now,
      });
    } else {
      accountId = account._id;
      if (account.dedupSecret === undefined) {
        // Back-fill escrow for a pre-existing Account (needs the client's secret).
        if (args.dedupSecret === undefined) {
          throw new ConvexError({
            code: "dedup_secret_required",
            message: "Account has no dedupSecret yet; include it to back-fill",
          });
        }
        dedupSecret = args.dedupSecret;
        await ctx.db.patch(accountId, { dedupSecret });
      } else {
        // Already escrowed: the stored value is authoritative.
        dedupSecret = account.dedupSecret;
      }
    }

    // Get-or-create the Device by (Account, deviceName). Names are unique per
    // Account by convention; a repeat call returns the existing Device.
    const existingDevices = await ctx.db
      .query("devices")
      .withIndex("by_account", (q) => q.eq("accountId", accountId))
      .collect();
    const existing = existingDevices.find((d) => d.name === args.deviceName);

    let deviceId: Id<"devices">;
    if (existing !== undefined) {
      deviceId = existing._id;
    } else {
      deviceId = await ctx.db.insert("devices", {
        accountId,
        name: args.deviceName,
        baseSeqInUse: 0,
      });
    }

    return { accountId, deviceId, dedupSecret };
  },
});
