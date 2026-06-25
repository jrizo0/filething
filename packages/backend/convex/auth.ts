// auth — minimal device pairing by code (Coordinator control plane).
//
// Decisions §0: "Auth = pairing mínimo por código de dispositivo." Better Auth /
// browser OAuth is a reserved hole (post-MVP). The pairing code is intentionally
// NON-cryptographic for the MVP — it only has to be hard enough to mistype, not
// to brute-force.
//
// Contract (BUILD-PLAN §3 ft-coordinator, mirrored 1:1 in the Rust client):
//   mutation auth:bootstrap({ deviceName })
//     -> { accountId, deviceId, pairingCode }   // first Device: Account+Device+code
//   mutation auth:claim({ code, deviceName })
//     -> { accountId, deviceId }                // second Device joins the Account
//
// The Coordinator never sees file bytes nor the Space key (format.md §1, §6).

import { v, ConvexError } from "convex/values";
import { mutation } from "./_generated/server";
import type { MutationCtx } from "./_generated/server";
import type { Id } from "./_generated/dataModel";

// UTF-8 encode a string into a fresh, standalone ArrayBuffer (the type
// v.bytes() stores). We copy into a new ArrayBuffer rather than reuse the
// encoder's view buffer so the value is unambiguously a plain ArrayBuffer
// (never a SharedArrayBuffer) and owns exactly its bytes.
function utf8ToArrayBuffer(s: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(s);
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

// Code alphabet: no 0/O/1/I/L to stay unambiguous when typed by a human.
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LEN = 8;

// Generates a short, human-typeable, NON-cryptographic pairing code (MVP).
// Uses Math.random — adequate for a one-shot, single-use pairing token; a real
// auth flow (reserved, post-MVP) would replace this with a proper secret.
function generatePairingCode(): string {
  let code = "";
  for (let i = 0; i < CODE_LEN; i++) {
    const idx = Math.floor(Math.random() * CODE_ALPHABET.length);
    code += CODE_ALPHABET[idx];
  }
  return code;
}

// Mints a fresh, not-yet-used pairing code, retrying on the (vanishingly rare)
// collision with an existing unclaimed code so the lookup-by-code stays
// unambiguous. Bounded retries keep the mutation well under Convex's CPU limit.
async function mintUniqueCode(ctx: MutationCtx): Promise<string> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const code = generatePairingCode();
    const existing = await ctx.db
      .query("pairing_codes")
      .withIndex("by_code", (q) => q.eq("code", code))
      .unique();
    if (existing === null) {
      return code;
    }
  }
  // Astronomically unlikely with 30^8 codes; surface as a distinguishable error
  // rather than risk an ambiguous duplicate.
  throw new ConvexError({
    code: "pairing_code_exhausted",
    message: "could not mint a unique pairing code",
  });
}

// First Device: creates the Account + this Device and mints a pairing code that
// a second Device can later claim to join the same Account.
export const bootstrap = mutation({
  args: {
    deviceName: v.string(),
  },
  returns: v.object({
    accountId: v.id("accounts"),
    deviceId: v.id("devices"),
    pairingCode: v.string(),
  }),
  handler: async (ctx, args) => {
    const now = Date.now();

    // The Account owns Spaces and Devices. `subject` is the stable external
    // identity; in the MVP we derive a throwaway one from the device + time
    // (real login subject is reserved, post-MVP). `name` is v.bytes() so it can
    // become ciphertext under zero-knowledge without a type change.
    const subject = `pairing:${now}:${args.deviceName}`;
    const accountId: Id<"accounts"> = await ctx.db.insert("accounts", {
      subject,
      name: utf8ToArrayBuffer(args.deviceName),
      createdAt: now,
    });

    const deviceId: Id<"devices"> = await ctx.db.insert("devices", {
      accountId,
      name: args.deviceName,
      baseSeqInUse: 0,
    });

    const pairingCode = await mintUniqueCode(ctx);
    await ctx.db.insert("pairing_codes", {
      code: pairingCode,
      accountId,
      createdAt: now,
      claimedAt: null,
    });

    return { accountId, deviceId, pairingCode };
  },
});

// Second Device: consumes a pairing code to join the Account that minted it,
// registering a new Device under that Account. The code is single-use.
export const claim = mutation({
  args: {
    code: v.string(),
    deviceName: v.string(),
  },
  returns: v.object({
    accountId: v.id("accounts"),
    deviceId: v.id("devices"),
  }),
  handler: async (ctx, args) => {
    const pairing = await ctx.db
      .query("pairing_codes")
      .withIndex("by_code", (q) => q.eq("code", args.code))
      .unique();

    if (pairing === null) {
      throw new ConvexError({
        code: "invalid_pairing_code",
        message: "no such pairing code",
      });
    }
    if (pairing.claimedAt !== null) {
      throw new ConvexError({
        code: "pairing_code_already_claimed",
        message: "pairing code has already been used",
      });
    }

    const now = Date.now();
    // Single-use: mark claimed inside this serializable mutation so two
    // concurrent claims of the same code cannot both succeed (OCC retry re-reads
    // the fresh row).
    await ctx.db.patch(pairing._id, { claimedAt: now });

    const deviceId: Id<"devices"> = await ctx.db.insert("devices", {
      accountId: pairing.accountId,
      name: args.deviceName,
      baseSeqInUse: 0,
    });

    return { accountId: pairing.accountId, deviceId };
  },
});
