// spaces — Space lifecycle and the reactive Space-head query (Coordinator).
//
// Contract (BUILD-PLAN §3 ft-coordinator). Every function is authenticated:
// the owning Account is derived from ctx.auth (requireAccount), never trusted
// from an arg, and ownership of the Space is enforced (requireOwnedSpace).
//   mutation spaces:create({ name (bytes UTF-8), metaBlobCid (bytes),
//                            spaceKey (bytes, 32) })  -> { spaceId }
//   query    spaces:get({ spaceId })                 -> the Space doc (incl. spaceKey)
//   query    spaces:listMine()                        -> Space[] for the caller
//   query    spaces:head({ spaceId })
//     -> { headRevisionId|null, seq|null, manifestRootCid|null, parent|null }
//   mutation spaces:refreshRetentionFloor({ spaceId })
//   mutation spaces:ensureSpaceKey({ spaceId, spaceKey }) -> null (first-write-wins)
//
// spaces:head is a QUERY so Convex's reactivity turns it into the change feed
// (format.md §8): a subscriber re-runs whenever headRevisionId — or the head
// Revision it points at — changes.
//
// All hashes (manifestRootCid, metaBlobCid) cross the wire as v.bytes()
// (ArrayBuffer <-> Vec<u8>), never v.string() (format.md §6.2, constraint 1).

import { v, ConvexError } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireAccount, requireOwnedSpace } from "./auth";

// Per-Space escrow key is a fixed 32-byte secret.
const SPACE_KEY_BYTES = 32;

// Create a Space with no head (the first Revision is committed later via
// revisions:commit). The owning Account comes from ctx.auth, not an arg. `name`
// and `metaBlobCid` are bytes; MVP `name` is cleartext UTF-8, `metaBlobCid`
// points at the Space metadata blob in the Vault — opaque to the Coordinator.
// `spaceKey` is the 32-byte escrow key the CLIENT generates; the Coordinator
// stores it and hands it back only to authenticated callers of this Account.
export const create = mutation({
  args: {
    name: v.bytes(),
    metaBlobCid: v.bytes(),
    spaceKey: v.bytes(),
  },
  returns: v.object({
    spaceId: v.id("spaces"),
  }),
  handler: async (ctx, args) => {
    const account = await requireAccount(ctx);
    if (args.spaceKey.byteLength !== SPACE_KEY_BYTES) {
      throw new ConvexError({
        code: "bad_space_key",
        message: `spaceKey must be exactly ${SPACE_KEY_BYTES} bytes`,
      });
    }
    const spaceId = await ctx.db.insert("spaces", {
      accountId: account._id,
      name: args.name,
      headRevisionId: null, // initial head = null (no Revision yet)
      metaBlobCid: args.metaBlobCid,
      spaceKey: args.spaceKey,
      retentionFloorSeq: 0, // MVP: GC off, floor at 0 (format.md §6.3)
    });
    return { spaceId };
  },
});

// Fetch the full Space document (including headRevisionId and the escrow
// spaceKey) by id — only for the owning Account.
export const get = query({
  args: {
    spaceId: v.id("spaces"),
  },
  handler: async (ctx, args) => {
    const account = await requireAccount(ctx);
    return await requireOwnedSpace(ctx, account, args.spaceId);
  },
});

// List every Space owned by the authenticated caller's Account.
export const listMine = query({
  args: {},
  handler: async (ctx) => {
    const account = await requireAccount(ctx);
    return await ctx.db
      .query("spaces")
      .withIndex("by_account", (q) => q.eq("accountId", account._id))
      .collect();
  },
});

// The Space head, resolved against the head Revision. REACTIVE = the change feed
// (§8): returns the current head pointer plus the head Revision's seq,
// manifestRootCid and parent, or all-null when the Space has no Revision yet.
export const head = query({
  args: {
    spaceId: v.id("spaces"),
  },
  returns: v.object({
    headRevisionId: v.union(v.id("revisions"), v.null()),
    seq: v.union(v.number(), v.null()),
    manifestRootCid: v.union(v.bytes(), v.null()),
    parent: v.union(v.id("revisions"), v.null()),
  }),
  handler: async (ctx, args) => {
    const account = await requireAccount(ctx);
    const space = await requireOwnedSpace(ctx, account, args.spaceId);
    if (space.headRevisionId === null) {
      return {
        headRevisionId: null,
        seq: null,
        manifestRootCid: null,
        parent: null,
      };
    }

    const headRev = await ctx.db.get(space.headRevisionId);
    if (headRev === null) {
      // Dangling head should never happen (Vault-before-head, §7), but stay
      // defensive: report the pointer with null Revision detail.
      return {
        headRevisionId: space.headRevisionId,
        seq: null,
        manifestRootCid: null,
        parent: null,
      };
    }

    return {
      headRevisionId: space.headRevisionId,
      seq: headRev.seq,
      manifestRootCid: headRev.manifestRootCid,
      parent: headRev.parent,
    };
  },
});

// Back-fill the escrow spaceKey on a pre-existing Space that predates it
// (schema.ts spaceKey is v.optional for exactly this reason: pairing-era
// Spaces created before spaceKey existed). First-write-wins: sets the key iff
// it is currently unset, then refuses any further call — once a Space has a
// key the client has already used it to encrypt/decrypt content, so silently
// overwriting it would strand that content. Used during the Fase 3 upgrade
// path (docs/PRODUCTION-SETUP.md, "Upgrade desde Fase 2") after
// migrations:claimAccount restores ownership of an old Space.
export const ensureSpaceKey = mutation({
  args: {
    spaceId: v.id("spaces"),
    spaceKey: v.bytes(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const account = await requireAccount(ctx);
    const space = await requireOwnedSpace(ctx, account, args.spaceId);
    if (args.spaceKey.byteLength !== SPACE_KEY_BYTES) {
      throw new ConvexError({
        code: "bad_space_key",
        message: `spaceKey must be exactly ${SPACE_KEY_BYTES} bytes`,
      });
    }
    if (space.spaceKey !== undefined) {
      throw new ConvexError({
        code: "space_key_already_set",
        message: "Space already has a spaceKey; ensureSpaceKey does not overwrite",
      });
    }
    await ctx.db.patch(args.spaceId, { spaceKey: args.spaceKey });
    return null;
  },
});

// Recompute and persist the Space's GC retention floor (§6.3, docs/adr/0007).
//
// The floor = min(baseSeqInUse) over every Device on the owning Account: the GC
// must never sweep objects reachable from a Revision with seq >= floor, so an
// offline Device sitting on an old base can still diff/reconcile against it.
// A Device reports its base via devices:setBaseSeq; the GC calls this right
// before a sweep so the floor reflects the freshest telemetry.
//
// Conservative by construction: baseSeqInUse is a single per-Device scalar (not
// per-Space), so a Device behind on ANOTHER Space drags this floor down and the
// GC over-retains — the safe direction for a destructive operation. Clamped to
// [0, headSeq]; with no Devices the floor stays 0 (retain all history).
export const refreshRetentionFloor = mutation({
  args: {
    spaceId: v.id("spaces"),
  },
  returns: v.object({
    retentionFloorSeq: v.number(),
    headSeq: v.union(v.number(), v.null()),
  }),
  handler: async (ctx, args) => {
    const account = await requireAccount(ctx);
    const space = await requireOwnedSpace(ctx, account, args.spaceId);

    // The head seq is the upper bound the floor can never exceed.
    let headSeq: number | null = null;
    if (space.headRevisionId !== null) {
      const headRev = await ctx.db.get(space.headRevisionId);
      headSeq = headRev === null ? null : headRev.seq;
    }

    const devices = await ctx.db
      .query("devices")
      .withIndex("by_account", (q) => q.eq("accountId", space.accountId))
      .collect();

    // No Devices → retain everything (floor 0). Otherwise the minimum base.
    let floor = 0;
    if (devices.length > 0) {
      floor = Math.min(...devices.map((d) => d.baseSeqInUse));
    }
    if (floor < 0) floor = 0;
    if (headSeq !== null && floor > headSeq) floor = headSeq;

    await ctx.db.patch(args.spaceId, { retentionFloorSeq: floor });
    return { retentionFloorSeq: floor, headSeq };
  },
});
