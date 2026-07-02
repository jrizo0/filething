// spaces — Space lifecycle and the reactive Space-head query (Coordinator).
//
// Contract (BUILD-PLAN §3 ft-coordinator):
//   mutation spaces:create({ accountId, name (bytes UTF-8), metaBlobCid (bytes) })
//     -> { spaceId }                                  // head starts null
//   query    spaces:get({ spaceId })                  -> the Space doc
//   query    spaces:listByAccount({ accountId })      -> Space[]
//   query    spaces:head({ spaceId })
//     -> { headRevisionId|null, seq|null, manifestRootCid|null, parent|null }
//
// spaces:head is a QUERY so Convex's reactivity turns it into the change feed
// (format.md §8): a subscriber re-runs whenever headRevisionId — or the head
// Revision it points at — changes.
//
// All hashes (manifestRootCid, metaBlobCid) cross the wire as v.bytes()
// (ArrayBuffer <-> Vec<u8>), never v.string() (format.md §6.2, constraint 1).

import { v, ConvexError } from "convex/values";
import { mutation, query } from "./_generated/server";

// Create a Space with no head (the first Revision is committed later via
// revisions:commit). `name` and `metaBlobCid` are bytes; in the MVP `name` is
// cleartext UTF-8 and `metaBlobCid` points at the Space metadata blob in the
// Vault (chunk secret, etc.) — opaque to the Coordinator.
export const create = mutation({
  args: {
    accountId: v.id("accounts"),
    name: v.bytes(),
    metaBlobCid: v.bytes(),
  },
  returns: v.object({
    spaceId: v.id("spaces"),
  }),
  handler: async (ctx, args) => {
    const spaceId = await ctx.db.insert("spaces", {
      accountId: args.accountId,
      name: args.name,
      headRevisionId: null, // initial head = null (no Revision yet)
      metaBlobCid: args.metaBlobCid,
      retentionFloorSeq: 0, // MVP: GC off, floor at 0 (format.md §6.3)
    });
    return { spaceId };
  },
});

// Fetch the full Space document (including headRevisionId) by id.
export const get = query({
  args: {
    spaceId: v.id("spaces"),
  },
  handler: async (ctx, args) => {
    return await ctx.db.get(args.spaceId);
  },
});

// List every Space owned by an Account, via the by_account index.
export const listByAccount = query({
  args: {
    accountId: v.id("accounts"),
  },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("spaces")
      .withIndex("by_account", (q) => q.eq("accountId", args.accountId))
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
    const space = await ctx.db.get(args.spaceId);
    if (space === null || space.headRevisionId === null) {
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
    const space = await ctx.db.get(args.spaceId);
    if (space === null) {
      throw new ConvexError({ code: "space_not_found", message: "no such Space" });
    }

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
