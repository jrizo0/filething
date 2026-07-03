// revisions — the linear Revision chain and the atomic commit CAS (Coordinator).
//
// Contract (BUILD-PLAN §3 ft-coordinator):
//   mutation revisions:commit({ spaceId, expectedBaseRevisionId|null,
//                               manifestRootCid (bytes), authorDeviceId })
//     -> { revisionId, seq }
//   query    revisions:bySeq({ spaceId, seq }) -> Revision
//
// CRITICAL (format.md §7 commit protocol): commit performs an ATOMIC
// compare-and-swap on the Space head. It reads the head INSIDE the transaction
// (it does NOT trust a stale client read); if the current head !=
// expectedBaseRevisionId it throws a DISTINGUISHABLE conflict error
// (ConvexError { code: "conflict" }) so the Rust client can branch on it. If the
// base matches, it inserts the Revision and patches the Space head. Convex
// mutations are serializable transactions (OCC with retry), so this
// read-then-write of the head is atomic.

import { v, ConvexError } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireAccount, requireOwnedSpace, requireOwnedDevice } from "./auth";

// Commit a new Revision iff the Space head still equals the expected base.
//
// Order guarantee from the client (§7): every Block and Manifest page is already
// in the Vault and verified BEFORE this mutation runs. The Coordinator only
// advances a tiny pointer here — it never sees bytes.
export const commit = mutation({
  args: {
    spaceId: v.id("spaces"),
    // The Revision the committing Device synced from (its base). null means the
    // Device expects the Space to still have NO head (first commit).
    expectedBaseRevisionId: v.union(v.id("revisions"), v.null()),
    manifestRootCid: v.bytes(), // 32B root of the Manifest B-tree in the Vault
    authorDeviceId: v.id("devices"),
  },
  returns: v.object({
    revisionId: v.id("revisions"),
    seq: v.number(),
  }),
  handler: async (ctx, args) => {
    // AUTHZ: the caller must own the Space AND the author Device. Reading the
    // Space here also serves as the in-txn head read (§7) below.
    const account = await requireAccount(ctx);
    const space = await requireOwnedSpace(ctx, account, args.spaceId);
    await requireOwnedDevice(ctx, account, args.authorDeviceId);

    // CAS: the current head MUST equal the base the client committed against.
    // Compared as strings because Convex Ids compare by value as strings, and
    // null === null handles the first-commit case.
    if (space.headRevisionId !== args.expectedBaseRevisionId) {
      throw new ConvexError({
        code: "conflict",
        message: "Space head moved since the expected base; reconcile and retry",
        // Surface the actual head so the client can pull it directly (§7, §10).
        currentHeadRevisionId: space.headRevisionId,
        expectedBaseRevisionId: args.expectedBaseRevisionId,
      });
    }

    // Next seq = head seq + 1, or 0 for the very first Revision.
    let seq = 0;
    if (space.headRevisionId !== null) {
      const baseRev = await ctx.db.get(space.headRevisionId);
      if (baseRev === null) {
        // Head points at a missing Revision: data-integrity fault, distinguishable.
        throw new ConvexError({
          code: "dangling_head",
          message: "Space head points at a missing Revision",
        });
      }
      seq = baseRev.seq + 1;
    }

    const revisionId = await ctx.db.insert("revisions", {
      spaceId: args.spaceId,
      parent: args.expectedBaseRevisionId, // ONE parent; linear chain (§6.2)
      seq,
      manifestRootCid: args.manifestRootCid,
      authorDeviceId: args.authorDeviceId,
      createdAt: Date.now(), // metadata only; NEVER used for conflict detection
    });

    // Advance the head atomically within this same serializable txn.
    await ctx.db.patch(args.spaceId, { headRevisionId: revisionId });

    return { revisionId, seq };
  },
});

// List every Revision at or above `minSeq` — the GC's "retained" set (§6.3,
// docs/adr/0007). Returns just the fields the sweeper needs (id + seq + the
// Manifest root it must keep reachable), newest last (by_space_seq is ascending).
// The GC unions the Manifest trees rooted at these `manifestRootCid`s; objects
// reachable from none of them (and older than the grace-period) are swept.
export const listFromSeq = query({
  args: {
    spaceId: v.id("spaces"),
    minSeq: v.number(),
  },
  returns: v.array(
    v.object({
      revisionId: v.id("revisions"),
      seq: v.number(),
      manifestRootCid: v.bytes(),
    }),
  ),
  handler: async (ctx, args) => {
    const account = await requireAccount(ctx);
    await requireOwnedSpace(ctx, account, args.spaceId);
    const rows = await ctx.db
      .query("revisions")
      .withIndex("by_space_seq", (q) =>
        q.eq("spaceId", args.spaceId).gte("seq", args.minSeq),
      )
      .collect();
    return rows.map((r) => ({
      revisionId: r._id,
      seq: r.seq,
      manifestRootCid: r.manifestRootCid,
    }));
  },
});

// Fetch a Revision by its (spaceId, seq) via the by_space_seq index.
export const bySeq = query({
  args: {
    spaceId: v.id("spaces"),
    seq: v.number(),
  },
  handler: async (ctx, args) => {
    const account = await requireAccount(ctx);
    await requireOwnedSpace(ctx, account, args.spaceId);
    return await ctx.db
      .query("revisions")
      .withIndex("by_space_seq", (q) =>
        q.eq("spaceId", args.spaceId).eq("seq", args.seq),
      )
      .unique();
  },
});
