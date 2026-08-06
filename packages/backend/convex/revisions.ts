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

// A Manifest root is a 32-byte Cid (schema.ts revisions.manifestRootCid).
const CID_BYTES = 32;

// Upper bound on the Revisions one listFromSeq call may return. Convex caps how
// much a single query may read, so an unbounded .collect() over a long chain
// throws an opaque runtime error; worse, any scheme that silently returned a
// SHORT list would be read by the GC as "nothing else is reachable" and it
// would sweep live objects (§6.3, docs/adr/0007). Bounded well under Convex's
// own read cap so exceeding it is our explicit, typed failure rather than the
// platform's.
const MAX_REVISIONS_PER_CALL = 4096;

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

    // v.bytes() accepts any length, and a stored root that is not a 32-byte Cid
    // wedges the Space permanently: every later read of it (spaces:head, the
    // client's Cid decode) fails on a Revision that can no longer be replaced.
    // Reject it at the only point where the chain is still healthy.
    if (args.manifestRootCid.byteLength !== CID_BYTES) {
      throw new ConvexError({
        code: "bad_manifest_root_cid",
        message: `manifestRootCid must be exactly ${CID_BYTES} bytes`,
      });
    }

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
//
// COMPLETE OR NOTHING: this is the mark phase of a destructive sweep, so a
// partial answer is worse than no answer. At most MAX_REVISIONS_PER_CALL rows
// come back; a window holding more throws `too_many_revisions` instead of
// truncating. `maxSeq` (inclusive) lets a caller walk a long chain in windows it
// knows are small enough — omit it for the whole tail, as the MVP GC does.
export const listFromSeq = query({
  args: {
    spaceId: v.id("spaces"),
    minSeq: v.number(),
    maxSeq: v.optional(v.number()),
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
    const maxSeq = args.maxSeq;
    const rows = await ctx.db
      .query("revisions")
      .withIndex("by_space_seq", (q) => {
        const from = q.eq("spaceId", args.spaceId).gte("seq", args.minSeq);
        return maxSeq === undefined ? from : from.lte("seq", maxSeq);
      })
      // One MORE than the bound: reading it is how we know the window was cut
      // short. Asking for exactly the bound cannot distinguish "complete" from
      // "truncated", which is the failure mode that loses live data.
      .take(MAX_REVISIONS_PER_CALL + 1);
    if (rows.length > MAX_REVISIONS_PER_CALL) {
      throw new ConvexError({
        code: "too_many_revisions",
        message:
          `more than ${MAX_REVISIONS_PER_CALL} Revisions at or above seq ${args.minSeq}; ` +
          "re-request in windows bounded by maxSeq",
        limit: MAX_REVISIONS_PER_CALL,
        minSeq: args.minSeq,
        maxSeq: maxSeq ?? null,
      });
    }
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
