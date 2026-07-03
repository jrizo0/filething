// devices — Device telemetry for the GC retention floor (Coordinator).
//
// Contract (BUILD-PLAN §3 ft-coordinator):
//   mutation devices:setBaseSeq({ deviceId, baseSeqInUse }) -> null
//
// A Device reports the lowest Revision seq it still uses as a sync base
// (format.md §6.3). The GC's retention floor is min(baseSeqInUse) over live
// Devices: objects reachable from Revisions with seq >= retentionFloorSeq must
// never be swept, so an offline Device can still diff and detect conflicts
// against its base. GC itself is post-MVP; this keeps the floor input fresh.

import { v } from "convex/values";
import { mutation } from "./_generated/server";
import { requireAccount, requireOwnedDevice } from "./auth";

export const setBaseSeq = mutation({
  args: {
    deviceId: v.id("devices"),
    baseSeqInUse: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    // Only the owning Account may move its own Device's retention base.
    const account = await requireAccount(ctx);
    await requireOwnedDevice(ctx, account, args.deviceId);
    await ctx.db.patch(args.deviceId, { baseSeqInUse: args.baseSeqInUse });
    return null;
  },
});
