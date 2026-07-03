// migrations — one-off operator-run mutations for upgrading pre-existing data
// across auth-model changes. Not reachable by any client; every export here
// is an internalMutation, runnable only with the deploy key:
//   npx convex run migrations:claimAccount '{"oldSubject": "...", "newSubject": "..."}'
//
// Context (docs/PRODUCTION-SETUP.md, "Upgrade desde Fase 2"): pre-Better-Auth
// Accounts are keyed by a pairing-era `subject` string. After the Better Auth
// upgrade the real owner logs in and auth:ensureDevice get-or-creates an
// Account keyed by the Better Auth JWT `sub` — a DIFFERENT string — so it
// creates a brand-new, empty Account instead of finding the old one. Every
// Space owned by the old Account then fails requireOwnedSpace forever: it is
// permanently orphaned. claimAccount re-points the OLD Account row's
// `subject` to the NEW Better Auth subject so its Spaces (and Devices) become
// reachable again under the real login.
//
// The stand-in Account created by that first post-upgrade login is NOT
// device-empty in practice: `filething login --signup` always calls
// ensureDevice, which get-or-creates a Device on the SAME call (apps/cli/src/
// commands.rs `login()`, step 3). If the owner reuses the same machine (the
// default Device name is the hostname — `default_device_name()`), that Device
// row's `name` collides with the Device the old Account already had. The CLI
// persists the Device id it gets back into config.json (`device_id`, apps/cli/
// src/config.rs `set_identity`) and every later command reads it back
// (`require_identity` in apps/cli/src/commands.rs) instead of re-resolving by
// name — so the row the LOCAL CLI now references must be the one that
// survives; see the per-Device handling below.

import { v, ConvexError } from "convex/values";
import { internalMutation } from "./_generated/server";
import type { Doc, Id } from "./_generated/dataModel";

export const claimAccount = internalMutation({
  args: {
    // The Account row to reclaim, identified by its CURRENT (pairing-era)
    // subject — this is what predates Better Auth and is otherwise unreachable.
    oldSubject: v.string(),
    // The Better Auth `sub` claim the real owner now logs in with (read it
    // off the Account Convex created via ensureDevice after the first
    // post-upgrade login, e.g. from the dashboard's accounts table).
    newSubject: v.string(),
  },
  returns: v.object({
    accountId: v.id("accounts"),
    // Set when a stand-in Account already existed at newSubject (created by
    // the post-upgrade ensureDevice call) and was discarded.
    deletedStandInAccountId: v.union(v.id("accounts"), v.null()),
    // Stand-in Devices moved onto the reclaimed (old) Account. These keep
    // their id — the local CLI that logged in already has it cached.
    reparentedDeviceIds: v.array(v.id("devices")),
    // Old Account Devices dropped because a stand-in Device of the same name
    // took their place (see the module comment). Only `baseSeqInUse` — a
    // scalar that only feeds the recomputable GC retention floor
    // (spaces:refreshRetentionFloor) — is lost; nothing else references these
    // rows once dropped (revisions.authorDeviceId is historical metadata,
    // never re-validated against a live Device).
    deletedDeviceIds: v.array(v.id("devices")),
  }),
  handler: async (ctx, args) => {
    if (args.oldSubject === args.newSubject) {
      throw new ConvexError({
        code: "noop",
        message: "oldSubject and newSubject are identical; nothing to claim",
      });
    }

    const oldAccount = await ctx.db
      .query("accounts")
      .withIndex("by_subject", (q) => q.eq("subject", args.oldSubject))
      .unique();
    if (oldAccount === null) {
      throw new ConvexError({
        code: "old_account_not_found",
        message: `no Account with subject "${args.oldSubject}"`,
      });
    }

    const newAccount = await ctx.db
      .query("accounts")
      .withIndex("by_subject", (q) => q.eq("subject", args.newSubject))
      .unique();

    let deletedStandInAccountId: Id<"accounts"> | null = null;
    let reparentedDeviceIds: Id<"devices">[] = [];
    let deletedDeviceIds: Id<"devices">[] = [];

    if (newAccount !== null) {
      // A stand-in Account already exists at the target subject — almost
      // certainly the one ensureDevice created on the owner's first
      // post-upgrade login. Spaces are real, ambiguous data: refuse rather
      // than silently combining two accounts' Spaces. Devices are expected
      // (see module comment) and handled below, never a reason to refuse.
      const newSpaces = await ctx.db
        .query("spaces")
        .withIndex("by_account", (q) => q.eq("accountId", newAccount._id))
        .collect();
      if (newSpaces.length > 0) {
        throw new ConvexError({
          code: "ambiguous_merge",
          message:
            `Account ${newAccount._id} (subject "${args.newSubject}") already owns ` +
            `${newSpaces.length} Space(s); refusing to silently merge it with the old ` +
            "Account. Resolve manually before retrying (e.g. move the new Account's " +
            "Spaces aside, or confirm they belong under the old Account and delete the " +
            "new Account's rows by hand).",
        });
      }

      const [newDevices, oldDevices] = await Promise.all([
        ctx.db
          .query("devices")
          .withIndex("by_account", (q) => q.eq("accountId", newAccount._id))
          .collect(),
        ctx.db
          .query("devices")
          .withIndex("by_account", (q) => q.eq("accountId", oldAccount._id))
          .collect(),
      ]);
      const oldDevicesByName = new Map<string, Doc<"devices">>(
        oldDevices.map((d) => [d.name, d]),
      );

      for (const newDevice of newDevices) {
        const collidingOld = oldDevicesByName.get(newDevice.name);
        if (collidingOld !== undefined) {
          // Same name on both sides: the LOCAL CLI already has `newDevice`'s
          // id cached (it just logged in), so that id must be the one that
          // keeps working — drop the old Account's same-name row instead.
          await ctx.db.delete(collidingOld._id);
          deletedDeviceIds.push(collidingOld._id);
        }
        await ctx.db.patch(newDevice._id, { accountId: oldAccount._id });
        reparentedDeviceIds.push(newDevice._id);
      }

      await ctx.db.delete(newAccount._id);
      deletedStandInAccountId = newAccount._id;
    }

    await ctx.db.patch(oldAccount._id, { subject: args.newSubject });
    return { accountId: oldAccount._id, deletedStandInAccountId, reparentedDeviceIds, deletedDeviceIds };
  },
});
