// filething Coordinator schema — control plane (Convex).
//
// Normative source: docs/format.md §6.2. The Coordinator stores ONLY tiny
// documents: manifest metadata (paths/block references live in cleartext inside
// Manifest pages in the Vault, NOT here), the Space head pointer, the linear
// Revision chain, Device telemetry and the optional cross-Device dedup cache.
// It NEVER stores file bytes nor a self-hosted Vault's storage keys.
//
// Type discipline (constraint 1, zero-knowledge ready):
//   - Cid / Pcid / manifestRoot are 32-byte hashes -> v.bytes() (never v.string()).
//   - Semantic metadata that becomes ciphertext under zero-knowledge (e.g. a
//     Space name) is v.bytes() too, so the wire type does not change when we
//     flip encryption on. In the MVP these carry cleartext UTF-8.
//   - seq is a u64-monotonic counter per Space -> v.number().

import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  // accounts — a single person's identity. Owns Spaces and Devices.
  // Referenced by spaces.accountId / devices.accountId / dedup.accountId.
  // (v1: Spaces are personal — exactly one Account per Space.)
  accounts: defineTable({
    // Stable external identity (e.g. pairing/login subject). Cleartext in MVP.
    subject: v.string(),
    // Display name; v.bytes() so it can become ciphertext under zero-knowledge.
    name: v.bytes(),
    createdAt: v.number(),
  }).index("by_subject", ["subject"]),

  // spaces — one row per Space.
  spaces: defineTable({
    accountId: v.id("accounts"),
    name: v.bytes(), // semantic metadata. v.bytes() (not v.string()) so under
    //                  zero-knowledge it is ciphertext without changing the type.
    //                  MVP: cleartext UTF-8.
    headRevisionId: v.union(v.id("revisions"), v.null()), // THE Space head; CAS here
    metaBlobCid: v.bytes(), // -> Vault: chunk secret (+ future encryptable
    //                         material). Opaque to the Coordinator.
    retentionFloorSeq: v.number(), // min(seq) the GC must NOT sweep (§6.3). MVP: 0.
  }).index("by_account", ["accountId"]),

  // revisions — LINEAR chain, ONE parent (constraint 7).
  revisions: defineTable({
    spaceId: v.id("spaces"),
    parent: v.union(v.id("revisions"), v.null()), // ONE parent; null = first Revision
    seq: v.number(), // u64 monotonic per Space (linear order of the change feed)
    manifestRootCid: v.bytes(), // 32B -> root of the Manifest B-tree in the Vault
    authorDeviceId: v.id("devices"),
    createdAt: v.number(), // metadata; NEVER used for conflict detection
  })
    .index("by_space_seq", ["spaceId", "seq"])
    .index("by_parent", ["parent"]),

  // devices — for the retention floor and sync telemetry.
  devices: defineTable({
    accountId: v.id("accounts"),
    name: v.string(),
    baseSeqInUse: v.number(), // min(base_seq) this Device still uses as base (§6.3)
  }).index("by_account", ["accountId"]),

  // dedup — OPTIONAL cross-Device acceleration CACHE, strict ACCOUNT scope
  // (constraint 1). NOT a source of truth: the real dedup lives in the Device's
  // local index (§9) plus a HEAD blocks/<cid> against the Vault before upload.
  dedup: defineTable({
    accountId: v.id("accounts"),
    pcid: v.bytes(), // hash of the CLEARTEXT. In escrow the Coordinator sees it;
    //                  in zero-knowledge it is omitted or encrypted.
    cid: v.bytes(), // -> blocks/<cid>
  }).index("by_account_pcid", ["accountId", "pcid"]),

  // pairing_codes — MINIMAL device-pairing-by-code (decisions §0: "Auth =
  // pairing mínimo por código de dispositivo"; Better Auth / browser OAuth is a
  // reserved hole, post-MVP). auth:bootstrap mints a row that binds a code to an
  // Account; auth:claim consumes it to join a second Device to that Account.
  // The code is NON-cryptographic for the MVP (constraint: keep it simple).
  pairing_codes: defineTable({
    code: v.string(), // short human-typeable code; looked up on claim
    accountId: v.id("accounts"), // the Account a claimer joins
    createdAt: v.number(),
    claimedAt: v.union(v.number(), v.null()), // null = still claimable (single-use)
  }).index("by_code", ["code"]),
});
