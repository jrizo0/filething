// Tests for the Revision-chain rules in revisions.ts, driven through each
// handler with the in-memory ctx from testCtx.stub.ts.
// Run with `bun test packages/backend/convex`.

import assert from "node:assert/strict";
import { commit, listFromSeq } from "./revisions";
import {
  StubDb,
  codeThrownBy,
  handlerOf,
  runChecks,
  seedOwnedSpace,
  stubCtx,
} from "./testCtx.stub";

const SUBJECT = "better-auth|owner";

const commitRevision = handlerOf(commit);
const listRevisionsFromSeq = handlerOf(listFromSeq);

function ownedSpace() {
  const db = new StubDb();
  const ids = seedOwnedSpace(db, SUBJECT);
  return { db, ...ids, ctx: stubCtx(db, SUBJECT) };
}

// ----- commit: manifestRootCid must be a 32-byte Cid -----

// v.bytes() takes any length, and the Revision that stores a short root can
// never be replaced — the Space is wedged for good.
async function committing_a_manifest_root_that_is_not_32_bytes_is_rejected() {
  for (const byteLength of [0, 31, 33, 64]) {
    const { ctx, spaceId, deviceId } = ownedSpace();
    const code = await codeThrownBy(() =>
      commitRevision(ctx, {
        spaceId,
        expectedBaseRevisionId: null,
        manifestRootCid: new ArrayBuffer(byteLength),
        authorDeviceId: deviceId,
      }),
    );
    assert.equal(code, "bad_manifest_root_cid", `byteLength ${byteLength}`);
  }
}

// The rejection must not be mistakable for the CAS conflict of §7: the Rust
// client classifies any error whose MESSAGE contains "conflict" as a commit
// conflict and would keep retrying a deterministic failure.
async function the_rejection_is_not_mistakable_for_a_commit_conflict() {
  const { ctx, spaceId, deviceId } = ownedSpace();
  let message = "";
  try {
    await commitRevision(ctx, {
      spaceId,
      expectedBaseRevisionId: null,
      manifestRootCid: new ArrayBuffer(31),
      authorDeviceId: deviceId,
    });
  } catch (error) {
    message = String((error as { message?: unknown }).message ?? error);
  }
  assert.ok(!message.toLowerCase().includes("conflict"), `message was: ${message}`);
}

async function committing_a_32_byte_manifest_root_still_advances_the_head() {
  const { ctx, db, spaceId, deviceId } = ownedSpace();
  const result = await commitRevision(ctx, {
    spaceId,
    expectedBaseRevisionId: null,
    manifestRootCid: new ArrayBuffer(32),
    authorDeviceId: deviceId,
  });
  assert.equal(result.seq, 0);
  assert.equal((await db.get(spaceId))?.headRevisionId, result.revisionId);
}

// ----- listFromSeq: complete or nothing -----

function seedRevisions(db: StubDb, spaceId: string, count: number) {
  for (let seq = 0; seq < count; seq++) {
    db.insertRow("revisions", {
      spaceId,
      parent: null,
      seq,
      manifestRootCid: new ArrayBuffer(32),
      authorDeviceId: "devices:1",
      createdAt: 0,
    });
  }
}

// The GC reads this list as the complete reachable set, so a silently truncated
// answer makes it sweep live objects. It must throw instead.
async function a_window_holding_more_revisions_than_the_bound_throws_instead_of_truncating() {
  const { ctx, db, spaceId } = ownedSpace();
  seedRevisions(db, spaceId, 4097);
  const code = await codeThrownBy(() => listRevisionsFromSeq(ctx, { spaceId, minSeq: 0 }));
  assert.equal(code, "too_many_revisions");
}

async function a_window_at_exactly_the_bound_is_returned_whole() {
  const { ctx, db, spaceId } = ownedSpace();
  seedRevisions(db, spaceId, 4096);
  const rows = await listRevisionsFromSeq(ctx, { spaceId, minSeq: 0 });
  assert.equal(rows.length, 4096);
}

// maxSeq is what lets a caller split a chain that would otherwise trip the bound
// into windows it knows are small enough.
async function maxSeq_bounds_the_window_so_a_long_chain_can_be_walked_in_pieces() {
  const { ctx, db, spaceId } = ownedSpace();
  seedRevisions(db, spaceId, 5000);
  const first = await listRevisionsFromSeq(ctx, { spaceId, minSeq: 0, maxSeq: 2499 });
  const second = await listRevisionsFromSeq(ctx, { spaceId, minSeq: 2500, maxSeq: 4999 });
  assert.equal(first.length, 2500);
  assert.equal(second.length, 2500);
  assert.equal(first[0]?.seq, 0);
  assert.equal(second[0]?.seq, 2500);
}

async function minSeq_still_drops_everything_below_the_retention_floor() {
  const { ctx, db, spaceId } = ownedSpace();
  seedRevisions(db, spaceId, 10);
  const rows = await listRevisionsFromSeq(ctx, { spaceId, minSeq: 7 });
  assert.deepEqual(
    rows.map((row) => row.seq),
    [7, 8, 9],
  );
}

// A caller of another Account must not learn the retained set of this Space.
async function listing_a_space_the_caller_does_not_own_is_forbidden() {
  const { db, spaceId } = ownedSpace();
  seedRevisions(db, spaceId, 3);
  db.insertRow("accounts", {
    subject: "better-auth|stranger",
    name: new ArrayBuffer(4),
    createdAt: 0,
  });
  const code = await codeThrownBy(() =>
    listRevisionsFromSeq(stubCtx(db, "better-auth|stranger"), { spaceId, minSeq: 0 }),
  );
  assert.equal(code, "forbidden");
}

await runChecks([
  committing_a_manifest_root_that_is_not_32_bytes_is_rejected,
  the_rejection_is_not_mistakable_for_a_commit_conflict,
  committing_a_32_byte_manifest_root_still_advances_the_head,
  a_window_holding_more_revisions_than_the_bound_throws_instead_of_truncating,
  a_window_at_exactly_the_bound_is_returned_whole,
  maxSeq_bounds_the_window_so_a_long_chain_can_be_walked_in_pieces,
  minSeq_still_drops_everything_below_the_retention_floor,
  listing_a_space_the_caller_does_not_own_is_forbidden,
]);
