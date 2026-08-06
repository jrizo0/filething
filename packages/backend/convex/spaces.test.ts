// Tests for the Space-creation argument rules in spaces.ts, driven through the
// handler with the in-memory ctx from testCtx.stub.ts.
// Run with `bun test packages/backend/convex`.

import assert from "node:assert/strict";
import { create } from "./spaces";
import { StubDb, codeThrownBy, handlerOf, runChecks, stubCtx } from "./testCtx.stub";

const SUBJECT = "better-auth|owner";

const createSpace = handlerOf(create);

function accountCtx() {
  const db = new StubDb();
  db.insertRow("accounts", {
    subject: SUBJECT,
    name: new ArrayBuffer(4),
    createdAt: 0,
  });
  return { db, ctx: stubCtx(db, SUBJECT) };
}

function args(overrides: { metaBlobCid?: ArrayBuffer; spaceKey?: ArrayBuffer } = {}) {
  return {
    name: new TextEncoder().encode("notes").buffer as ArrayBuffer,
    metaBlobCid: overrides.metaBlobCid ?? new ArrayBuffer(32),
    spaceKey: overrides.spaceKey ?? new ArrayBuffer(32),
  };
}

// metaBlobCid is written once, at creation: a wrong length is unfixable later.
async function creating_a_space_with_a_meta_blob_cid_that_is_not_32_bytes_is_rejected() {
  for (const byteLength of [0, 31, 33, 64]) {
    const { ctx } = accountCtx();
    const code = await codeThrownBy(() =>
      createSpace(ctx, args({ metaBlobCid: new ArrayBuffer(byteLength) })),
    );
    assert.equal(code, "bad_meta_blob_cid", `byteLength ${byteLength}`);
  }
}

async function creating_a_space_with_a_space_key_that_is_not_32_bytes_is_rejected() {
  const { ctx } = accountCtx();
  const code = await codeThrownBy(() => createSpace(ctx, args({ spaceKey: new ArrayBuffer(16) })));
  assert.equal(code, "bad_space_key");
}

async function creating_a_space_with_32_byte_escrow_material_succeeds() {
  const { ctx, db } = accountCtx();
  const { spaceId } = await createSpace(ctx, args());
  const space = await db.get(spaceId);
  assert.equal(space?.headRevisionId, null);
  assert.equal((space?.metaBlobCid as ArrayBuffer).byteLength, 32);
}

await runChecks([
  creating_a_space_with_a_meta_blob_cid_that_is_not_32_bytes_is_rejected,
  creating_a_space_with_a_space_key_that_is_not_32_bytes_is_rejected,
  creating_a_space_with_32_byte_escrow_material_succeeds,
]);
