// Tests for the Vault key/verb rules in vault.ts. Pure: no ctx, no deployment.
// Run with `bun test packages/backend/convex`.

import assert from "node:assert/strict";
import { commandForOp, parseKey } from "./vault";
import { runChecks, thrownCode } from "./testCtx.stub";

const HASH = "ab".repeat(32); // 64 hex chars, first byte "ab"
const CONTENT_KEY = `blocks/ab/${HASH}`;
const ESCROW_KEY = `keys/kg2abc123def45678/ab/${HASH}`;

function precondition(method: "HEAD" | "GET" | "PUT"): unknown {
  const command = commandForOp("vault", { key: CONTENT_KEY, method });
  return (command.input as { IfNoneMatch?: unknown }).IfNoneMatch;
}

// ----- create-only PUT -----

// The bucket has no per-Account prefix, so a signed PUT that could overwrite is
// a signed PUT over another Account's object.
function a_signed_put_of_a_content_addressed_object_can_only_create_never_overwrite() {
  assert.equal(precondition("PUT"), "*");
}

function a_signed_put_of_a_per_space_escrow_object_is_also_create_only() {
  const command = commandForOp("vault", { key: ESCROW_KEY, method: "PUT" });
  assert.equal((command.input as { IfNoneMatch?: unknown }).IfNoneMatch, "*");
}

// A read must not carry a precondition: `If-None-Match: *` on GET/HEAD means
// "304 if it exists", i.e. it would break every read.
function a_signed_read_carries_no_precondition() {
  assert.equal(precondition("GET"), undefined);
  assert.equal(precondition("HEAD"), undefined);
}

function every_signed_command_targets_exactly_the_requested_bucket_and_key() {
  for (const method of ["HEAD", "GET", "PUT"] as const) {
    const input = commandForOp("vault", { key: CONTENT_KEY, method }).input as {
      Bucket?: string;
      Key?: string;
    };
    assert.equal(input.Bucket, "vault");
    assert.equal(input.Key, CONTENT_KEY);
  }
}

// ----- key parsing -----

function a_content_addressed_key_reports_no_owning_space() {
  assert.equal(parseKey(CONTENT_KEY).spaceId, null);
}

function a_per_space_escrow_key_reports_the_space_it_must_be_authorized_against() {
  assert.equal(parseKey(ESCROW_KEY).spaceId, "kg2abc123def45678");
}

function a_fanout_shard_that_disagrees_with_its_own_hash_is_rejected() {
  let code: string | undefined;
  try {
    parseKey(`blocks/cd/${HASH}`);
  } catch (error) {
    code = thrownCode(error);
  }
  assert.equal(code, "bad_key");
}

function keys_outside_the_signable_prefixes_are_rejected() {
  for (const key of ["", "blocks/ab", `secrets/ab/${HASH}`, `blocks/ab/${HASH}/x`]) {
    let code: string | undefined;
    try {
      parseKey(key);
    } catch (error) {
      code = thrownCode(error);
    }
    assert.equal(code, "bad_key", `expected bad_key for ${JSON.stringify(key)}`);
  }
}

await runChecks([
  a_signed_put_of_a_content_addressed_object_can_only_create_never_overwrite,
  a_signed_put_of_a_per_space_escrow_object_is_also_create_only,
  a_signed_read_carries_no_precondition,
  every_signed_command_targets_exactly_the_requested_bucket_and_key,
  a_content_addressed_key_reports_no_owning_space,
  a_per_space_escrow_key_reports_the_space_it_must_be_authorized_against,
  a_fanout_shard_that_disagrees_with_its_own_hash_is_rejected,
  keys_outside_the_signable_prefixes_are_rejected,
]);
