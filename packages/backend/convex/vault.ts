"use node";

// vault — pre-signed S3/R2 URLs for the Vault (data plane), so the Rust client
// never holds S3 credentials (ADR pending: 0016).
//
// Context (docs/format.md §6.1/§6.2, ADR 0007/0012): the Coordinator is the
// control plane — it only stores tiny pointers (Space head, Revision chain,
// manifest metadata). The Vault is the data plane: content-addressed Blocks,
// Manifest pages and per-Space escrow blobs, keyed by `blocks/`, `manifest/`,
// `blocklist/`, `meta/` and `keys/<space>/` prefixes. Until now the CLI talked
// to the Vault (Cloudflare R2 / any S3-compatible store) directly with static
// S3 credentials baked into its own env — fine for a self-hosted operator, but
// wrong for a managed Coordinator serving end users we don't want holding
// bucket-wide keys. `vault:sign` closes that gap: the Coordinator holds the
// one S3 credential (server-side env, never shipped to a client) and hands out
// short-lived, single-object, single-verb pre-signed URLs instead.
//
// Threat model: a pre-signed URL is only as safe as the key it points at.
//   - `blocks/`, `manifest/`, `blocklist/`, `meta/` keys are content-addressed
//     (a 32-byte cid keyed by the per-Account dedup secret, ADR 0003) and fan
//     out into a 2-hex-char shard equal to the cid's own first byte — nobody
//     can forge or guess one without the secret AND the bytes, and the content
//     behind it is opaque ciphertext once a Space enables alg=1 (format.md
//     §6.2). We still gate the fan-out shard against the cid to reject
//     typo'd/foreign keys early.
//   - `keys/<space_id>/` keys hold per-Space escrow material (dedup/meta
//     secrets). Unlike content-addressed keys these are guessable-ish (a
//     Space id is not a secret), so this is the one prefix that needs an
//     explicit ownership check: we require the caller's Account to own the
//     Space before signing anything under it.
//   - `list` and `delete` are deliberately NOT signable here: they are
//     account-wide, destructive-adjacent operations reserved for the GC
//     (docs/adr/0012), which still runs with direct S3 credentials as a
//     trusted operator job, never as a per-request grant to a client.
//
// Contract (mirrored in the Rust client):
//   action vault:sign({ ops: [{ key, method: "HEAD"|"GET"|"PUT" }, ...] })
//     -> [{ key, method, url }, ...]   // same order as `ops`, 15 min TTL
//
// Batched (up to 256 ops/call) so a sync round can fetch every URL it needs
// for a Revision's Blocks + Manifest pages in one round-trip instead of one
// action call per object.

import { S3Client, HeadObjectCommand, GetObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { v, ConvexError } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";

const MAX_OPS = 256;
const URL_TTL_SECONDS = 900; // 15 minutes

// Content-addressed prefixes: <prefix>/<aa>/<64 hex sha256>, where <aa> is the
// same two hex chars as the hash's first byte (the storage fan-out shard).
const CONTENT_ADDRESSED_KEY = /^(blocks|manifest|blocklist|meta)\/([0-9a-f]{2})\/([0-9a-f]{64})$/;

// Per-Space escrow prefix: keys/<space_id>/<aa>/<64 hex>, fan-out gated the
// same way. <space_id> is opaque here (checked against ownership below, not
// against the Convex "spaces" id format) because normalizeId is what actually
// validates it.
const SPACE_ESCROW_KEY = /^keys\/([a-z0-9]{16,64})\/([0-9a-f]{2})\/([0-9a-f]{64})$/;

function badKey(key: string): never {
  throw new ConvexError({
    code: "bad_key",
    message: `not a valid Vault key: ${key}`,
  });
}

// Parse and validate a single Vault key, returning the owning space_id when
// the key is under keys/ (null for content-addressed keys, which need no
// ownership check beyond the shape itself).
function parseKey(key: string): { spaceId: string | null } {
  const contentMatch = CONTENT_ADDRESSED_KEY.exec(key);
  if (contentMatch !== null) {
    const [, , shard, hash] = contentMatch;
    if (shard !== hash.slice(0, 2)) badKey(key);
    return { spaceId: null };
  }

  const escrowMatch = SPACE_ESCROW_KEY.exec(key);
  if (escrowMatch !== null) {
    const [, spaceId, shard, hash] = escrowMatch;
    if (shard !== hash.slice(0, 2)) badKey(key);
    return { spaceId };
  }

  return badKey(key);
}

function s3ClientFromEnv(): { client: S3Client; bucket: string } {
  const endpoint = process.env.S3_ENDPOINT;
  const region = process.env.S3_REGION;
  const accessKeyId = process.env.S3_ACCESS_KEY;
  const secretAccessKey = process.env.S3_SECRET_KEY;
  const bucket = process.env.S3_BUCKET;
  if (
    endpoint === undefined ||
    region === undefined ||
    accessKeyId === undefined ||
    secretAccessKey === undefined ||
    bucket === undefined
  ) {
    throw new ConvexError({
      code: "storage_unconfigured",
      message:
        "the Vault is not configured on this Coordinator deployment; the operator must " +
        "run `convex env set S3_ENDPOINT/S3_REGION/S3_ACCESS_KEY/S3_SECRET_KEY/S3_BUCKET`",
    });
  }
  const client = new S3Client({
    endpoint,
    region,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true, // R2 / MinIO / any non-AWS S3-compatible endpoint
  });
  return { client, bucket };
}

export const sign = action({
  args: {
    ops: v.array(
      v.object({
        key: v.string(),
        method: v.union(v.literal("HEAD"), v.literal("GET"), v.literal("PUT")),
      }),
    ),
  },
  returns: v.array(
    v.object({
      key: v.string(),
      method: v.string(),
      url: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    if (args.ops.length < 1 || args.ops.length > MAX_OPS) {
      throw new ConvexError({
        code: "bad_request",
        message: `ops must have between 1 and ${MAX_OPS} entries`,
      });
    }

    const { accountId } = await ctx.runQuery(internal.auth.callerAccount, {});

    const parsed = args.ops.map((op) => ({ ...op, ...parseKey(op.key) }));

    const spaceIds = [
      ...new Set(
        parsed
          .map((op) => op.spaceId)
          .filter((spaceId): spaceId is string => spaceId !== null),
      ),
    ];
    if (spaceIds.length > 0) {
      await ctx.runQuery(internal.auth.assertOwnedSpaces, { accountId, spaceIds });
    }

    const { client, bucket } = s3ClientFromEnv();

    // The AWS SDK (command construction + getSignedUrl) can throw plain Errors:
    // an unreachable/misconfigured endpoint, a signing/credential fault, clock
    // skew, etc. Convex redacts any non-ConvexError to an opaque "Server Error"
    // on the client, which is exactly the unactionable message the Rust client
    // used to surface. Wrap them into a typed ConvexError so the client maps it
    // to CoordinatorError::VaultUnavailable (a real ConvexError is re-thrown
    // untouched so its own code survives).
    const results = [];
    try {
      for (const op of parsed) {
        const commandInput = { Bucket: bucket, Key: op.key };
        const command =
          op.method === "HEAD"
            ? new HeadObjectCommand(commandInput)
            : op.method === "GET"
              ? new GetObjectCommand(commandInput)
              : new PutObjectCommand(commandInput);
        const url = await getSignedUrl(client, command, { expiresIn: URL_TTL_SECONDS });
        results.push({ key: op.key, method: op.method, url });
      }
    } catch (err) {
      if (err instanceof ConvexError) throw err;
      throw new ConvexError({
        code: "vault_unavailable",
        message: `failed to pre-sign a Vault URL: ${
          err instanceof Error ? err.message : String(err)
        }`,
      });
    }
    return results;
  },
});
