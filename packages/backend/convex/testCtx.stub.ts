// A minimal in-memory stand-in for the Convex ctx a query/mutation handler
// receives, so the authorization + validation rules in spaces.ts / revisions.ts
// can be exercised with `bun test` without a deployment. Convex's bundler skips
// files whose basename holds more than one dot, so this never ships.
//
// It implements only what the handlers under test actually touch: ctx.auth,
// ctx.db.get/insert/patch and a `withIndex` query whose range builder
// accumulates eq/gte/lte predicates (rows come back sorted by `seq`, matching
// by_space_seq's ascending order).

import type { RegisteredMutation, RegisteredQuery } from "convex/server";
import type { Id } from "./_generated/dataModel";

type Row = Record<string, unknown> & { _id: string };

type Predicate = (row: Row) => boolean;

// Records the eq/gte/lte calls a handler makes on an index range builder.
function rangeBuilder(predicates: Predicate[]) {
  const builder = {
    eq(field: string, value: unknown) {
      predicates.push((row) => row[field] === value);
      return builder;
    },
    gte(field: string, value: number) {
      predicates.push((row) => (row[field] as number) >= value);
      return builder;
    },
    lte(field: string, value: number) {
      predicates.push((row) => (row[field] as number) <= value);
      return builder;
    },
  };
  return builder;
}

export class StubDb {
  readonly tables: Record<string, Row[]> = {};
  private nextId = 1;

  // Ids carry their table so `get` can resolve one without being told.
  insertRow(table: string, fields: Record<string, unknown>): string {
    const _id = `${table}:${this.nextId++}`;
    (this.tables[table] ??= []).push({ ...fields, _id });
    return _id;
  }

  async get(id: string): Promise<Row | null> {
    const table = id.slice(0, id.indexOf(":"));
    return (this.tables[table] ?? []).find((row) => row._id === id) ?? null;
  }

  async insert(table: string, fields: Record<string, unknown>): Promise<string> {
    return this.insertRow(table, fields);
  }

  async patch(id: string, fields: Record<string, unknown>): Promise<void> {
    const row = await this.get(id);
    if (row === null) throw new Error(`patch on missing row ${id}`);
    Object.assign(row, fields);
  }

  query(table: string) {
    const rowsOf = () => this.tables[table] ?? [];
    return {
      withIndex(_index: string, build: (q: ReturnType<typeof rangeBuilder>) => unknown) {
        const predicates: Predicate[] = [];
        build(rangeBuilder(predicates));
        const matched = rowsOf()
          .filter((row) => predicates.every((predicate) => predicate(row)))
          .sort((a, b) => ((a.seq as number) ?? 0) - ((b.seq as number) ?? 0));
        return {
          async unique() {
            return matched[0] ?? null;
          },
          async take(count: number) {
            return matched.slice(0, count);
          },
          async collect() {
            return matched;
          },
        };
      },
    };
  }
}

// A ctx whose caller is the identity `subject` (null = unauthenticated).
export function stubCtx(db: StubDb, subject: string | null) {
  return {
    db,
    auth: {
      async getUserIdentity() {
        return subject === null ? null : { subject };
      },
    },
  };
}

// `any` in these probe positions is deliberate: they only exist to pull the Args
// and Returns type parameters back out of a registered function's type.
type ArgsOf<F> =
  F extends RegisteredMutation<any, infer A, any>
    ? A
    : F extends RegisteredQuery<any, infer A, any>
      ? A
      : never;
type ReturnsOf<F> =
  F extends RegisteredMutation<any, any, infer R>
    ? R
    : F extends RegisteredQuery<any, any, infer R>
      ? R
      : never;

// Convex's registered query/mutation objects carry the raw handler on
// `_handler`, but the public Registered* types do not expose it. One narrow cast
// here keeps every call site clean and fully typed on args and result.
export function handlerOf<F>(registered: F): (ctx: unknown, args: ArgsOf<F>) => ReturnsOf<F> {
  return (registered as { _handler: (ctx: unknown, args: ArgsOf<F>) => ReturnsOf<F> })._handler;
}

// Seeds an Account + Space + Device owned by `subject` and hands back their ids.
// Ids are branded so handler args typecheck without casts at the call site.
export function seedOwnedSpace(db: StubDb, subject: string) {
  const accountId = db.insertRow("accounts", {
    subject,
    name: new ArrayBuffer(4),
    createdAt: 0,
  });
  const spaceId = db.insertRow("spaces", {
    accountId,
    name: new ArrayBuffer(4),
    headRevisionId: null,
    metaBlobCid: new ArrayBuffer(32),
    spaceKey: new ArrayBuffer(32),
    retentionFloorSeq: 0,
  });
  const deviceId = db.insertRow("devices", {
    accountId,
    name: "laptop",
    baseSeqInUse: 0,
  });
  return {
    accountId: accountId as Id<"accounts">,
    spaceId: spaceId as Id<"spaces">,
    deviceId: deviceId as Id<"devices">,
  };
}

// The ConvexError `code` a thrown value carries, or undefined for anything else.
// Every backend throw uses `{ code, message, ... }` as its data payload.
export function thrownCode(error: unknown): string | undefined {
  const data = (error as { data?: unknown }).data;
  if (typeof data !== "object" || data === null) return undefined;
  const code = (data as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

// Runs `body` and returns the ConvexError code it threw, or null if it returned.
export async function codeThrownBy(body: () => Promise<unknown>): Promise<string | null> {
  try {
    await body();
    return null;
  } catch (error) {
    return thrownCode(error) ?? `untyped: ${String(error)}`;
  }
}

// Runs each check in order and names it on stdout. `bun test` fails a file whose
// top level throws, which is the whole assertion mechanism here; registering
// with `bun:test` instead would need @types/bun, a dependency this package does
// not carry, so bun's own pass/fail counters stay at 0 and this log is the
// record of what actually ran.
export async function runChecks(checks: Array<() => unknown>): Promise<void> {
  for (const check of checks) {
    await check();
    console.log(`  ok  ${check.name}`);
  }
}
