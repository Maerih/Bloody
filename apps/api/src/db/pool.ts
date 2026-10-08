import pg from "pg";

/**
 * Database access.
 *
 *  - `app` pool: the non-superuser, RLS-enforced role `bloody_app`. EVERY request-path query
 *    runs through {@link Database.withTenant}, which opens a transaction and sets the
 *    transaction-local GUC `app.tenant_id`; Postgres row-level security then refuses any row of
 *    another tenant even if a query forgets its `tenant_id` predicate.
 *  - Pre-authentication lookups (login e-mail, API-key prefix → tenant) use
 *    {@link Database.withoutTenant} against the `auth_lookup` directory, the only table the
 *    runtime role can read without a tenant context (it holds digests only, no customer data).
 *  - `privileged` pool (superuser / schema owner): migrations, the development seed and test
 *    fixtures only. Request handlers never receive it.
 */

export type Queryable = Pick<pg.PoolClient, "query">;
export type Tx = pg.PoolClient;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class TenantContextError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TenantContextError";
  }
}

const builtins = pg.types;
/** pg-types' TypeId union omits array OIDs; the runtime accepts any OID. */
const builtinParser = builtins.getTypeParser as unknown as (oid: number, format?: "text" | "binary") => (v: string) => unknown;
const parseTimestamptz = builtinParser(1184, "text") as (v: string) => Date | string;
const parseTimestamp = builtinParser(1114, "text") as (v: string) => Date | string;

function toIso(v: Date | string): string {
  return v instanceof Date ? (Number.isNaN(v.getTime()) ? String(v) : v.toISOString()) : v;
}

/** Type parsers: bigint/numeric → number, timestamps → ISO-8601 strings (API wire format). */
export const typeParsers = {
  getTypeParser(oid: number, format?: "text" | "binary") {
    if (format === undefined || format === "text") {
      switch (oid) {
        case 20: // int8
          return (v: string) => Number(v);
        case 1700: // numeric
          return (v: string) => Number(v);
        case 1184: // timestamptz
          return (v: string) => toIso(parseTimestamptz(v));
        case 1114: // timestamp
          return (v: string) => toIso(parseTimestamp(v));
        case 1016: // int8[]
          return (v: string) => (builtinParser(1016, "text")(v) as Array<string | number | null>).map((x) => (x === null ? null : Number(x)));
        case 1185: // timestamptz[]
          return (v: string) => (builtinParser(1185, "text")(v) as Array<Date | string | null>).map((x) => (x === null ? null : toIso(x)));
        default:
          break;
      }
    }
    return builtinParser(oid, format ?? "text");
  },
};

export interface PoolOptions {
  connectionString: string;
  max?: number;
  statementTimeoutMs?: number;
  applicationName?: string;
}

export function createPool(opts: PoolOptions): pg.Pool {
  const pool = new pg.Pool({
    connectionString: opts.connectionString,
    max: opts.max ?? 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    application_name: opts.applicationName ?? "bloody-api",
    ...(opts.statementTimeoutMs ? { statement_timeout: opts.statementTimeoutMs } : {}),
    types: typeParsers as unknown as pg.CustomTypesConfig,
  });
  // An idle client error must not crash the process; the pool discards the client.
  pool.on("error", () => undefined);
  return pool;
}

export class Database {
  constructor(
    readonly app: pg.Pool,
    private readonly privilegedPool: pg.Pool | null = null,
  ) {}

  /**
   * Run `fn` inside a transaction bound to `tenantId` (SET LOCAL app.tenant_id). Rolls back on
   * error. This is the only way request handlers touch tenant data.
   */
  async withTenant<T>(tenantId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    if (typeof tenantId !== "string" || !UUID_RE.test(tenantId)) throw new TenantContextError("withTenant requires a tenant uuid");
    return this.transaction(this.app, async (tx) => {
      await tx.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId.toLowerCase()]);
      return fn(tx);
    });
  }

  /** Transaction WITHOUT a tenant context (RLS hides every tenant row): pre-auth directory lookups. */
  async withoutTenant<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.transaction(this.app, async (tx) => {
      await tx.query("SELECT set_config('app.tenant_id', '', true)");
      return fn(tx);
    });
  }

  /** Privileged path (migrations, dev seed, tests). Throws when no privileged pool was configured. */
  async withPrivileged<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    if (!this.privilegedPool) throw new TenantContextError("No privileged database connection configured");
    return this.transaction(this.privilegedPool, fn);
  }

  get hasPrivileged(): boolean {
    return this.privilegedPool !== null;
  }

  async ping(): Promise<void> {
    await this.app.query("SELECT 1");
  }

  async close(): Promise<void> {
    await this.app.end();
    if (this.privilegedPool && this.privilegedPool !== this.app) await this.privilegedPool.end();
  }

  private async transaction<T>(pool: pg.Pool, fn: (tx: Tx) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    let released = false;
    try {
      await client.query("BEGIN");
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // connection is broken: destroy it instead of returning it to the pool
        client.release(true);
        released = true;
      }
      throw err;
    } finally {
      if (!released) client.release();
    }
  }
}

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

/**
 * Run query thunks one after another. A pg client executes one query at a time, so queries
 * sharing a transaction must be sequenced explicitly (never `Promise.all` over one client).
 */
export async function inOrder<T extends readonly unknown[]>(thunks: { readonly [K in keyof T]: () => Promise<T[K]> }): Promise<T> {
  const out: unknown[] = [];
  for (const thunk of thunks as readonly (() => Promise<unknown>)[]) out.push(await thunk());
  return out as unknown as T;
}
