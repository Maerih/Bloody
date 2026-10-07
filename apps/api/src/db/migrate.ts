import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import pg from "pg";

/**
 * Raw-SQL migration runner.
 *
 *  - Migrations are `migrations/NNNN_name.sql`, applied in lexical order, each in its own
 *    transaction together with its `schema_migrations` row (all-or-nothing per file).
 *  - A sha256 checksum of every applied file is recorded; an edited, already-applied migration
 *    aborts the run (write a new migration instead).
 *  - A session advisory lock serializes concurrent runners (several API replicas starting).
 *  - Before migrating, the runtime role `bloody_app` is created when missing (requires
 *    CREATEROLE; managed deployments pre-create it). After migrating, privileges are re-applied
 *    idempotently and the runner verifies that every tenant table has FORCE ROW LEVEL SECURITY.
 */

export const APP_ROLE = "bloody_app";
const LOCK_KEY = 0x0b100d; // arbitrary, stable advisory-lock key for the runner

export interface MigrationFile {
  version: string;
  name: string;
  file: string;
  sql: string;
  checksum: string;
}

export interface MigrationResult {
  applied: string[];
  skipped: string[];
  roleCreated: boolean;
}

export interface MigrateOptions {
  connectionString: string;
  migrationsDir?: string;
  appRolePassword?: string;
  log?: (msg: string) => void;
}

export function defaultMigrationsDir(): string {
  if (process.env.MIGRATIONS_DIR) return path.resolve(process.env.MIGRATIONS_DIR);
  // src/db/migrate.ts and dist/db/migrate.js both sit two levels below the package root.
  return fileURLToPath(new URL("../../migrations/", import.meta.url));
}

export async function loadMigrations(dir: string): Promise<MigrationFile[]> {
  const entries = (await readdir(dir)).filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f)).sort();
  const out: MigrationFile[] = [];
  const seen = new Set<string>();
  for (const file of entries) {
    const version = file.slice(0, 4);
    if (seen.has(version)) throw new Error(`Duplicate migration version ${version}`);
    seen.add(version);
    const sql = await readFile(path.join(dir, file), "utf8");
    out.push({ version, name: file.slice(5, -4), file, sql, checksum: createHash("sha256").update(sql, "utf8").digest("hex") });
  }
  return out;
}

async function ensureMigrationsTable(client: pg.ClientBase): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version      text PRIMARY KEY,
      name         text NOT NULL,
      checksum     text NOT NULL,
      applied_at   timestamptz NOT NULL DEFAULT now(),
      execution_ms integer NOT NULL
    )`);
}

/** Create the runtime role when missing (needs CREATEROLE). Returns true when created. */
export async function ensureAppRole(client: pg.ClientBase, password: string, log: (m: string) => void = () => undefined): Promise<boolean> {
  const exists = await client.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [APP_ROLE]);
  const me = await client.query<{ rolsuper: boolean; rolcreaterole: boolean }>("SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user");
  const privileged = me.rows[0]?.rolsuper === true || me.rows[0]?.rolcreaterole === true;
  if (exists.rowCount === 0) {
    if (!privileged) {
      log(`role ${APP_ROLE} does not exist and the migration user cannot create roles — create it out of band`);
      return false;
    }
    // Password literal: escaped through format(%L) server-side, never string-concatenated here.
    const { rows } = await client.query<{ stmt: string }>(
      "SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD %L', $1::text, $2::text) AS stmt",
      [APP_ROLE, password],
    );
    await client.query(rows[0]!.stmt);
    log(`created role ${APP_ROLE}`);
    return true;
  }
  if (me.rows[0]?.rolsuper) {
    // Guard against a misconfigured runtime role silently bypassing RLS.
    await client.query(`ALTER ROLE ${APP_ROLE} NOSUPERUSER NOBYPASSRLS`);
  }
  return false;
}

/** Idempotent least-privilege grants for the runtime role. */
export async function applyGrants(client: pg.ClientBase): Promise<void> {
  const role = await client.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [APP_ROLE]);
  if (role.rowCount === 0) return;
  await client.query(`GRANT USAGE ON SCHEMA public TO ${APP_ROLE}`);
  const { rows: tables } = await client.query<{ relname: string; relispartition: boolean }>(`
    SELECT c.relname, c.relispartition
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')`);
  for (const t of tables) {
    const ident = pgIdent(t.relname);
    if (t.relispartition) {
      // Partitions are reached only through their (RLS-protected) parent.
      await client.query(`REVOKE ALL ON TABLE ${ident} FROM ${APP_ROLE}`);
      continue;
    }
    switch (t.relname) {
      case "audit_log":
        await client.query(`GRANT SELECT, INSERT ON TABLE ${ident} TO ${APP_ROLE}`);
        await client.query(`REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE ${ident} FROM ${APP_ROLE}`);
        break;
      case "auth_lookup":
      case "schema_migrations":
        await client.query(`GRANT SELECT ON TABLE ${ident} TO ${APP_ROLE}`);
        await client.query(`REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE ${ident} FROM ${APP_ROLE}`);
        break;
      default:
        await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ${ident} TO ${APP_ROLE}`);
        await client.query(`REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE ${ident} FROM ${APP_ROLE}`);
    }
  }
  await client.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${APP_ROLE}`);
  await client.query(`GRANT EXECUTE ON FUNCTION ensure_events_partition(timestamptz) TO ${APP_ROLE}`);
}

/** Every table carrying tenant_id must have ENABLE + FORCE row level security. */
export async function verifyRowLevelSecurity(client: pg.ClientBase): Promise<void> {
  const { rows } = await client.query<{ relname: string }>(`
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> 'auth_lookup'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
      AND NOT (c.relrowsecurity AND c.relforcerowsecurity)`);
  if (rows.length > 0) throw new Error(`Row level security missing on tenant tables: ${rows.map((r) => r.relname).join(", ")}`);
}

function pgIdent(name: string): string {
  if (!/^[a-z_][a-z0-9_]*$/.test(name)) throw new Error(`Unexpected identifier ${name}`);
  return `"${name}"`;
}

export async function migrate(opts: MigrateOptions): Promise<MigrationResult> {
  const log = opts.log ?? (() => undefined);
  const migrations = await loadMigrations(opts.migrationsDir ?? defaultMigrationsDir());
  const client = new pg.Client({ connectionString: opts.connectionString, application_name: "bloody-migrate" });
  await client.connect();
  const result: MigrationResult = { applied: [], skipped: [], roleCreated: false };
  try {
    await client.query("SELECT pg_advisory_lock($1)", [LOCK_KEY]);
    try {
      result.roleCreated = await ensureAppRole(client, opts.appRolePassword ?? "bloody_app", log);
      await ensureMigrationsTable(client);
      const { rows } = await client.query<{ version: string; checksum: string; name: string }>("SELECT version, checksum, name FROM schema_migrations");
      const applied = new Map(rows.map((r) => [r.version, r]));
      for (const m of migrations) {
        const prior = applied.get(m.version);
        if (prior) {
          if (prior.checksum !== m.checksum) {
            throw new Error(`Migration ${m.file} was modified after it was applied (checksum ${prior.checksum.slice(0, 12)}… ≠ ${m.checksum.slice(0, 12)}…). Add a new migration instead.`);
          }
          result.skipped.push(m.file);
          continue;
        }
        const started = Date.now();
        await client.query("BEGIN");
        try {
          await client.query(m.sql);
          await client.query("INSERT INTO schema_migrations (version, name, checksum, execution_ms) VALUES ($1, $2, $3, $4)", [m.version, m.name, m.checksum, Date.now() - started]);
          await client.query("COMMIT");
        } catch (err) {
          await client.query("ROLLBACK");
          const msg = err instanceof Error ? err.message : String(err);
          throw new Error(`Migration ${m.file} failed: ${msg}`);
        }
        result.applied.push(m.file);
        log(`applied ${m.file} (${Date.now() - started} ms)`);
      }
      for (const v of applied.keys()) {
        if (!migrations.some((m) => m.version === v)) log(`warning: migration ${v} is recorded in schema_migrations but its file is missing`);
      }
      await applyGrants(client);
      await verifyRowLevelSecurity(client);
    } finally {
      await client.query("SELECT pg_advisory_unlock($1)", [LOCK_KEY]);
    }
  } finally {
    await client.end();
  }
  return result;
}

/** Applied / pending status without changing anything. */
export async function migrationStatus(connectionString: string, migrationsDir = defaultMigrationsDir()): Promise<Array<{ file: string; state: "applied" | "pending" | "modified" }>> {
  const migrations = await loadMigrations(migrationsDir);
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    const exists = await client.query("SELECT to_regclass('public.schema_migrations') IS NOT NULL AS ok");
    const applied = new Map<string, string>();
    if (exists.rows[0]?.ok) {
      const { rows } = await client.query<{ version: string; checksum: string }>("SELECT version, checksum FROM schema_migrations");
      for (const r of rows) applied.set(r.version, r.checksum);
    }
    return migrations.map((m) => ({ file: m.file, state: !applied.has(m.version) ? "pending" : applied.get(m.version) === m.checksum ? "applied" : "modified" }));
  } finally {
    await client.end();
  }
}

async function main(): Promise<void> {
  const { loadConfig } = await import("../config.js");
  const config = loadConfig();
  const redacted = (() => {
    const u = new URL(config.database.privilegedUrl);
    if (u.password) u.password = "***";
    return u.toString();
  })();
  if (process.argv.includes("--status")) {
    for (const s of await migrationStatus(config.database.privilegedUrl)) console.log(`${s.state.padEnd(8)} ${s.file}`);
    return;
  }
  console.log(`bloody migrate → ${redacted}`);
  const result = await migrate({ connectionString: config.database.privilegedUrl, appRolePassword: config.database.appPassword, log: (m) => console.log(`  ${m}`) });
  console.log(`done: ${result.applied.length} applied, ${result.skipped.length} already up to date${result.roleCreated ? ", runtime role created" : ""}`);
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
