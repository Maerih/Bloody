import { randomBytes } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type pg from "pg";
import { hashPassword, verifyPassword } from "../security/passwords.js";

/** The password every demo login is seeded with (seed-dev.ts) — publicly known. */
export const DEMO_PASSWORD = "ChangeMe!123";

/**
 * Operator CLI for real (non-demo) installs: create the first account and its administrator, or
 * reset an administrator's password. Runs on the privileged (migration) connection.
 *
 *   pnpm admin create-account --name "Acme SOC" --email admin@acme.example [--kind mssp|enterprise]
 *   pnpm admin reset-password --email admin@acme.example
 *   pnpm admin status
 *
 * Passwords are generated (never taken from the command line, which would land in shell history)
 * and printed once.
 */

export function generatePassword(): string {
  // 20 characters from an unambiguous alphabet, plus the classes the password policy expects.
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = randomBytes(20);
  const body = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
  return `${body.slice(0, 10)}-${body.slice(10)}!7`;
}

const slugify = (name: string) =>
  name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 50) || "account";

export interface CreatedAccount {
  tenantId: string;
  email: string;
  password: string | null;
  created: boolean;
}

/** Create an account with its first administrator. Idempotent: an existing user keeps its password. */
export async function createAccountWithAdmin(
  pool: pg.Pool,
  input: { name: string; email: string; kind?: "mssp" | "enterprise"; displayName?: string },
): Promise<CreatedAccount> {
  const email = input.email.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error(`invalid email "${input.email}"`);
  const name = input.name.trim();
  if (name.length < 2 || name.length > 200) throw new Error("--name must be 2-200 characters");
  const kind = input.kind ?? "mssp";
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const existing = await client.query<{ tenant_id: string }>("SELECT tenant_id FROM users WHERE lower(email) = $1 LIMIT 1", [email]);
    if (existing.rows[0]) {
      await client.query("ROLLBACK");
      return { tenantId: existing.rows[0].tenant_id, email, password: null, created: false };
    }
    const slugBase = slugify(name);
    const taken = await client.query<{ slug: string }>("SELECT slug FROM accounts WHERE slug LIKE $1 || '%'", [slugBase]);
    const used = new Set(taken.rows.map((r) => r.slug));
    let slug = slugBase;
    for (let i = 2; used.has(slug); i++) slug = `${slugBase}-${i}`;
    const acc = await client.query<{ id: string }>("INSERT INTO accounts (name, slug, kind, plan) VALUES ($1, $2, $3, $4) RETURNING id", [
      name,
      slug,
      kind,
      kind === "mssp" ? "mssp" : "enterprise",
    ]);
    const tenantId = acc.rows[0]!.id;
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    if (kind === "enterprise") {
      // A company runs its own SOC: one organization for its own estate.
      await client.query("INSERT INTO organizations (tenant_id, name, slug, retention_days) VALUES ($1, $2, $3, 90)", [tenantId, name, slugify(name).slice(0, 63)]);
    }
    const password = generatePassword();
    const user = await client.query<{ id: string }>(
      "INSERT INTO users (tenant_id, email, display_name, title, status) VALUES ($1, $2, $3, 'Administrator', 'active') RETURNING id",
      [tenantId, email, input.displayName ?? "Administrator"],
    );
    const uid = user.rows[0]!.id;
    await client.query("INSERT INTO user_credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)", [uid, tenantId, await hashPassword(password)]);
    await client.query("INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id) VALUES ($1, 'user', $2, 'mssp_admin', NULL)", [tenantId, uid]);
    await client.query("COMMIT");
    return { tenantId, email, password, created: true };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

/** Set a new generated password, unlock the user and revoke their sessions. */
export async function resetPassword(pool: pg.Pool, rawEmail: string): Promise<string> {
  const email = rawEmail.trim().toLowerCase();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ id: string; tenant_id: string }>("SELECT id, tenant_id FROM users WHERE lower(email) = $1", [email]);
    if (rows.length === 0) throw new Error(`no user with email ${email}`);
    if (rows.length > 1) throw new Error(`${email} exists in ${rows.length} accounts; reset it from the UI of the right account`);
    const u = rows[0]!;
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [u.tenant_id]);
    const password = generatePassword();
    await client.query(
      `INSERT INTO user_credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, password_changed_at = now()`,
      [u.id, u.tenant_id, await hashPassword(password)],
    );
    await client.query("UPDATE users SET failed_login_count = 0, locked_until = NULL, status = 'active' WHERE id = $1", [u.id]);
    await client.query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [u.id]);
    await client.query("COMMIT");
    return password;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

export async function accountSummary(pool: pg.Pool): Promise<{ accounts: number; users: number; demo: boolean; demoPasswordUsers: string[] }> {
  const { rows } = await pool.query<{ accounts: number; users: number; demo: boolean }>(
    `SELECT (SELECT count(*)::int FROM accounts) AS accounts, (SELECT count(*)::int FROM users) AS users,
            EXISTS (SELECT 1 FROM users WHERE lower(email) = 'admin@bloody.local') AS demo`,
  );
  // Active users who can still log in with the publicly known demo password (offline hash check:
  // no login attempt, so no lockout counters or audit noise).
  const creds = await pool.query<{ email: string; password_hash: string }>(
    `SELECT u.email, c.password_hash FROM users u JOIN user_credentials c ON c.user_id = u.id
     WHERE u.status = 'active' ORDER BY u.email LIMIT 500`,
  );
  const demoPasswordUsers: string[] = [];
  for (const c of creds.rows) if (await verifyPassword(c.password_hash, DEMO_PASSWORD).catch(() => false)) demoPasswordUsers.push(c.email);
  return { ...rows[0]!, demoPasswordUsers };
}

async function main(): Promise<void> {
  const { loadDotEnv } = await import("../env-file.js");
  loadDotEnv();
  const { loadConfig } = await import("../config.js");
  const { createPool } = await import("./pool.js");
  const config = loadConfig();
  const [command, ...rest] = process.argv.slice(2);
  const arg = (name: string) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const pool = createPool({ connectionString: config.database.privilegedUrl, max: 2, applicationName: "bloody-admin" });
  try {
    switch (command) {
      case "create-account": {
        const name = arg("--name");
        const email = arg("--email");
        const kind = (arg("--kind") ?? "mssp") as "mssp" | "enterprise";
        if (!name || !email) throw new Error('usage: create-account --name "Company" --email admin@company.example [--kind mssp|enterprise]');
        if (kind !== "mssp" && kind !== "enterprise") throw new Error("--kind must be mssp or enterprise");
        const r = await createAccountWithAdmin(pool, { name, email, kind });
        if (r.created) console.log(`created ${kind} account "${name}"\n  login:    ${r.email}\n  password: ${r.password}\n  (shown once — change it after the first login)`);
        else console.log(`${r.email} already exists — nothing changed (use reset-password to set a new password)`);
        break;
      }
      case "reset-password": {
        const email = arg("--email");
        if (!email) throw new Error("usage: reset-password --email admin@company.example");
        const password = await resetPassword(pool, email);
        console.log(`new password for ${email.toLowerCase()}: ${password}\n  (shown once; all of their sessions were signed out)`);
        break;
      }
      case "status": {
        const s = await accountSummary(pool);
        console.log(JSON.stringify(s));
        break;
      }
      default:
        throw new Error("commands: create-account, reset-password, status");
    }
  } finally {
    await pool.end();
  }
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
