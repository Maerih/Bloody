import { buildApp } from "./app.js";
import { ConfigError, loadConfig } from "./config.js";
import { Database, createPool } from "./db/pool.js";

/**
 * Production entry point. Request handling uses ONLY the RLS-enforced runtime role
 * (`bloody_app` via DATABASE_APP_URL); the privileged connection is never opened here —
 * migrations run as a separate step (`pnpm --filter @bloody/api migrate`).
 */
async function main(): Promise<void> {
  const config = loadConfig();
  const pool = createPool({
    connectionString: config.database.appUrl,
    max: config.database.poolMax,
    statementTimeoutMs: config.database.statementTimeoutMs,
    applicationName: "bloody-api",
  });
  const db = new Database(pool, null);

  // Refuse to serve with a role that bypasses row-level security (defence in depth).
  const role = await pool.query<{ rolsuper: boolean; rolbypassrls: boolean; current_user: string }>(
    "SELECT r.rolsuper, r.rolbypassrls, current_user FROM pg_roles r WHERE r.rolname = current_user",
  );
  const r = role.rows[0];
  if (r && (r.rolsuper || r.rolbypassrls)) {
    const msg = `database role "${r.current_user}" bypasses row-level security; configure DATABASE_APP_URL with the bloody_app role`;
    if (config.env === "production") throw new ConfigError(msg);
    console.warn(`[bloody-api] WARNING: ${msg}`);
  }

  const { app } = await buildApp({ config, db });
  for (const warning of config.warnings) app.log.warn(`[config] ${warning}`);

  let closing = false;
  const shutdown = async (signal: string) => {
    if (closing) return;
    closing = true;
    app.log.info({ signal }, "shutting down");
    const force = setTimeout(() => process.exit(1), 15_000);
    force.unref();
    try {
      await app.close();
      await db.close();
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, "shutdown failed");
      process.exit(1);
    }
  };
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("unhandledRejection", (err) => app.log.error({ err }, "unhandled rejection"));

  await app.listen({ host: config.host, port: config.port });
}

main().catch((err: unknown) => {
  console.error(`[bloody-api] failed to start: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
