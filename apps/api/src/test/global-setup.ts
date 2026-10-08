import pg from "pg";
import { migrate } from "../db/migrate.js";
import { testAppRolePassword, testDatabaseUrl } from "./db-url.js";

/**
 * Vitest global setup: rebuild the test database schema from scratch and apply every migration
 * exactly as production does (including the runtime role, grants and the RLS verification).
 * Refuses to touch any database whose name does not end in `_test`.
 */
export default async function setup(): Promise<void> {
  const url = testDatabaseUrl();
  const client = new pg.Client({ connectionString: url, application_name: "bloody-test-setup" });
  await client.connect();
  try {
    await client.query("SET client_min_messages = warning");
    await client.query("DROP SCHEMA IF EXISTS public CASCADE");
    await client.query("CREATE SCHEMA public");
  } finally {
    await client.end();
  }
  await migrate({ connectionString: url, appRolePassword: testAppRolePassword() });
}
