import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { testAppRolePassword, testDatabaseUrl } from "../test/db-url.js";
import { defaultMigrationsDir, loadMigrations, migrate, migrationStatus } from "./migrate.js";

const dirs: string[] = [];
async function copyMigrations(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "bloody-migrations-"));
  dirs.push(dir);
  await cp(defaultMigrationsDir(), dir, { recursive: true });
  return dir;
}
afterAll(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

describe("migration runner", () => {
  it("loads ordered, checksummed migrations", async () => {
    const list = await loadMigrations(defaultMigrationsDir());
    expect(list.length).toBeGreaterThanOrEqual(9);
    expect(list.map((m) => m.version)).toEqual([...list.map((m) => m.version)].sort());
    expect(list.every((m) => /^[0-9a-f]{64}$/.test(m.checksum))).toBe(true);
  });

  it("is idempotent: a second run applies nothing and re-verifies RLS", async () => {
    const result = await migrate({ connectionString: testDatabaseUrl(), appRolePassword: testAppRolePassword() });
    expect(result.applied).toEqual([]);
    expect(result.skipped.length).toBeGreaterThanOrEqual(9);
    const status = await migrationStatus(testDatabaseUrl());
    expect(status.every((s) => s.state === "applied")).toBe(true);
  });

  it("refuses to run when an applied migration was edited", async () => {
    const dir = await copyMigrations();
    const file = path.join(dir, "0001_foundation.sql");
    await writeFile(file, `${await readFile(file, "utf8")}\n-- edited after release\n`);
    await expect(migrate({ connectionString: testDatabaseUrl(), migrationsDir: dir })).rejects.toThrow(/was modified after it was applied/);
    expect((await migrationStatus(testDatabaseUrl(), dir)).find((s) => s.file === "0001_foundation.sql")?.state).toBe("modified");
  });

  it("rolls a failing migration back atomically", async () => {
    const dir = await copyMigrations();
    await writeFile(path.join(dir, "9999_broken.sql"), "CREATE TABLE half_applied (id int);\nSELECT * FROM table_that_does_not_exist;\n");
    await expect(migrate({ connectionString: testDatabaseUrl(), migrationsDir: dir })).rejects.toThrow(/9999_broken\.sql failed/);
    const status = await migrationStatus(testDatabaseUrl(), dir);
    expect(status.find((s) => s.file === "9999_broken.sql")?.state).toBe("pending");
    const pg = await import("pg");
    const client = new pg.default.Client({ connectionString: testDatabaseUrl() });
    await client.connect();
    try {
      expect((await client.query("SELECT to_regclass('public.half_applied') AS t")).rows[0].t).toBeNull();
    } finally {
      await client.end();
    }
  });

  it("rejects duplicate versions", async () => {
    const dir = await copyMigrations();
    await writeFile(path.join(dir, "0001_duplicate.sql"), "SELECT 1;");
    await expect(loadMigrations(dir)).rejects.toThrow(/Duplicate migration version 0001/);
  });
});
