import { defineConfig } from "vitest/config";

/**
 * API tests run against a real Postgres database (default `bloody_test`). The global setup
 * drops and recreates the schema and applies every migration once per run; each test file then
 * provisions its own tenants, so files are isolated by tenant rather than by database.
 * Files run one at a time: they share one database and Argon2 hashing is CPU-heavy.
 */
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    globalSetup: ["./src/test/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 120_000,
    restoreMocks: true,
  },
});
