/**
 * Test database location. `TEST_DATABASE_URL` wins, then `DATABASE_URL`; the default is the
 * local `bloody_test` database. The schema is dropped on every run, so anything that is not
 * clearly a test database is refused.
 */
export const DEFAULT_TEST_DATABASE_URL = "postgres://postgres:postgres@localhost:5432/bloody_test";

export function testDatabaseUrl(): string {
  const url = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? DEFAULT_TEST_DATABASE_URL;
  const name = new URL(url).pathname.replace(/^\//, "");
  if (!/_test$/.test(name)) {
    throw new Error(`Refusing to run API tests against database "${name}": the test schema is dropped on every run, so the database name must end in "_test" (set TEST_DATABASE_URL).`);
  }
  return url;
}

export function testAppRolePassword(): string {
  return process.env.BLOODY_APP_DB_PASSWORD ?? "bloody_app";
}
