import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTenant, createTestApp, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let token: string;

const batch = (n: number) => ({
  organizationId: tenant.orgIds[0],
  events: Array.from({ length: n }, (_, i) => ({
    timestamp: new Date(Date.now() - i * 1000).toISOString(),
    source: { kind: "endpoint", product: "test" },
    category: "process",
    eventType: "process_start",
    asset: { hostname: `gz-host-${i}` },
    provenance: { adapter: "test", adapterVersion: "1", receivedAt: new Date().toISOString() },
  })),
});

function post(body: Buffer, encoding: string) {
  return t.app.inject({ method: "POST", url: "/api/v1/ingest/events", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "content-encoding": encoding }, payload: body });
}

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 1 });
  token = (await login(t.app, tenant.admin.email)).token;
});
afterAll(async () => {
  await t?.close();
});

describe("compressed request bodies", () => {
  it.each([
    ["gzip", gzipSync],
    ["deflate", deflateSync],
    ["br", brotliCompressSync],
  ] as const)("accepts %s", async (enc, fn) => {
    const res = await post(fn(Buffer.from(JSON.stringify(batch(5)))), enc);
    expect(res.statusCode).toBeLessThan(300);
    expect(res.json().accepted).toBe(5);
  });

  it("rejects unknown encodings with 415", async () => {
    const res = await post(Buffer.from(JSON.stringify(batch(1))), "compress");
    expect(res.statusCode).toBe(415);
  });

  it("rejects a corrupt gzip body without crashing", async () => {
    const res = await post(Buffer.from("definitely not gzip"), "gzip");
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect(res.statusCode).toBeLessThan(500);
  });

  it("enforces the body limit on the decoded size (zip-bomb guard)", async () => {
    const bomb = gzipSync(Buffer.alloc(40 * 1024 * 1024, 0x20));
    expect(bomb.length).toBeLessThan(200_000);
    const res = await post(bomb, "gzip");
    expect(res.statusCode).toBe(413);
  });
});
