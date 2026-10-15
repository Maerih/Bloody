import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestApp, type TestApp } from "../test/harness.js";

const URL_ = process.env.TEST_VALKEY_URL ?? "redis://127.0.0.1:6380/5";
let available = false;
let a: TestApp | null = null;
let b: TestApp | null = null;

beforeAll(async () => {
  const probe = new Redis(URL_, { lazyConnect: true, maxRetriesPerRequest: 0, connectTimeout: 500, enableOfflineQueue: false });
  try {
    await probe.connect();
    await probe.flushdb();
    available = true;
  } catch {
    available = false;
  } finally {
    probe.disconnect();
  }
  if (!available) return;
  const env = { VALKEY_URL: URL_, LOGIN_RATE_LIMIT_PER_MINUTE: "10" };
  a = await createTestApp({ env });
  b = await createTestApp({ env });
});
afterAll(async () => {
  await a?.close();
  await b?.close();
});

const hit = (t: TestApp) =>
  t.app.inject({ method: "POST", url: "/api/v1/auth/login", remoteAddress: "203.0.113.77", payload: { email: "nobody@bloody.local", password: "wrong-password-123" } });

describe("login rate limits shared through Valkey", () => {
  it("counts requests across API replicas", async (ctx) => {
    if (!available) ctx.skip();
    for (let i = 0; i < 6; i++) expect((await hit(a!)).statusCode).not.toBe(429);
    const codes: number[] = [];
    for (let i = 0; i < 6; i++) codes.push((await hit(b!)).statusCode);
    // Replica B sees replica A's 6 requests: the limit of 10 is reached within B's batch.
    expect(codes).toContain(429);
    expect(codes.slice(0, 4)).not.toContain(429);
  });

  it("fails open when Valkey is unreachable", async () => {
    const t = await createTestApp({ env: { VALKEY_URL: "redis://127.0.0.1:6399/0", LOGIN_RATE_LIMIT_PER_MINUTE: "10" } });
    try {
      const res = await t.app.inject({ method: "GET", url: "/api/v1/healthz" });
      expect(res.statusCode).toBe(200);
      expect((await hit(t)).statusCode).toBe(401);
      expect((await hit(t)).statusCode).toBe(401);
    } finally {
      await t.close();
    }
  });
});
