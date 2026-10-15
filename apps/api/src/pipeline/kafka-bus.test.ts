import { randomUUID } from "node:crypto";
import { Socket } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, credentialTheftChain, login } from "../test/harness.js";
import { KafkaEventBus } from "./kafka-bus.js";

const BROKERS = (process.env.TEST_KAFKA_BROKERS ?? "127.0.0.1:19092").split(",");
let available = false;

beforeAll(async () => {
  const [host, port] = BROKERS[0]!.split(":");
  available = await new Promise<boolean>((resolve) => {
    const s = new Socket();
    s.setTimeout(800);
    s.once("connect", () => (s.destroy(), resolve(true)));
    s.once("error", () => resolve(false));
    s.once("timeout", () => (s.destroy(), resolve(false)));
    s.connect(Number(port), host!);
  });
});

describe("KafkaEventBus (real broker)", () => {
  let bus: KafkaEventBus;
  afterAll(async () => {
    await bus?.close();
  });

  it("delivers in order per key, retries, dead-letters poison messages and drains", async (ctx) => {
    if (!available) ctx.skip();
    const topic = `bloody.test.${randomUUID().slice(0, 8)}.v1`;
    bus = new KafkaEventBus({ brokers: BROKERS, groupId: `g-${randomUUID().slice(0, 8)}`, retryDelayMs: 10 });
    const seen: number[] = [];
    let flaky = 0;
    bus.subscribe<{ n: number; poison?: boolean; flaky?: boolean }>(topic, async (m) => {
      if (m.payload.poison) throw new Error("poison");
      if (m.payload.flaky && flaky++ < 1) throw new Error("transient");
      seen.push(m.payload.n);
    });
    await bus.ready();
    for (let n = 1; n <= 20; n++) await bus.publish(topic, "same-key", { n, ...(n === 7 ? { flaky: true } : {}) });
    await bus.publish(topic, "same-key", { n: 99, poison: true });
    await bus.drain();
    expect(seen).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    expect(bus.stats()).toMatchObject({ depth: 0, deadLetters: 1 });
  }, 90_000);
});

describe("analytics pipeline over Kafka", () => {
  it("turns ingested events into an incident through the Kafka backbone", async (ctx) => {
    if (!available) ctx.skip();
    const t = await createTestApp({ env: { BLOODY_EVENT_BUS: "kafka", KAFKA_BROKERS: BROKERS.join(","), KAFKA_CONSUMER_GROUP: `pipeline-${randomUUID().slice(0, 8)}` }, deps: { startPipeline: true } });
    try {
      await (t.services.bus as KafkaEventBus).ready();
      const tenant = await createTenant(t, { orgs: 1 });
      const admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
      const res = await admin.post("/ingest/events", { organizationId: tenant.orgIds[0], events: credentialTheftChain("kafka-host-01") });
      expect(res.body.accepted).toBe(3);
      await t.services.bus.drain();
      let incidents = 0;
      for (let i = 0; i < 40 && incidents === 0; i++) {
        incidents = (await admin.get("/incidents")).body.items.length;
        if (!incidents) await new Promise((r) => setTimeout(r, 250));
      }
      expect(incidents).toBeGreaterThan(0);
    } finally {
      await t.close();
    }
  }, 120_000);
});
