import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTenant, createTestApp, login, type TestApp, type TestTenant } from "../test/harness.js";

const FIX = fileURLToPath(new URL("../../../../packages/adapters/fixtures/", import.meta.url));
const eveLines = readFileSync(`${FIX}suricata/eve.json`, "utf8").split("\n").filter((l) => l.trim());
const syslogLines = readFileSync(`${FIX}syslog/messages.log`, "utf8").split("\n").filter((l) => l.trim());
const otlp = (bodies: string[]) => ({ resourceLogs: [{ resource: { attributes: [] }, scopeLogs: [{ scope: {}, logRecords: bodies.map((b) => ({ body: { stringValue: b } })) }] }] });

let t: TestApp;
let tenant: TestTenant;
let token: string;

const post = (adapter: string, payload: unknown, contentType = "application/json") =>
  t.app.inject({ method: "POST", url: `/api/v1/ingest/${adapter}?organizationId=${tenant.orgIds[0]}`, headers: { authorization: `Bearer ${token}`, "content-type": contentType }, payload: typeof payload === "string" ? payload : JSON.stringify(payload) });

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 1 });
  token = (await login(t.app, tenant.admin.email)).token;
});
afterAll(async () => {
  await t?.close();
});

describe("adapter ingest of OTLP-wrapped engine logs", () => {
  it("unwraps Suricata EVE records and matches direct NDJSON ingest", async () => {
    const direct = await post("suricata", eveLines.join("\n"), "application/x-ndjson");
    expect(direct.statusCode).toBeLessThan(300);
    const wrapped = await post("suricata", otlp(eveLines));
    expect(wrapped.statusCode).toBeLessThan(300);
    expect(direct.json().normalization.events).toBeGreaterThan(0);
    expect(wrapped.json().normalization).toMatchObject({ records: direct.json().normalization.records, events: direct.json().normalization.events, rejected: 0 });
  });

  it("unwraps plain-text syslog bodies", async () => {
    const res = await post("syslog", otlp(syslogLines));
    expect(res.statusCode).toBeLessThan(300);
    expect(res.json().normalization).toMatchObject({ records: syslogLines.length, rejected: 0 });
  });
});
