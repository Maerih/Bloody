import { describe, expect, it } from "vitest";
import { EngineClient } from "../http/client.js";
import { fixtureJson } from "../test-support/fixtures.js";
import { mockFetch, testResolver } from "../test-support/http.js";
import { createMispClient, mispHealthCheck, parseMispAttributes, pullMispIndicators } from "./misp.js";
import { IndicatorRecord } from "./types.js";

const NOW = "2026-10-07T12:00:00.000Z";
const parsed = parseMispAttributes(fixtureJson("misp/restsearch.json"), { now: NOW });
const byValue = (v: string) => parsed.records.find((r) => r.value === v);

describe("MISP connector — attribute mapping", () => {
  it("maps supported attribute types and reports unsupported/invalid ones", () => {
    expect(parsed.records).toHaveLength(6);
    expect(parsed.skipped).toEqual([
      { ref: "a0000000-0000-4000-8000-000000000105", reason: 'MISP type "regkey" has no Bloody indicator mapping' },
      { ref: "a0000000-0000-4000-8000-000000000107", reason: "invalid ip value" },
    ]);
    for (const r of parsed.records) expect(IndicatorRecord.safeParse(r).success).toBe(true);
  });

  it("detection-grade IP: confidence model, TLP, galaxy actor and ATT&CK, decay window", () => {
    const ip = byValue("198.51.100.23");
    expect(ip).toMatchObject({
      type: "ip",
      externalRef: "misp:attribute:a0000000-0000-4000-8000-000000000100",
      source: "misp",
      confidence: 90,
      severity: "high",
      tlp: "amber",
      threatActor: "FIN-SPIDER",
      description: "Beacon C2",
      firstSeenAt: "2026-10-06T15:20:00.000Z",
      expiresAt: "2026-11-05T15:20:00.000Z",
      revoked: false,
    });
    expect(ip?.attack).toEqual([{ id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" }]);
    expect(ip?.tags).toEqual(expect.arrayContaining(["kill-chain:command-and-control", "misp:category:Network activity", "misp:event:4021"]));
    expect(ip?.scoring.join(" | ")).toContain("to_ids");
    expect(ip?.scoring.join(" | ")).toContain("+15 for MISP event threat level high");
  });

  it("confidence-level tags override the base; composite and defanged values are normalized", () => {
    expect(byValue("cdn-update.badcdn.net")).toMatchObject({ confidence: 95, malware: "Cobalt Strike" });
    expect(parsed.records.find((r) => r.type === "sha256")?.value).toMatch(/^[0-9a-f]{64}$/);
    expect(byValue("http://dl.badcdn.net/payload/stage2.bin")).toMatchObject({ confidence: 55 });
    expect(byValue("CVE-2021-44228")).toMatchObject({ type: "cve", confidence: 35, severity: "low", tlp: "green", expiresAt: null });
    expect(byValue("203.0.113.45")?.revoked).toBe(true);
  });
});

describe("MISP connector — REST client", () => {
  it("POSTs restSearch with the API key header and stops when a page is short", async () => {
    const body = fixtureJson<{ response: { Attribute: unknown[] } }>("misp/restsearch.json");
    const { fetch, calls } = mockFetch([{ method: "POST", path: "/attributes/restSearch", json: body }]);
    const client = createMispClient({ baseUrl: "https://misp.acme.example", apiKey: "misp-key-123", fetch, resolveHost: testResolver });
    const out = await pullMispIndicators(client, { last: "7d", limit: 1000 }, { now: NOW });
    expect(out.pages).toBe(1);
    expect(out.records).toHaveLength(6);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers["authorization"]).toBe("misp-key-123");
    const sent = JSON.parse(calls[0]?.body ?? "{}") as Record<string, unknown>;
    expect(sent).toMatchObject({ returnFormat: "json", page: 1, limit: 1000, to_ids: 1, last: "7d", includeEventTags: true });
    expect(sent["type"]).toContain("ip-dst");
  });

  it("health check reads /servers/getVersion", async () => {
    const { fetch } = mockFetch([{ method: "GET", path: "/servers/getVersion", json: { version: "2.4.190", perm_sync: false } }]);
    const client = new EngineClient({ engine: "misp", baseUrl: "https://misp.acme.example", fetch, resolveHost: testResolver });
    const h = await mispHealthCheck(client);
    expect(h).toMatchObject({ engine: "misp", status: "healthy", ok: true, version: "2.4.190" });
  });
});
