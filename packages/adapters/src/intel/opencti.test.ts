import { describe, expect, it } from "vitest";
import { fixtureJson } from "../test-support/fixtures.js";
import { mockFetch, testResolver } from "../test-support/http.js";
import { createOpenCtiClient, openCtiHealthCheck, parseOpenCtiIndicators, pullOpenCtiIndicators } from "./opencti.js";
import { IndicatorRecord } from "./types.js";

const NOW = "2026-10-07T12:00:00.000Z";

describe("OpenCTI connector", () => {
  const out = parseOpenCtiIndicators(fixtureJson("opencti/indicators.json"), { now: NOW });

  it("maps STIX-pattern indicators; detection-rule patterns and revoked indicators are skipped", () => {
    expect(out.records).toHaveLength(2);
    expect(out.skipped.map((s) => s.reason)).toEqual(['pattern type "yara" is a detection rule, not an atomic indicator', "revoked"]);
    for (const r of out.records) expect(IndicatorRecord.safeParse(r).success).toBe(true);
    expect(out.hasNextPage).toBe(false);
    expect(out.endCursor).toBe("c4");
  });

  it("resolves score, TLP marking, relationships (malware, intrusion set, ATT&CK) and references", () => {
    const ip = out.records.find((r) => r.type === "ip");
    expect(ip).toMatchObject({
      value: "198.51.100.23",
      externalRef: "opencti:indicator--00000001-1111-4222-8333-444455556666",
      source: "opencti",
      confidence: 80,
      severity: "medium",
      tlp: "amber",
      malware: "Cobalt Strike",
      threatActor: "FIN-SPIDER",
      expiresAt: "2026-12-01T00:00:00.000Z",
      references: ["https://intel.acme.example/r/12"],
    });
    expect(ip?.attack).toEqual([{ id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" }]);
    expect(ip?.tags).toEqual(["c2", "tactic:command-and-control"]);
  });

  it("supports OpenCTI 5 edge shapes for labels/markings", () => {
    const hash = out.records.find((r) => r.type === "sha256");
    expect(hash).toMatchObject({ confidence: 95, severity: "high", tlp: "red" });
    expect(hash?.tags).toContain("loader");
  });

  it("pulls incrementally over GraphQL with a bearer token and modified>since filter", async () => {
    const { fetch, calls } = mockFetch([{ method: "POST", path: "/graphql", json: fixtureJson("opencti/indicators.json") }]);
    const client = createOpenCtiClient({ baseUrl: "https://opencti.acme.example", token: "octi-token", fetch, resolveHost: testResolver });
    const res = await pullOpenCtiIndicators(client, { since: "2026-10-01T00:00:00.000Z", now: NOW });
    expect(res.records).toHaveLength(2);
    expect(res.pages).toBe(1);
    expect(calls[0]?.headers["authorization"]).toBe("Bearer octi-token");
    const body = JSON.parse(calls[0]?.body ?? "{}") as { query: string; variables: { filters: { filters: Array<{ key: string; values: string[]; operator: string }> } } };
    expect(body.query).toContain("indicators(first: $first");
    expect(body.variables.filters.filters[0]).toMatchObject({ key: "modified", values: ["2026-10-01T00:00:00.000Z"], operator: "gt" });
  });

  it("surfaces GraphQL errors and reports health", async () => {
    const { fetch } = mockFetch([
      { method: "POST", path: "/graphql", json: { errors: [{ message: "Access denied" }] }, times: 1 },
      { method: "POST", path: "/graphql", json: { data: { about: { version: "6.3.1" } } } },
    ]);
    const client = createOpenCtiClient({ baseUrl: "https://opencti.acme.example", token: "t", fetch, resolveHost: testResolver });
    await expect(pullOpenCtiIndicators(client, { now: NOW })).rejects.toThrow(/Access denied/);
    expect(await openCtiHealthCheck(client)).toMatchObject({ status: "healthy", version: "6.3.1" });
  });
});
