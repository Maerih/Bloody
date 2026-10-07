import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { AdapterSignal } from "../core/signals.js";
import { createGreenboneAdapter } from "../normalizers/greenbone.js";
import { createNucleiAdapter } from "../normalizers/nuclei.js";
import { createTrivyAdapter } from "../normalizers/trivy.js";
import { ctx, fixtureJson, fixtureText } from "../test-support/fixtures.js";
import { mockFetch, testResolver } from "../test-support/http.js";
import { createEpssClient, EpssTable, fetchEpssScores } from "./epss.js";
import { createKevClient, fetchKevCatalog, KevCatalog } from "./kev.js";
import { IndicatorRecord } from "./types.js";
import { enrichCve, kevSignals, vulnerabilityFindingsFromEvents } from "./vulnerabilities.js";

const NOW = "2026-10-07T12:00:00.000Z";
const kev = KevCatalog.parse(fixtureJson("kev/known_exploited_vulnerabilities.json"));
const epss = EpssTable.fromCsv(fixtureText("epss/epss_scores-current.csv"));

describe("CISA KEV", () => {
  it("parses the catalog, skips invalid rows, normalizes dates", () => {
    expect(kev.size).toBe(3);
    expect(kev.invalid).toBe(1);
    expect(kev.catalogVersion).toBe("2026.10.06");
    expect(kev.get("cve-2021-44228")).toMatchObject({ knownRansomwareCampaignUse: true, dueDate: "2021-12-24T23:59:59.000Z", dateAdded: "2021-12-10T00:00:00.000Z" });
    expect(kev.has("CVE-2011-3374")).toBe(false);
  });

  it("exports KEV entries as cve indicators (critical when ransomware use is known)", () => {
    const out = kev.toIndicators(NOW);
    expect(out.records).toHaveLength(3);
    for (const r of out.records) expect(IndicatorRecord.safeParse(r).success).toBe(true);
    expect(out.records.find((r) => r.value === "CVE-2021-44228")).toMatchObject({ severity: "critical", confidence: 100, source: "cisa_kev", tags: expect.arrayContaining(["ransomware"]) });
  });

  it("fetches the public feed (key-less) through the SSRF-guarded client", async () => {
    const { fetch, calls } = mockFetch([{ method: "GET", path: "/sites/default/files/feeds/known_exploited_vulnerabilities.json", json: fixtureJson("kev/known_exploited_vulnerabilities.json") }]);
    const catalog = await fetchKevCatalog(createKevClient({ fetch, resolveHost: testResolver }));
    expect(catalog.size).toBe(3);
    expect(calls[0]?.url.origin).toBe("https://www.cisa.gov");
    expect(calls[0]?.headers["authorization"]).toBeUndefined();
  });
});

describe("FIRST EPSS", () => {
  it("parses the daily CSV (plain or gzip) with model metadata", () => {
    expect(epss.size).toBe(5);
    expect(epss.invalidRows).toBe(1);
    expect(epss.modelVersion).toBe("v2025.03.14");
    expect(epss.scoreDate).toBe("2026-10-07T00:00:00.000Z");
    expect(epss.get("CVE-2024-3094")).toEqual({ cve: "CVE-2024-3094", epss: 0.84271, percentile: 0.99283, date: "2026-10-07T00:00:00.000Z" });
    const gz = EpssTable.fromCsv(new Uint8Array(gzipSync(Buffer.from(fixtureText("epss/epss_scores-current.csv")))));
    expect(gz.size).toBe(5);
  });

  it("parses API responses and batches lookups", async () => {
    const { fetch, calls } = mockFetch([{ method: "GET", path: "/data/v1/epss", json: fixtureJson("epss/api-response.json") }]);
    const table = await fetchEpssScores(createEpssClient({ fetch, resolveHost: testResolver }), ["CVE-2024-6387", "cve-2021-44228", "bogus"], { batchSize: 1 });
    expect(calls).toHaveLength(2);
    expect(calls[0]?.url.searchParams.get("cve")).toBe("CVE-2024-6387");
    expect(table.get("CVE-2024-6387")).toMatchObject({ epss: 0.61234, percentile: 0.97901 });
  });
});

describe("Vulnerability enrichment & findings", () => {
  it("enrichCve explains KEV and EPSS evidence and derives a severity floor", () => {
    const xz = enrichCve("CVE-2024-3094", { kev, epss });
    expect(xz).toMatchObject({ knownExploited: true, epss: 0.84271, severityFloor: "high" });
    expect(xz.evidence[0]).toContain("Listed in CISA KEV since 2024-03-29");
    expect(xz.evidence.join(" ")).toContain("EPSS 84.3%");
    expect(enrichCve("CVE-2021-44228", { kev }).severityFloor).toBe("critical");
    expect(enrichCve("CVE-2024-27316", { epss }).severityFloor).toBeNull();
    expect(enrichCve("CVE-2099-0001", {})).toMatchObject({ knownExploited: false, epss: null, evidence: [] });
  });

  const events = [
    ...createTrivyAdapter().normalize(fixtureText("trivy/image-report.json"), ctx()),
    ...createNucleiAdapter().normalize(fixtureText("nuclei/findings.jsonl"), ctx()),
    ...createGreenboneAdapter().normalize(fixtureText("greenbone/report.xml"), ctx()),
  ];
  const findings = vulnerabilityFindingsFromEvents(events, { kev, epss });

  it("groups scanner events into enriched, asset-scoped findings", () => {
    const xz = findings.find((f) => f.cve === "CVE-2024-3094");
    expect(xz).toMatchObject({
      source: "trivy",
      severity: "critical",
      knownExploited: true,
      patchAvailable: true,
      cvss: 10,
      epss: 0.84271,
      slaDueAt: "2024-04-19T23:59:59.000Z",
      asset: { artifact: "registry.local/payments-api:2.4.1" },
    });
    const apt = findings.find((f) => f.cve === "CVE-2011-3374");
    expect(apt).toMatchObject({ severity: "low", knownExploited: false, patchAvailable: false });
    const apache = findings.filter((f) => f.source === "greenbone" && f.cve !== null);
    expect(apache.map((f) => f.cve).sort()).toEqual(["CVE-2024-24795", "CVE-2024-27316"]);
    expect(findings.find((f) => f.cve === "CVE-2021-44228")).toMatchObject({ source: "nuclei", severity: "critical", asset: { hostname: "portal.acme-corp.example.com" } });
    expect(findings.find((f) => f.ruleId === "tech-detect")?.cve).toBeNull();
  });

  it("raises vulnerability.kev_detected signals routed to SOC + customer (+ MSSP for ransomware)", () => {
    const signals = kevSignals(findings, { organizationRef: "org-1", now: NOW });
    expect(signals.map((s) => s.facts["cve"]).sort()).toEqual(["CVE-2021-44228", "CVE-2023-4911", "CVE-2024-3094"]);
    for (const s of signals) expect(AdapterSignal.safeParse(s).success).toBe(true);
    const log4j = signals.find((s) => s.facts["cve"] === "CVE-2021-44228");
    expect(log4j).toMatchObject({ event: "vulnerability.kev_detected", emit: "on_create", audience: ["soc", "customer", "mssp"] });
    expect(log4j?.title).toBe("Known-exploited vulnerability CVE-2021-44228 found on portal.acme-corp.example.com");
    expect(log4j?.summary).toContain("Remediate before 2021-12-24");
  });
});
