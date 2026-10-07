import { ENGINES } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { defineAdapter } from "./core/adapter.js";
import { buildIngestReport, ingestHealthSignal, mergeIngestReports } from "./core/report.js";
import { AdapterSignal } from "./core/signals.js";
import { AdapterRegistry, AdapterRegistryError, createDefaultRegistry, GENERIC_SOURCES, INTEL_CONNECTORS, isKnownSourceKey, RESPONSE_CONNECTORS } from "./registry.js";
import { ctx, fixtureText } from "./test-support/fixtures.js";

describe("AdapterRegistry", () => {
  const registry = createDefaultRegistry();

  it("registers every built-in adapter under an ENGINES or generic source key", () => {
    expect(registry.list().map((a) => a.key)).toEqual([
      "aws_cloudtrail",
      "cef",
      "copilot",
      "falco",
      "greenbone",
      "keycloak",
      "nuclei",
      "opencanary",
      "osquery",
      "suricata",
      "syslog",
      "trivy",
      "velociraptor",
      "wazuh",
      "zeek",
    ]);
    for (const a of registry.list()) expect(isKnownSourceKey(a.key)).toBe(true);
    for (const g of GENERIC_SOURCES) expect(ENGINES.some((e) => e.key === g.key)).toBe(false);
  });

  it("catalog joins licence/mode metadata, response actions and health probes", () => {
    const catalog = registry.catalog();
    const wazuh = catalog.find((c) => c.key === "wazuh");
    expect(wazuh).toMatchObject({ engine: { license: "GPL-2.0-only", mode: "network_api", licenseRisk: "medium" }, actions: ["block_ip", "disable_identity"], healthCheck: true, generic: false });
    expect(catalog.find((c) => c.key === "velociraptor")?.actions).toEqual(["isolate_endpoint", "release_endpoint", "collect_evidence", "run_yara_scan"]);
    expect(catalog.find((c) => c.key === "copilot")).toMatchObject({ engine: { license: "AGPL-3.0-only" }, healthCheck: true });
    expect(catalog.find((c) => c.key === "syslog")).toMatchObject({ engine: null, generic: true, actions: [] });
    expect(registry.supportedActions("wazuh")).toEqual(["block_ip", "disable_identity"]);
    expect(createDefaultRegistry({ wazuhActiveResponse: false }).supportedActions("wazuh")).toEqual([]);
    expect(INTEL_CONNECTORS.map((c) => c.key)).toEqual(["misp", "opencti", "stix", "cisa_kev", "first_epss"]);
    expect(RESPONSE_CONNECTORS.map((c) => c.key)).toEqual(["wazuh.active_response", "velociraptor.collect", "webhook.block"]);
  });

  it("rejects unknown keys, duplicates and unknown lookups", () => {
    const r = new AdapterRegistry();
    const custom = defineAdapter({ key: "acme_edr", version: "1.0.0", name: "x", sourceKind: "endpoint", consumes: [], map: () => undefined });
    expect(() => r.register(custom)).toThrow(AdapterRegistryError);
    expect(() => new AdapterRegistry({ allowCustomKeys: true }).register(custom)).not.toThrow();
    const wazuh = registry.require("wazuh");
    r.register(wazuh);
    expect(() => r.register(wazuh)).toThrow(/already registered/);
    expect(() => r.register(wazuh, { replace: true })).not.toThrow();
    expect(() => r.normalize("nope", "{}", ctx())).toThrow(/no adapter/);
    expect(() => r.normalize("wazuh", "{}", { receivedAt: "yesterday" })).toThrow(/receivedAt/);
  });
});

describe("Ingest reporting", () => {
  const registry = createDefaultRegistry();
  const { result, report } = registry.ingest("wazuh", fixtureText("wazuh/alerts.jsonl"), ctx(), { now: new Date("2026-10-07T12:00:00.000Z") });

  it("summarizes a batch for SOC / MSSP / customer reports", () => {
    expect(result.events).toHaveLength(4);
    expect(report.totals).toEqual({ records: 6, events: 4, skipped: 1, rejected: 1, acceptanceRate: 0.8, truncated: false });
    expect(report.window).toEqual({ from: "2026-10-07T08:15:02.481Z", to: "2026-10-07T09:30:00.000Z" });
    expect(report.bySeverity).toEqual({ info: 0, low: 0, medium: 1, high: 1, critical: 2 });
    expect(report.byCategory).toEqual({ authentication: 1, file: 1, vulnerability: 1, detection: 1 });
    expect(report.attack.map((a) => a.id).sort()).toEqual(["T1110", "T1486", "T1565.001"]);
    expect(report.tactics).toEqual(expect.arrayContaining([{ tactic: "Impact", count: 2 }]));
    expect(report.topAssets[0]).toEqual({ asset: "build-02", events: 1, maxSeverity: "critical" });
    expect(report.indicators.byType).toMatchObject({ ip: 1, cve: 1 });
    expect(report.rejections[0]).toMatchObject({ count: 1, sampleIndexes: [5] });
    expect(report.health).toEqual({ status: "degraded", reasons: ["20% of records rejected"] });
    expect(report.headline).toBe("wazuh: 4 events from 6 records, 3 high/critical, 3 ATT&CK techniques, 1 rejected — source degraded");
  });

  it("merges batch reports and raises a data-source health signal", () => {
    const merged = mergeIngestReports([report, buildIngestReport(registry.normalize("wazuh", fixtureText("wazuh/windows.jsonl"), ctx()))]);
    expect(merged?.totals).toMatchObject({ records: 13, events: 11, rejected: 1 });
    expect(merged?.health.status).toBe("degraded");
    expect(merged?.window?.to).toBe("2026-10-07T10:08:00.000Z");
    const s = ingestHealthSignal(report, { organizationRef: null, integrationRef: "integration:wazuh-1", now: "2026-10-07T12:00:00.000Z" });
    expect(AdapterSignal.safeParse(s).success).toBe(true);
    expect(s).toMatchObject({ event: "agent.unresponsive", severity: "medium", audience: ["soc", "mssp"], subject: { kind: "integration" }, emit: "on_change" });
    expect(ingestHealthSignal(buildIngestReport(registry.normalize("zeek", fixtureText("zeek/conn.log"), ctx())), { organizationRef: null, integrationRef: "x" })).toBeUndefined();
  });

  it("a payload where nothing normalizes is reported as failing", () => {
    const r = buildIngestReport(registry.normalize("suricata", "{bad\n{also bad", ctx()));
    expect(r.health.status).toBe("failing");
    expect(r.totals.acceptanceRate).toBe(0);
  });
});
