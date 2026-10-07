import { describe, expect, it } from "vitest";
import { assertSchemaValid, byType, ctx, fixtureText, TENANT_ID } from "../test-support/fixtures.js";
import { createWazuhAdapter, wazuhLevelToSeverity } from "./wazuh.js";

const adapter = createWazuhAdapter();

describe("Wazuh adapter — alerts.json", () => {
  const result = adapter.normalizeDetailed(fixtureText("wazuh/alerts.jsonl"), ctx());

  it("normalizes every alert, rejects broken JSON and skips non-alerts with reasons", () => {
    expect(result.records).toBe(6);
    expect(result.events).toHaveLength(4);
    expect(result.rejected).toEqual([{ index: 5, reason: expect.stringContaining("invalid JSON") }]);
    expect(result.skipped).toEqual([{ index: 4, reason: "not a Wazuh alert (no rule)" }]);
    assertSchemaValid(result.events);
  });

  it("maps sshd brute force: level → severity, mitre → attack, agent → asset, srcip → identity + indicator", () => {
    const e = byType(result.events, "wazuh.authentication_failure");
    expect(e.timestamp).toBe("2026-10-07T08:15:02.481Z");
    expect(e.severity).toBe("high");
    expect(e.category).toBe("authentication");
    expect(e.outcome).toBe("failure");
    expect(e.attack).toEqual([{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }]);
    expect(e.asset).toEqual({ hostname: "web-01", ip: ["10.0.1.15"], agentId: "001" });
    expect(e.identity).toMatchObject({ provider: "ssh", principal: "oracle", sourceIp: "203.0.113.45", outcome: "failure" });
    expect(e.network).toMatchObject({ srcIp: "203.0.113.45", srcPort: 51234 });
    expect(e.indicators).toEqual([{ type: "ip", value: "203.0.113.45" }]);
    expect(e.detection).toEqual({ ruleId: "5712", ruleName: expect.stringContaining("brute force"), engine: "wazuh" });
    expect(e.labels["severity_basis"]).toBe("wazuh rule.level 10");
    expect(e.labels["wazuh.rule_groups"]).toBe("syslog,sshd,authentication_failures");
    expect(e.source).toMatchObject({ kind: "endpoint", product: "wazuh", vendor: "Wazuh" });
    expect(e.provenance).toMatchObject({ adapter: "wazuh", adapterVersion: "1.0.0", receivedAt: "2026-10-07T12:00:00.000Z" });
  });

  it("maps syscheck to a file event with hashes, size and the auditing process", () => {
    const e = byType(result.events, "wazuh.fim.modified");
    expect(e.category).toBe("file");
    expect(e.severity).toBe("medium");
    expect(e.file).toMatchObject({ path: "/etc/passwd", name: "passwd", action: "modify", size: 2875 });
    expect(e.file?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(e.user).toEqual({ name: "root" });
    expect(e.process).toMatchObject({ name: "useradd", path: "/usr/sbin/useradd", pid: 33120 });
    expect(e.labels["fim.changed_attributes"]).toContain("sha256");
  });

  it("maps vulnerability-detector alerts with CVE indicator and vendor severity", () => {
    const e = byType(result.events, "wazuh.vulnerability");
    expect(e.category).toBe("vulnerability");
    expect(e.severity).toBe("critical");
    expect(e.indicators).toEqual([{ type: "cve", value: "CVE-2024-3094" }]);
    expect(e.labels).toMatchObject({ "vuln.cvss": "10", "vuln.package": "xz-utils", "vuln.installed_version": "5.6.0-0.2" });
  });

  it("unwraps indexer _source documents and treats level 15 as critical", () => {
    const e = byType(result.events, "wazuh.alert");
    expect(e.severity).toBe("critical");
    expect(e.attack[0]?.id).toBe("T1486");
    expect(e.asset?.hostname).toBe("fs-01");
    expect(e.indicators.map((i) => i.type).sort()).toEqual(["sha256", "url"]);
  });

  it("produces deterministic, tenant-scoped ids when an id namespace is given", () => {
    const a = adapter.normalize(fixtureText("wazuh/alerts.jsonl"), ctx({ idNamespace: TENANT_ID }));
    const b = adapter.normalize(fixtureText("wazuh/alerts.jsonl"), ctx({ idNamespace: TENANT_ID }));
    const other = adapter.normalize(fixtureText("wazuh/alerts.jsonl"), ctx({ idNamespace: "11111111-2222-4333-8444-555555555555" }));
    expect(a.map((e) => e.id)).toEqual(b.map((e) => e.id));
    expect(a[0]?.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(a[0]?.id).not.toBe(other[0]?.id);
    expect(a[0]?.labels["dedup_key"]).toBe(other[0]?.labels["dedup_key"]);
  });

  it("level mapping covers the 0-15 scale", () => {
    expect([0, 2, 3, 6, 7, 9, 10, 12, 13, 15].map(wazuhLevelToSeverity)).toEqual(["info", "info", "low", "low", "medium", "medium", "high", "high", "critical", "critical"]);
  });

  it("can omit raw provenance and caps oversized raw payloads", () => {
    const noRaw = adapter.normalize(fixtureText("wazuh/alerts.jsonl"), ctx({ includeRaw: false }));
    expect(noRaw.every((e) => e.provenance.raw === undefined)).toBe(true);
    const capped = adapter.normalize(fixtureText("wazuh/alerts.jsonl"), ctx({ maxRawBytes: 64 }));
    expect(capped[0]?.provenance.raw).toBeUndefined();
    expect(capped[0]?.labels["raw_omitted"]).toMatch(/^size:\d+$/);
  });
});
