import { AUTOMATION_EVENTS } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { AttackPathEngine } from "../attack-path/engine.js";
import { Correlator } from "../correlation/correlator.js";
import type { RuleMetrics } from "../detection/engine.js";
import type { DetectionMatch } from "../detection/types.js";
import { automationEventFor, notificationTemplateContext, playbookTriggerFor, safeSink, type EngineNotification } from "../notifications.js";
import { RiskEngine } from "../risk/risk-engine.js";
import { BUILTIN_RULES } from "../rules/index.js";
import { at, ORG_1, ORG_2, TENANT_A } from "../test-support/fixtures.js";
import { detectionCoverage, ruleEfficacy, summarizeMatches } from "./detection-report.js";
import { narrateAttackPaths, narrateExposure, narrateIncident, narrateRisk } from "./narrative.js";

const m = (rule: string, severity: DetectionMatch["severity"], org = ORG_1, attack = [{ id: "T1003.001" }]): DetectionMatch => ({
  id: `${rule}-${Math.random()}`,
  tenantId: TENANT_A,
  organizationId: org,
  rule: { id: rule, name: rule.toUpperCase(), version: 1, kind: "sigma" },
  title: rule,
  severity,
  confidence: 0.8,
  attack,
  events: [],
  entities: [
    { kind: "endpoint", key: "ws-1", label: "WS-1" },
    { kind: "technique", key: "T1003.001", label: "T1003.001" },
  ],
  explanation: [],
  firstSeenAt: at(0),
  lastSeenAt: at(0),
  detectedAt: at(0),
});

describe("detection reporting", () => {
  it("computes ATT&CK coverage of the built-in pack", () => {
    const cov = detectionCoverage(BUILTIN_RULES);
    expect(cov.enabledRules).toBe(BUILTIN_RULES.length);
    expect(cov.rulesWithTests).toBe(BUILTIN_RULES.length);
    expect(cov.techniques.find((t) => t.id === "T1003.001")).toMatchObject({ tactic: "credential-access", rules: ["bloody-edr-lsass-credential-access"] });
    const tactics = cov.tactics.map((t) => t.tactic);
    expect(tactics).toEqual(expect.arrayContaining(["initial-access", "execution", "persistence", "credential-access", "command-and-control", "impact"]));
    expect(tactics.indexOf("initial-access")).toBeLessThan(tactics.indexOf("impact")); // kill-chain order
    expect(cov.uncoveredTactics).toEqual(expect.arrayContaining(["reconnaissance", "exfiltration"]));
    expect(detectionCoverage(BUILTIN_RULES.map((r) => ({ ...r, enabled: false }))).enabledRules).toBe(0);
  });

  it("summarizes matches by severity, rule, tactic, entity and organization", () => {
    const s = summarizeMatches([m("lsass", "critical"), m("lsass", "high"), m("spray", "high", ORG_2, [{ id: "T1110.003" }])]);
    expect(s.total).toBe(3);
    expect(s.bySeverity).toMatchObject({ critical: 1, high: 2 });
    expect(s.byRule[0]).toMatchObject({ ruleId: "lsass", count: 2, maxSeverity: "critical" });
    expect(s.byTactic).toEqual([{ tactic: "credential-access", count: 3 }]);
    expect(s.topEntities).toEqual([{ kind: "endpoint", key: "ws-1", label: "WS-1", count: 3 }]);
    expect(s.byOrganization[0]).toMatchObject({ organizationId: ORG_1, critical: 1 });
  });

  it("recommends tuning actions from metrics and analyst feedback", () => {
    const metric = (ruleId: string, p: Partial<RuleMetrics>): RuleMetrics => ({ ruleId, name: ruleId, version: 1, kind: "sigma", enabled: true, evaluated: 100, matched: 0, suppressed: 0, cooledDown: 0, errors: 0, lastMatchAt: null, lastError: null, activeStates: 0, ...p });
    const rows = ruleEfficacy(
      [metric("ok", { matched: 10 }), metric("noisy", { matched: 2, suppressed: 8 }), metric("broken", { errors: 3 }), metric("quiet", {}), metric("imprecise", { matched: 10 })],
      [{ tenantId: TENANT_A, ruleId: "imprecise", truePositives: 1, falsePositives: 4, benignPositives: 0, precision: 0.2 }],
    );
    expect(Object.fromEntries(rows.map((r) => [r.ruleId, r.recommendation]))).toEqual({ ok: "healthy", noisy: "review", broken: "fix", quiet: "silent", imprecise: "review" });
    expect(rows[0]!.ruleId).toBe("broken");
  });
});

describe("audience narratives", () => {
  const engine = new RiskEngine();
  const asset = engine.scoreAsset({
    asset: { name: "payments-db", criticality: "crown_jewel", internetFacing: true },
    vulnerabilities: [{ cve: "CVE-2024-3400", cvss: 10, epss: 0.95, knownExploited: true }],
    controls: { edr: true },
  });

  it("produces executive, customer, analyst and MSSP variants from the same explanation", () => {
    const exec = narrateRisk(asset, { audience: "executive", subject: "Payments database", actions: ["Patch CVE-2024-3400 this week"] });
    expect(exec.headline).toMatch(/^Payments database: (critical|high) risk/);
    expect(exec.paragraphs.join(" ")).toMatch(/Existing safeguards \(edr coverage\)/);
    expect(exec.actions).toEqual(["Patch CVE-2024-3400 this week"]);
    const customer = narrateRisk(asset, { audience: "customer", subject: "Payments database" });
    expect(customer.paragraphs[0]).toMatch(/^What we found: /);
    expect(customer.actions.length).toBe(1);
    const analyst = narrateRisk(asset, { audience: "analyst", subject: "payments-db" });
    expect(analyst.paragraphs.some((p) => /^\+\d+\.\d{2} Known exploited vulnerability \[likelihood/.test(p))).toBe(true);
    expect(analyst.paragraphs.at(-1)).toMatch(/Inherent score without controls/);
    const mssp = narrateRisk(asset, { audience: "mssp", subject: "Contoso" });
    expect(mssp.headline).toMatch(/^Contoso \d+(\.\d)?\/100 \w+ · top driver: /);
  });

  it("narrates exposure, attack paths and incidents", () => {
    const exposure = engine.exposureScore({ organizationName: "Contoso", assets: { total: 100, internetFacing: 10, crownJewels: 2 }, vulnerabilities: { knownExploitedOnInternetFacing: 1 }, identities: { privilegedWithoutMfa: 2 } });
    expect(narrateExposure(exposure, { audience: "executive", organizationName: "Contoso" }).paragraphs.join(" ")).toMatch(/Largest exposure areas/);
    expect(narrateExposure(exposure, { audience: "analyst" }).paragraphs.some((p) => p.startsWith("exploitable vulnerabilities:"))).toBe(true);

    const none = narrateAttackPaths(new AttackPathEngine().analyze({ nodes: [], edges: [] }), { audience: "executive", organizationName: "Contoso" });
    expect(none.headline).toMatch(/No attack paths/);
    const graph = {
      nodes: [
        { id: "I", kind: "internet" as const, key: "internet", label: "Internet", organizationId: ORG_1, props: {} },
        { id: "W", kind: "server" as const, key: "web", label: "web-01", organizationId: ORG_1, props: { internetFacing: true } },
        { id: "V", kind: "vulnerability" as const, key: "CVE-1", label: "CVE-1", organizationId: ORG_1, props: { cve: "CVE-1", cvss: 9.8, epss: 0.9 } },
        { id: "D", kind: "data_store" as const, key: "db", label: "payments-db", organizationId: ORG_1, props: { criticality: "crown_jewel" } },
      ],
      edges: [
        { id: "e1", kind: "exposes" as const, from: "I", to: "W", props: {} },
        { id: "e2", kind: "has_vulnerability" as const, from: "W", to: "V", props: { status: "open" } },
        { id: "e3", kind: "has_access_to" as const, from: "W", to: "D", props: {} },
      ],
    };
    const analysis = new AttackPathEngine().analyze(graph);
    const execPaths = narrateAttackPaths(analysis, { audience: "executive", organizationName: "Contoso" });
    expect(execPaths.headline).toMatch(/could reach 1 of Contoso's most critical system\(s\) through 1 route/);
    expect(execPaths.paragraphs[0]).toMatch(/web-01 → payments-db/);
    expect(narrateAttackPaths(analysis, { audience: "analyst" }).paragraphs[0]).toMatch(/-\[T1190/);

    const c = new Correlator();
    const draft = c.add(m("lsass", "critical")).incident;
    const customer = narrateIncident(draft, { audience: "customer" });
    expect(customer.paragraphs[1]).toMatch(/approvals agreed with you/);
    expect(narrateIncident(draft, { audience: "executive" }).headline).toMatch(/^Critical-severity incident/);
    expect(narrateIncident(draft, { audience: "mssp", organizationName: "Contoso" }).headline).toMatch(/^Contoso: critical incident/);
  });
});

describe("automation notifications", () => {
  const base = { tenantId: TENANT_A, organizationId: ORG_1, at: at(0) };
  const all: EngineNotification[] = [
    { ...base, type: "detection.matched", matchId: "m", ruleId: "r", ruleName: "R", severity: "high", confidence: 0.8, entityLabels: ["WS-1"] },
    { ...base, type: "indicator.matched", matchId: "m", indicators: [{ type: "ip", value: "1.2.3.4", source: "misp", confidence: 90, severity: "high" }], entityLabels: [] },
    { ...base, type: "incident.created", incidentDraftId: "i", title: "T", severity: "critical", riskScore: 92 },
    { ...base, type: "incident.severity_changed", incidentDraftId: "i", title: "T", severity: "critical", previousSeverity: "high", riskScore: 92, reasons: [] },
    { ...base, type: "vulnerability.kev_detected", cve: "CVE-1", assetNodeId: "n", assetLabel: "web", internetFacing: true, criticality: "high" },
    { ...base, type: "attack_path.crown_jewel_exposed", paths: 2, targets: ["db"], topRemediation: "Patch", maxRiskScore: 80 },
  ];
  it("maps to contract automation events and playbook triggers", () => {
    const events = all.map(automationEventFor);
    expect(events).toEqual([null, "indicator.matched", "incident.created", "incident.severity_changed", "vulnerability.kev_detected", null]);
    for (const e of events) if (e) expect(AUTOMATION_EVENTS).toContain(e);
    expect(all.map(playbookTriggerFor)).toEqual(["alert.created", "indicator.matched", "incident.created", "incident.updated", null, null]);
  });
  it("flattens notifications for email / chat templates", () => {
    const ctx = notificationTemplateContext(all[1]!);
    expect(ctx).toMatchObject({ type: "indicator.matched", tenantId: TENANT_A, organizationId: ORG_1 });
    expect(ctx.indicators).toContain('"value":"1.2.3.4"');
    expect(notificationTemplateContext(all[0]!).entityLabels).toBe("WS-1");
  });
  it("safeSink shields engines from failing consumers", () => {
    const errors: unknown[] = [];
    const sink = safeSink({ emit: () => { throw new Error("smtp down"); } }, (e) => errors.push(e));
    expect(() => sink.emit(all[2]!)).not.toThrow();
    expect(errors).toHaveLength(1);
  });
});
