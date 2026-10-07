import { describe, expect, it } from "vitest";
import { toGeminiSchema } from "../providers/gemini.js";
import { FakeSocPort, IDS, sampleAlerts, sampleRisk } from "../test-support/fake-soc.js";
import { FixedClock, ORG_A1, TENANT_A, TENANT_B, principal, sequentialIds } from "../test-support/fixtures.js";
import { STANDARD_SOC_TOOL_NAMES, createStandardSocTools, explainRiskText, summarizeAlertSet } from "./catalog.js";
import { TOOL_NAME_RE, ToolGateway } from "./gateway.js";
import type { AiAuditEvent, ToolInvocationContext } from "./types.js";

function setup() {
  const port = new FakeSocPort();
  const audit: AiAuditEvent[] = [];
  const gateway = new ToolGateway(createStandardSocTools(port), {
    approvals: { requestApproval: async (r) => ({ approvalId: `appr-${r.actionId}` }) },
    audit: { record: async (e) => void audit.push(e) },
    clock: new FixedClock(),
    ids: sequentialIds(),
  });
  const ctx = (over: Partial<ToolInvocationContext> = {}): ToolInvocationContext => ({
    principal: principal("incident_responder"),
    tenantId: TENANT_A,
    organizationId: ORG_A1,
    providerMaxTier: "require_approval",
    conversationId: "c0000000-0000-4000-8000-000000000001",
    ...over,
  });
  const call = (name: string, args: Record<string, unknown>, over: Partial<ToolInvocationContext> = {}) => gateway.invoke(ctx(over), { id: `call-${name}`, name, arguments: args });
  return { port, gateway, audit, ctx, call };
}

describe("Standard AI SOC tool catalog", () => {
  it("defines every standard tool with valid names and provider-compatible schemas", () => {
    const tools = createStandardSocTools(new FakeSocPort());
    expect(tools.map((t) => t.name)).toEqual([...STANDARD_SOC_TOOL_NAMES]);
    const { gateway, ctx } = setup();
    const specs = gateway.specsFor(ctx({ providerMaxTier: "execute" }));
    expect(specs).toHaveLength(tools.length);
    for (const spec of specs) {
      expect(spec.name).toMatch(TOOL_NAME_RE);
      expect(spec.parameters.type).toBe("object");
      expect(toGeminiSchema(spec.parameters).type).toBe("object");
    }
    const tiers = Object.fromEntries(tools.map((t) => [t.name, t.tier]));
    expect(tiers).toMatchObject({ get_incident: "read", search_events: "investigate", hunt: "investigate", add_investigation_note: "investigate", recommend_remediation: "recommend", draft_sigma_rule: "recommend", request_response_action: "require_approval", send_notification: "execute" });
  });

  it("returns tenant-scoped incident data and nothing across tenants", async () => {
    const { call } = setup();
    const res = await call("get_incident", { incidentId: IDS.incident, includeTimeline: true });
    expect(res.status).toBe("completed");
    const data = res.result as { incident: { number: number; attack: string[] }; alerts: unknown[]; timeline: unknown[] };
    expect(data.incident.number).toBe(1042);
    expect(data.incident.attack).toEqual(["T1003.001 LSASS Memory"]);
    expect(data.alerts).toHaveLength(2);
    expect(data.timeline).toHaveLength(1);
    const foreign = await call("get_incident", { incidentId: IDS.incident }, { principal: principal("incident_responder", { tenantId: TENANT_B }), tenantId: TENANT_B });
    expect(foreign).toMatchObject({ status: "failed", reason: "Incident not found in this organization" });
  });

  it("never sends raw provenance to the model from SIEM searches", async () => {
    const { call, gateway } = setup();
    const res = await call("search_events", { query: "process.name:rundll32.exe", lookbackHours: 48 });
    const content = gateway.toModelContent(res);
    expect(content).toContain("rundll32.exe");
    expect(content).not.toContain("raw payload must never reach the model");
    expect((res.result as { window: { from: string; to: string } }).window).toEqual({ from: "2026-10-05T12:00:00.000Z", to: "2026-10-07T12:00:00.000Z" });
    expect((await call("search_events", { query: "x", from: "2026-10-07T00:00:00Z", to: "2026-10-06T00:00:00Z" })).status).toBe("failed");
  });

  it("summarizes alerts deterministically", () => {
    const s = summarizeAlertSet(sampleAlerts()) as Record<string, unknown>;
    expect(s).toMatchObject({
      total: 2,
      bySeverity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
      maxRiskScore: 92,
      averageConfidence: 0.9,
      linkedToIncidents: 2,
      timeRange: { first: "2026-10-07T10:00:00.000Z", last: "2026-10-07T11:00:00.000Z" },
    });
    expect(s.topTechniques).toEqual([
      { key: "T1003.001 LSASS Memory", count: 1 },
      { key: "T1021.002", count: 1 },
    ]);
    expect((s.highestRisk as Array<{ id: string }>)[0]!.id).toBe(IDS.alert1);
  });

  it("explains risk from its factors", async () => {
    expect(explainRiskText(sampleRisk())).toBe(
      "Score 88/100 (high); likelihood 80%, impact 70%. Main drivers: Known exploited vulnerability (+30.0) — CVE-2026-0001 is in KEV; Active critical alerts (+22.5) — 2 alerts in 24h. Compensating factors: EDR coverage (-5.0).",
    );
    const { call } = setup();
    expect((await call("explain_risk", { entityKind: "asset", id: IDS.asset })).status).toBe("completed");
  });

  it("drafts Sigma rules, validates them and never deploys", async () => {
    const { call } = setup();
    const ok = await call("draft_sigma_rule", {
      title: "LSASS dump via comsvcs",
      description: "Detects MiniDump of LSASS through comsvcs.dll",
      logsource: { product: "windows", category: "process_creation" },
      detection: { selection: { "Image|endswith": "\\rundll32.exe", "CommandLine|contains|all": ["comsvcs", "MiniDump"] }, filter: { User: "SYSTEM's" } },
      condition: "selection and not filter",
      level: "high",
      attack: ["T1003.001"],
      tactics: ["credential-access"],
      falsepositives: ["Admin troubleshooting"],
    });
    expect(ok.status).toBe("completed");
    const r = ok.result as { rule: string; deployed: boolean; validation: { valid: boolean; testMatches: number } };
    expect(r.deployed).toBe(false);
    expect(r.validation).toMatchObject({ valid: true, testMatches: 3 });
    expect(r.rule).toContain("title: 'LSASS dump via comsvcs'");
    expect(r.rule).toContain("    Image|endswith: '\\rundll32.exe'");
    expect(r.rule).toContain("    CommandLine|contains|all:\n      - 'comsvcs'\n      - 'MiniDump'");
    expect(r.rule).toContain("    User: 'SYSTEM''s'");
    expect(r.rule).toContain("  condition: selection and not filter");
    expect(r.rule).toContain("  - attack.credential_access\n  - attack.t1003.001");
    const bad = await call("draft_sigma_rule", {
      title: "Bad rule",
      description: "Bad rule test",
      logsource: { product: "windows" },
      detection: { selection: { "CommandLine|bogus": "x" } },
      condition: "selection or missing",
      level: "low",
    });
    const v = (bad.result as { validation: { valid: boolean; errors: string[] } }).validation;
    expect(v.valid).toBe(false);
    expect(v.errors).toEqual(expect.arrayContaining(["condition references undefined selection 'missing'", "selection 'selection': unknown modifier 'bogus' on 'CommandLine|bogus'"]));
    expect((await call("draft_sigma_rule", { title: "x", description: "yyy", logsource: {}, detection: {}, condition: "a", level: "low" })).code).toBe("invalid_arguments");
  });

  it("ranks remediation with evidence and approval requirements", async () => {
    const { call } = setup();
    const res = await call("recommend_remediation", { incidentId: IDS.incident });
    expect(res.status).toBe("completed");
    const recs = (res.result as { recommendations: Array<{ id: string; title: string; priority: number; category: string; responseAction?: { action: string; requiresHumanApproval: boolean; minimumAiTier: string } }> }).recommendations;
    const ids = recs.map((r) => r.id);
    expect(ids[0]).toBe(`patch:${IDS.vulnKev}`);
    expect(ids).toContain(`contain:isolate:${IDS.asset}`);
    expect(ids).toContain(`contain:revoke:${IDS.identity}`);
    expect(ids).toContain(`contain:disable:${IDS.identity}`);
    expect(ids).toContain(`identity:mfa:${IDS.identity}`);
    expect(ids).toContain(`hardening:fw:${IDS.asset}`);
    expect(ids.indexOf(`patch:${IDS.vulnKev}`)).toBeLessThan(ids.indexOf(`patch:${IDS.vulnLow}`));
    const isolate = recs.find((r) => r.id === `contain:isolate:${IDS.asset}`)!;
    expect(isolate.responseAction).toMatchObject({ action: "isolate_endpoint", requiresHumanApproval: true, minimumAiTier: "require_approval" });
    const evidence = recs.find((r) => r.id === `contain:evidence:${IDS.incident}`)!;
    expect(evidence.responseAction).toMatchObject({ action: "collect_evidence", requiresHumanApproval: false, minimumAiTier: "execute" });
    for (let i = 1; i < recs.length; i++) expect(recs[i - 1]!.priority).toBeGreaterThanOrEqual(recs[i]!.priority);
  });

  it("queues response actions for approval and hands approved ones to SOAR", async () => {
    const { call, gateway, port } = setup();
    const mismatch = await call("request_response_action", { action: "isolate_endpoint", target: { kind: "identity", id: IDS.identity }, reason: "contain" });
    expect(mismatch.code).toBe("invalid_arguments");
    const pending = await call("request_response_action", { action: "isolate_endpoint", target: { kind: "asset", id: IDS.asset, label: "FIN-WS-01" }, incidentId: IDS.incident, reason: "Active credential theft" });
    expect(pending).toMatchObject({ status: "pending_approval", risk: "high" });
    expect(port.submitted).toHaveLength(0);
    const executed = await gateway.executeApproved({ action: pending.action, approver: principal("incident_responder", { id: "lead-1" }), tenantId: TENANT_A, organizationId: ORG_A1 });
    expect(executed.status).toBe("completed");
    expect(port.submitted[0]!.input).toMatchObject({ action: "isolate_endpoint", requestedVia: "ai", aiActionId: pending.action.id, incidentId: IDS.incident });
    expect(port.submitted[0]!.scope).toMatchObject({ approvedBy: "lead-1", principalId: "user-incident_responder", tenantId: TENANT_A });
  });

  it("assesses SOAR actions without executing them", async () => {
    const { call } = setup();
    const res = await call("recommend_soar_action", { action: "collect_evidence", target: { kind: "asset", id: IDS.asset }, reason: "Preserve memory" });
    expect(res.result).toMatchObject({ risk: "low", requiresHumanApproval: false, minimumAiTier: "execute" });
  });

  it("attributes investigation notes to the AI acting for the analyst", async () => {
    const { call, port } = setup();
    const res = await call("add_investigation_note", { investigationId: IDS.investigation, title: "LSASS access confirmed", body: "Evidence: event " + IDS.event, refs: [IDS.event] });
    expect(res.status).toBe("completed");
    expect(port.notes[0]!.input.author).toEqual({ kind: "ai", onBehalfOf: "user-incident_responder", conversationId: "c0000000-0000-4000-8000-000000000001", aiActionId: res.action.id });
  });

  it("sends notifications only to enabled channels and only with execute trust", async () => {
    const { call, port } = setup();
    const args = { channelIds: [IDS.channel, IDS.channelDisabled], subject: "Incident #1042 contained", body: "Update for the customer." };
    expect((await call("send_notification", args)).status).toBe("pending_approval");
    const sent = await call("send_notification", args, { providerMaxTier: "execute" });
    expect(sent.result).toMatchObject({ channels: 1, skippedChannels: 1 });
    expect(port.sent[0]!.input).toMatchObject({ channelIds: [IDS.channel], aiGenerated: true });
    expect((await call("send_notification", { ...args, subject: "two\nlines" }, { providerMaxTier: "execute" })).code).toBe("invalid_arguments");
    const channels = await call("list_notification_channels", {});
    expect(JSON.stringify(channels.result)).not.toContain("soc@corp.example");
  });

  it("prepares audience-specific report drafts", async () => {
    const { call } = setup();
    const res = await call("draft_report", { reportType: "customer_monthly", periodDays: 30 });
    expect(res.result).toMatchObject({ status: "draft", published: false, audience: "customer", organizationName: "Acme Corp", data: { incidents: 12 } });
    expect((res.result as { outline: string[] }).outline).toContain("Actions required from you");
    expect((await call("draft_report", { reportType: "incident" })).code).toBe("invalid_arguments");
  });
});
