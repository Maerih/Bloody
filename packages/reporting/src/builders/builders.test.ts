import { REPORT_TYPES, type ReportType } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import type { Kpi, ReportData } from "../model.js";
import { ReportScopeError } from "../datasource.js";
import { EmptyReportDataSource, FakeReportDataSource, NOW, ORG_A, ORG_B, PERIOD, TENANT } from "../test-support/fake-datasource.js";
import { buildReport, REPORT_BUILDERS } from "./index.js";
import { ReportRequestError } from "./context.js";

const clock = { now: () => NOW };
let seq = 0;
const ids = (): string => `00000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;

async function build(type: ReportType, opts: { orgs?: string[] | "all"; ds?: FakeReportDataSource; options?: Parameters<typeof buildReport>[0]["options"]; branding?: Parameters<typeof buildReport>[0]["branding"] } = {}): Promise<ReportData> {
  return buildReport(
    { type, tenantId: TENANT, organizationIds: opts.orgs ?? "all", period: PERIOD, ...(opts.options ? { options: opts.options } : {}), ...(opts.branding !== undefined ? { branding: opts.branding } : {}) },
    { dataSource: opts.ds ?? new FakeReportDataSource(), clock, ids },
  );
}

function allKpis(r: ReportData): Kpi[] {
  return [...r.summary.kpis, ...r.sections.flatMap((s) => s.blocks.flatMap((b) => (b.kind === "kpis" ? b.items : [])))];
}

function kpiOf(r: ReportData, key: string): Kpi {
  const k = allKpis(r).find((x) => x.key === key);
  if (!k) throw new Error(`kpi ${key} missing`);
  return k;
}

describe("report builders", () => {
  it("has a builder for every REPORT_TYPES entry and each produces a complete document", async () => {
    expect(Object.keys(REPORT_BUILDERS).sort()).toEqual(REPORT_TYPES.map((t) => t.key).sort());
    for (const t of REPORT_TYPES) {
      const r = await build(t.key);
      expect(r.schemaVersion).toBe("1.0");
      expect(r.type).toBe(t.key);
      expect(r.audience).toBe(t.audience);
      expect(r.typeLabel).toBe(t.label);
      expect(r.title.length).toBeGreaterThan(3);
      expect(r.summary.headline.length).toBeGreaterThan(10);
      expect(r.summary.kpis.length).toBeGreaterThan(0);
      expect(r.sections.length).toBeGreaterThan(1);
      expect(r.period).toMatchObject({ from: PERIOD.from.toISOString(), to: PERIOD.to.toISOString(), days: 30, previousFrom: "2026-08-02T00:00:00.000Z" });
      expect(r.period.label).toMatch(/^1 – 30 Sept? 2026$/);
      for (const k of allKpis(r)) expect(k.explanation.length, `${t.key}.${k.key}`).toBeGreaterThan(5);
      for (const s of r.sections) for (const b of s.blocks) if (b.kind === "risks") for (const it of b.items) expect(Array.isArray(it.factors)).toBe(true);
    }
  });

  it("executive: derives MTTD/MTTR, SLA attainment and trends vs the previous period", async () => {
    const r = await build("executive");
    expect(kpiOf(r, "incidents")).toMatchObject({ value: 5, delta: { previous: 4, direction: "up", sentiment: "bad" } });
    expect(kpiOf(r, "critical_incidents").value).toBe(2);
    expect(kpiOf(r, "mttr").value).toBeCloseTo(502.5, 5);
    expect(kpiOf(r, "mttd").value).toBeCloseTo(90, 5);
    expect(kpiOf(r, "mtta").value).toBeCloseTo(37, 5);
    expect(kpiOf(r, "mttc").value).toBeCloseTo(75, 5);
    const sla = kpiOf(r, "sla");
    expect(sla.value).toBeCloseTo((6 / 9) * 100, 5);
    expect(sla.delta).toMatchObject({ previous: 87.5, direction: "down", sentiment: "bad" });
    expect(sla.status).toBe("bad");
    expect(kpiOf(r, "risk_score")).toMatchObject({ value: 49.5, delta: { previous: 54, direction: "down", sentiment: "good" } });
    expect(kpiOf(r, "kev_open")).toMatchObject({ value: 2, delta: { previous: 4, sentiment: "good" } });
    expect(kpiOf(r, "escalations_on_time").value).toBeCloseTo(100 / 3, 5);
    const risks = r.sections.find((s) => s.id === "risk")!.blocks.find((b) => b.kind === "risks");
    expect(risks && risks.kind === "risks" && risks.items[0]!.title).toBe("Attack path: vpn-edge-01 → dc-01");
    const recs = r.sections[0]!.blocks.find((b) => b.kind === "recommendations");
    expect(recs && recs.kind === "recommendations" && recs.items[0]!.priority).toBe("critical");
    expect(recs && recs.kind === "recommendations" && recs.items[0]!.title).toMatch(/Patch 2 known-exploited vulnerabilities/);
    const techniques = r.sections.find((s) => s.id === "threats")!.blocks.find((b) => b.kind === "chart" && b.chart.id === "top-techniques");
    expect(techniques && techniques.kind === "chart" && techniques.chart.categories[0]).toMatch(/^T1059\.001/);
    expect(r.methodology.map((m) => m.term)).toContain("MTTR");
  });

  it("respects the organization scope in every data-source call", async () => {
    const ds = new FakeReportDataSource();
    const r = await build("customer_monthly", { orgs: [ORG_A], ds });
    expect(ds.calls.length).toBeGreaterThan(5);
    for (const c of ds.calls) {
      expect(c.q.tenantId).toBe(TENANT);
      expect(c.q.organizationIds).toEqual([ORG_A]);
    }
    expect(r.scope).toMatchObject({ organizationName: "Acme Corp", organizationCount: 1, organizationIds: [ORG_A] });
    expect(kpiOf(r, "incidents").value).toBe(3);
    const actions = r.sections.find((s) => s.id === "your-actions")!.blocks[0]!;
    expect(actions.kind === "recommendations" && actions.items.map((i) => i.title)).toContain("Respond to 1 open escalation");
    expect(actions.kind === "recommendations" && actions.items.find((i) => i.title === "Respond to 1 open escalation")!.priority).toBe("high");
  });

  it("aborts when a data source leaks rows from outside the scope", async () => {
    const ds = new FakeReportDataSource();
    ds.leak = true;
    await expect(build("executive", { orgs: [ORG_A], ds })).rejects.toBeInstanceOf(ReportScopeError);
  });

  it("validates requests", async () => {
    await expect(buildReport({ type: "nope" as ReportType, tenantId: TENANT, organizationIds: "all", period: PERIOD }, { dataSource: new FakeReportDataSource() })).rejects.toBeInstanceOf(ReportRequestError);
    await expect(buildReport({ type: "executive", tenantId: "not-a-uuid", organizationIds: "all", period: PERIOD }, { dataSource: new FakeReportDataSource() })).rejects.toThrow(/tenantId/);
    await expect(buildReport({ type: "executive", tenantId: TENANT, organizationIds: [], period: PERIOD }, { dataSource: new FakeReportDataSource() })).rejects.toThrow(/scope is empty/);
    await expect(buildReport({ type: "executive", tenantId: TENANT, organizationIds: "all", period: { from: PERIOD.to, to: PERIOD.from } }, { dataSource: new FakeReportDataSource() })).rejects.toThrow(/after its start/);
    await expect(buildReport({ type: "executive", tenantId: TENANT, organizationIds: "all", period: { days: 0 } }, { dataSource: new FakeReportDataSource() })).rejects.toThrow(/1-366/);
    const byDays = await buildReport({ type: "executive", tenantId: TENANT, organizationIds: "all", period: { days: 30, endingAt: NOW } }, { dataSource: new FakeReportDataSource(), clock });
    expect(byDays.period.from).toBe(PERIOD.from.toISOString());
  });

  it("SOC operations: funnel, response-time table by severity and rule tuning", async () => {
    const ds = new FakeReportDataSource();
    const r = await build("soc_operations", { ds });
    const stats = await ds.alertStats({ tenantId: TENANT, organizationIds: "all", from: PERIOD.from, to: PERIOD.to });
    expect(kpiOf(r, "alerts").value).toBe(stats.total);
    expect(kpiOf(r, "fp_rate").value).toBeCloseTo((stats.falsePositives / stats.total) * 100, 5);
    expect(kpiOf(r, "backlog").value).toBe(2); // #103 open and #099 carried over
    const timing = r.sections.find((s) => s.id === "response-times")!.blocks[0]!;
    expect(timing.kind === "table" && timing.table.rows.find((x) => x["severity"] === "critical")).toMatchObject({ incidents: 2, ackSla: 50, resolveSla: 50 });
    const rules = r.sections.find((s) => s.id === "quality")!.blocks[0]!;
    expect(rules.kind === "table" && rules.table.rows.length).toBe(3);
  });

  it("incident: post-incident report for a single incident", async () => {
    const r = await build("incident", { orgs: [ORG_A], options: { incidentId: "i-101" } });
    expect(r.title).toBe("Incident report #101");
    expect(kpiOf(r, "ttr").value).toBe(180);
    expect(kpiOf(r, "tta")).toMatchObject({ value: 10, status: "good" });
    const timeline = r.sections.find((s) => s.id === "timeline")!.blocks[0]!;
    expect(timeline.kind === "table" && timeline.table.rows.map((x) => x["title"])).toEqual(["Encoded PowerShell detected", "Host isolation approved by Finn Responder", "Encryptor hash submitted to sandbox"]);
    const iocs = r.sections.find((s) => s.id === "scope")!.blocks.find((b) => b.kind === "table" && b.table.id === "indicators")!;
    expect(iocs.kind === "table" && iocs.table.rows[0]!["value"]).toBe("update-check[.]evil-cdn[.]com");
    await expect(build("incident", { orgs: [ORG_B], options: { incidentId: "i-101" } })).rejects.toThrow(/not found/);
    const summary = await build("incident");
    expect(kpiOf(summary, "incidents").value).toBe(5);
    expect(kpiOf(summary, "closed").value).toBe(4);
  });

  it("vulnerability, threat intel and compliance compute their headline metrics", async () => {
    const v = await build("vulnerability");
    expect(kpiOf(v, "open")).toMatchObject({ value: 91, delta: { previous: 99, sentiment: "good" } });
    expect(kpiOf(v, "kev").value).toBe(2);
    const priorities = v.sections.find((s) => s.id === "priorities")!.blocks[0]!;
    expect(priorities.kind === "risks" && priorities.items[0]!.factors.map((f) => f.label)).toEqual(["Known exploited", "Internet-facing", "EPSS 94%"]);

    const ti = await build("threat_intel");
    expect(kpiOf(ti, "new")).toMatchObject({ value: 1210, delta: { previous: 980 } });
    const matched = ti.sections.find((s) => s.id === "matches")!.blocks[0]!;
    expect(matched.kind === "table" && matched.table.rows[0]!["value"]).toBe("update-check[.]evil-cdn[.]com");

    const c = await build("compliance");
    expect(kpiOf(c, "compliance").value).toBeCloseTo(78.125, 5);
    expect(kpiOf(c, "edr").value).toBeCloseTo((173 / 180) * 100, 5);
    const gaps = c.sections.find((s) => s.id === "gaps")!.blocks[0]!;
    expect(gaps.kind === "table" && gaps.table.rows[0]!["severity"]).toBe("high");
  });

  it("SLA: explains every breach and applies per-organization targets", async () => {
    const r = await build("sla");
    expect(kpiOf(r, "ack").value).toBeCloseTo(60, 5);
    expect(kpiOf(r, "resolve").value).toBeCloseTo(75, 5);
    expect(kpiOf(r, "breaches").value).toBe(2);
    const breaches = r.sections.find((s) => s.id === "breaches")!.blocks[0]!;
    const rows = breaches.kind === "table" ? breaches.table.rows : [];
    expect(rows.find((x) => x["number"] === 201)!["reason"]).toBe("acknowledged after 20m (target 10m); resolved after 6h 0m (target 4h 0m)");
    expect(rows.find((x) => x["number"] === 102)!["reason"]).toBe("acknowledged after 1h 30m (target 1h 0m)");
    const byCustomer = r.sections.find((s) => s.id === "by-customer")!.blocks[1]!;
    expect(byCustomer.kind === "table" && byCustomer.table.rows.map((x) => x["organization"])).toEqual(["Globex", "Acme Corp"]);
  });

  it("analyst activity and MSSP portfolio", async () => {
    const a = await build("analyst_activity");
    expect(kpiOf(a, "analysts").value).toBe(3);
    expect(kpiOf(a, "closed")).toMatchObject({ value: 4, delta: { previous: 1, direction: "up", sentiment: "good" } });

    const m = await build("mssp_portfolio");
    expect(kpiOf(m, "mrr")).toMatchObject({ value: 14000, currency: "USD", delta: { previous: 4500, sentiment: "good" } });
    expect(kpiOf(m, "arr").value).toBe(168000);
    expect(kpiOf(m, "customers").explanation).toMatch(/^1 onboarded/);
    const attention = m.sections.find((s) => s.id === "attention")!.blocks[0]!;
    expect(attention.kind === "risks" && attention.items[0]!.title).toBe("Acme Corp");
    expect(attention.kind === "risks" && attention.items[0]!.factors.find((f) => f.key === "licence")!.explanation).toMatch(/120%/);
  });

  it("renders real empty states for a fresh tenant", async () => {
    for (const t of REPORT_TYPES) {
      if (t.key === "incident") continue;
      const r = await build(t.key, { ds: new EmptyReportDataSource() });
      expect(r.sections.length).toBeGreaterThan(0);
      expect(r.summary.headline.length).toBeGreaterThan(0);
    }
    const c = await build("compliance", { ds: new EmptyReportDataSource() });
    expect(c.dataQuality.join(" ")).toMatch(/No compliance controls are mapped/);
  });

  it("adds AI commentary when a narrative provider is configured, and degrades gracefully", async () => {
    const r = await buildReport(
      { type: "executive", tenantId: TENANT, organizationIds: "all", period: PERIOD },
      { dataSource: new FakeReportDataSource(), clock, narrative: async (input) => ({ headline: `AI view of ${input.kpis.length} KPIs`, summary: "Risk is trending down but SLA slipped.", keyFindings: ["Two ransomware incidents"], model: "local-llm" }) },
    );
    const ai = r.sections.find((s) => s.id === "ai-commentary")!;
    expect(ai.blocks[0]).toMatchObject({ kind: "narrative", tone: "ai" });
    expect(r.sections[1]!.id).toBe("ai-commentary");
    const failed = await buildReport(
      { type: "executive", tenantId: TENANT, organizationIds: "all", period: PERIOD },
      { dataSource: new FakeReportDataSource(), clock, narrative: async () => Promise.reject(new Error("model offline")) },
    );
    expect(failed.sections.some((s) => s.id === "ai-commentary")).toBe(false);
    expect(failed.dataQuality.join(" ")).toMatch(/AI commentary unavailable: model offline/);
  });

  it("applies white-label branding and reports invalid branding fields", async () => {
    const r = await build("customer_monthly", { orgs: [ORG_A], branding: { name: "Acme MSSP", primaryColor: "#0055AA", poweredBy: true } });
    expect(r.branding).toMatchObject({ name: "Acme MSSP", primaryColor: "#0055AA", poweredBy: true });
    expect(r.preparedBy).toBe("Acme MSSP Security Operations");
    const bad = await build("executive", { branding: { name: "X", primaryColor: "javascript:alert(1)", logoDataUrl: "data:image/svg+xml;base64,PHN2Zz4=" } });
    expect(bad.branding.primaryColor).toBe("#B4232C");
    expect(bad.branding.logoDataUrl).toBeNull();
    expect(bad.dataQuality.filter((d) => d.startsWith("branding."))).toHaveLength(2);
  });
});
