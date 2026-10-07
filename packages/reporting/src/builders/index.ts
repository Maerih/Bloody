import { REPORT_TYPES, ReportType } from "@bloody/contracts";
import { randomUUID } from "node:crypto";
import { resolveReportBranding } from "../branding.js";
import { scopedDataSource, type ReportQuery } from "../datasource.js";
import { formatPeriod } from "../format.js";
import type { ReportAudience, ReportData, ReportSection } from "../model.js";
import { buildAnalystActivity } from "./analyst-activity.js";
import { buildCompliance } from "./compliance.js";
import { GLOSSARY, ReportRequestError, resolvePeriod, slaResolver, type BuildContext, type ReportBuildDeps, type ReportBuilder, type ReportRequest } from "./context.js";
import { buildCustomerMonthly } from "./customer-monthly.js";
import { buildExecutive } from "./executive.js";
import { buildIncident } from "./incident.js";
import { buildMsspPortfolio } from "./mssp-portfolio.js";
import { buildSla } from "./sla.js";
import { buildSocOperations } from "./soc-operations.js";
import { buildThreatIntel } from "./threat-intel.js";
import { buildVulnerability } from "./vulnerability.js";

/** One builder per REPORT_TYPES entry. */
export const REPORT_BUILDERS: Record<ReportType, ReportBuilder> = {
  executive: buildExecutive,
  soc_operations: buildSocOperations,
  incident: buildIncident,
  vulnerability: buildVulnerability,
  threat_intel: buildThreatIntel,
  compliance: buildCompliance,
  sla: buildSla,
  analyst_activity: buildAnalystActivity,
  customer_monthly: buildCustomerMonthly,
  mssp_portfolio: buildMsspPortfolio,
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Build a report. The caller (API) passes the tenant and the organization scope it derived
 * from the authenticated principal — never from the request body. The data source is wrapped
 * so any row outside that scope aborts the report.
 */
export async function buildReport(request: ReportRequest, deps: ReportBuildDeps): Promise<ReportData> {
  const typeParsed = ReportType.safeParse(request.type);
  if (!typeParsed.success) throw new ReportRequestError(`unknown report type "${String(request.type)}"`);
  const type = typeParsed.data;
  if (!UUID_RE.test(request.tenantId)) throw new ReportRequestError("tenantId must be a UUID");
  if (request.organizationIds !== "all") {
    if (request.organizationIds.length === 0) throw new ReportRequestError("organization scope is empty");
    for (const id of request.organizationIds) if (!UUID_RE.test(id)) throw new ReportRequestError(`invalid organization id "${id}"`);
  }
  const now = (deps.clock ?? { now: () => new Date() }).now();
  const { from, to, prevFrom } = resolvePeriod(request.period, now);
  const options = request.options ?? {};
  const timeZone = options.timeZone ?? "UTC";
  const scope: readonly string[] | "all" = request.organizationIds === "all" ? "all" : [...new Set(request.organizationIds)];
  const q: ReportQuery = { tenantId: request.tenantId, organizationIds: scope, from, to };
  const prev: ReportQuery = { tenantId: request.tenantId, organizationIds: scope, from: prevFrom, to: from };
  const ds = scopedDataSource(deps.dataSource);
  const organizations = await ds.organizations(q);
  if (scope !== "all" && organizations.length === 0) throw new ReportRequestError("no organizations found in scope");
  const names = new Map(organizations.map((o) => [o.id, o.name]));
  const { branding, issues } = resolveReportBranding(request.branding ?? null);
  const notes: string[] = [...issues];
  const meta = REPORT_TYPES.find((t) => t.key === type)!;
  const period = {
    from: from.toISOString(),
    to: to.toISOString(),
    days: Math.round(((to.getTime() - from.getTime()) / 86_400_000) * 10) / 10,
    label: formatPeriod(from, to, timeZone),
    previousFrom: prevFrom.toISOString(),
    previousTo: from.toISOString(),
  };
  const ctx: BuildContext = {
    type,
    ds,
    q,
    prev,
    from,
    to,
    period,
    organizations,
    scopeName: organizations.length === 1 ? organizations[0]!.name : null,
    orgName: (id) => names.get(id) ?? "Unknown organization",
    slaTargetsFor: slaResolver(options.slaTargets, organizations),
    topN: Math.max(3, Math.min(50, Math.floor(options.topN ?? 10))),
    currency: options.currency ?? "USD",
    locale: options.locale ?? "en-US",
    timeZone,
    options,
    now,
    notes,
  };
  const result = await REPORT_BUILDERS[type](ctx);
  const audience: ReportAudience = meta.audience;
  const sections: ReportSection[] = [...result.sections];

  if (deps.narrative) {
    try {
      const n = await deps.narrative({
        type,
        audience,
        title: result.title,
        periodLabel: period.label,
        organizationName: ctx.scopeName,
        kpis: result.summary.kpis,
        highlights: result.summary.highlights,
        recommendations: result.recommendations,
      });
      sections.splice(1, 0, {
        id: "ai-commentary",
        title: "Analyst commentary",
        description: "Drafted by the AI SOC analyst from the figures in this report.",
        blocks: [
          { kind: "narrative", tone: "ai", label: `AI-generated${n.model ? ` (${n.model})` : ""} — ${n.disclaimer ?? "review before relying on it"}`, paragraphs: [n.headline, n.summary, ...(n.outlook ? [n.outlook] : [])].filter((p) => p.trim().length > 0) },
          ...(n.keyFindings.length > 0 ? [{ kind: "narrative" as const, tone: "ai" as const, label: "Key findings", paragraphs: n.keyFindings.map((f) => `• ${f}`) }] : []),
          ...(n.recommendations && n.recommendations.length > 0
            ? [{ kind: "recommendations" as const, title: "AI-suggested actions", items: n.recommendations.slice(0, 8).map((r) => ({ priority: r.priority, title: r.action, rationale: "Suggested by the AI analyst; verify against the data above.", owner: null })) }]
            : []),
        ],
      });
    } catch (err) {
      notes.push(`AI commentary unavailable: ${err instanceof Error ? err.message.slice(0, 200) : "provider error"}.`);
    }
  }

  const terms = [...new Set(result.terms)].filter((t) => GLOSSARY[t]);
  return {
    schemaVersion: "1.0",
    id: (deps.ids ?? randomUUID)(),
    type,
    typeLabel: meta.label,
    title: result.title,
    subtitle: result.subtitle,
    audience,
    generatedAt: now.toISOString(),
    period,
    scope: { tenantId: request.tenantId, organizationIds: scope === "all" ? "all" : [...scope], organizationName: ctx.scopeName, organizationCount: organizations.length },
    branding,
    classification: options.classification?.trim().slice(0, 60) || "Confidential",
    preparedFor: options.preparedFor?.trim().slice(0, 200) || ctx.scopeName,
    preparedBy: options.preparedBy?.trim().slice(0, 200) || `${branding.name} Security Operations`,
    summary: result.summary,
    sections,
    methodology: terms.map((t) => ({ term: t, definition: GLOSSARY[t]! })),
    dataQuality: notes,
  };
}

export { ReportRequestError } from "./context.js";
