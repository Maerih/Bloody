import { ACTIVE_INCIDENT_STATUSES, PLANS, severityFromScore } from "@bloody/contracts";
import type { RiskFactor } from "@bloody/contracts";
import { formatCurrency, formatNumber, formatPercent } from "../format.js";
import { countBySeverity, inWindow, kpi, percent, sumBy } from "../metrics.js";
import type { RiskItem } from "../model.js";
import { evaluateIncidentSla } from "../sla.js";
import { chart, changePhrase, hbar, narrative, plural, severityDonut, table, topNamed } from "./blocks.js";
import type { BuildContext, BuilderResult } from "./context.js";

/**
 * MSSP portfolio & revenue — the business view across every customer: revenue, growth,
 * service quality, risk concentration, licence utilisation and customers needing attention.
 */
export async function buildMsspPortfolio(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, from, to, topN } = ctx;
  const [incidents, billing, usage, orgPosture, analysts] = await Promise.all([ds.incidents(q), ds.billing(q), ds.usage(q), ds.organizationPosture(q), ds.analystActivity(q)]);
  const currency = billing[0]?.currency ?? ctx.currency;
  if (new Set(billing.map((b) => b.currency)).size > 1) ctx.notes.push("Customers are billed in several currencies; revenue totals use each customer's amount without conversion.");
  const detected = incidents.filter((i) => inWindow(i.detectedAt, from, to));
  const mrr = sumBy(billing, (b) => b.mrr);
  const prevMrrKnown = billing.filter((b) => b.previousMrr !== null);
  const prevMrr = prevMrrKnown.length > 0 ? sumBy(prevMrrKnown, (b) => b.previousMrr ?? 0) + sumBy(billing.filter((b) => b.previousMrr === null), () => 0) : null;
  const newCustomers = ctx.organizations.filter((o) => inWindow(o.createdAt, from, to)).length;
  const sla = evaluateIncidentSla(detected, ctx.slaTargetsFor, to);
  const active = incidents.filter((i) => ACTIVE_INCIDENT_STATUSES.includes(i.status) && Date.parse(i.detectedAt) < to.getTime() && (!i.closedAt || Date.parse(i.closedAt) >= to.getTime()));

  const rows = ctx.organizations.map((o) => {
    const b = billing.find((x) => x.organizationId === o.id);
    const u = usage.find((x) => x.organizationId === o.id);
    const p = orgPosture.find((x) => x.organizationId === o.id);
    const orgIncidents = detected.filter((i) => i.organizationId === o.id);
    const s = evaluateIncidentSla(orgIncidents, ctx.slaTargetsFor, to);
    const utilisation = u && u.endpointsLicensed ? (u.endpoints / u.endpointsLicensed) * 100 : null;
    return {
      id: o.id,
      customer: o.name,
      plan: b?.plan ? PLANS[b.plan].name : o.plan ? PLANS[o.plan].name : "—",
      mrr: b?.mrr ?? null,
      mrrChange: b && b.previousMrr !== null ? b.mrr - b.previousMrr : null,
      risk: p?.riskScore ?? null,
      incidents: orgIncidents.length,
      critical: countBySeverity(orgIncidents).critical,
      active: active.filter((i) => i.organizationId === o.id).length,
      sla: s.overall.attainmentPct,
      breaches: s.overall.breached,
      endpoints: u?.endpoints ?? null,
      utilisation,
      unhealthy: p ? percent(p.agentsUnhealthy, p.agentsTotal) : null,
      kev: p?.knownExploitedOpen ?? 0,
    };
  });

  // Explainable "customer attention" score: risk, SLA breaches, unhealthy agents, critical incidents, licence over-use.
  const attention: RiskItem[] = rows
    .map((r) => {
      const factors: RiskFactor[] = [];
      const add = (key: string, label: string, value: number, weight: number, explanation: string): void => {
        const v = Math.max(0, Math.min(1, value));
        if (v > 0) factors.push({ key, label, value: v, weight, contribution: Math.round(v * weight * 10) / 10, explanation });
      };
      add("risk", "Security risk", (r.risk ?? 0) / 100, 35, `Organization risk score ${r.risk === null ? "unknown" : Math.round(r.risk)}/100.`);
      add("sla", "SLA breaches", Math.min(1, r.breaches / 5), 25, `${plural(r.breaches, "SLA objective")} missed this period.`);
      add("agents", "Unhealthy agents", (r.unhealthy ?? 0) / 25, 15, `${formatPercent(r.unhealthy)} of agents unresponsive, outdated or isolated.`);
      add("critical", "Critical incidents", Math.min(1, r.critical / 3), 15, `${plural(r.critical, "critical incident")} this period.`);
      add("licence", "Licence over-use", r.utilisation !== null && r.utilisation > 100 ? Math.min(1, (r.utilisation - 100) / 25) : 0, 10, `${formatPercent(r.utilisation)} of licensed endpoints in use.`);
      const score = Math.min(100, factors.reduce((s, f) => s + f.contribution, 0));
      const top = [...factors].sort((a, b) => b.contribution - a.contribution)[0];
      return {
        id: r.id,
        title: r.customer,
        subject: `${r.plan} · ${r.mrr !== null ? formatCurrency(r.mrr, currency) : "no billing data"} MRR`,
        severity: severityFromScore(score),
        score,
        factors,
        recommendation: top ? (top.key === "sla" ? "Review staffing for this customer and brief the account manager." : top.key === "risk" ? "Schedule a risk review with the customer and prioritise the top remediation items." : top.key === "agents" ? "Coordinate an agent health campaign with the customer's IT team." : top.key === "licence" ? "Discuss a licence true-up with the customer." : "Hold a post-incident review with the customer.") : null,
      };
    })
    .filter((r) => r.score >= 25)
    .sort((a, b) => b.score - a.score)
    .slice(0, topN);

  const byPlan = new Map<string, number>();
  for (const b of billing) byPlan.set(b.plan ? PLANS[b.plan].name : "Unassigned", (byPlan.get(b.plan ? PLANS[b.plan].name : "Unassigned") ?? 0) + b.mrr);
  const planEntries = [...byPlan.entries()].sort((a, b) => b[1] - a[1]);
  const totalEndpoints = sumBy(usage, (u) => u.endpoints);
  const topShare = mrr > 0 ? ((billing.map((b) => b.mrr).sort((a, b) => b - a).slice(0, 3).reduce((s, v) => s + v, 0)) / mrr) * 100 : null;
  const activeAnalysts = analysts.filter((a) => a.incidentsAssigned + a.alertsTriaged > 0).length;

  const kpis = [
    kpi({ key: "customers", label: "Customers", value: ctx.organizations.length, unit: "count", betterWhen: "higher", explanation: `${newCustomers} onboarded during the period.` }),
    kpi({ key: "mrr", label: "Monthly recurring revenue", value: mrr, unit: "currency", currency, previous: prevMrr, betterWhen: "higher", explanation: "Sum of customer subscription MRR at period end." }),
    kpi({ key: "arr", label: "Annual run rate", value: mrr * 12, unit: "currency", currency, previous: prevMrr === null ? null : prevMrr * 12, betterWhen: "higher", explanation: "MRR × 12." }),
    kpi({ key: "sla", label: "Portfolio SLA attainment", value: sla.overall.attainmentPct, unit: "percent", betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `${sla.overall.met} of ${sla.overall.met + sla.overall.breached} objectives met across all customers.` }),
    kpi({ key: "incidents", label: "Incidents", value: detected.length, unit: "count", betterWhen: "lower", explanation: `${countBySeverity(detected).critical} critical; ${active.length} active at period end.` }),
    kpi({ key: "attention", label: "Customers needing attention", value: attention.length, unit: "count", betterWhen: "lower", explanation: "Customers with an attention score ≥ 25 (risk, SLA, agent health, incidents, licence)." }),
  ];

  return {
    title: "MSSP portfolio & revenue report",
    subtitle: `${plural(ctx.organizations.length, "customer")} · ${ctx.period.label}`,
    summary: {
      headline: `${formatCurrency(mrr, currency)} MRR across ${plural(ctx.organizations.length, "customer")}${prevMrr !== null ? ` (${changePhrase(mrr, prevMrr, { up: "up", down: "down" })})` : ""}; ${formatPercent(sla.overall.attainmentPct)} portfolio SLA attainment; ${plural(attention.length, "customer")} need attention.`,
      highlights: [
        `${formatNumber(totalEndpoints)} endpoints under management, ${plural(activeAnalysts, "active analyst")} (${activeAnalysts > 0 ? formatNumber(Math.round(ctx.organizations.length / activeAnalysts)) : "—"} customers per analyst).`,
        topShare !== null ? `Top 3 customers represent ${formatPercent(topShare)} of MRR${topShare > 50 ? " — high revenue concentration" : ""}.` : "No billing data available.",
        `${newCustomers} new ${newCustomers === 1 ? "customer" : "customers"} this period.`,
      ],
      kpis,
    },
    recommendations: attention.slice(0, 5).map((a) => ({ priority: a.score >= 60 ? "high" : "medium", title: `Engage ${a.title}`, rationale: `${a.factors.sort((x, y) => y.contribution - x.contribution).slice(0, 2).map((f) => f.explanation).join(" ")}`, owner: "mssp" as const })),
    terms: ["MRR", "SLA attainment", "Risk score"],
    sections: [
      {
        id: "overview",
        title: "Portfolio overview",
        blocks: [
          { kind: "kpis", items: kpis },
          narrative([
            `The portfolio generated ${formatCurrency(mrr, currency)} in monthly recurring revenue (${formatCurrency(mrr * 12, currency)} annual run rate) from ${plural(ctx.organizations.length, "customer")}.`,
            `Service quality: ${formatPercent(sla.overall.attainmentPct)} of response objectives met, ${plural(detected.length, "incident")} handled (${plural(countBySeverity(detected).critical, "critical")}).`,
          ]),
        ],
      },
      {
        id: "revenue",
        title: "Revenue",
        blocks: [
          chart({ id: "mrr-by-plan", type: "donut", title: "MRR by plan", unit: "currency", currency, categories: planEntries.map(([p]) => p), series: [{ key: "mrr", name: "MRR", values: planEntries.map(([, v]) => v) }], emptyMessage: "No billing data." }),
          chart(hbar("mrr-by-customer", "Top customers by MRR", topNamed(billing.map((b) => ({ name: ctx.orgName(b.organizationId), count: b.mrr })), 10), { unit: "currency", currency, seriesName: "MRR" })),
        ],
      },
      {
        id: "attention",
        title: "Customers needing attention",
        description: "Explainable attention score combining risk, SLA breaches, agent health, critical incidents and licence over-use.",
        blocks: [{ kind: "risks", items: attention, emptyMessage: "No customer currently needs special attention." }],
      },
      {
        id: "customers",
        title: "Customer scorecard",
        blocks: [
          table("scorecard", "All customers", [
            { key: "customer", label: "Customer", width: 1.8 },
            { key: "plan", label: "Plan" },
            { key: "mrr", label: "MRR", format: "currency", align: "right" },
            { key: "risk", label: "Risk", format: "score", align: "right" },
            { key: "incidents", label: "Incidents", format: "number", align: "right" },
            { key: "critical", label: "Critical", format: "number", align: "right" },
            { key: "sla", label: "SLA", format: "percent", align: "right" },
            { key: "endpoints", label: "Endpoints", format: "number", align: "right" },
            { key: "utilisation", label: "Licence use", format: "percent", align: "right" },
            { key: "unhealthy", label: "Unhealthy agents", format: "percent", align: "right" },
          ], [...rows].sort((a, b) => (b.mrr ?? 0) - (a.mrr ?? 0)).map(({ id: _id, mrrChange: _c, active: _a, breaches: _b, kev: _k, ...r }) => r), { currency, emptyMessage: "No customers in scope." }),
          chart(hbar("incidents-by-customer", "Incidents by customer", topNamed(rows.map((r) => ({ name: r.customer, count: r.incidents })), 10), { seriesName: "Incidents" })),
          chart(severityDonut("portfolio-severity", "Portfolio incidents by severity", countBySeverity(detected))),
        ],
      },
    ],
  };
}
