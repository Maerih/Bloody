import { formatDuration, formatNumber, formatPercent } from "../format.js";
import { coefficientOfVariation, kpi, percent, sumBy } from "../metrics.js";
import { barChart, chart, narrative, plural, table } from "./blocks.js";
import type { BuildContext, BuilderResult } from "./context.js";

/** Analyst activity — workload, throughput, speed and balance across the SOC team. */
export async function buildAnalystActivity(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev } = ctx;
  const [analysts, prevAnalysts, response] = await Promise.all([ds.analystActivity(q), ds.analystActivity(prev), ds.responseStats(q)]);
  const active = analysts.filter((a) => a.incidentsAssigned + a.alertsTriaged + a.investigationsLed + a.notesWritten > 0);
  const closed = sumBy(analysts, (a) => a.incidentsClosed);
  const prevClosed = sumBy(prevAnalysts, (a) => a.incidentsClosed);
  const triaged = sumBy(analysts, (a) => a.alertsTriaged);
  const prevTriaged = sumBy(prevAnalysts, (a) => a.alertsTriaged);
  const assigned = active.map((a) => a.incidentsAssigned);
  const cv = coefficientOfVariation(assigned);
  const weighted = (f: (a: (typeof analysts)[number]) => number | null): number | null => {
    const rows = active.filter((a) => f(a) !== null && a.incidentsClosed > 0);
    const w = sumBy(rows, (a) => a.incidentsClosed);
    return w > 0 ? sumBy(rows, (a) => f(a)! * a.incidentsClosed) / w : null;
  };
  const meanResolve = weighted((a) => a.meanResolveMinutes);
  const meanAck = weighted((a) => a.meanAcknowledgeMinutes);
  const aiAssists = sumBy(analysts, (a) => a.aiAssists);
  const top = [...active].sort((a, b) => b.incidentsClosed - a.incidentsClosed || b.alertsTriaged - a.alertsTriaged);
  const kpis = [
    kpi({ key: "analysts", label: "Active analysts", value: active.length, unit: "count", previous: prevAnalysts.filter((a) => a.incidentsAssigned + a.alertsTriaged > 0).length, betterWhen: "neutral", explanation: "Analysts with at least one triage, incident, investigation or note in the period." }),
    kpi({ key: "closed", label: "Incidents closed", value: closed, unit: "count", previous: prevClosed, betterWhen: "higher", explanation: "Incidents closed by the team." }),
    kpi({ key: "triaged", label: "Alerts triaged", value: triaged, unit: "count", previous: prevTriaged, betterWhen: "neutral", explanation: "Alerts with an analyst disposition." }),
    kpi({ key: "per_analyst", label: "Closed per analyst", value: active.length > 0 ? closed / active.length : null, unit: "count", betterWhen: "neutral", explanation: "Incidents closed ÷ active analysts." }),
    kpi({ key: "balance", label: "Workload balance (CV)", value: cv === null ? null : cv * 100, unit: "percent", betterWhen: "lower", thresholds: { good: 35, warn: 60 }, explanation: "Coefficient of variation of incidents assigned per analyst; lower is more even." }),
    kpi({ key: "ai", label: "AI analyst assists", value: aiAssists, unit: "count", betterWhen: "neutral", explanation: "AI SOC investigations, summaries and drafts used by analysts." }),
  ];
  return {
    title: "Analyst activity report",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · ${ctx.period.label}` : `${ctx.organizations.length} organizations · ${ctx.period.label}`,
    summary: {
      headline: `${plural(active.length, "analyst")} closed ${formatNumber(closed)} incidents and triaged ${formatNumber(triaged)} alerts; mean resolve time ${formatDuration(meanResolve)}.`,
      highlights: [
        cv !== null ? `Workload balance (CV) ${formatPercent(cv * 100)} — ${cv < 0.35 ? "evenly distributed" : cv < 0.6 ? "moderately uneven" : "concentrated on a few analysts"}.` : "Not enough analysts to assess workload balance.",
        `${formatNumber(response.actionsTotal)} response actions requested, ${formatNumber(sumBy(analysts, (a) => a.actionsApproved))} approvals given.`,
        `Mean time to acknowledge across the team ${formatDuration(meanAck)}.`,
      ],
      kpis,
    },
    recommendations:
      cv !== null && cv >= 0.6
        ? [{ priority: "medium", title: "Rebalance incident assignment", rationale: `Assignment is concentrated (CV ${formatPercent(cv * 100)}). Consider round-robin or skill-based auto-assignment to reduce burnout and SLA risk.`, owner: "soc" }]
        : [],
    terms: ["Workload balance", "MTTA", "MTTR", "Trend vs previous period"],
    sections: [
      {
        id: "overview",
        title: "Team overview",
        blocks: [
          { kind: "kpis", items: kpis },
          chart(barChart("workload", "Incidents assigned and closed per analyst", top.slice(0, 15).map((a) => a.name), [
            { key: "assigned", name: "Assigned", values: top.slice(0, 15).map((a) => a.incidentsAssigned) },
            { key: "closed", name: "Closed", values: top.slice(0, 15).map((a) => a.incidentsClosed) },
          ], "count")),
          narrative(["Activity metrics describe workload, not individual performance: incident complexity, customer mix and on-call rotations vary. Use them to staff and balance the team."], { tone: "note" }),
        ],
      },
      {
        id: "analysts",
        title: "Per-analyst activity",
        blocks: [
          table("analyst-table", "Analysts", [
            { key: "name", label: "Analyst", width: 1.6 },
            { key: "role", label: "Role", width: 1.2 },
            { key: "assigned", label: "Assigned", format: "number", align: "right" },
            { key: "closed", label: "Closed", format: "number", align: "right" },
            { key: "closeRate", label: "Close rate", format: "percent", align: "right" },
            { key: "triaged", label: "Alerts", format: "number", align: "right" },
            { key: "investigations", label: "Investigations", format: "number", align: "right" },
            { key: "ack", label: "Mean ack", format: "minutes", align: "right" },
            { key: "resolve", label: "Mean resolve", format: "minutes", align: "right" },
            { key: "orgs", label: "Customers", format: "number", align: "right" },
          ], top.map((a) => ({ name: a.name, role: a.role ?? "—", assigned: a.incidentsAssigned, closed: a.incidentsClosed, closeRate: percent(a.incidentsClosed, a.incidentsAssigned), triaged: a.alertsTriaged, investigations: a.investigationsLed, ack: a.meanAcknowledgeMinutes, resolve: a.meanResolveMinutes, orgs: a.organizationsServed })), { emptyMessage: "No analyst activity in this period." }),
          table("response", "Response activity", [
            { key: "name", label: "Analyst", width: 2 },
            { key: "requested", label: "Actions requested", format: "number", align: "right" },
            { key: "approved", label: "Approvals given", format: "number", align: "right" },
            { key: "notes", label: "Notes", format: "number", align: "right" },
            { key: "ai", label: "AI assists", format: "number", align: "right" },
          ], top.map((a) => ({ name: a.name, requested: a.actionsRequested, approved: a.actionsApproved, notes: a.notesWritten, ai: a.aiAssists })), { emptyMessage: "No response activity." }),
        ],
      },
    ],
  };
}
