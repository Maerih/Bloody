import type { Severity } from "@bloody/contracts";
import { formatDuration, formatPercent } from "../format.js";
import { inWindow, kpi, SEVERITIES_DESC } from "../metrics.js";
import { evaluateEscalations, evaluateIncidentSla } from "../sla.js";
import { barChart, chart, changePhrase, hbar, narrative, plural, table } from "./blocks.js";
import { SEVERITY_LABEL, type BuildContext, type BuilderResult } from "./context.js";
import { deriveRecommendations } from "./recommendations.js";

/** SLA performance — attainment per severity, per customer, breaches with explicit reasons. */
export async function buildSla(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, from, to, topN } = ctx;
  const [incidents, prevIncidents, escalations, prevEscalations] = await Promise.all([ds.incidents(q), ds.incidents(prev), ds.escalations(q), ds.escalations(prev)]);
  const detected = incidents.filter((i) => inWindow(i.detectedAt, from, to));
  const prevDetected = prevIncidents.filter((i) => inWindow(i.detectedAt, prev.from, prev.to));
  const sla = evaluateIncidentSla(detected, ctx.slaTargetsFor, to);
  const prevSla = evaluateIncidentSla(prevDetected, ctx.slaTargetsFor, prev.to);
  const esc = evaluateEscalations(escalations.filter((e) => Date.parse(e.createdAt) < to.getTime()), to);
  const prevEsc = evaluateEscalations(prevEscalations.filter((e) => Date.parse(e.createdAt) < prev.to.getTime()), prev.to);
  const breached = sla.incidents.filter((r) => r.acknowledge.outcome === "breached" || r.resolve.outcome === "breached");
  const openBreaches = breached.filter((r) => r.resolve.outcome === "breached" && r.resolve.minutes === null).map((r) => (to.getTime() - Date.parse(r.incident.detectedAt)) / 60_000);
  const longestOpen = openBreaches.length > 0 ? Math.max(...openBreaches) : null;

  const kpis = [
    kpi({ key: "overall", label: "Overall SLA attainment", value: sla.overall.attainmentPct, unit: "percent", previous: prevSla.overall.attainmentPct, betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `${sla.overall.met} met / ${sla.overall.met + sla.overall.breached} due objectives (${sla.overall.pending} not yet due).` }),
    kpi({ key: "ack", label: "Acknowledge SLA", value: sla.acknowledge.attainmentPct, unit: "percent", previous: prevSla.acknowledge.attainmentPct, betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `${sla.acknowledge.met} of ${sla.acknowledge.met + sla.acknowledge.breached} incidents acknowledged within target.` }),
    kpi({ key: "resolve", label: "Resolve SLA", value: sla.resolve.attainmentPct, unit: "percent", previous: prevSla.resolve.attainmentPct, betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `${sla.resolve.met} of ${sla.resolve.met + sla.resolve.breached} incidents resolved within target.` }),
    kpi({ key: "breaches", label: "Incidents with a breach", value: breached.length, unit: "count", previous: prevSla.incidents.filter((r) => r.acknowledge.outcome === "breached" || r.resolve.outcome === "breached").length, betterWhen: "lower", explanation: "Incidents where at least one objective was missed." }),
    kpi({ key: "escalations", label: "Escalations on time", value: esc.onTimePct, unit: "percent", previous: prevEsc.onTimePct, betterWhen: "higher", explanation: `${esc.onTime} on time, ${esc.late} late, ${esc.overdueOpen} overdue and open.` }),
  ];
  const recommendations = deriveRecommendations({ audience: "mssp", slaAttainmentPct: sla.overall.attainmentPct, overdueEscalations: esc.overdueOpen, openEscalationsForCustomer: esc.overdueOpen + esc.openWithinDue });

  const sevs = SEVERITIES_DESC.filter((s) => s !== "info");
  const targetRows = sevs.map((s: Severity) => {
    const sample = ctx.organizations[0] ? ctx.slaTargetsFor(ctx.organizations[0].id) : ctx.slaTargetsFor("");
    const b = sla.bySeverity[s];
    return {
      severity: s,
      ackTarget: sample.acknowledgeMinutes[s],
      ackPct: b.acknowledge.attainmentPct,
      ackBreaches: b.acknowledge.breached,
      resolveTarget: sample.resolveMinutes[s],
      resolvePct: b.resolve.attainmentPct,
      resolveBreaches: b.resolve.breached,
    };
  });

  const orgRows = ctx.organizations
    .map((o) => {
      const s = evaluateIncidentSla(detected.filter((i) => i.organizationId === o.id), ctx.slaTargetsFor, to);
      const e = evaluateEscalations(escalations.filter((x) => x.organizationId === o.id), to);
      return { organization: o.name, incidents: s.incidents.length, attainment: s.overall.attainmentPct, ackPct: s.acknowledge.attainmentPct, resolvePct: s.resolve.attainmentPct, breaches: s.overall.breached, escalationsOverdue: e.overdueOpen };
    })
    .filter((r) => r.incidents > 0 || r.escalationsOverdue > 0)
    .sort((a, b) => (a.attainment ?? 101) - (b.attainment ?? 101));

  return {
    title: "SLA performance report",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · ${ctx.period.label}` : `${ctx.organizations.length} organizations · ${ctx.period.label}`,
    summary: {
      headline: sla.overall.attainmentPct === null ? "No SLA objectives fell due in this period." : `${formatPercent(sla.overall.attainmentPct)} of SLA objectives met (${changePhrase(sla.overall.attainmentPct, prevSla.overall.attainmentPct, { up: "up", down: "down" })}); ${plural(breached.length, "incident")} with a breach.`,
      highlights: [
        `Acknowledge ${formatPercent(sla.acknowledge.attainmentPct)}, resolve ${formatPercent(sla.resolve.attainmentPct)}.`,
        `${plural(esc.overdueOpen, "escalation")} overdue at period end.`,
        orgRows[0] && orgRows[0].attainment !== null && orgRows.length > 1 ? `Lowest attainment: ${orgRows[0].organization} at ${formatPercent(orgRows[0].attainment)}.` : null,
      ].filter((h): h is string => h !== null),
      kpis,
    },
    recommendations,
    terms: ["SLA attainment", "Escalation on-time rate", "Trend vs previous period"],
    sections: [
      {
        id: "overview",
        title: "SLA overview",
        blocks: [
          { kind: "kpis", items: kpis },
          narrative([
            "Objectives are evaluated for incidents detected in the period. An unacknowledged or unresolved incident counts as a breach as soon as its target elapses; objectives that are not yet due are excluded rather than counted as met.",
          ], { tone: "note" }),
          { kind: "recommendations", items: recommendations, emptyMessage: "SLA objectives are on track." },
        ],
      },
      {
        id: "by-severity",
        title: "Attainment by severity",
        blocks: [
          chart(barChart("sla-severity", "SLA attainment by severity", sevs.map((s) => SEVERITY_LABEL[s]), [
            { key: "ack", name: "Acknowledge", values: targetRows.map((r) => r.ackPct) },
            { key: "resolve", name: "Resolve", values: targetRows.map((r) => r.resolvePct) },
          ], "percent")),
          table("targets", "Objectives and results", [
            { key: "severity", label: "Severity", format: "severity" },
            { key: "ackTarget", label: "Ack target", format: "minutes", align: "right" },
            { key: "ackPct", label: "Ack met", format: "percent", align: "right" },
            { key: "ackBreaches", label: "Ack breaches", format: "number", align: "right" },
            { key: "resolveTarget", label: "Resolve target", format: "minutes", align: "right" },
            { key: "resolvePct", label: "Resolve met", format: "percent", align: "right" },
            { key: "resolveBreaches", label: "Resolve breaches", format: "number", align: "right" },
          ], targetRows, { note: ctx.organizations.length > 1 ? "Targets shown are the tenant defaults; organizations with contract-specific targets are evaluated against their own." : undefined }),
        ],
      },
      ...(ctx.organizations.length > 1
        ? [
            {
              id: "by-customer",
              title: "Attainment by customer",
              blocks: [
                chart(hbar("customers", "Lowest SLA attainment", orgRows.filter((r) => r.attainment !== null).slice(0, 10).map((r) => ({ name: r.organization, count: Math.round((r.attainment ?? 0) * 10) / 10 })), { unit: "percent", seriesName: "Attainment" })),
                table("orgs", "Customers", [
                  { key: "organization", label: "Customer", width: 2 },
                  { key: "incidents", label: "Incidents", format: "number", align: "right" },
                  { key: "attainment", label: "Overall", format: "percent", align: "right" },
                  { key: "ackPct", label: "Ack", format: "percent", align: "right" },
                  { key: "resolvePct", label: "Resolve", format: "percent", align: "right" },
                  { key: "breaches", label: "Breaches", format: "number", align: "right" },
                  { key: "escalationsOverdue", label: "Overdue escalations", format: "number", align: "right" },
                ], orgRows, { emptyMessage: "No customer had SLA-relevant activity." }),
              ],
            },
          ]
        : []),
      {
        id: "breaches",
        title: "Breaches",
        description: "Every missed objective with the measured time against its target.",
        blocks: [
          table("breach-list", "SLA breaches", [
            { key: "number", label: "#", format: "number", width: 0.5 },
            { key: "title", label: "Incident", width: 2.4 },
            { key: "organization", label: "Customer", width: 1.4 },
            { key: "severity", label: "Severity", format: "severity" },
            { key: "reason", label: "Why", width: 3 },
          ], breached.slice(0, Math.max(topN, 25)).map((r) => ({ number: r.incident.number, title: r.incident.title, organization: ctx.orgName(r.incident.organizationId), severity: r.incident.severity, reason: r.reasons.join("; ") })), { totalRows: breached.length, emptyMessage: "No SLA breaches in this period." }),
          table("overdue-escalations", "Overdue escalations", [
            { key: "title", label: "Escalation", width: 3 },
            { key: "organization", label: "Customer", width: 1.4 },
            { key: "severity", label: "Severity", format: "severity" },
            { key: "dueAt", label: "Due", format: "datetime" },
            { key: "overdue", label: "Overdue by", format: "minutes", align: "right" },
          ], esc.overdue.slice(0, topN).map((e) => ({ title: e.title, organization: ctx.orgName(e.organizationId), severity: e.severity, dueAt: e.dueAt, overdue: (to.getTime() - Date.parse(e.dueAt)) / 60_000 })), { totalRows: esc.overdue.length, emptyMessage: "No overdue escalations." }),
          narrative([longestOpen !== null ? `The longest-running unresolved breach has been open for ${formatDuration(longestOpen)}.` : null]),
        ],
      },
    ],
  };
}
