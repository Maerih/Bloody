import { ACTIVE_INCIDENT_STATUSES } from "@bloody/contracts";
import { formatDuration, formatNumber, formatPercent } from "../format.js";
import { countBySeverity, incidentTimings, inWindow, kpi, minutesBetween, percent } from "../metrics.js";
import { evaluateEscalations, evaluateIncidentSla } from "../sla.js";
import { barChart, chart, changePhrase, lineChart, narrative, plural, severityDonut, severityPhrase, table } from "./blocks.js";
import type { BuildContext, BuilderResult } from "./context.js";
import { deriveRecommendations } from "./recommendations.js";

/**
 * Customer monthly service review — written for the customer's stakeholders: what the SOC
 * watched and handled on their behalf, what they must do (clearly marked), and how their
 * posture is trending. Usually white-labelled with the MSSP's brand.
 */
export async function buildCustomerMonthly(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, from, to, topN } = ctx;
  const [incidents, prevIncidents, alerts, prevAlerts, events, prevEvents, escalations, vulns, prevVulns, posture, trend, response] = await Promise.all([
    ds.incidents(q),
    ds.incidents(prev),
    ds.alertStats(q),
    ds.alertStats(prev),
    ds.eventStats(q),
    ds.eventStats(prev),
    ds.escalations(q),
    ds.vulnerabilityStats(q),
    ds.vulnerabilityStats(prev),
    ds.posture(q),
    ds.postureTrend(q),
    ds.responseStats(q),
  ]);
  if (ctx.organizations.length > 1) ctx.notes.push("This customer review covers several organizations; figures are combined.");
  const customer = ctx.scopeName ?? "your organization";
  const detected = incidents.filter((i) => inWindow(i.detectedAt, from, to));
  const prevDetected = prevIncidents.filter((i) => inWindow(i.detectedAt, prev.from, prev.to));
  const sev = countBySeverity(detected);
  const t = incidentTimings(incidents, from, to);
  const sla = evaluateIncidentSla(detected, ctx.slaTargetsFor, to);
  const esc = evaluateEscalations(escalations, to);
  const openEsc = escalations.filter((e) => !e.resolvedAt);
  const active = incidents.filter((i) => ACTIVE_INCIDENT_STATUSES.includes(i.status) && Date.parse(i.detectedAt) < to.getTime() && (!i.closedAt || Date.parse(i.closedAt) >= to.getTime()));
  const coverage = percent(posture.agents.protected, posture.agents.total);

  const kpis = [
    kpi({ key: "events", label: "Events monitored", value: events.total, unit: "count", previous: prevEvents.total, betterWhen: "neutral", explanation: "Security events collected and analysed on your behalf." }),
    kpi({ key: "alerts", label: "Alerts investigated", value: alerts.total, unit: "count", previous: prevAlerts.total, betterWhen: "neutral", explanation: "Every alert was triaged by an analyst or an approved automation." }),
    kpi({ key: "incidents", label: "Incidents handled", value: detected.length, unit: "count", previous: prevDetected.length, betterWhen: "lower", explanation: "Confirmed security incidents opened this period." }),
    kpi({ key: "mttr", label: "Average time to resolve", value: t.mttr.mean, unit: "minutes", betterWhen: "lower", explanation: `Detection → closure across ${t.mttr.n} resolved incidents.` }),
    kpi({ key: "sla", label: "Service level met", value: sla.overall.attainmentPct, unit: "percent", betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `${sla.overall.met} of ${sla.overall.met + sla.overall.breached} contractual response objectives met.` }),
    kpi({ key: "coverage", label: "Devices protected", value: coverage, unit: "percent", betterWhen: "higher", target: 98, thresholds: { good: 98, warn: 90 }, explanation: `${posture.agents.protected} of ${posture.agents.total} devices with a healthy agent.` }),
  ];

  const recommendations = deriveRecommendations({
    audience: "customer",
    openEscalationsForCustomer: openEsc.length,
    overdueEscalations: esc.overdueOpen,
    knownExploitedOpen: vulns.knownExploitedOpen,
    privilegedWithoutMfa: posture.identities.privilegedWithoutMfa,
    unresponsiveAgents: posture.agents.unresponsive,
    outdatedAgents: posture.agents.outdated,
    internetFacingCritical: vulns.internetFacingCriticalOpen,
    overdueVulnerabilities: vulns.overdueSla,
  });
  const yours = recommendations.filter((r) => r.owner === "customer" || r.owner === "it");
  const ours = recommendations.filter((r) => !(r.owner === "customer" || r.owner === "it"));

  const notable = [...detected].sort((a, b) => b.riskScore - a.riskScore).slice(0, topN);
  const headline =
    detected.length === 0
      ? `A quiet month for ${customer}: ${formatNumber(events.total, { compact: true })} events monitored and ${formatNumber(alerts.total)} alerts investigated, with no confirmed incidents.`
      : `We monitored ${formatNumber(events.total, { compact: true })} events for ${customer}, investigated ${formatNumber(alerts.total)} alerts and handled ${plural(detected.length, "incident")} (${severityPhrase(sev)}).`;

  return {
    title: "Monthly security service review",
    subtitle: `${customer} · ${ctx.period.label}`,
    summary: {
      headline,
      highlights: [
        sla.overall.attainmentPct !== null ? `${formatPercent(sla.overall.attainmentPct)} of response objectives met; incidents resolved in ${formatDuration(t.mttr.mean)} on average.` : "No response objectives fell due this period.",
        yours.length > 0 ? `${plural(yours.length, "action")} ${yours.length === 1 ? "needs" : "need"} your attention — see "Actions for you".` : "No actions are required from you this month.",
        `Open critical/high vulnerabilities ${changePhrase(vulns.openBySeverity.critical + vulns.openBySeverity.high, prevVulns.openBySeverity.critical + prevVulns.openBySeverity.high)}.`,
      ],
      kpis,
    },
    recommendations,
    terms: ["MTTR", "SLA attainment", "Risk score", "KEV", "Trend vs previous period"],
    sections: [
      {
        id: "summary",
        title: "Your month at a glance",
        blocks: [
          { kind: "kpis", items: kpis },
          narrative([
            headline,
            `Incident volume ${changePhrase(detected.length, prevDetected.length)} compared with last period. ${active.length > 0 ? `${plural(active.length, "incident")} ${active.length === 1 ? "is" : "are"} still being worked on.` : "All incidents are closed."}`,
            response.automated > 0 ? `${plural(response.automated, "response action")} ran automatically to contain threats quickly; high-impact actions were approved by an analyst first.` : null,
          ]),
        ],
      },
      {
        id: "your-actions",
        title: "Actions for you",
        description: "Items only your team can complete. We will follow up on each of them.",
        blocks: [
          { kind: "recommendations", items: yours, emptyMessage: "Nothing is waiting on you — thank you!" },
          table("open-escalations", "Open escalations awaiting your response", [
            { key: "title", label: "Escalation", width: 3 },
            { key: "severity", label: "Severity", format: "severity" },
            { key: "dueAt", label: "Respond by", format: "datetime" },
            { key: "status", label: "Status", format: "status" },
          ], openEsc.map((e) => ({ title: e.title, severity: e.severity, dueAt: e.dueAt, status: Date.parse(e.dueAt) < to.getTime() ? "overdue" : e.status })), { emptyMessage: "No open escalations." }),
        ],
      },
      {
        id: "what-we-did",
        title: "What we handled for you",
        blocks: [
          chart(severityDonut("incidents-by-severity", "Incidents by severity", sev)),
          table("incidents", "Notable incidents", [
            { key: "number", label: "#", format: "number", width: 0.5 },
            { key: "title", label: "Incident", width: 3.2 },
            { key: "severity", label: "Severity", format: "severity" },
            { key: "status", label: "Status", format: "status" },
            { key: "detectedAt", label: "Detected", format: "date" },
            { key: "resolvedIn", label: "Resolved in", format: "minutes", align: "right" },
          ], notable.map((i) => ({ number: i.number, title: i.title, severity: i.severity, status: i.status, detectedAt: i.detectedAt, resolvedIn: i.closedAt ? minutesBetween(i.detectedAt, i.closedAt) : null })), { totalRows: detected.length, emptyMessage: "No incidents this period." }),
          { kind: "recommendations", title: "What we are doing next", items: ours, emptyMessage: "No additional SOC actions planned." },
        ],
      },
      {
        id: "posture",
        title: "Your security posture",
        blocks: [
          chart(lineChart("risk-trend", "Risk score trend", trend.map((p) => p.date.slice(5).replace("-", "/")), [{ key: "risk", name: "Risk score", values: trend.map((p) => p.riskScore) }], "score", { subtitle: "0-100, lower is better" })),
          chart(barChart("agents", "Device protection status", ["Protected", "Unresponsive", "Outdated", "Isolated"], [{ key: "agents", name: "Devices", values: [posture.agents.protected, posture.agents.unresponsive, posture.agents.outdated, posture.agents.isolated] }], "count", { categoryColors: ["#1BAF7A", "#D03B3B", "#E0A100", "#4A3AA7"] })),
          chart(severityDonut("vulns", "Open vulnerabilities by severity", vulns.openBySeverity)),
        ],
      },
    ],
  };
}
