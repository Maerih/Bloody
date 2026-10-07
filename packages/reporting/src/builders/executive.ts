import { ACTIVE_INCIDENT_STATUSES } from "@bloody/contracts";
import { severityFromScore } from "@bloody/contracts";
import { formatDuration, formatNumber, formatPercent } from "../format.js";
import { bucketBySeverity, countBySeverity, incidentTimings, inWindow, kpi, percent, round, timeBuckets, topTechniques } from "../metrics.js";
import type { RiskItem } from "../model.js";
import { evaluateEscalations, evaluateIncidentSla } from "../sla.js";
import { chart, changePhrase, hbar, lineChart, narrative, plural, severityDonut, severityPhrase, severityStacked, table } from "./blocks.js";
import type { BuildContext, BuilderResult } from "./context.js";
import { deriveRecommendations } from "./recommendations.js";

/** Executive / CISO summary — business language, risk trend, decisions needed. */
export async function buildExecutive(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, from, to, topN } = ctx;
  const [incidents, prevIncidents, alerts, events, escalations, vulns, prevVulns, posture, prevPosture, trend, riskyAssets, topVulns, paths, response] = await Promise.all([
    ds.incidents(q),
    ds.incidents(prev),
    ds.alertStats(q),
    ds.eventStats(q),
    ds.escalations(q),
    ds.vulnerabilityStats(q),
    ds.vulnerabilityStats(prev),
    ds.posture(q),
    ds.posture(prev),
    ds.postureTrend(q),
    ds.riskyAssets(q, 5),
    ds.topVulnerabilities(q, 5),
    ds.attackPaths(q, 5),
    ds.responseStats(q),
  ]);

  const detected = incidents.filter((i) => inWindow(i.detectedAt, from, to));
  const prevDetected = prevIncidents.filter((i) => inWindow(i.detectedAt, prev.from, prev.to));
  const sev = countBySeverity(detected);
  const prevSev = countBySeverity(prevDetected);
  const timings = incidentTimings(incidents, from, to);
  const prevTimings = incidentTimings(prevIncidents, prev.from, prev.to);
  const sla = evaluateIncidentSla(detected, ctx.slaTargetsFor, to);
  const prevSla = evaluateIncidentSla(prevDetected, ctx.slaTargetsFor, prev.to);
  const esc = evaluateEscalations(escalations, to);
  const openAtEnd = incidents.filter((i) => ACTIVE_INCIDENT_STATUSES.includes(i.status) && (!i.closedAt || Date.parse(i.closedAt) >= to.getTime()) && Date.parse(i.detectedAt) < to.getTime());
  const coverage = percent(posture.agents.protected, posture.agents.total);
  const openCritHigh = vulns.openBySeverity.critical + vulns.openBySeverity.high;
  const prevOpenCritHigh = prevVulns.openBySeverity.critical + prevVulns.openBySeverity.high;

  if (timings.mttd.n === 0 && detected.length > 0) ctx.notes.push("MTTD is unavailable: no incident in the period has a recorded first-activity time.");
  if (posture.riskScore === null) ctx.notes.push("No organization risk score is available for the period end.");

  const kpis = [
    kpi({ key: "risk_score", label: "Risk score", value: posture.riskScore, unit: "score", previous: prevPosture.riskScore, betterWhen: "lower", thresholds: { good: 39, warn: 69 }, explanation: "Risk Engine organization score at period end (0-100, explainable factors)." }),
    kpi({ key: "incidents", label: "Incidents", value: detected.length, unit: "count", previous: prevDetected.length, betterWhen: "lower", explanation: "Incidents detected during the period." }),
    kpi({ key: "critical_incidents", label: "Critical incidents", value: sev.critical, unit: "count", previous: prevSev.critical, betterWhen: "lower", explanation: "Incidents of critical severity detected during the period." }),
    kpi({ key: "mttr", label: "Mean time to resolve", value: timings.mttr.mean, unit: "minutes", previous: prevTimings.mttr.mean, betterWhen: "lower", explanation: `Mean detection-to-closure time over ${timings.mttr.n} incidents closed in the period.` }),
    kpi({ key: "sla", label: "SLA attainment", value: sla.overall.attainmentPct, unit: "percent", previous: prevSla.overall.attainmentPct, betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `${sla.overall.met} of ${sla.overall.met + sla.overall.breached} due acknowledge/resolve objectives met.` }),
    kpi({ key: "kev_open", label: "Known-exploited vulns open", value: vulns.knownExploitedOpen, unit: "count", previous: prevVulns.knownExploitedOpen, betterWhen: "lower", thresholds: { good: 0, warn: 5 }, explanation: "Open vulnerabilities listed as exploited in the wild (KEV) at period end." }),
  ];

  const recommendations = deriveRecommendations({
    audience: "business",
    knownExploitedOpen: vulns.knownExploitedOpen,
    attackPathsToCrownJewels: paths.toCrownJewels,
    privilegedWithoutMfa: posture.identities.privilegedWithoutMfa,
    internetFacingCritical: vulns.internetFacingCriticalOpen,
    slaAttainmentPct: sla.overall.attainmentPct,
    overdueVulnerabilities: vulns.overdueSla,
    unresponsiveAgents: posture.agents.unresponsive,
    silentLogSources: posture.logSources.silent,
  });

  const riskDir = posture.riskScore !== null && prevPosture.riskScore !== null ? (posture.riskScore > prevPosture.riskScore + 1 ? "increased" : posture.riskScore < prevPosture.riskScore - 1 ? "decreased" : "held steady") : null;
  const headline =
    detected.length === 0
      ? `No incidents were detected; ${posture.riskScore !== null ? `the overall risk score is ${Math.round(posture.riskScore)}/100` : "posture data is limited"}.`
      : `${plural(detected.length, "incident")} handled (${severityPhrase(sev)}); ${sla.overall.attainmentPct !== null ? `${formatPercent(sla.overall.attainmentPct)} of SLA objectives met` : "no SLA objectives fell due"}${riskDir ? `, overall risk ${riskDir}` : ""}.`;

  const highlights = [
    `${formatNumber(events.total, { compact: true })} security events analysed and ${formatNumber(alerts.total)} alerts triaged.`,
    `Incident volume ${changePhrase(detected.length, prevDetected.length)} versus the previous period.`,
    timings.mttr.mean !== null ? `Incidents were resolved in ${formatDuration(timings.mttr.mean)} on average.` : null,
    vulns.knownExploitedOpen > 0 ? `${plural(vulns.knownExploitedOpen, "known-exploited vulnerability", "known-exploited vulnerabilities")} remain open.` : "No known-exploited vulnerabilities are open.",
    paths.toCrownJewels > 0 ? `${plural(paths.toCrownJewels, "attack path")} lead to crown-jewel assets.` : null,
    esc.overdueOpen > 0 ? `${plural(esc.overdueOpen, "escalation")} awaiting action are overdue.` : null,
  ].filter((h): h is string => h !== null);

  const buckets = timeBuckets(from, to);
  const trendCats = trend.map((p) => p.date.slice(5).replace("-", "/"));
  const risks: RiskItem[] = [
    ...riskyAssets.map((a) => ({ id: `asset-${a.id}`, title: a.name, subject: `${a.kind.replace(/_/g, " ")} · ${a.criticality.replace("_", " ")} criticality · ${ctx.orgName(a.organizationId)}`, severity: severityFromScore(a.riskScore), score: a.riskScore, factors: a.factors, recommendation: a.openCriticalVulnerabilities > 0 ? `Remediate ${plural(a.openCriticalVulnerabilities, "critical vulnerability", "critical vulnerabilities")} on this asset.` : a.openIncidents > 0 ? `Close ${plural(a.openIncidents, "open incident")} involving this asset.` : null })),
    ...paths.top.slice(0, 3).map((p) => ({ id: `path-${p.id}`, title: `Attack path: ${p.entry} → ${p.target}`, subject: `${p.hops} hops · ${ctx.orgName(p.organizationId)}`, severity: p.severity, score: p.score, factors: p.factors, recommendation: p.remediation })),
  ]
    .sort((a, b) => b.score - a.score)
    .slice(0, topN);

  const techniques = topTechniques(detected, alerts.topTechniques, 8);
  const notable = [...detected].sort((a, b) => b.riskScore - a.riskScore).slice(0, topN);

  return {
    title: "Executive security summary",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · ${ctx.period.label}` : `${ctx.organizations.length} organizations · ${ctx.period.label}`,
    summary: { headline, highlights, kpis },
    recommendations,
    terms: ["Risk score", "Exposure score", "MTTD", "MTTR", "SLA attainment", "KEV", "Trend vs previous period"],
    sections: [
      {
        id: "summary",
        title: "Executive summary",
        description: "Where we stand, what changed and what needs a decision.",
        blocks: [
          narrative([
            `${headline}`,
            `Over ${ctx.period.label}, the security operations centre analysed ${formatNumber(events.total, { compact: true })} events, triaged ${formatNumber(alerts.total)} alerts and opened ${plural(detected.length, "incident")}. ${openAtEnd.length > 0 ? `${plural(openAtEnd.length, "incident")} ${openAtEnd.length === 1 ? "remains" : "remain"} active at period end.` : "No incidents remain active at period end."}`,
            posture.riskScore !== null ? `The overall risk score is ${Math.round(posture.riskScore)}/100${prevPosture.riskScore !== null ? ` (${changePhrase(posture.riskScore, prevPosture.riskScore)} from ${Math.round(prevPosture.riskScore)})` : ""}; open critical and high vulnerabilities ${changePhrase(openCritHigh, prevOpenCritHigh)} to ${formatNumber(openCritHigh)}.` : null,
            recommendations.length > 0 ? `${plural(recommendations.length, "recommendation")} follow; the first ${Math.min(3, recommendations.length)} carry the largest risk reduction.` : "No corrective actions are required this period.",
          ]),
          { kind: "kpis", items: kpis },
          { kind: "recommendations", title: "Decisions and actions", items: recommendations.slice(0, 6), emptyMessage: "No corrective actions are required this period." },
        ],
      },
      {
        id: "risk",
        title: "Risk posture",
        description: "How exposed the business is, and the specific risks driving the score.",
        blocks: [
          chart(lineChart("risk-trend", "Risk and exposure score", trendCats, [
            { key: "risk", name: "Risk score", values: trend.map((p) => p.riskScore) },
            { key: "exposure", name: "Exposure score", values: trend.map((p) => p.exposureScore) },
          ], "score", { subtitle: "0-100, lower is better" })),
          ...(paths.toCrownJewels > 0
            ? [{ kind: "callout" as const, tone: "critical" as const, title: `${plural(paths.toCrownJewels, "attack path")} to crown jewels`, text: "Exploitable chains connect exposed entry points to your most critical assets. Breaking them is the single most effective risk reduction available." }]
            : []),
          { kind: "risks", title: "Top risks", items: risks, emptyMessage: "No scored assets or attack paths in scope." },
        ],
      },
      {
        id: "threats",
        title: "Threat activity",
        description: "Incidents over time, their severity and the attacker techniques observed.",
        blocks: [
          chart(severityStacked("incidents-over-time", "Incidents detected", buckets, bucketBySeverity(detected, (i) => i.detectedAt, buckets), { subtitle: `per ${buckets.granularity}` })),
          chart(severityDonut("incidents-by-severity", "Incidents by severity", sev)),
          chart(hbar("top-techniques", "Most observed ATT&CK techniques", techniques.map((t) => ({ name: t.name ? `${t.id} ${t.name}` : t.id, count: t.count })), { seriesName: "Observations" })),
          table(
            "notable-incidents",
            "Most significant incidents",
            [
              { key: "number", label: "#", format: "number", width: 0.5 },
              { key: "title", label: "Incident", width: 3 },
              { key: "organization", label: "Organization", width: 1.5 },
              { key: "severity", label: "Severity", format: "severity" },
              { key: "risk", label: "Risk", format: "score", align: "right" },
              { key: "status", label: "Status", format: "status" },
              { key: "detectedAt", label: "Detected", format: "date" },
            ],
            notable.map((i) => ({ number: i.number, title: i.title, organization: ctx.orgName(i.organizationId), severity: i.severity, risk: i.riskScore, status: i.status, detectedAt: i.detectedAt })),
            { totalRows: detected.length, emptyMessage: "No incidents were detected in this period." },
          ),
        ],
      },
      {
        id: "exposure",
        title: "Vulnerability exposure",
        description: "Open vulnerabilities at period end and how quickly they are fixed.",
        blocks: [
          {
            kind: "kpis",
            items: [
              kpi({ key: "open_crit_high", label: "Open critical + high", value: openCritHigh, unit: "count", previous: prevOpenCritHigh, betterWhen: "lower", explanation: "Open critical and high severity vulnerabilities at period end." }),
              kpi({ key: "overdue", label: "Past remediation SLA", value: vulns.overdueSla, unit: "count", previous: prevVulns.overdueSla, betterWhen: "lower", explanation: "Open vulnerabilities whose remediation due date has passed." }),
              kpi({ key: "mttrem", label: "Mean time to remediate", value: vulns.meanTimeToRemediateDays, unit: "days", previous: prevVulns.meanTimeToRemediateDays, betterWhen: "lower", explanation: "Mean days from detection to resolution for vulnerabilities resolved in the period." }),
            ],
          },
          chart(severityDonut("vulns-by-severity", "Open vulnerabilities by severity", vulns.openBySeverity)),
          table(
            "top-vulns",
            "Highest-risk vulnerabilities",
            [
              { key: "cve", label: "CVE", format: "code" },
              { key: "title", label: "Vulnerability", width: 2.5 },
              { key: "asset", label: "Asset", width: 1.5 },
              { key: "severity", label: "Severity", format: "severity" },
              { key: "kev", label: "KEV", format: "status" },
              { key: "risk", label: "Risk", format: "score", align: "right" },
            ],
            topVulns.map((v) => ({ cve: v.cve ?? "—", title: v.title, asset: v.assetName, severity: v.severity, kev: v.knownExploited ? "exploited" : "no", risk: v.riskScore })),
            { emptyMessage: "No open vulnerabilities." },
          ),
        ],
      },
      {
        id: "operations",
        title: "Security operations performance",
        description: "Speed and reliability of detection and response.",
        blocks: [
          {
            kind: "kpis",
            items: [
              kpi({ key: "mttd", label: "Mean time to detect", value: timings.mttd.mean, unit: "minutes", previous: prevTimings.mttd.mean, betterWhen: "lower", explanation: `First malicious activity → detection, ${timings.mttd.n} incidents.` }),
              kpi({ key: "mtta", label: "Mean time to acknowledge", value: timings.mtta.mean, unit: "minutes", previous: prevTimings.mtta.mean, betterWhen: "lower", explanation: `Detection → analyst acknowledgement, ${timings.mtta.n} incidents.` }),
              kpi({ key: "mttc", label: "Mean time to contain", value: timings.mttc.mean, unit: "minutes", previous: prevTimings.mttc.mean, betterWhen: "lower", explanation: `Detection → containment, ${timings.mttc.n} incidents.` }),
              kpi({ key: "coverage", label: "Endpoint protection coverage", value: coverage, unit: "percent", betterWhen: "higher", target: 98, thresholds: { good: 98, warn: 90 }, explanation: `${posture.agents.protected} of ${posture.agents.total} agents reporting healthy at period end.` }),
              kpi({ key: "escalations_on_time", label: "Escalations resolved on time", value: esc.onTimePct, unit: "percent", betterWhen: "higher", explanation: `${esc.onTime} on time, ${esc.late} late, ${esc.overdueOpen} overdue and still open.` }),
              kpi({ key: "automation", label: "Automated response actions", value: response.automated, unit: "count", betterWhen: "neutral", explanation: `${response.playbookRuns} playbook runs (${response.playbookSucceeded} succeeded)${response.estimatedMinutesSaved !== null ? `, ~${formatDuration(response.estimatedMinutesSaved)} analyst time saved` : ""}.` }),
            ],
          },
          narrative([
            `Detection-to-resolution performance: MTTA ${formatDuration(timings.mtta.mean)}, MTTC ${formatDuration(timings.mttc.mean)}, MTTR ${formatDuration(timings.mttr.mean)}. ${sla.overall.breached > 0 ? `${plural(sla.overall.breached, "SLA objective")} ${sla.overall.breached === 1 ? "was" : "were"} breached.` : "No SLA objectives were breached."}`,
            round(coverage) !== null && coverage! < 98 ? `Endpoint protection coverage is ${formatPercent(coverage)}; unprotected devices are blind spots for detection and response.` : null,
          ]),
        ],
      },
    ],
  };
}
