import { ACTIVE_INCIDENT_STATUSES, type Severity } from "@bloody/contracts";
import { CATEGORICAL } from "../branding.js";
import { formatDuration, formatNumber, formatPercent } from "../format.js";
import { bucketBySeverity, bucketDaily, countBySeverity, incidentTimings, inWindow, kpi, minutesBetween, percent, SEVERITIES_DESC, timeBuckets, topTechniques } from "../metrics.js";
import { evaluateIncidentSla } from "../sla.js";
import { barChart, chart, changePhrase, hbar, lineChart, narrative, plural, severityStacked, table, topNamed } from "./blocks.js";
import { SEVERITY_LABEL, type BuildContext, type BuilderResult } from "./context.js";
import { deriveRecommendations } from "./recommendations.js";

/** SOC operations — volumes, funnel, response times by severity, detection quality, backlog, automation. */
export async function buildSocOperations(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, from, to, topN } = ctx;
  const [incidents, prevIncidents, alerts, prevAlerts, events, prevEvents, response, posture] = await Promise.all([
    ds.incidents(q),
    ds.incidents(prev),
    ds.alertStats(q),
    ds.alertStats(prev),
    ds.eventStats(q),
    ds.eventStats(prev),
    ds.responseStats(q),
    ds.posture(q),
  ]);
  const detected = incidents.filter((i) => inWindow(i.detectedAt, from, to));
  const prevDetected = prevIncidents.filter((i) => inWindow(i.detectedAt, prev.from, prev.to));
  const t = incidentTimings(incidents, from, to);
  const pt = incidentTimings(prevIncidents, prev.from, prev.to);
  const fpRate = percent(alerts.falsePositives, alerts.total);
  const prevFpRate = percent(prevAlerts.falsePositives, prevAlerts.total);
  const backlog = incidents.filter((i) => ACTIVE_INCIDENT_STATUSES.includes(i.status) && Date.parse(i.detectedAt) < to.getTime() && (!i.closedAt || Date.parse(i.closedAt) >= to.getTime()));
  const aged = backlog.filter((i) => minutesBetween(i.detectedAt, to) > 7 * 1440);
  const sla = evaluateIncidentSla(detected, ctx.slaTargetsFor, to);
  const signalRatio = events.total > 0 ? alerts.total / events.total : null;
  const promoteRate = percent(alerts.promoted, alerts.total);

  const kpis = [
    kpi({ key: "events", label: "Events analysed", value: events.total, unit: "count", previous: prevEvents.total, betterWhen: "neutral", explanation: "Normalised security events ingested during the period." }),
    kpi({ key: "alerts", label: "Alerts", value: alerts.total, unit: "count", previous: prevAlerts.total, betterWhen: "neutral", explanation: "Detections raised by the detection engine and integrated sources." }),
    kpi({ key: "incidents", label: "Incidents", value: detected.length, unit: "count", previous: prevDetected.length, betterWhen: "lower", explanation: "Incidents created by correlation or analysts." }),
    kpi({ key: "fp_rate", label: "False-positive rate", value: fpRate, unit: "percent", previous: prevFpRate, betterWhen: "lower", thresholds: { good: 20, warn: 40 }, explanation: `${alerts.falsePositives} of ${alerts.total} alerts closed as false positive.` }),
    kpi({ key: "mtta", label: "MTTA", value: t.mtta.mean, unit: "minutes", previous: pt.mtta.mean, betterWhen: "lower", explanation: `Mean detection → acknowledgement over ${t.mtta.n} incidents (median ${formatDuration(t.mtta.median)}).` }),
    kpi({ key: "mttr", label: "MTTR", value: t.mttr.mean, unit: "minutes", previous: pt.mttr.mean, betterWhen: "lower", explanation: `Mean detection → closure over ${t.mttr.n} incidents closed in the period (median ${formatDuration(t.mttr.median)}).` }),
    kpi({ key: "backlog", label: "Open incidents at period end", value: backlog.length, unit: "count", betterWhen: "lower", explanation: `${aged.length} of them open for more than 7 days.` }),
    kpi({ key: "sla", label: "SLA attainment", value: sla.overall.attainmentPct, unit: "percent", betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `${sla.overall.met} met, ${sla.overall.breached} breached, ${sla.overall.pending} not yet due.` }),
  ];

  const noisy = [...alerts.topRules].filter((r) => r.count >= 5).sort((a, b) => b.falsePositives / b.count - a.falsePositives / a.count).filter((r) => r.falsePositives / r.count > 0.5);
  const recommendations = deriveRecommendations({
    audience: "soc",
    falsePositiveRatePct: fpRate,
    noisyRules: noisy.map((r) => r.name),
    backlogOlderThan7d: aged.length,
    slaAttainmentPct: sla.overall.attainmentPct,
    mttaMinutes: t.mtta.mean,
    mttaTargetMinutes: 60,
    silentLogSources: posture.logSources.silent,
    unresponsiveAgents: posture.agents.unresponsive,
    playbookFailures: response.playbookFailed,
    pendingApprovals: response.pendingApproval,
  });

  const buckets = timeBuckets(from, to);
  const timingRows = SEVERITIES_DESC.filter((s) => s !== "info").map((s: Severity) => {
    const subset = incidents.filter((i) => i.severity === s);
    const st = incidentTimings(subset, from, to);
    const b = sla.bySeverity[s];
    return {
      severity: s,
      incidents: subset.filter((i) => inWindow(i.detectedAt, from, to)).length,
      mttaMedian: st.mtta.median,
      mttaP90: st.mtta.p90,
      mttcMedian: st.mttc.median,
      mttrMedian: st.mttr.median,
      mttrP90: st.mttr.p90,
      ackSla: b.acknowledge.attainmentPct,
      resolveSla: b.resolve.attainmentPct,
    };
  });

  const ruleRows = topNamed(alerts.topRules.map((r) => ({ name: r.ruleId, count: r.count })), topN).map((nc) => {
    const r = alerts.topRules.find((x) => x.ruleId === nc.name)!;
    const fp = r.count > 0 ? (r.falsePositives / r.count) * 100 : null;
    return { rule: r.name, alerts: r.count, falsePositives: r.falsePositives, fpRate: fp, action: fp !== null && fp > 50 ? "tune" : fp !== null && fp > 25 ? "review" : "ok" };
  });

  const techniques = topTechniques(detected, alerts.topTechniques, topN);
  const backlogRows = [...backlog]
    .sort((a, b) => a.detectedAt.localeCompare(b.detectedAt))
    .slice(0, topN)
    .map((i) => ({ number: i.number, title: i.title, organization: ctx.orgName(i.organizationId), severity: i.severity, status: i.status, assignee: i.assigneeName ?? "unassigned", age: minutesBetween(i.detectedAt, to) }));

  const headline = `${formatNumber(events.total, { compact: true })} events → ${formatNumber(alerts.total)} alerts → ${plural(detected.length, "incident")}; MTTA ${formatDuration(t.mtta.mean)}, MTTR ${formatDuration(t.mttr.mean)}.`;

  return {
    title: "SOC operations report",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · ${ctx.period.label}` : `${ctx.organizations.length} organizations · ${ctx.period.label}`,
    summary: {
      headline,
      highlights: [
        `Alert volume ${changePhrase(alerts.total, prevAlerts.total)}; incident volume ${changePhrase(detected.length, prevDetected.length)}.`,
        fpRate !== null ? `False-positive rate ${formatPercent(fpRate)} (${prevFpRate !== null ? `previously ${formatPercent(prevFpRate)}` : "no previous data"}).` : "No alerts were raised.",
        `${plural(backlog.length, "incident")} open at period end, ${aged.length} older than 7 days.`,
        response.playbookRuns > 0 ? `${plural(response.playbookRuns, "playbook run")}, ${formatPercent(percent(response.playbookSucceeded, response.playbookRuns))} successful.` : "No playbooks ran.",
      ],
      kpis,
    },
    recommendations,
    terms: ["MTTA", "MTTC", "MTTR", "SLA attainment", "False-positive rate", "Trend vs previous period"],
    sections: [
      {
        id: "overview",
        title: "Operations overview",
        blocks: [
          { kind: "kpis", items: kpis },
          narrative([
            headline,
            signalRatio !== null ? `Signal-to-noise: one alert per ${formatNumber(Math.round(1 / Math.max(signalRatio, 1e-9)))} events; ${formatPercent(promoteRate)} of alerts were promoted to incidents.` : null,
          ]),
          { kind: "recommendations", title: "Operational actions", items: recommendations, emptyMessage: "No operational issues detected." },
        ],
      },
      {
        id: "volume",
        title: "Detection funnel and volume",
        description: "Events and alerts over time, and where they come from.",
        blocks: [
          chart(barChart("alerts-over-time", "Alerts", buckets.labels, [{ key: "alerts", name: "Alerts", values: bucketDaily(alerts.daily, buckets) }], "count", { subtitle: `per ${buckets.granularity}` })),
          chart(lineChart("events-over-time", "Events analysed", buckets.labels, [{ key: "events", name: "Events", values: bucketDaily(events.daily, buckets), color: CATEGORICAL[0] }], "count", { subtitle: `per ${buckets.granularity}` })),
          chart(severityStacked("incidents-over-time", "Incidents by severity", buckets, bucketBySeverity(detected, (i) => i.detectedAt, buckets))),
          chart(hbar("alerts-by-source", "Alerts by source", topNamed(alerts.bySource, 8), { seriesName: "Alerts" })),
        ],
      },
      {
        id: "response-times",
        title: "Response times by severity",
        description: "Medians and 90th percentiles are shown because averages hide long tails.",
        blocks: [
          table(
            "timings",
            "Response times",
            [
              { key: "severity", label: "Severity", format: "severity" },
              { key: "incidents", label: "Incidents", format: "number", align: "right" },
              { key: "mttaMedian", label: "Ack (median)", format: "minutes", align: "right" },
              { key: "mttaP90", label: "Ack (p90)", format: "minutes", align: "right" },
              { key: "mttcMedian", label: "Contain (median)", format: "minutes", align: "right" },
              { key: "mttrMedian", label: "Resolve (median)", format: "minutes", align: "right" },
              { key: "mttrP90", label: "Resolve (p90)", format: "minutes", align: "right" },
              { key: "ackSla", label: "Ack SLA", format: "percent", align: "right" },
              { key: "resolveSla", label: "Resolve SLA", format: "percent", align: "right" },
            ],
            timingRows,
          ),
          chart(barChart("sla-by-severity", "SLA attainment by severity", timingRows.map((r) => SEVERITY_LABEL[r.severity]), [
            { key: "ack", name: "Acknowledge", values: timingRows.map((r) => r.ackSla) },
            { key: "resolve", name: "Resolve", values: timingRows.map((r) => r.resolveSla) },
          ], "percent")),
        ],
      },
      {
        id: "quality",
        title: "Detection quality and tuning",
        description: "Rules ranked by volume with their false-positive rates; 'tune' marks rules where most alerts were false positives.",
        blocks: [
          table(
            "rules",
            "Top detection rules",
            [
              { key: "rule", label: "Rule", width: 3 },
              { key: "alerts", label: "Alerts", format: "number", align: "right" },
              { key: "falsePositives", label: "False positives", format: "number", align: "right" },
              { key: "fpRate", label: "FP rate", format: "percent", align: "right" },
              { key: "action", label: "Action", format: "status" },
            ],
            ruleRows,
            { totalRows: alerts.topRules.length, emptyMessage: "No rule activity in this period." },
          ),
          chart(hbar("techniques", "Top ATT&CK techniques", techniques.map((x) => ({ name: x.name ? `${x.id} ${x.name}` : x.id, count: x.count })), { seriesName: "Observations" })),
        ],
      },
      {
        id: "backlog",
        title: "Incident backlog",
        description: "Open incidents at period end, oldest first.",
        blocks: [
          table(
            "backlog",
            "Open incidents",
            [
              { key: "number", label: "#", format: "number", width: 0.5 },
              { key: "title", label: "Incident", width: 3 },
              { key: "organization", label: "Organization", width: 1.4 },
              { key: "severity", label: "Severity", format: "severity" },
              { key: "status", label: "Status", format: "status" },
              { key: "assignee", label: "Assignee", width: 1.2 },
              { key: "age", label: "Age", format: "minutes", align: "right" },
            ],
            backlogRows,
            { totalRows: backlog.length, emptyMessage: "The backlog is empty." },
          ),
        ],
      },
      {
        id: "automation",
        title: "Response and automation",
        blocks: [
          {
            kind: "kpis",
            items: [
              kpi({ key: "actions", label: "Response actions", value: response.actionsTotal, unit: "count", betterWhen: "neutral", explanation: `${response.automated} automated, ${response.manual} manual, ${response.aiInitiated} proposed by the AI analyst.` }),
              kpi({ key: "playbooks", label: "Playbook success rate", value: percent(response.playbookSucceeded, response.playbookRuns), unit: "percent", betterWhen: "higher", explanation: `${response.playbookSucceeded} of ${response.playbookRuns} playbook runs succeeded.` }),
              kpi({ key: "approval_time", label: "Mean approval time", value: response.meanApprovalMinutes, unit: "minutes", betterWhen: "lower", explanation: "Mean time from approval request to decision for gated actions." }),
              kpi({ key: "saved", label: "Analyst time saved", value: response.estimatedMinutesSaved, unit: "minutes", betterWhen: "higher", explanation: "Estimated from per-action effort configured by the tenant." }),
            ],
          },
          chart(hbar("actions-by-type", "Response actions by type", topNamed(response.byAction, 10), { seriesName: "Actions" })),
        ],
      },
    ],
  };
}
