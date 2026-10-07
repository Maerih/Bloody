import { severityFromScore } from "@bloody/contracts";
import { defang, formatDateTime, formatDuration, formatNumber } from "../format.js";
import { countBySeverity, incidentTimings, inWindow, kpi, minutesBetween, topTechniques } from "../metrics.js";
import type { ReportSection } from "../model.js";
import { evaluateIncidentSla } from "../sla.js";
import { barChart, chart, hbar, narrative, plural, severityDonut, severityPhrase, table, topNamed } from "./blocks.js";
import { ReportRequestError, type BuildContext, type BuilderResult } from "./context.js";

/** Incident report — a post-incident report for one incident, or a period incident summary. */
export async function buildIncident(ctx: BuildContext): Promise<BuilderResult> {
  return ctx.options.incidentId ? buildPostIncident(ctx, ctx.options.incidentId) : buildIncidentSummary(ctx);
}

async function buildPostIncident(ctx: BuildContext, incidentId: string): Promise<BuilderResult> {
  const detail = await ctx.ds.incidentDetail(ctx.q, incidentId);
  if (!detail) throw new ReportRequestError("incident not found in this scope");
  const inc = detail.incident;
  const targets = ctx.slaTargetsFor(inc.organizationId);
  const sla = evaluateIncidentSla([inc], () => targets, ctx.now).incidents[0]!;
  const ttd = inc.firstActivityAt ? minutesBetween(inc.firstActivityAt, inc.detectedAt) : null;
  const tta = inc.acknowledgedAt ? minutesBetween(inc.detectedAt, inc.acknowledgedAt) : null;
  const ttc = inc.containedAt ? minutesBetween(inc.detectedAt, inc.containedAt) : null;
  const ttr = inc.closedAt ? minutesBetween(inc.detectedAt, inc.closedAt) : null;
  if (ttd === null) ctx.notes.push("Time to detect is unavailable: the first malicious activity time is unknown.");

  const kpis = [
    kpi({ key: "risk", label: "Risk score", value: inc.riskScore, unit: "score", betterWhen: "lower", explanation: "Risk Engine incident score at report time." }),
    kpi({ key: "ttd", label: "Time to detect", value: ttd, unit: "minutes", betterWhen: "lower", explanation: "First malicious activity → detection." }),
    kpi({ key: "tta", label: "Time to acknowledge", value: tta, unit: "minutes", betterWhen: "lower", target: targets.acknowledgeMinutes[inc.severity], explanation: `SLA objective ${formatDuration(targets.acknowledgeMinutes[inc.severity])} for ${inc.severity} incidents (${sla.acknowledge.outcome}).` }),
    kpi({ key: "ttc", label: "Time to contain", value: ttc, unit: "minutes", betterWhen: "lower", explanation: "Detection → containment." }),
    kpi({ key: "ttr", label: "Time to resolve", value: ttr, unit: "minutes", betterWhen: "lower", target: targets.resolveMinutes[inc.severity], explanation: `SLA objective ${formatDuration(targets.resolveMinutes[inc.severity])} (${sla.resolve.outcome}).` }),
    kpi({ key: "scope", label: "Affected assets", value: detail.assets.length, unit: "count", betterWhen: "lower", explanation: `${detail.identities.length} identities and ${detail.assets.length} assets linked in the Security Graph.` }),
  ].map((k) => ({ ...k, status: k.key === "tta" ? (sla.acknowledge.outcome === "breached" ? ("bad" as const) : sla.acknowledge.outcome === "met" ? ("good" as const) : null) : k.key === "ttr" ? (sla.resolve.outcome === "breached" ? ("bad" as const) : sla.resolve.outcome === "met" ? ("good" as const) : null) : k.status }));

  const sections: ReportSection[] = [
    {
      id: "overview",
      title: "Incident overview",
      blocks: [
        { kind: "kpis", items: kpis },
        narrative([
          `Incident #${inc.number} "${inc.title}" affecting ${ctx.orgName(inc.organizationId)} was detected on ${formatDateTime(inc.detectedAt, ctx.timeZone)} with ${inc.severity} severity and is currently ${inc.status.replace(/_/g, " ")}.`,
          inc.summary,
          detail.rootCause ? `Root cause: ${detail.rootCause}` : null,
          sla.reasons.length > 0 ? `SLA: ${sla.reasons.join("; ")}.` : "All applicable SLA objectives were met.",
        ]),
        ...(inc.riskFactors && inc.riskFactors.length > 0
          ? [{ kind: "risks" as const, title: "Why this incident scored as it did", items: [{ id: inc.id, title: inc.title, subject: `Incident #${inc.number}`, severity: severityFromScore(inc.riskScore), score: inc.riskScore, factors: inc.riskFactors, recommendation: null }] }]
          : []),
      ],
    },
    {
      id: "timeline",
      title: "Timeline",
      blocks: [
        table(
          "timeline",
          "Timeline of events",
          [
            { key: "at", label: "Time", format: "datetime", width: 1.4 },
            { key: "kind", label: "Type", format: "status" },
            { key: "title", label: "What happened", width: 4 },
            { key: "actor", label: "Actor", width: 1.2 },
          ],
          [...detail.timeline].sort((a, b) => a.at.localeCompare(b.at)).map((e) => ({ at: e.at, kind: e.kind, title: e.title, actor: e.actor ?? "system" })),
          { emptyMessage: "No timeline entries were recorded." },
        ),
      ],
    },
    {
      id: "scope",
      title: "Scope and impact",
      blocks: [
        table("assets", "Affected assets", [
          { key: "name", label: "Asset", width: 2 },
          { key: "kind", label: "Type" },
          { key: "criticality", label: "Criticality", format: "status" },
          { key: "risk", label: "Risk", format: "score", align: "right" },
        ], detail.assets.map((a) => ({ name: a.name, kind: a.kind.replace(/_/g, " "), criticality: a.criticality, risk: a.riskScore })), { emptyMessage: "No assets linked." }),
        table("identities", "Involved identities", [
          { key: "principal", label: "Identity", width: 2 },
          { key: "provider", label: "Provider" },
          { key: "privileged", label: "Privileged", format: "status" },
          { key: "mfa", label: "MFA", format: "status" },
        ], detail.identities.map((i) => ({ principal: i.principal, provider: i.provider, privileged: i.privileged ? "yes" : "no", mfa: i.mfaEnabled ? "enabled" : "missing" })), { emptyMessage: "No identities linked." }),
        table("indicators", "Indicators of compromise (defanged)", [
          { key: "type", label: "Type", format: "code" },
          { key: "value", label: "Value", format: "code", width: 3 },
          { key: "source", label: "Source" },
        ], detail.indicators.map((i) => ({ type: i.type, value: defang(i.value), source: i.source ?? "investigation" })), { emptyMessage: "No indicators recorded." }),
        table("techniques", "MITRE ATT&CK techniques", [
          { key: "id", label: "Technique", format: "code" },
          { key: "name", label: "Name", width: 2 },
          { key: "tactic", label: "Tactic" },
        ], inc.attack.map((a) => ({ id: a.id, name: a.name ?? "—", tactic: a.tactic ?? "—" })), { emptyMessage: "No techniques mapped." }),
      ],
    },
    {
      id: "response",
      title: "Response",
      blocks: [
        table("actions", "Response actions", [
          { key: "at", label: "Time", format: "datetime", width: 1.4 },
          { key: "action", label: "Action", format: "status" },
          { key: "target", label: "Target", width: 1.6 },
          { key: "status", label: "Result", format: "status" },
          { key: "requestedBy", label: "Requested by" },
          { key: "approvedBy", label: "Approved by" },
        ], detail.actions.map((a) => ({ at: a.at, action: a.action, target: a.target, status: a.status, requestedBy: a.requestedBy, approvedBy: a.approvedBy ?? "—" })), { emptyMessage: "No response actions were taken.", note: "High-risk actions require approval by a different person; approvals are recorded in the audit log." }),
        table("evidence", "Evidence (chain of custody)", [
          { key: "name", label: "Item", width: 1.6 },
          { key: "kind", label: "Type" },
          { key: "sha256", label: "SHA-256", format: "code", width: 3 },
          { key: "collectedBy", label: "Collected by" },
          { key: "at", label: "Collected", format: "datetime" },
        ], detail.evidence.map((e) => ({ name: e.name, kind: e.kind, sha256: e.sha256, collectedBy: e.collectedBy, at: e.at })), { emptyMessage: "No evidence items were collected." }),
      ],
    },
    {
      id: "lessons",
      title: "Lessons learned",
      blocks: [
        detail.lessonsLearned.length > 0
          ? { kind: "recommendations", items: detail.lessonsLearned.map((l) => ({ priority: "medium" as const, title: l, rationale: "Recorded during the post-incident review.", owner: null })) }
          : narrative(["No lessons learned have been recorded yet. Complete the post-incident review to capture improvements."], { tone: "note" }),
      ],
    },
  ];

  return {
    title: `Incident report #${inc.number}`,
    subtitle: `${inc.title} · ${ctx.orgName(inc.organizationId)}`,
    summary: {
      headline: `${inc.severity.charAt(0).toUpperCase()}${inc.severity.slice(1)} incident "${inc.title}" — ${inc.status.replace(/_/g, " ")}${ttr !== null ? `, resolved in ${formatDuration(ttr)}` : ""}.`,
      highlights: [
        `Detected ${formatDateTime(inc.detectedAt, ctx.timeZone)}${ttd !== null ? `, ${formatDuration(ttd)} after first malicious activity` : ""}.`,
        `${plural(detail.assets.length, "asset")} and ${plural(detail.identities.length, "identity", "identities")} affected; ${plural(detail.actions.length, "response action")} taken.`,
        inc.attack.length > 0 ? `Techniques: ${inc.attack.map((a) => a.id).join(", ")}.` : "No ATT&CK techniques mapped.",
      ],
      kpis,
    },
    recommendations: [],
    terms: ["MTTD", "MTTA", "MTTC", "MTTR", "SLA attainment", "Risk score"],
    sections,
  };
}

async function buildIncidentSummary(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, from, to, topN } = ctx;
  const [incidents, prevIncidents, alerts] = await Promise.all([ds.incidents(q), ds.incidents(prev), ds.alertStats(q)]);
  const detected = incidents.filter((i) => inWindow(i.detectedAt, from, to));
  const prevDetected = prevIncidents.filter((i) => inWindow(i.detectedAt, prev.from, prev.to));
  const sev = countBySeverity(detected);
  const t = incidentTimings(incidents, from, to);
  const pt = incidentTimings(prevIncidents, prev.from, prev.to);
  const sla = evaluateIncidentSla(detected, ctx.slaTargetsFor, to);
  const closed = incidents.filter((i) => inWindow(i.closedAt, from, to));
  const fps = detected.filter((i) => i.status === "false_positive").length;
  const statusCounts = new Map<string, number>();
  for (const i of detected) statusCounts.set(i.status, (statusCounts.get(i.status) ?? 0) + 1);
  const byOrg = new Map<string, number>();
  for (const i of detected) byOrg.set(i.organizationId, (byOrg.get(i.organizationId) ?? 0) + 1);
  const techniques = topTechniques(detected, alerts.topTechniques, topN);

  const kpis = [
    kpi({ key: "incidents", label: "Incidents detected", value: detected.length, unit: "count", previous: prevDetected.length, betterWhen: "lower", explanation: "Incidents detected in the period." }),
    kpi({ key: "closed", label: "Incidents closed", value: closed.length, unit: "count", betterWhen: "higher", explanation: "Incidents closed in the period (including older ones)." }),
    kpi({ key: "critical", label: "Critical", value: sev.critical, unit: "count", previous: countBySeverity(prevDetected).critical, betterWhen: "lower", explanation: "Critical incidents detected." }),
    kpi({ key: "mttc", label: "Mean time to contain", value: t.mttc.mean, unit: "minutes", previous: pt.mttc.mean, betterWhen: "lower", explanation: `Detection → containment over ${t.mttc.n} incidents.` }),
    kpi({ key: "mttr", label: "Mean time to resolve", value: t.mttr.mean, unit: "minutes", previous: pt.mttr.mean, betterWhen: "lower", explanation: `Detection → closure over ${t.mttr.n} incidents.` }),
    kpi({ key: "sla", label: "SLA attainment", value: sla.overall.attainmentPct, unit: "percent", betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `${sla.overall.met} of ${sla.overall.met + sla.overall.breached} due objectives met.` }),
  ];

  const rows = [...detected]
    .sort((a, b) => b.riskScore - a.riskScore || a.detectedAt.localeCompare(b.detectedAt))
    .slice(0, Math.max(topN, 25))
    .map((i) => {
      const s = sla.incidents.find((r) => r.incident.id === i.id)!;
      return {
        number: i.number,
        title: i.title,
        organization: ctx.orgName(i.organizationId),
        severity: i.severity,
        status: i.status,
        detectedAt: i.detectedAt,
        ttr: i.closedAt ? minutesBetween(i.detectedAt, i.closedAt) : null,
        sla: s.acknowledge.outcome === "breached" || s.resolve.outcome === "breached" ? "breached" : s.resolve.outcome === "pending" ? "pending" : "met",
        assignee: i.assigneeName ?? "unassigned",
      };
    });

  return {
    title: "Incident report",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · ${ctx.period.label}` : `${ctx.organizations.length} organizations · ${ctx.period.label}`,
    summary: {
      headline: detected.length === 0 ? "No incidents were detected in this period." : `${plural(detected.length, "incident")} detected (${severityPhrase(sev)}); ${closed.length} closed; ${fps} false positives.`,
      highlights: [
        `Mean time to resolve ${formatDuration(t.mttr.mean)}; mean time to contain ${formatDuration(t.mttc.mean)}.`,
        `${sla.overall.breached} SLA objectives breached.`,
        techniques[0] ? `Most observed technique: ${techniques[0].id}${techniques[0].name ? ` ${techniques[0].name}` : ""} (${formatNumber(techniques[0].count)}).` : "No techniques mapped.",
      ],
      kpis,
    },
    recommendations: [],
    terms: ["MTTC", "MTTR", "SLA attainment"],
    sections: [
      {
        id: "overview",
        title: "Overview",
        blocks: [
          { kind: "kpis", items: kpis },
          chart(severityDonut("by-severity", "Incidents by severity", sev)),
          chart(barChart("by-status", "Incidents by current status", [...statusCounts.keys()].map((s) => s.replace(/_/g, " ")), [{ key: "count", name: "Incidents", values: [...statusCounts.values()] }], "count")),
          ...(byOrg.size > 1 ? [chart(hbar("by-org", "Incidents by organization", topNamed([...byOrg.entries()].map(([id, count]) => ({ name: ctx.orgName(id), count })), 10), { seriesName: "Incidents" }))] : []),
        ],
      },
      {
        id: "incidents",
        title: "Incidents",
        blocks: [
          table("incidents", "Incidents in the period", [
            { key: "number", label: "#", format: "number", width: 0.5 },
            { key: "title", label: "Incident", width: 3 },
            { key: "organization", label: "Organization", width: 1.4 },
            { key: "severity", label: "Severity", format: "severity" },
            { key: "status", label: "Status", format: "status" },
            { key: "detectedAt", label: "Detected", format: "datetime", width: 1.3 },
            { key: "ttr", label: "Resolved in", format: "minutes", align: "right" },
            { key: "sla", label: "SLA", format: "status" },
            { key: "assignee", label: "Assignee" },
          ], rows, { totalRows: detected.length, emptyMessage: "No incidents were detected in this period." }),
        ],
      },
      {
        id: "techniques",
        title: "Attacker techniques",
        blocks: [chart(hbar("techniques", "Top ATT&CK techniques", techniques.map((x) => ({ name: x.name ? `${x.id} ${x.name}` : x.id, count: x.count })), { seriesName: "Observations" }))],
      },
    ],
  };
}
