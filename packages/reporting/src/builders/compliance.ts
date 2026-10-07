import { SEVERITY_RANK } from "@bloody/contracts";
import { formatPercent } from "../format.js";
import { kpi, percent } from "../metrics.js";
import type { ComplianceControlFact } from "../datasource.js";
import { barChart, chart, narrative, plural, table } from "./blocks.js";
import type { BuildContext, BuilderResult } from "./context.js";
import { deriveRecommendations } from "./recommendations.js";

function score(controls: readonly ComplianceControlFact[]): number | null {
  const applicable = controls.filter((c) => c.status !== "not_applicable" && c.status !== "unknown");
  if (applicable.length === 0) return null;
  const pts = applicable.reduce((s, c) => s + (c.status === "pass" ? 1 : c.status === "partial" ? 0.5 : 0), 0);
  return (pts / applicable.length) * 100;
}

/** Compliance posture — evidence-based control status per framework plus operational hygiene indicators. */
export async function buildCompliance(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, topN } = ctx;
  const [controls, prevControls, posture, vulns] = await Promise.all([ds.complianceControls(q), ds.complianceControls(prev), ds.posture(q), ds.vulnerabilityStats(q)]);
  const frameworks = [...new Set(controls.map((c) => c.framework))].sort();
  const overall = score(controls);
  const prevOverall = score(prevControls);
  const failing = controls.filter((c) => c.status === "fail" || c.status === "partial").sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.framework.localeCompare(b.framework) || a.controlId.localeCompare(b.controlId));
  const failingHigh = failing.filter((c) => c.status === "fail" && (c.severity === "critical" || c.severity === "high")).length;
  const unknown = controls.filter((c) => c.status === "unknown").length;
  if (controls.length === 0) ctx.notes.push("No compliance controls are mapped for this scope; framework scores are unavailable. Map controls in Settings → Compliance.");
  if (unknown > 0) ctx.notes.push(`${unknown} controls have no recent evidence and are excluded from scores.`);
  const openVulns = Object.values(vulns.openBySeverity).reduce((s, n) => s + n, 0);
  const edr = percent(posture.agents.protected, posture.agents.total);
  const mfa = posture.identities.privileged > 0 ? percent(posture.identities.privileged - posture.identities.privilegedWithoutMfa, posture.identities.privileged) : null;
  const patchSla = openVulns > 0 ? 100 - (percent(vulns.overdueSla, openVulns) ?? 0) : null;
  const logging = percent(posture.logSources.healthy, posture.logSources.total);

  const kpis = [
    kpi({ key: "compliance", label: "Compliance score", value: overall, unit: "percent", previous: prevOverall, betterWhen: "higher", thresholds: { good: 90, warn: 75 }, explanation: `(pass + ½ partial) ÷ applicable, across ${controls.length - unknown} evaluated controls in ${frameworks.length} frameworks.` }),
    kpi({ key: "failing", label: "Failing controls", value: controls.filter((c) => c.status === "fail").length, unit: "count", previous: prevControls.filter((c) => c.status === "fail").length, betterWhen: "lower", explanation: "Controls whose evidence shows the requirement is not met." }),
    kpi({ key: "edr", label: "Endpoint protection coverage", value: edr, unit: "percent", betterWhen: "higher", target: 98, thresholds: { good: 98, warn: 90 }, explanation: `${posture.agents.protected} of ${posture.agents.total} endpoints with a healthy agent.` }),
    kpi({ key: "mfa", label: "Privileged MFA coverage", value: mfa, unit: "percent", betterWhen: "higher", target: 100, thresholds: { good: 100, warn: 95 }, explanation: `${posture.identities.privileged - posture.identities.privilegedWithoutMfa} of ${posture.identities.privileged} privileged identities enforce MFA.` }),
    kpi({ key: "patch", label: "Patch SLA compliance", value: patchSla, unit: "percent", betterWhen: "higher", target: 95, thresholds: { good: 95, warn: 85 }, explanation: `Share of open vulnerabilities within their remediation window (${vulns.overdueSla} overdue of ${openVulns}).` }),
    kpi({ key: "logging", label: "Log source health", value: logging, unit: "percent", betterWhen: "higher", target: 100, thresholds: { good: 98, warn: 90 }, explanation: `${posture.logSources.healthy} of ${posture.logSources.total} log sources reporting; ${posture.logSources.silent} silent.` }),
  ];
  const recommendations = deriveRecommendations({
    audience: "business",
    failingCriticalControls: failingHigh,
    privilegedWithoutMfa: posture.identities.privilegedWithoutMfa,
    unresponsiveAgents: posture.agents.unresponsive,
    silentLogSources: posture.logSources.silent,
    overdueVulnerabilities: vulns.overdueSla,
  });
  const fwRows = frameworks.map((fw) => {
    const subset = controls.filter((c) => c.framework === fw);
    return {
      framework: fw,
      controls: subset.length,
      pass: subset.filter((c) => c.status === "pass").length,
      partial: subset.filter((c) => c.status === "partial").length,
      fail: subset.filter((c) => c.status === "fail").length,
      na: subset.filter((c) => c.status === "not_applicable" || c.status === "unknown").length,
      score: score(subset),
      previous: score(prevControls.filter((c) => c.framework === fw)),
    };
  });
  return {
    title: "Compliance posture report",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · ${ctx.period.label}` : `${ctx.organizations.length} organizations · ${ctx.period.label}`,
    summary: {
      headline: overall !== null ? `Compliance score ${formatPercent(overall)} across ${plural(frameworks.length, "framework")}; ${plural(failing.length, "control")} need attention (${failingHigh} high severity).` : "No compliance controls are mapped for this scope yet.",
      highlights: [
        `Endpoint protection coverage ${formatPercent(edr)}; privileged MFA coverage ${formatPercent(mfa)}.`,
        `Patch SLA compliance ${formatPercent(patchSla)}; log source health ${formatPercent(logging)}.`,
        "Scores are evidence-based indicators from platform telemetry, not an audit opinion or certification.",
      ],
      kpis,
    },
    recommendations,
    terms: ["Compliance score", "KEV"],
    sections: [
      {
        id: "overview",
        title: "Compliance overview",
        blocks: [
          { kind: "kpis", items: kpis },
          { kind: "callout", tone: "info", title: "About these scores", text: "Control status is derived automatically from platform evidence (agent coverage, identity configuration, vulnerability SLAs, logging and cloud posture checks). Use it to prepare for audits; it does not replace an independent assessment." },
          { kind: "recommendations", items: recommendations, emptyMessage: "No high-priority control gaps." },
        ],
      },
      {
        id: "frameworks",
        title: "Frameworks",
        blocks: [
          chart(barChart("framework-scores", "Score by framework", fwRows.map((r) => r.framework), [
            { key: "previous", name: "Previous period", values: fwRows.map((r) => r.previous) },
            { key: "current", name: "This period", values: fwRows.map((r) => r.score) },
          ], "percent")),
          table("frameworks", "Control status by framework", [
            { key: "framework", label: "Framework", width: 2 },
            { key: "controls", label: "Controls", format: "number", align: "right" },
            { key: "pass", label: "Pass", format: "number", align: "right" },
            { key: "partial", label: "Partial", format: "number", align: "right" },
            { key: "fail", label: "Fail", format: "number", align: "right" },
            { key: "na", label: "N/A / unknown", format: "number", align: "right" },
            { key: "score", label: "Score", format: "percent", align: "right" },
          ], fwRows, { emptyMessage: "No frameworks are mapped." }),
        ],
      },
      {
        id: "gaps",
        title: "Control gaps",
        description: "Failing and partially met controls, most severe first, with the evidence behind each status.",
        blocks: [
          table("failing", "Controls needing attention", [
            { key: "framework", label: "Framework" },
            { key: "control", label: "Control", format: "code" },
            { key: "title", label: "Requirement", width: 2.6 },
            { key: "severity", label: "Severity", format: "severity" },
            { key: "status", label: "Status", format: "status" },
            { key: "evidence", label: "Evidence", width: 2.4 },
            { key: "owner", label: "Owner" },
          ], failing.slice(0, Math.max(topN, 25)).map((c) => ({ framework: c.framework, control: c.controlId, title: c.title, severity: c.severity, status: c.status, evidence: c.evidence ?? "—", owner: c.owner ?? "unassigned" })), { totalRows: failing.length, emptyMessage: "All evaluated controls pass." }),
          narrative([failing.length > Math.max(topN, 25) ? `${failing.length - Math.max(topN, 25)} further gaps are listed in the CSV export.` : null], { tone: "note" }),
        ],
      },
    ],
  };
}
