import { formatNumber, formatPercent } from "../format.js";
import { kpi, percent, sumBy } from "../metrics.js";
import type { Recommendation } from "../model.js";
import { narrative, plural, table } from "./blocks.js";
import type { BuildContext, BuilderResult } from "./context.js";

/** Endpoint security posture from the SCIAT Agent: patching, unsupported OS, antivirus, hardening, persistence. */
export async function buildEndpointPosture(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, topN } = ctx;
  const cur = await ds.endpointPosture(q);
  const multiOrg = cur.length > 1;
  const endpoints = sumBy(cur, (o) => o.endpoints);
  const reporting = sumBy(cur, (o) => o.reporting);
  const offline = sumBy(cur, (o) => o.offline);
  const avProtected = sumBy(cur, (o) => o.antivirus.protected);
  const avUnhealthy = sumBy(cur, (o) => o.antivirus.unhealthy);
  const avUnmanaged = sumBy(cur, (o) => o.antivirus.unmanaged);
  const patchCurrent = sumBy(cur, (o) => o.patching.current);
  const patchGraded = sumBy(cur, (o) => o.patching.current + o.patching.behind + o.patching.breached);
  const breached = sumBy(cur, (o) => o.patching.breached);
  const securityUpdates = sumBy(cur, (o) => o.patching.securityUpdates);
  const rebootPending = sumBy(cur, (o) => o.patching.rebootPending);
  const unsupported = cur.flatMap((o) => o.unsupportedOs.map((u) => ({ ...u, org: ctx.orgName(o.organizationId) })));
  const scored = cur.filter((o) => o.hardeningScore !== null);
  const hardening = scored.length ? Math.round(sumBy(scored, (o) => o.hardeningScore! * Math.max(1, o.reporting)) / sumBy(scored, (o) => Math.max(1, o.reporting))) : null;
  const suspicious = sumBy(cur, (o) => o.footholds.suspicious);
  const malicious = sumBy(cur, (o) => o.footholds.malicious);
  const rmm = cur.flatMap((o) => o.unapprovedRemoteAccess.map((r) => ({ ...r, org: ctx.orgName(o.organizationId) })));
  const round = (v: number | null) => (v === null ? null : Math.round(v));
  const compliance = round(percent(patchCurrent, patchGraded));
  const avRate = round(percent(avProtected, avProtected + avUnhealthy + avUnmanaged));

  const kpis = [
    kpi({ key: "patch_compliance", label: "Patch compliance", value: compliance, unit: "percent", betterWhen: "higher", thresholds: { good: 90, warn: 70 }, explanation: `${formatNumber(patchCurrent)} of ${plural(patchGraded, "computer", "computers")} that reported update status ${patchCurrent === 1 ? "is" : "are"} up to date.` }),
    kpi({ key: "unsupported_os", label: "Unsupported operating systems", value: unsupported.length, unit: "count", betterWhen: "lower", thresholds: { good: 0, warn: 0 }, explanation: "Computers whose operating system no longer gets security updates." }),
    kpi({ key: "antivirus", label: "Antivirus protected", value: avRate, unit: "percent", betterWhen: "higher", thresholds: { good: 98, warn: 90 }, explanation: `${plural(avProtected, "computer has", "computers have")} working antivirus with real-time protection and current definitions.` }),
    kpi({ key: "hardening", label: "Hardening score", value: hardening, unit: "score", betterWhen: "higher", thresholds: { good: 85, warn: 70 }, explanation: "Average Attack Reduction score over computers that reported hardening facts." }),
    kpi({ key: "footholds", label: "Suspicious persistence", value: suspicious + malicious, unit: "count", betterWhen: "lower", thresholds: { good: 0, warn: 0 }, explanation: "Autostart entries rated suspicious and not reviewed, plus entries marked malicious." }),
  ];

  const recommendations: Recommendation[] = [];
  if (endpoints === 0) recommendations.push({ priority: "high", title: "Install the SCIAT Agent", rationale: "No computer runs the SCIAT Agent, so patching, antivirus, hardening and persistence cannot be measured. Deploy it with the organization's RMM, MDM or Group Policy.", owner: "mssp" });
  if (unsupported.length) recommendations.push({ priority: "high", title: "Replace or upgrade unsupported operating systems", rationale: `${plural(unsupported.length, "computer runs", "computers run")} an operating system that no longer gets security fixes. Every new vulnerability on ${unsupported.length === 1 ? "it" : "them"} stays open for good.`, owner: "customer" });
  if (breached > 0 && securityUpdates > 0) recommendations.push({ priority: "high", title: "Install outstanding security updates", rationale: `${plural(breached, "computer is", "computers are")} out of patch compliance. ${formatNumber(securityUpdates)} security updates are waiting across the estate.`, owner: "customer" });
  if (securityUpdates > 0 && breached === 0) recommendations.push({ priority: "medium", title: "Install waiting security updates", rationale: `${plural(securityUpdates, "security update is", "security updates are")} waiting. Installing them before the 30-day SLA keeps computers compliant.`, owner: "customer" });
  if (rebootPending) recommendations.push({ priority: "medium", title: "Restart computers to finish updates", rationale: `${plural(rebootPending, "computer needs", "computers need")} a restart before installed updates take effect.`, owner: "customer" });
  if (avUnhealthy + avUnmanaged) {
    const parts = [avUnhealthy ? `${plural(avUnhealthy, "computer has", "computers have")} antivirus turned off or out of date` : null, avUnmanaged ? `${plural(avUnmanaged, "computer has", "computers have")} no antivirus at all` : null].filter(Boolean);
    recommendations.push({ priority: "high", title: "Fix antivirus coverage", rationale: `${parts.join("; ")}. Without it, common malware runs unchallenged.`, owner: "mssp" });
  }
  if (malicious) recommendations.push({ priority: "high", title: "Remove malicious persistence", rationale: `${plural(malicious, "autostart entry is", "autostart entries are")} marked malicious. Isolate the affected computers and clean them.`, owner: "mssp" });
  if (suspicious) recommendations.push({ priority: "medium", title: "Review suspicious autostart entries", rationale: `${plural(suspicious, "entry has", "entries have")} not been reviewed. Mark what is expected so real threats stand out.`, owner: "mssp" });
  if (rmm.length) recommendations.push({ priority: "medium", title: "Approve or block remote-access tools", rationale: `Unapproved remote-access tools found: ${rmm.map((r) => r.tool).join(", ")}. Attackers use these to keep control of computers.`, owner: "customer" });
  if (hardening !== null && hardening < 70) recommendations.push({ priority: "medium", title: "Raise endpoint hardening", rationale: `The average hardening score is ${hardening}. The weakest settings are listed in this report; most can be fixed by the SCIAT Agent after approval.`, owner: "mssp" });
  if (offline) recommendations.push({ priority: "low", title: "Check computers that stopped reporting", rationale: `${plural(offline, "computer has", "computers have")} not checked in for more than a day; they may be off, retired or have had the agent removed.`, owner: "customer" });

  const atRisk = cur
    .flatMap((o) => o.atRisk.map((a) => ({ ...a, org: ctx.orgName(o.organizationId) })))
    .sort((a, b) => b.issues.length - a.issues.length)
    .slice(0, topN);
  const weakest = cur
    .flatMap((o) => o.weakestChecks.map((c) => ({ ...c, org: ctx.orgName(o.organizationId) })))
    .sort((a, b) => b.failing - a.failing)
    .slice(0, topN);
  const footholds = cur.flatMap((o) => o.footholds.top.map((f) => ({ ...f, org: ctx.orgName(o.organizationId) }))).slice(0, topN);
  const asOf = new Date(Math.min(Date.now(), q.to.getTime())).toISOString().slice(0, 10);
  const org = multiOrg ? [{ key: "org", label: "Organization" }] : [];

  return {
    title: "Endpoint security posture",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · as of ${asOf}` : `${ctx.organizations.length} organizations · as of ${asOf}`,
    summary: {
      headline:
        endpoints === 0
          ? "No computer runs the SCIAT Agent yet."
          : `${plural(endpoints, "computer", "computers")} protected by the SCIAT Agent; ${compliance === null ? "patch status not reported yet" : `${formatPercent(compliance)} patch compliant`}${unsupported.length ? `; ${plural(unsupported.length, "computer runs", "computers run")} an unsupported operating system` : ""}.`,
      highlights: [
        breached ? `${plural(breached, "computer is", "computers are")} out of patch compliance, with ${formatNumber(securityUpdates)} security updates waiting.` : "No computer is out of patch compliance.",
        avUnhealthy + avUnmanaged ? `${plural(avUnhealthy + avUnmanaged, "computer lacks", "computers lack")} working antivirus.` : "Every reporting computer has working antivirus.",
        malicious + suspicious ? `${plural(malicious + suspicious, "autostart entry needs", "autostart entries need")} attention (${formatNumber(malicious)} malicious).` : "No suspicious persistence was found.",
      ],
      kpis,
    },
    recommendations,
    terms: ["Patch compliance", "Unsupported operating system", "Hardening score", "Persistent foothold"],
    sections: [
      {
        id: "overview",
        title: "Overview",
        blocks: [
          { kind: "kpis", items: kpis },
          narrative([
            `This report shows the state of the organization's computers on ${asOf}, as reported by the SCIAT Agent: whether they are patched and supported, protected by antivirus, hardened against common attack techniques, and free of suspicious persistence.`,
            reporting < endpoints ? `${plural(endpoints - reporting, "computer has", "computers have")} not sent a full report yet and ${endpoints - reporting === 1 ? "is" : "are"} not included in every figure.` : null,
          ]),
          { kind: "recommendations", items: recommendations, emptyMessage: "Endpoints are in good shape; keep patching and reviewing new findings." },
        ],
      },
      {
        id: "attention",
        title: "Computers that need attention",
        description: "Computers with the most open problems.",
        blocks: [
          table("endpoint-at-risk", "Computers that need attention", [...org, { key: "hostname", label: "Computer" }, { key: "os", label: "Operating system" }, { key: "issues", label: "Problems" }], atRisk.map((a) => ({ org: a.org, hostname: a.hostname, os: a.os ?? "—", issues: a.issues.join("; ") })), {
            emptyMessage: "No computer has open problems.",
          }),
        ],
      },
      {
        id: "patching",
        title: "Patching and operating systems",
        description: "Security updates waiting longer than 30 days, or an operating system without vendor security updates, put a computer out of compliance.",
        blocks: [
          table(
            "patching-summary",
            "Patch status",
            [...org, { key: "current", label: "Up to date", format: "number" as const, align: "right" as const }, { key: "behind", label: "Behind", format: "number" as const, align: "right" as const }, { key: "breached", label: "Out of compliance", format: "number" as const, align: "right" as const }, { key: "unknown", label: "Not reported", format: "number" as const, align: "right" as const }, { key: "security", label: "Security updates waiting", format: "number" as const, align: "right" as const }],
            cur.map((o) => ({ org: ctx.orgName(o.organizationId), current: o.patching.current, behind: o.patching.behind, breached: o.patching.breached, unknown: o.patching.unknown, security: o.patching.securityUpdates })),
          ),
          table("unsupported-os", "Unsupported operating systems", [...org, { key: "hostname", label: "Computer" }, { key: "os", label: "Operating system" }, { key: "endsOn", label: "Security updates ended", format: "date" as const }], unsupported.map((u) => ({ org: u.org, hostname: u.hostname, os: u.os, endsOn: u.endsOn })), {
            emptyMessage: "Every computer runs a supported operating system.",
          }),
        ],
      },
      {
        id: "protection",
        title: "Antivirus and hardening",
        blocks: [
          table(
            "antivirus",
            "Antivirus",
            [...org, { key: "protected", label: "Protected", format: "number" as const, align: "right" as const }, { key: "unhealthy", label: "Off or out of date", format: "number" as const, align: "right" as const }, { key: "unmanaged", label: "None", format: "number" as const, align: "right" as const }],
            cur.map((o) => ({ org: ctx.orgName(o.organizationId), ...o.antivirus })),
          ),
          table("weakest-checks", "Weakest hardening settings", [...org, { key: "title", label: "Setting" }, { key: "failing", label: "Computers failing", format: "number" as const, align: "right" as const }], weakest.map((w) => ({ org: w.org, title: w.title, failing: w.failing })), {
            emptyMessage: "No hardening check is failing.",
          }),
        ],
      },
      {
        id: "persistence",
        title: "Persistence and remote access",
        description: "Autostart entries attackers could use to come back after a reboot, and remote-access tools the organization has not approved.",
        blocks: [
          table(
            "footholds",
            "Suspicious autostart entries",
            [...org, { key: "name", label: "Entry" }, { key: "kind", label: "Type" }, { key: "level", label: "Rating" }, { key: "reason", label: "Main reason" }, { key: "endpoints", label: "Computers", format: "number" as const, align: "right" as const }],
            footholds.map((f) => ({ org: f.org, name: f.name, kind: f.kind, level: f.level, reason: f.reason, endpoints: f.endpoints })),
            { emptyMessage: "No suspicious or malicious autostart entry." },
          ),
          table("rmm", "Unapproved remote-access tools", [...org, { key: "tool", label: "Tool" }, { key: "endpoints", label: "Computers", format: "number" as const, align: "right" as const }], rmm.map((r) => ({ org: r.org, tool: r.tool, endpoints: r.endpoints })), {
            emptyMessage: "No unapproved remote-access tool found.",
          }),
        ],
      },
    ],
  };
}
