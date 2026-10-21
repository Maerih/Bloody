import { AUTORUN_KIND_LABELS, ENDPOINT_ACTIVITY_LABELS } from "@bloody/contracts";
import { formatDate, formatDateTime } from "../format.js";
import { countBySeverity, kpi } from "../metrics.js";
import type { Recommendation, ReportSection } from "../model.js";
import { narrative, plural, severityPhrase, table } from "./blocks.js";
import { ReportRequestError, type BuildContext, type BuilderResult } from "./context.js";

/** Reasons are short phrases; end each with a full stop. */
const sentences = (items: readonly string[]) => items.map((x) => x.trim().replace(/[.]?$/, ".")).join(" ");
const yesNo = (v: boolean | null | undefined) => (v === null || v === undefined ? "unknown" : v ? "yes" : "no");

/**
 * Single-computer report: everything about one computer — its agent and isolation, protection,
 * patching, hardening, persistence, remote-access tools, vulnerabilities, detections, inventory
 * and a timeline of what happened to it in the period.
 */
export async function buildComputerReport(ctx: BuildContext, assetId: string): Promise<BuilderResult> {
  const detail = await ctx.ds.endpointDetail(ctx.q, assetId);
  if (!detail) throw new ReportRequestError("computer not found in this scope");
  const { asset, dossier: d, inventory: inv } = detail;
  const tz = ctx.timeZone;
  const name = asset.hostname ?? asset.name;
  const agent = d.agents.find((a) => a.engine === "sciat") ?? d.agents[0] ?? null;
  const isolated = d.agents.find((a) => a.isolation) ?? null;
  const p = d.patching;
  const h = d.hardening;
  const flagged = d.footholds.filter((f) => f.verdict === "malicious" || (f.verdict === null && f.level !== "low"));
  const unapproved = d.remoteAccess.filter((r) => !r.approved);
  const failing = (h?.checks ?? []).filter((c) => c.status === "fail" && !c.accepted);
  const vulns = detail.vulnerabilities ?? [];
  const alerts = detail.alerts ?? [];
  const incidents = detail.incidents ?? [];
  const offline = agent?.lastCheckinAt ? ctx.now.getTime() - Date.parse(agent.lastCheckinAt) > 86_400_000 : agent !== null;

  const kpis = [
    kpi({ key: "risk", label: "Risk score", value: asset.riskScore, unit: "score", betterWhen: "lower", thresholds: { good: 39, warn: 69 }, explanation: "Risk Engine score of the computer at report time." }),
    kpi({ key: "security_updates", label: "Security updates waiting", value: p ? p.securityCount : null, unit: "count", betterWhen: "lower", thresholds: { good: 0, warn: 2 }, explanation: p ? `${plural(p.pendingCount, "update")} waiting in total${p.criticalCount ? `, ${p.criticalCount} critical` : ""}.` : "Not reported by the SCIAT Agent yet." }),
    kpi({ key: "hardening", label: "Hardening score", value: h?.score ?? null, unit: "score", betterWhen: "higher", thresholds: { good: 80, warn: 60 }, explanation: "Share of applicable Attack Reduction checks the computer passes (accepted exceptions excluded)." }),
    kpi({ key: "persistence", label: "Suspicious autostart entries", value: flagged.length, unit: "count", betterWhen: "lower", thresholds: { good: 0, warn: 0 }, explanation: "Autostart entries rated suspicious and not marked expected, or marked malicious." }),
    kpi({ key: "vulns", label: "Open vulnerabilities", value: detail.vulnerabilities ? vulns.length : null, unit: "count", betterWhen: "lower", explanation: detail.vulnerabilities ? severityPhrase(countBySeverity(vulns)) : "Not included: no access to vulnerability data." }),
    kpi({ key: "alerts", label: "Alerts in the period", value: detail.alerts ? alerts.length : null, unit: "count", betterWhen: "lower", explanation: detail.alerts ? severityPhrase(countBySeverity(alerts)) : "Not included: no access to alerts." }),
  ].map((k) =>
    // Waiting updates are rated by the patch deadline, not by how many there are.
    k.key === "security_updates" && p ? { ...k, status: p.grade.state === "breached" ? ("bad" as const) : p.securityCount === 0 ? ("good" as const) : ("warn" as const) } : k,
  );

  const problems: string[] = [];
  if (isolated?.isolation) problems.push(`it is isolated ${isolated.isolation.mode === "lan" ? "from the local network" : "from every network"} since ${formatDateTime(isolated.isolation.since, tz)}`);
  if (offline) problems.push("its agent has not checked in for more than a day");
  if (p?.grade.state === "breached") problems.push("security updates are past the patch deadline");
  if (p?.osSupport.status === "ended") problems.push("its operating system no longer gets security updates");
  if (flagged.length) problems.push(`${plural(flagged.length, "suspicious autostart entry", "suspicious autostart entries")} need review`);
  if (unapproved.length) problems.push(`unapproved remote-access software is present (${unapproved.map((r) => r.name).join(", ")})`);

  const recommendations: Recommendation[] = [];
  if (isolated?.isolation) recommendations.push({ priority: "critical", title: "Finish the investigation, then release the computer from isolation", rationale: "While isolated the user cannot work normally; release it from the computer's page once it is confirmed clean.", owner: "soc" });
  for (const f of flagged.slice(0, 3)) recommendations.push({ priority: f.verdict === "malicious" || f.level === "high" ? "critical" : "high", title: `Review the autostart entry “${f.name}”`, rationale: `${f.reasons.slice(0, 2).join("; ") || "Rated suspicious"}. Remove it if nobody can explain it, or mark it expected.`, owner: "soc" });
  if (p && p.securityCount > 0) recommendations.push({ priority: p.grade.state === "breached" || p.criticalCount > 0 ? "high" : "medium", title: `Install ${plural(p.securityCount, "waiting security update")}${p.rebootRequired ? " and restart" : ""}`, rationale: p.grade.reasons[0] ?? "Security updates are waiting.", owner: "it" });
  if (p?.osSupport.status === "ended") recommendations.push({ priority: "high", title: "Upgrade or replace the operating system", rationale: `${p.os ?? "The operating system"} no longer receives security updates${p.osSupport.endsOn ? ` (support ended ${p.osSupport.endsOn})` : ""}.`, owner: "it" });
  for (const r of unapproved) recommendations.push({ priority: "high", title: `Remove or approve ${r.name}`, rationale: "Attackers use remote-access tools to keep hands-on access; only approved tools should be present.", owner: "it" });
  for (const c of failing.filter((c) => c.severity === "high").slice(0, 3)) recommendations.push({ priority: "medium", title: `Hardening: ${c.title}`, rationale: c.fix, owner: "it" });

  const activity = d.activity;
  const sections: ReportSection[] = [
    {
      id: "overview",
      title: "Computer overview",
      blocks: [
        { kind: "kpis", items: kpis },
        narrative([
          `${name} is a ${asset.kind.replace(/_/g, " ")} of ${ctx.orgName(asset.organizationId)}${asset.owner ? `, used by ${asset.owner}` : ""}, running ${asset.os ?? "an unknown operating system"}.`,
          problems.length ? `Needs attention: ${problems.join("; ")}.` : "Nothing on this computer needs attention right now.",
        ]),
        { kind: "recommendations", title: "What to do", items: recommendations, emptyMessage: "Nothing to do: keep the agent running and review new findings." },
        table(
          "identity",
          "Identification",
          [
            { key: "k", label: "Item", width: 1.2 },
            { key: "v", label: "Value", width: 3 },
          ],
          [
            { k: "Hostname", v: name },
            { k: "Operating system", v: asset.os ?? "—" },
            { k: "IP addresses", v: asset.ips.join(", ") || "—" },
            { k: "Owner", v: asset.owner ?? "—" },
            { k: "Criticality", v: asset.criticality.replace(/_/g, " ") },
            { k: "Internet-facing", v: yesNo(asset.internetFacing) },
            { k: "Last seen", v: asset.lastSeenAt ? formatDateTime(asset.lastSeenAt, tz) : "—" },
            { k: "Tags", v: asset.tags.join(", ") || "—" },
          ],
        ),
      ],
    },
    {
      id: "agent",
      title: "Agent and isolation",
      blocks: [
        table(
          "agents",
          "Agents on this computer",
          [
            { key: "engine", label: "Agent" },
            { key: "version", label: "Version", format: "code" },
            { key: "status", label: "Status", format: "status" },
            { key: "isolation", label: "Isolation", width: 1.6 },
            { key: "enrolled", label: "Installed", format: "datetime" },
            { key: "checkin", label: "Last check-in", format: "datetime" },
          ],
          d.agents.map((a) => ({
            engine: a.engine === "sciat" ? "SCIAT Agent" : a.engine,
            version: a.version ?? "—",
            status: a.status,
            isolation: a.isolation ? `${a.isolation.mode === "lan" ? "LAN only" : "Full"} since ${formatDateTime(a.isolation.since, tz)}` : "Not isolated",
            enrolled: a.enrolledAt,
            checkin: a.lastCheckinAt,
          })),
          { emptyMessage: "No agent is installed on this computer." },
        ),
      ],
    },
    {
      id: "protection",
      title: "Protection",
      blocks: inv
        ? [
            table(
              "antivirus",
              "Antivirus",
              [
                { key: "name", label: "Product", width: 2 },
                { key: "enabled", label: "On", format: "status" },
                { key: "realtime", label: "Real-time", format: "status" },
                { key: "tamper", label: "Tamper protection", format: "status" },
                { key: "updated", label: "Definitions", width: 1.2 },
              ],
              inv.antivirus.map((a) => ({ name: a.name, enabled: yesNo(a.enabled), realtime: yesNo(a.realTimeProtection), tamper: yesNo(a.tamperProtection), updated: a.upToDate === false ? "out of date" : a.signatureAgeDays !== null ? `${a.signatureAgeDays} days old` : "up to date" })),
              { emptyMessage: "No antivirus product reported.", ...(inv.antivirusIssues.length ? { note: `Issues: ${inv.antivirusIssues.join("; ")}.` } : {}) },
            ),
            narrative([`Host firewall: ${inv.firewall ? (inv.firewall.enabled ? "on" : "OFF") : "not reported"}${inv.firewall?.detail ? ` (${inv.firewall.detail})` : ""}. Inventory collected ${formatDateTime(inv.collectedAt, tz)}.`]),
          ]
        : [narrative(["The SCIAT Agent has not sent a host inventory for this computer yet."], { tone: "note" })],
    },
    {
      id: "patching",
      title: "Patching",
      blocks: p
        ? [
            narrative([
              `Status: ${p.grade.state === "current" ? "up to date" : p.grade.state === "breached" ? "out of compliance" : p.grade.state}. ${sentences(p.grade.reasons)}`,
              `Operating system support: ${p.osSupport.status === "ended" ? `ended${p.osSupport.endsOn ? ` on ${p.osSupport.endsOn}` : ""}` : p.osSupport.status === "ending_soon" ? `ends ${p.osSupport.endsOn}` : p.osSupport.status === "supported" ? "supported" : "unknown"}.${p.osSupport.note ? ` ${p.osSupport.note}.` : ""}`,
              `Last update installed: ${p.lastInstalledAt ? formatDate(p.lastInstalledAt, tz) : "unknown"}; restart needed: ${yesNo(p.rebootRequired)}.`,
            ]),
            table(
              "pending",
              "Updates waiting to be installed",
              [
                { key: "title", label: "Update", width: 3 },
                { key: "id", label: "KB / package", format: "code" },
                { key: "type", label: "Type", format: "status" },
              ],
              [...p.pending].sort((a, b) => Number(b.security) - Number(a.security)).map((u) => ({ title: u.title, id: u.id ?? "—", type: u.security ? (u.severity === "unspecified" ? "security" : u.severity) : "other" })),
              { emptyMessage: "Nothing is waiting to be installed." },
            ),
          ]
        : [narrative(["Update status has not been reported by the SCIAT Agent yet (version 1.5 or later sends it with the inventory)."], { tone: "note" })],
    },
    {
      id: "hardening",
      title: "Hardening",
      blocks: h
        ? [
            table(
              "checks",
              `Attack Reduction checks (score ${h.score ?? "—"} / 100)`,
              [
                { key: "title", label: "Check", width: 2.4 },
                { key: "severity", label: "Severity", format: "status" },
                { key: "status", label: "Result", format: "status" },
                { key: "detail", label: "Detail", width: 2 },
              ],
              [...h.checks]
                .filter((c) => c.status !== "unknown")
                .sort((a, b) => (a.status === "fail" ? 0 : 1) - (b.status === "fail" ? 0 : 1))
                .map((c) => ({ title: c.title, severity: c.severity, status: c.accepted && c.status === "fail" ? "accepted" : c.status, detail: c.detail ?? "" })),
              (() => {
                const unknown = h.checks.filter((c) => c.status === "unknown").length;
                return unknown ? { note: `${plural(unknown, "further check")} not reported by this computer's agent yet.` } : {};
              })(),
            ),
          ]
        : [narrative(["Hardening checks need a host inventory from the SCIAT Agent."], { tone: "note" })],
    },
    {
      id: "persistence",
      title: "Persistence and remote access",
      blocks: [
        table(
          "footholds",
          "Autostart entries needing review",
          [
            { key: "name", label: "Entry", width: 1.6 },
            { key: "kind", label: "Type" },
            { key: "command", label: "Runs", format: "code", width: 3 },
            { key: "rating", label: "Rating", format: "status" },
            { key: "why", label: "Why", width: 2.2 },
          ],
          flagged.map((f) => ({ name: f.name, kind: AUTORUN_KIND_LABELS[f.kind], command: f.command ?? f.location, rating: f.verdict ?? (f.level === "high" ? "highly suspicious" : "suspicious"), why: f.reasons.slice(0, 3).join("; ") })),
          { emptyMessage: `No suspicious autostart entries among ${plural(d.footholds.length, "entry", "entries")} reported.` },
        ),
        table(
          "remote",
          "Remote-access software",
          [
            { key: "name", label: "Tool", width: 1.4 },
            { key: "vendor", label: "Vendor" },
            { key: "approved", label: "Approved", format: "status" },
            { key: "evidence", label: "Evidence", width: 2.6 },
          ],
          d.remoteAccess.map((r) => ({ name: r.name, vendor: r.vendor, approved: r.approved ? "yes" : "no", evidence: r.evidence.join("; ") })),
          { emptyMessage: "No remote-access tools found." },
        ),
      ],
    },
    {
      id: "detections",
      title: "Vulnerabilities and detections",
      blocks: [
        detail.vulnerabilities
          ? table(
              "vulns",
              "Open vulnerabilities",
              [
                { key: "cve", label: "CVE", format: "code" },
                { key: "title", label: "Title", width: 3 },
                { key: "severity", label: "Severity", format: "severity" },
                { key: "kev", label: "Exploited", format: "status" },
                { key: "status", label: "Status", format: "status" },
              ],
              vulns.map((v) => ({ cve: v.cve ?? "—", title: v.title, severity: v.severity, kev: v.kev ? "yes" : "no", status: v.status })),
              { emptyMessage: "No open vulnerabilities." },
            )
          : narrative(["Vulnerabilities are not included: the report was requested without access to vulnerability data."], { tone: "note" }),
        detail.alerts
          ? table(
              "alerts",
              "Alerts in the period",
              [
                { key: "at", label: "First seen", format: "datetime", width: 1.3 },
                { key: "title", label: "Alert", width: 3 },
                { key: "severity", label: "Severity", format: "severity" },
                { key: "status", label: "Status", format: "status" },
              ],
              alerts.map((a) => ({ at: a.firstSeenAt, title: a.title, severity: a.severity, status: a.status })),
              { emptyMessage: "No alerts in the period." },
            )
          : narrative(["Alerts are not included: the report was requested without access to alerts."], { tone: "note" }),
        detail.incidents
          ? table(
              "incidents",
              "Incidents",
              [
                { key: "number", label: "#", format: "code" },
                { key: "title", label: "Incident", width: 3 },
                { key: "severity", label: "Severity", format: "severity" },
                { key: "status", label: "Status", format: "status" },
                { key: "at", label: "Detected", format: "datetime" },
              ],
              incidents.map((i) => ({ number: String(i.number), title: i.title, severity: i.severity, status: i.status, at: i.detectedAt })),
              { emptyMessage: "No incidents involved this computer." },
            )
          : narrative(["Incidents are not included: the report was requested without access to incidents."], { tone: "note" }),
      ],
    },
    {
      id: "activity",
      title: "Activity",
      blocks: [
        table(
          "activity",
          `What happened to ${name}`,
          [
            { key: "at", label: "Time", format: "datetime", width: 1.3 },
            { key: "kind", label: "Type" },
            { key: "title", label: "What happened", width: 3 },
            { key: "actor", label: "By", width: 1.2 },
            { key: "outcome", label: "Result", format: "status" },
          ],
          activity.map((e) => ({ at: e.at, kind: ENDPOINT_ACTIVITY_LABELS[e.kind], title: e.detail ? `${e.title} — ${e.detail}` : e.title, actor: e.actor ?? "—", outcome: e.outcome ?? "" })),
          { emptyMessage: "Nothing was recorded for this computer in the period.", ...(d.activityTruncated ? { note: `Only the latest ${activity.length} entries are shown.` } : {}) },
        ),
      ],
    },
    ...(inv
      ? [
          {
            id: "inventory",
            title: "Inventory",
            blocks: [
              table(
                "users",
                "Local accounts",
                [
                  { key: "name", label: "Account", width: 1.6 },
                  { key: "admin", label: "Administrator", format: "status" },
                  { key: "enabled", label: "Enabled", format: "status" },
                  { key: "loggedIn", label: "Signed in", format: "status" },
                ],
                inv.users.map((u) => ({ name: u.name, admin: yesNo(u.admin), enabled: yesNo(u.enabled), loggedIn: yesNo(u.loggedIn) })),
                { emptyMessage: "No local accounts reported." },
              ),
              table(
                "ports",
                "Listening ports",
                [
                  { key: "port", label: "Port", format: "code" },
                  { key: "protocol", label: "Protocol" },
                  { key: "address", label: "Address", format: "code" },
                  { key: "process", label: "Process", width: 2 },
                ],
                inv.ports.slice(0, 60).map((x) => ({ port: String(x.port), protocol: x.protocol, address: x.address, process: x.process ?? "—" })),
                { emptyMessage: "No listening ports reported.", ...(inv.ports.length > 60 ? { totalRows: inv.ports.length } : {}) },
              ),
              table(
                "software",
                `Installed software (${inv.software.length})`,
                [
                  { key: "name", label: "Name", width: 2.4 },
                  { key: "version", label: "Version", format: "code" },
                  { key: "publisher", label: "Publisher", width: 1.6 },
                ],
                [...inv.software].sort((a, b) => a.name.localeCompare(b.name)).slice(0, 150).map((x) => ({ name: x.name, version: x.version ?? "—", publisher: x.publisher ?? "—" })),
                { emptyMessage: "No software reported.", ...(inv.software.length > 150 ? { totalRows: inv.software.length } : {}), note: `${inv.services.running} of ${inv.services.total} services running.` },
              ),
            ],
          } satisfies ReportSection,
        ]
      : []),
  ];

  return {
    title: `Computer report: ${name}`,
    fileLabel: `${name}-computer-report`,
    subtitle: `${ctx.orgName(asset.organizationId)} · ${asset.os ?? asset.kind.replace(/_/g, " ")}`,
    summary: {
      headline: problems.length ? `${name} needs attention: ${problems[0]}.` : `${name} is protected and up to date.`,
      highlights: [
        agent ? `${agent.engine === "sciat" ? "SCIAT Agent" : agent.engine} ${agent.version ?? ""} — last check-in ${agent.lastCheckinAt ? formatDateTime(agent.lastCheckinAt, tz) : "never"}.` : "No agent installed.",
        p ? `${plural(p.securityCount, "security update")} waiting; patch status ${p.grade.state === "current" ? "up to date" : p.grade.state}.` : "Patch status not reported yet.",
        `${plural(activity.length, "event")} recorded in the period${detail.alerts ? `, including ${plural(alerts.length, "alert")}` : ""}.`,
      ],
      kpis,
    },
    recommendations,
    terms: ["Risk score", "Patch compliance", "Hardening score", "Persistent foothold", "Unsupported operating system", "Endpoint isolation"],
    sections,
  };
}
