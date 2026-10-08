import type { AutomationEvent } from "@bloody/contracts";

/**
 * `{{variable}}` templates used by automation rules and notification channels. The variables
 * available per event mirror what the automation engine places in the render context.
 */

export interface TemplateVariable {
  name: string;
  description: string;
}

const COMMON: TemplateVariable[] = [
  { name: "title", description: "Subject of the event (incident title, escalation title…)" },
  { name: "severity", description: "Severity of the subject" },
  { name: "organization", description: "Organization name" },
  { name: "link", description: "Deep link into Bloody" },
  { name: "event", description: "Event name, e.g. incident.created" },
  { name: "at", description: "When the event happened (ISO 8601)" },
];

const BY_EVENT: Partial<Record<AutomationEvent, TemplateVariable[]>> = {
  "incident.created": [{ name: "number", description: "Incident number" }, { name: "riskScore", description: "Incident risk score" }, { name: "summary", description: "Incident summary" }],
  "incident.severity_changed": [{ name: "number", description: "Incident number" }, { name: "previousSeverity", description: "Severity before the change" }],
  "incident.closed": [{ name: "number", description: "Incident number" }, { name: "status", description: "Closing status" }],
  "escalation.created": [{ name: "dueAt", description: "When the escalation is due" }],
  "escalation.overdue": [{ name: "dueAt", description: "When the escalation was due" }],
  "response.pending_approval": [{ name: "action", description: "Response action" }, { name: "target", description: "Action target" }, { name: "reason", description: "Requester's reason" }, { name: "requestedBy", description: "Who requested it" }],
  "agent.unresponsive": [{ name: "hostname", description: "Endpoint hostname" }, { name: "lastCheckinAt", description: "Last agent check-in" }],
  "indicator.matched": [{ name: "indicator", description: "Indicator value" }, { name: "indicatorType", description: "Indicator type" }, { name: "entity", description: "Where it was seen" }],
  "vulnerability.kev_detected": [{ name: "cve", description: "CVE id" }, { name: "asset", description: "Affected asset" }, { name: "cvss", description: "CVSS score" }],
  "report.generated": [{ name: "report", description: "Report name" }, { name: "period", description: "Report period" }],
  "trial.ending": [{ name: "module", description: "Module in trial" }, { name: "trialEndsAt", description: "Trial end date" }],
  "usage.quota_exceeded": [{ name: "meter", description: "Usage meter" }, { name: "used", description: "Current usage" }, { name: "limit", description: "Plan limit" }],
};

export function templateVariables(event: AutomationEvent): TemplateVariable[] {
  return [...COMMON, ...(BY_EVENT[event] ?? [])];
}

export type TemplateSegment = { kind: "text"; text: string } | { kind: "variable"; name: string; known: boolean; description: string | null };

const VAR_RE = /\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}/g;

/** Split a template into literal text and variable references (for highlighted previews). */
export function parseTemplate(template: string, variables: TemplateVariable[]): TemplateSegment[] {
  const out: TemplateSegment[] = [];
  let last = 0;
  for (const m of template.matchAll(VAR_RE)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push({ kind: "text", text: template.slice(last, idx) });
    const name = m[1]!;
    const def = variables.find((v) => v.name === name);
    out.push({ kind: "variable", name, known: Boolean(def), description: def?.description ?? null });
    last = idx + m[0].length;
  }
  if (last < template.length) out.push({ kind: "text", text: template.slice(last) });
  return out;
}

/** Variables referenced by the template that the event does not provide. */
export function unknownVariables(template: string, variables: TemplateVariable[]): string[] {
  return [...new Set(parseTemplate(template, variables).flatMap((s) => (s.kind === "variable" && !s.known ? [s.name] : [])))];
}
