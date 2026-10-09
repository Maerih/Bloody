import type { AutomationEvent } from "@bloody/contracts";
import type { AutomationTemplatePreset } from "../api/types";

/**
 * `{{variable}}` templates used by automation rules (same logic-less syntax as the automation
 * engine: dotted paths and optional filters, e.g. `{{incident.title}}`,
 * `{{severity | upper}}`, `{{incident.summary | default:"n/a"}}`). The variable catalogue mirrors
 * what the engine places in the render context; the server presets (GET /automations/templates)
 * extend it per event when available.
 */

export interface TemplateVariable {
  /** Dotted path, e.g. `incident.title`. */
  name: string;
  description: string;
}

/** Variables available for every event (engine render context). */
export const COMMON_VARIABLES: TemplateVariable[] = [
  { name: "event", description: "Event name, e.g. incident.created" },
  { name: "severity", description: "Severity: info | low | medium | high | critical" },
  { name: "occurredAt", description: "When the event happened (ISO 8601)" },
  { name: "organization.name", description: "Organization (customer) name" },
  { name: "organization.id", description: "Organization id" },
  { name: "subject.kind", description: "Kind of entity the event is about" },
  { name: "subject.id", description: "Entity id" },
  { name: "subject.label", description: "Entity display label" },
  { name: "link.url", description: "Deep link into the Command Center" },
  { name: "brand.name", description: "Sender brand (MSSP white label or Bloody)" },
];

/** Per-event payload variables (used until the server presets load, or if they are unavailable). */
const BY_EVENT: Record<AutomationEvent, TemplateVariable[]> = {
  "incident.created": [
    { name: "incident.number", description: "Incident number" },
    { name: "incident.title", description: "Incident title" },
    { name: "incident.summary", description: "Incident summary" },
    { name: "incident.riskScore", description: "Incident risk score (0–100)" },
  ],
  "incident.severity_changed": [
    { name: "incident.number", description: "Incident number" },
    { name: "incident.title", description: "Incident title" },
    { name: "previousSeverity", description: "Severity before the change" },
  ],
  "incident.closed": [
    { name: "incident.number", description: "Incident number" },
    { name: "incident.title", description: "Incident title" },
    { name: "incident.status", description: "Closing status" },
  ],
  "escalation.created": [
    { name: "escalation.title", description: "Escalation title" },
    { name: "escalation.dueAt", description: "When the escalation is due" },
  ],
  "escalation.overdue": [
    { name: "escalation.title", description: "Escalation title" },
    { name: "escalation.dueAt", description: "When the escalation was due" },
  ],
  "response.pending_approval": [
    { name: "action.label", description: "Response action" },
    { name: "action.target", description: "Action target" },
    { name: "action.reason", description: "Requester's reason" },
    { name: "action.requestedBy", description: "Who requested it" },
  ],
  "agent.unresponsive": [
    { name: "agent.hostname", description: "Endpoint hostname" },
    { name: "agent.lastCheckinAt", description: "Last agent check-in" },
  ],
  "indicator.matched": [
    { name: "indicator.value", description: "Indicator value" },
    { name: "indicator.type", description: "Indicator type" },
    { name: "match.entity", description: "Where it was seen" },
  ],
  "vulnerability.kev_detected": [
    { name: "vulnerability.cve", description: "CVE id" },
    { name: "asset.name", description: "Affected asset" },
    { name: "vulnerability.cvss", description: "CVSS score" },
  ],
  "report.generated": [
    { name: "report.name", description: "Report name" },
    { name: "report.periodDays", description: "Report period in days" },
  ],
  "trial.ending": [
    { name: "module", description: "Module in trial" },
    { name: "trialEndsAt", description: "Trial end date" },
  ],
  "usage.quota_exceeded": [
    { name: "meter", description: "Usage meter" },
    { name: "used", description: "Current usage" },
    { name: "limit", description: "Plan limit" },
  ],
};

/** Variables for an event: common + the server preset's (when loaded) or the built-in catalogue. */
export function templateVariables(event: AutomationEvent, preset?: AutomationTemplatePreset | null): TemplateVariable[] {
  const specific = preset && preset.variables.length > 0 ? preset.variables.map((v) => ({ name: v.path, description: v.description })) : BY_EVENT[event];
  const seen = new Set<string>();
  return [...COMMON_VARIABLES, ...specific].filter((v) => (seen.has(v.name) ? false : (seen.add(v.name), true)));
}

export type TemplateSegment = { kind: "text"; text: string } | { kind: "variable"; name: string; filters: string | null; known: boolean; description: string | null };

const VAR_RE = /\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*(\|[^}]*)?\}\}/g;

/** Split a template into literal text and variable references (for highlighted previews). */
export function parseTemplate(template: string, variables: TemplateVariable[]): TemplateSegment[] {
  const out: TemplateSegment[] = [];
  let last = 0;
  for (const m of template.matchAll(VAR_RE)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push({ kind: "text", text: template.slice(last, idx) });
    const name = m[1]!;
    // A variable is known when it, or one of its parents (`incident` for `incident.title`), is provided.
    const def = variables.find((v) => v.name === name || name.startsWith(`${v.name}.`) || v.name.startsWith(`${name}.`));
    out.push({ kind: "variable", name, filters: m[2] ? m[2].slice(1).trim() : null, known: Boolean(def), description: def?.description ?? null });
    last = idx + m[0].length;
  }
  if (last < template.length) out.push({ kind: "text", text: template.slice(last) });
  return out;
}

/** Variables referenced by the template that the event does not provide. */
export function unknownVariables(template: string, variables: TemplateVariable[]): string[] {
  return [...new Set(parseTemplate(template, variables).flatMap((s) => (s.kind === "variable" && !s.known ? [s.name] : [])))];
}

/** Insert `{{name}}` at the cursor position of a text value. */
export function insertVariable(value: string, name: string, start: number | null, end: number | null): { value: string; cursor: number } {
  const token = `{{${name}}}`;
  const s = start ?? value.length;
  const e = end ?? s;
  return { value: value.slice(0, s) + token + value.slice(e), cursor: s + token.length };
}

/**
 * Nested sample payload for the server-side preview: every known variable path gets a readable
 * placeholder ("‹incident.title›") so analysts see where each value lands. Not tenant data.
 */
export function samplePayload(variables: TemplateVariable[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const v of variables) {
    if (["event", "severity", "occurredAt"].includes(v.name) || v.name.startsWith("organization.") || v.name.startsWith("brand.") || v.name.startsWith("subject.")) continue;
    const parts = v.name.split(".");
    let cur: Record<string, unknown> = out;
    parts.forEach((p, i) => {
      if (i === parts.length - 1) {
        if (!(p in cur)) cur[p] = `‹${v.name}›`;
      } else {
        const next = cur[p];
        if (typeof next !== "object" || next === null) cur[p] = {};
        cur = cur[p] as Record<string, unknown>;
      }
    });
  }
  return out;
}
