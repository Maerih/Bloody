import type { AutomationEvent } from "@bloody/contracts";

/**
 * Ready-made notification templates for every automation event — the starting point offered
 * by the rule editor ("Use template"). Subjects are single-line; bodies use the light text
 * formatting understood by every channel (blank-line paragraphs, "- " bullets, **bold**).
 * Variables are documented per event so the editor can autocomplete and validate them.
 */
export interface RuleTemplatePreset {
  event: AutomationEvent;
  name: string;
  description: string;
  /** Primary audience the wording is written for. */
  audience: "soc" | "mssp" | "customer" | "business";
  subject: string;
  body: string;
  /** Variables the event payload is expected to provide (beyond the common ones). */
  variables: { path: string; description: string }[];
  /** Suggested throttle window. */
  throttleMinutes: number;
}

/** Variables available for every event. */
export const COMMON_TEMPLATE_VARIABLES: { path: string; description: string }[] = [
  { path: "event", description: "Event name, e.g. incident.created" },
  { path: "severity", description: "Severity: info | low | medium | high | critical" },
  { path: "occurredAt", description: "When the event happened (ISO 8601; use | datetime)" },
  { path: "organization.id", description: "Organization id" },
  { path: "organization.name", description: "Organization (customer) name" },
  { path: "subject.kind", description: "Kind of entity the event is about" },
  { path: "subject.id", description: "Entity id" },
  { path: "subject.label", description: "Entity display label" },
  { path: "link.url", description: "Deep link into the Command Center" },
  { path: "brand.name", description: "Sender brand (MSSP white label or Bloody)" },
];

export const DEFAULT_RULE_TEMPLATES: Record<AutomationEvent, RuleTemplatePreset> = {
  "incident.created": {
    event: "incident.created",
    name: "New incident",
    description: "Alert the SOC when an incident is opened.",
    audience: "soc",
    subject: "[{{severity | upper}}] Incident #{{incident.number}}: {{incident.title}}",
    body: [
      "A new **{{severity}}** incident was opened for {{organization.name}}.",
      "{{incident.summary | default:\"No summary yet — triage pending.\"}}",
      "- Risk score: {{incident.riskScore | default:\"n/a\"}}\n- Affected assets: {{incident.assetCount | default:0}}\n- Techniques: {{incident.techniques | join:\", \" | default:\"none mapped yet\"}}\n- Detected: {{incident.detectedAt | datetime}}",
      "Open the incident in the Command Center to triage and contain.",
    ].join("\n\n"),
    variables: [
      { path: "incident.number", description: "Incident number" },
      { path: "incident.title", description: "Incident title" },
      { path: "incident.summary", description: "Summary" },
      { path: "incident.riskScore", description: "Risk score 0-100" },
      { path: "incident.assetCount", description: "Number of affected assets" },
      { path: "incident.techniques", description: "MITRE ATT&CK technique ids" },
      { path: "incident.detectedAt", description: "Detection time" },
    ],
    throttleMinutes: 0,
  },
  "incident.severity_changed": {
    event: "incident.severity_changed",
    name: "Incident severity changed",
    description: "Tell responders when an incident is escalated or de-escalated.",
    audience: "soc",
    subject: "Incident #{{incident.number}} is now {{severity | upper}}: {{incident.title}}",
    body: [
      "Severity changed from **{{previousSeverity | severity}}** to **{{severity | severity}}** for {{organization.name}}.",
      "Why: {{reasons | join:\"; \" | default:\"risk re-assessment\"}}",
      "- Risk score: {{incident.riskScore | default:\"n/a\"}}\n- Assignee: {{incident.assigneeName | default:\"unassigned\"}}",
    ].join("\n\n"),
    variables: [
      { path: "incident.number", description: "Incident number" },
      { path: "incident.title", description: "Incident title" },
      { path: "previousSeverity", description: "Severity before the change" },
      { path: "reasons", description: "Explanations of the change" },
      { path: "incident.assigneeName", description: "Assigned analyst" },
    ],
    throttleMinutes: 15,
  },
  "incident.closed": {
    event: "incident.closed",
    name: "Incident closed",
    description: "Close-out summary for the customer or SOC lead.",
    audience: "customer",
    subject: "Resolved: incident #{{incident.number}} — {{incident.title}}",
    body: [
      "Incident #{{incident.number}} for {{organization.name}} has been closed as **{{incident.resolution | default:\"resolved\" | title}}**.",
      "{{incident.closingSummary | default:\"\"}}",
      "- Time to resolve: {{incident.timeToResolve | default:\"n/a\"}}\n- Actions taken: {{incident.actions | join:\", \" | default:\"none recorded\"}}",
      "The full incident report is available in the customer portal.",
    ].join("\n\n"),
    variables: [
      { path: "incident.resolution", description: "Resolution (remediated, false_positive…)" },
      { path: "incident.closingSummary", description: "Analyst close-out notes" },
      { path: "incident.timeToResolve", description: "Human-readable duration" },
      { path: "incident.actions", description: "Response actions taken" },
    ],
    throttleMinutes: 0,
  },
  "escalation.created": {
    event: "escalation.created",
    name: "Escalation to customer",
    description: "Ask the customer to act on something only they can do.",
    audience: "customer",
    subject: "Action required: {{escalation.title}}",
    body: [
      "Our security operations team needs your help with a **{{severity}}** issue affecting {{organization.name}}.",
      "{{escalation.details | default:\"Please review the escalation in the portal.\"}}",
      "- Please respond by: {{escalation.dueAt | datetime}}\n- Related incident: #{{incident.number | default:\"n/a\"}}",
      "Reply in the portal so the response is recorded against the incident.",
    ].join("\n\n"),
    variables: [
      { path: "escalation.title", description: "Escalation title" },
      { path: "escalation.details", description: "What the customer must do" },
      { path: "escalation.dueAt", description: "Response deadline" },
    ],
    throttleMinutes: 0,
  },
  "escalation.overdue": {
    event: "escalation.overdue",
    name: "Escalation overdue",
    description: "Remind owners and SOC leads about escalations past their deadline.",
    audience: "mssp",
    subject: "Overdue: {{escalation.title}} ({{organization.name}})",
    body: [
      "The escalation **{{escalation.title}}** for {{organization.name}} passed its deadline ({{escalation.dueAt | datetime}}) and is still {{escalation.status | default:\"open\"}}.",
      "- Overdue by: {{escalation.overdueBy | default:\"n/a\"}}\n- Severity: {{severity | severity}}",
      "Follow up with the customer contact or re-route the escalation.",
    ].join("\n\n"),
    variables: [
      { path: "escalation.title", description: "Escalation title" },
      { path: "escalation.dueAt", description: "Deadline" },
      { path: "escalation.overdueBy", description: "Human-readable overdue duration" },
    ],
    throttleMinutes: 240,
  },
  "response.pending_approval": {
    event: "response.pending_approval",
    name: "Approval needed",
    description: "Ask approvers to review a high-risk response action.",
    audience: "soc",
    subject: "Approval needed: {{action.label}} on {{target.label | default:\"target\"}} ({{organization.name}})",
    body: [
      "**{{requestedBy.name | default:\"An analyst\"}}** requested **{{action.label}}** ({{action.risk}} risk) for {{organization.name}}.",
      "Reason: {{reason}}",
      "- Target: {{target.label | default:\"\"}} ({{target.kind}})\n- Requested via: {{requestedVia | default:\"user\"}}\n- Expires: {{expiresAt | datetime}}",
      "Requesters cannot approve their own actions. Review and decide in the Command Center.",
    ].join("\n\n"),
    variables: [
      { path: "action.label", description: "Action name" },
      { path: "action.risk", description: "low | medium | high" },
      { path: "target.label", description: "Target display name" },
      { path: "reason", description: "Justification" },
      { path: "requestedBy.name", description: "Requester" },
      { path: "expiresAt", description: "Approval deadline" },
    ],
    throttleMinutes: 0,
  },
  "agent.unresponsive": {
    event: "agent.unresponsive",
    name: "Agent unresponsive",
    description: "Endpoint agent stopped checking in.",
    audience: "customer",
    subject: "Endpoint agent not reporting: {{agent.hostname}}",
    body: [
      "The protection agent on **{{agent.hostname}}** ({{organization.name}}) has not checked in since {{agent.lastCheckinAt | datetime}}.",
      "Until it reconnects this device is not monitored. Please confirm the device is powered on and connected, or tell us if it was decommissioned.",
      "- Platform: {{agent.platform | default:\"unknown\"}}\n- Agent version: {{agent.version | default:\"unknown\"}}",
    ].join("\n\n"),
    variables: [
      { path: "agent.hostname", description: "Host name" },
      { path: "agent.lastCheckinAt", description: "Last check-in" },
      { path: "agent.platform", description: "windows | macos | linux" },
    ],
    throttleMinutes: 1440,
  },
  "indicator.matched": {
    event: "indicator.matched",
    name: "Threat intelligence match",
    description: "A known-bad indicator was observed in the environment.",
    audience: "soc",
    subject: "Intel match: {{indicator.type | upper}} {{indicator.value | defang}} ({{organization.name}})",
    body: [
      "Threat intelligence indicator **{{indicator.value | defang}}** ({{indicator.type}}) was observed on {{entities | join:\", \" | default:\"an asset\"}}.",
      "- Source: {{indicator.source}}\n- Confidence: {{indicator.confidence}}%\n- Threat actor: {{indicator.threatActor | default:\"unattributed\"}}\n- Malware: {{indicator.malware | default:\"n/a\"}}",
      "Indicators are defanged in notifications; do not visit them.",
    ].join("\n\n"),
    variables: [
      { path: "indicator.type", description: "ip | domain | url | sha256 …" },
      { path: "indicator.value", description: "Indicator value (use | defang)" },
      { path: "indicator.source", description: "Feed / source" },
      { path: "indicator.confidence", description: "0-100" },
      { path: "entities", description: "Entities that matched" },
    ],
    throttleMinutes: 60,
  },
  "vulnerability.kev_detected": {
    event: "vulnerability.kev_detected",
    name: "Known-exploited vulnerability",
    description: "A CISA KEV vulnerability appeared on an asset.",
    audience: "customer",
    subject: "Known-exploited vulnerability {{vulnerability.cve}} on {{asset.name}}",
    body: [
      "**{{vulnerability.cve}}** — {{vulnerability.title}} — is being actively exploited in the wild and was found on **{{asset.name}}** ({{asset.criticality | default:\"unknown\"}} criticality).",
      "- CVSS: {{vulnerability.cvss | default:\"n/a\"}}\n- EPSS: {{vulnerability.epss | percent | default:\"n/a\"}}\n- Patch available: {{vulnerability.patchAvailable}}\n- Remediation due: {{vulnerability.slaDueAt | date | default:\"as soon as possible\"}}",
      "Prioritise patching or apply the vendor mitigation.",
    ].join("\n\n"),
    variables: [
      { path: "vulnerability.cve", description: "CVE id" },
      { path: "vulnerability.title", description: "Title" },
      { path: "asset.name", description: "Affected asset" },
      { path: "vulnerability.slaDueAt", description: "SLA due date" },
    ],
    throttleMinutes: 1440,
  },
  "report.generated": {
    event: "report.generated",
    name: "Report ready",
    description: "A scheduled or on-demand report finished.",
    audience: "business",
    subject: "{{report.title}} — {{report.periodLabel}}",
    body: ["Your **{{report.title}}** for {{organization.name}} ({{report.periodLabel}}) is ready.", "{{report.headline | default:\"\"}}", "Open the report in the portal or use the attached file."].join("\n\n"),
    variables: [
      { path: "report.title", description: "Report title" },
      { path: "report.periodLabel", description: "Reporting period" },
      { path: "report.headline", description: "One-line summary" },
    ],
    throttleMinutes: 0,
  },
  "trial.ending": {
    event: "trial.ending",
    name: "Trial ending",
    description: "Commercial reminder before a module trial ends.",
    audience: "business",
    subject: "Your {{module.name}} trial ends {{trial.endsAt | date}}",
    body: [
      "The {{module.name}} trial for {{organization.name}} ends on **{{trial.endsAt | date}}**.",
      "During the trial: {{trial.highlights | join:\"; \" | default:\"see the module dashboard for activity\"}}.",
      "Contact your account manager to keep protection active.",
    ].join("\n\n"),
    variables: [
      { path: "module.name", description: "Module name" },
      { path: "trial.endsAt", description: "End date" },
      { path: "trial.highlights", description: "What the module found during the trial" },
    ],
    throttleMinutes: 1440,
  },
  "usage.quota_exceeded": {
    event: "usage.quota_exceeded",
    name: "Usage quota exceeded",
    description: "Plan limit reached (endpoints, events/day, AI requests).",
    audience: "mssp",
    subject: "Quota exceeded: {{quota.name}} for {{organization.name}}",
    body: [
      "{{organization.name}} is using **{{quota.used | number}}** of {{quota.limit | number}} {{quota.unit | default:\"\"}} ({{quota.percent | percent}}) on the {{plan.name | default:\"current\"}} plan.",
      "Ingestion and protection continue; review the plan or usage to avoid overage charges.",
    ].join("\n\n"),
    variables: [
      { path: "quota.name", description: "Quota (endpoints, events/day…)" },
      { path: "quota.used", description: "Current usage" },
      { path: "quota.limit", description: "Limit" },
      { path: "quota.percent", description: "Utilisation ratio" },
    ],
    throttleMinutes: 1440,
  },
};
