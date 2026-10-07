import { z } from "zod";
import { IsoDateTime, Uuid } from "./common.js";

/** SOAR response actions. High-risk actions always pass an approval gate. */
export const RESPONSE_ACTIONS = [
  { key: "isolate_endpoint", label: "Isolate endpoint", risk: "high", target: "asset" },
  { key: "release_endpoint", label: "Release endpoint from isolation", risk: "medium", target: "asset" },
  { key: "kill_process", label: "Kill process", risk: "medium", target: "asset" },
  { key: "quarantine_file", label: "Quarantine file", risk: "medium", target: "asset" },
  { key: "block_ip", label: "Block IP", risk: "high", target: "indicator" },
  { key: "block_domain", label: "Block domain", risk: "high", target: "indicator" },
  { key: "disable_identity", label: "Disable identity", risk: "high", target: "identity" },
  { key: "revoke_sessions", label: "Revoke sessions", risk: "high", target: "identity" },
  { key: "revoke_token", label: "Revoke token", risk: "high", target: "identity" },
  { key: "create_case", label: "Create case", risk: "low", target: "incident" },
  { key: "notify_analyst", label: "Notify analyst", risk: "low", target: "incident" },
  { key: "collect_evidence", label: "Collect evidence", risk: "low", target: "asset" },
  { key: "launch_investigation", label: "Launch investigation", risk: "low", target: "incident" },
  { key: "run_yara_scan", label: "Run YARA scan", risk: "low", target: "asset" },
  { key: "send_email", label: "Send email", risk: "low", target: "incident" },
] as const;

export type ResponseActionKey = (typeof RESPONSE_ACTIONS)[number]["key"];
export const ResponseActionKey = z.enum(RESPONSE_ACTIONS.map((a) => a.key) as [ResponseActionKey, ...ResponseActionKey[]]);
export type ActionRisk = "low" | "medium" | "high";

export function actionRisk(key: ResponseActionKey): ActionRisk {
  return RESPONSE_ACTIONS.find((a) => a.key === key)!.risk;
}

export const ResponseActionStatus = z.enum(["pending_approval", "approved", "rejected", "queued", "running", "succeeded", "failed", "cancelled"]);
export type ResponseActionStatus = z.infer<typeof ResponseActionStatus>;

export const ResponseActionRequest = z.object({
  action: ResponseActionKey,
  organizationId: Uuid,
  incidentId: Uuid.optional(),
  target: z.object({ kind: z.enum(["asset", "identity", "indicator", "incident"]), id: z.string(), label: z.string().optional() }),
  parameters: z.record(z.unknown()).default({}),
  reason: z.string().min(3).max(2000),
});
export type ResponseActionRequest = z.input<typeof ResponseActionRequest>;

export const ResponseActionRecord = z.object({
  id: Uuid,
  tenantId: Uuid,
  organizationId: Uuid,
  incidentId: Uuid.nullable(),
  action: ResponseActionKey,
  target: z.object({ kind: z.string(), id: z.string(), label: z.string().optional() }),
  parameters: z.record(z.unknown()),
  reason: z.string(),
  status: ResponseActionStatus,
  requestedBy: z.string(),
  requestedVia: z.enum(["user", "playbook", "ai"]),
  approvedBy: z.string().nullable(),
  executor: z.string().nullable(),
  result: z.unknown().nullable(),
  createdAt: IsoDateTime,
  updatedAt: IsoDateTime,
});
export type ResponseActionRecord = z.infer<typeof ResponseActionRecord>;

/** Playbook = trigger + conditions + ordered steps (detection-as-code style, versioned). */
export const PlaybookTrigger = z.object({
  on: z.enum(["incident.created", "incident.updated", "alert.created", "indicator.matched", "escalation.overdue", "schedule", "manual"]),
  cron: z.string().optional(),
});
export const PlaybookCondition = z.object({
  field: z.string(),
  op: z.enum(["eq", "neq", "gte", "lte", "in", "contains", "exists"]),
  value: z.unknown().optional(),
});
export type PlaybookCondition = z.infer<typeof PlaybookCondition>;
export const PlaybookStep = z.object({
  id: z.string(),
  action: ResponseActionKey,
  parameters: z.record(z.unknown()).default({}),
  /** Force an approval even for low-risk actions. High-risk actions always require approval. */
  requireApproval: z.boolean().default(false),
  continueOnError: z.boolean().default(false),
});
export const Playbook = z.object({
  id: Uuid,
  tenantId: Uuid,
  /** null = global MSSP playbook, applied to all organizations unless overridden. */
  organizationId: Uuid.nullable(),
  name: z.string(),
  description: z.string().nullable(),
  version: z.number().int(),
  enabled: z.boolean(),
  trigger: PlaybookTrigger,
  conditions: z.array(PlaybookCondition),
  steps: z.array(PlaybookStep),
});
export type Playbook = z.infer<typeof Playbook>;

// ─── Notifications & automations ────────────────────────────────────────────

export const NotificationChannelKind = z.enum(["email", "webhook", "slack", "teams", "syslog", "in_app"]);
export type NotificationChannelKind = z.infer<typeof NotificationChannelKind>;

export const NotificationChannel = z.object({
  id: Uuid,
  tenantId: Uuid,
  organizationId: Uuid.nullable(),
  name: z.string(),
  kind: NotificationChannelKind,
  /** email: { to: string[] }, webhook/slack/teams: { url } (url stored as secret ref), syslog: { host, port } */
  config: z.record(z.unknown()),
  enabled: z.boolean(),
});
export type NotificationChannel = z.infer<typeof NotificationChannel>;

export const AUTOMATION_EVENTS = [
  "incident.created",
  "incident.severity_changed",
  "incident.closed",
  "escalation.created",
  "escalation.overdue",
  "response.pending_approval",
  "agent.unresponsive",
  "indicator.matched",
  "vulnerability.kev_detected",
  "report.generated",
  "trial.ending",
  "usage.quota_exceeded",
] as const;
export const AutomationEvent = z.enum(AUTOMATION_EVENTS);
export type AutomationEvent = z.infer<typeof AutomationEvent>;

/** "When <event> and <conditions>, notify <channels> using <template>." */
export const AutomationRule = z.object({
  id: Uuid,
  tenantId: Uuid,
  organizationId: Uuid.nullable(),
  name: z.string(),
  event: AutomationEvent,
  conditions: z.array(PlaybookCondition),
  channelIds: z.array(Uuid),
  template: z.object({ subject: z.string(), body: z.string() }),
  /** Suppress repeats for the same subject within this many minutes. */
  throttleMinutes: z.number().int().min(0).max(10080),
  enabled: z.boolean(),
});
export type AutomationRule = z.infer<typeof AutomationRule>;

// ─── Reporting ──────────────────────────────────────────────────────────────

export const REPORT_TYPES = [
  { key: "executive", label: "Executive / CISO summary", audience: "business" },
  { key: "soc_operations", label: "SOC operations", audience: "soc" },
  { key: "incident", label: "Incident report", audience: "soc" },
  { key: "vulnerability", label: "Vulnerability & exposure", audience: "soc" },
  { key: "threat_intel", label: "Threat intelligence", audience: "soc" },
  { key: "compliance", label: "Compliance posture", audience: "business" },
  { key: "sla", label: "SLA performance", audience: "mssp" },
  { key: "analyst_activity", label: "Analyst activity", audience: "mssp" },
  { key: "customer_monthly", label: "Customer monthly service review", audience: "customer" },
  { key: "mssp_portfolio", label: "MSSP portfolio & revenue", audience: "mssp" },
] as const;
export type ReportType = (typeof REPORT_TYPES)[number]["key"];
export const ReportType = z.enum(REPORT_TYPES.map((r) => r.key) as [ReportType, ...ReportType[]]);
export const ReportFormat = z.enum(["html", "pdf", "csv", "json"]);
export type ReportFormat = z.infer<typeof ReportFormat>;

export const ReportSchedule = z.object({
  id: Uuid,
  tenantId: Uuid,
  organizationId: Uuid.nullable(),
  type: ReportType,
  name: z.string(),
  cron: z.string(),
  format: ReportFormat,
  periodDays: z.number().int().min(1).max(366),
  channelIds: z.array(Uuid),
  enabled: z.boolean(),
  lastRunAt: IsoDateTime.nullable(),
});
export type ReportSchedule = z.infer<typeof ReportSchedule>;
