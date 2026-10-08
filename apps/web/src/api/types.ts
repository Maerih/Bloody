import type {
  Account,
  Agent,
  AgentStatus,
  AiActionRecord,
  AiMessage,
  AiToolTier,
  AttackPath,
  AttackTechnique,
  AutomationEvent,
  CanonicalEvent,
  Criticality,
  Evidence,
  Indicator,
  IndicatorType,
  Investigation,
  NodeKind,
  Playbook,
  PlaybookCondition,
  Alert,
  Asset,
  AssetKind,
  Entitlement,
  Identity,
  Incident,
  IncidentStatus,
  ModuleKey,
  NotificationChannelKind,
  Organization,
  PlanKey,
  Principal,
  ReportFormat,
  ReportType,
  ResponseActionStatus,
  RiskAssessment,
  RiskFactor,
  RoleBinding,
  RoleKey,
  Severity,
  TimelineEntry,
  Vulnerability,
} from "@bloody/contracts";

type InvestigationStatus = Investigation["status"];

/**
 * Web-side DTOs for responses documented in docs/ARCHITECTURE.md §5 that do not (yet) have a
 * dedicated export in @bloody/contracts. Everything else is imported from contracts directly.
 * Optional fields are tolerated extensions: the UI renders them when the API provides them and
 * never invents values when it does not.
 */

export interface AccountTeamMember {
  name: string;
  email: string;
  title?: string | null;
  avatarUrl?: string | null;
}

/** GET /auth/me */
export interface MeResponse {
  principal: Principal;
  account: Account;
  organizations: Organization[];
  entitlements: EntitlementView[];
  plan: PlanKey;
  /** Named account team (CSM / sales engineer) when the account has one assigned. */
  accountTeam?: AccountTeamMember[] | null;
}

export interface EntitlementView extends Entitlement {
  /** When a lapsed trial's agents/integrations are automatically removed, if scheduled. */
  uninstallAt?: string | null;
}

export interface LoginRequest {
  email: string;
  password: string;
  /** TOTP code when the account enforces MFA. */
  totp?: string;
}

/** POST /auth/login — the session itself lives in an httpOnly cookie. */
export interface LoginResponse {
  token?: string;
  expiresAt?: string;
  mfaRequired?: boolean;
  principal?: Principal;
}

export interface OidcStartResponse {
  url?: string;
  authorizationUrl?: string;
}

/** One normalized global-search hit (GET /search?q). */
export interface SearchHit {
  kind: string;
  id: string;
  title: string;
  subtitle?: string | null;
  organizationId?: string | null;
  organizationName?: string | null;
  severity?: Severity | null;
  href?: string | null;
}

export interface IncidentFilters {
  organizationId?: string | null;
  severity?: Severity[];
  status?: IncidentStatus[];
  q?: string;
  assigneeId?: string;
  limit?: number;
  cursor?: string;
}

/** GET /incidents/:id — base incident plus optional embedded context. */
export interface IncidentDetail extends Incident {
  risk?: RiskAssessment | null;
  alerts?: Alert[];
  assets?: Asset[];
  identities?: Identity[];
  organizationName?: string | null;
  assigneeName?: string | null;
}

export interface EscalationFilters {
  organizationId?: string | null;
  status?: ("open" | "acknowledged" | "resolved")[];
  limit?: number;
  cursor?: string;
}

export interface AlertFilters {
  organizationId?: string | null;
  incidentId?: string;
  assetId?: string;
  identityId?: string;
  severity?: Severity[];
  status?: AlertStatus[];
  ruleId?: string;
  /** true = alerts not yet correlated into an incident. */
  unlinked?: boolean;
  q?: string;
  from?: string;
  to?: string;
  sort?: "recent" | "risk";
  limit?: number;
  cursor?: string;
}

export type AlertStatus = Alert["status"];

export interface ResponseActionFilters {
  organizationId?: string | null;
  incidentId?: string;
  status?: ResponseActionStatus[];
  limit?: number;
}

/** GET /users */
export interface UserSummary {
  id: string;
  email: string;
  displayName: string | null;
  bindings?: RoleBinding[];
  mfaEnabled?: boolean;
  lastLoginAt?: string | null;
  disabled?: boolean;
  title?: string | null;
  status?: "active" | "invited" | "disabled" | string;
  organizationId?: string | null;
  locked?: boolean;
  createdAt?: string;
  teams?: { id: string; name: string; memberRole: string }[];
}

/** POST /reports/generate */
export interface GenerateReportRequest {
  type: ReportType;
  format: ReportFormat;
  organizationId: string | null;
  periodDays: number;
  parameters?: Record<string, unknown>;
}

/** POST /reports/schedules */
export interface CreateReportScheduleInput {
  type: ReportType;
  name: string;
  cron: string;
  format: ReportFormat;
  periodDays: number;
  organizationId: string | null;
  channelIds: string[];
  enabled: boolean;
}

export interface ReportTypeInfo {
  key: ReportType;
  label: string;
  audience: string;
}

/** Aggregated, actionable notification shown in the bell panel. */
export interface NotificationItem {
  id: string;
  kind: "escalation" | "approval" | "incident";
  title: string;
  detail: string;
  severity: Severity;
  organizationId: string | null;
  at: string;
  href: string;
}

export interface NotificationChannelSummary {
  id: string;
  name: string;
  kind: NotificationChannelKind;
  enabled: boolean;
  organizationId: string | null;
}

/** GET /billing/usage */
export interface BillingUsage {
  plan: PlanKey;
  period?: { start: string; end: string };
  usage: Record<string, { used: number; limit: number | null }>;
}

/** POST /notifications/channels. Webhook/Slack/Teams URLs are write-only secrets server-side. */
export interface CreateNotificationChannelInput {
  name: string;
  kind: NotificationChannelKind;
  organizationId: string | null;
  config: Record<string, unknown>;
  enabled: boolean;
}

/** POST /automations — "When <event> and <conditions>, notify <channels> using <template>." */
export interface CreateAutomationRuleInput {
  name: string;
  organizationId: string | null;
  event: AutomationEvent;
  conditions: PlaybookCondition[];
  channelIds: string[];
  template: { subject: string; body: string };
  throttleMinutes: number;
  enabled: boolean;
}

// ════════════════════════════════════════════════════════════════════════════
// Part B — module workspaces. Shapes follow docs/ARCHITECTURE.md §5 and the
// implemented routes in apps/api/src/routes; optional fields are tolerated
// extensions rendered only when present.
// ════════════════════════════════════════════════════════════════════════════

// ─── Investigations ─────────────────────────────────────────────────────────

/** GET /investigations (list rows carry denormalized context). */
export interface InvestigationSummary extends Investigation {
  organizationName?: string | null;
  incidentNumber?: number | null;
  incidentSeverity?: Severity | null;
  openTasks?: number;
  evidenceCount?: number;
}

export interface InvestigationFilters {
  organizationId?: string | null;
  incidentId?: string;
  status?: InvestigationStatus[];
  q?: string;
  limit?: number;
  cursor?: string;
}

export interface InvestigationNote {
  id: string;
  organizationId: string;
  incidentId: string | null;
  investigationId: string | null;
  authorId: string;
  authorLabel: string | null;
  body: string;
  visibility: "internal" | "customer";
  createdAt: string;
}

export type TaskStatus = "open" | "in_progress" | "done" | "cancelled";

export interface InvestigationTask {
  id: string;
  investigationId: string;
  organizationId: string;
  title: string;
  description: string | null;
  status: TaskStatus;
  assigneeId: string | null;
  dueAt: string | null;
  completedAt: string | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
  overdue?: boolean;
}

export interface CustodyEntry {
  at: string;
  actor: string;
  action: string;
  hash: string;
  note?: string;
}

export type EvidenceKind = Evidence["kind"];

/** Evidence with its hash-chained custody log and the server's chain verification. */
export interface EvidenceView extends Omit<Evidence, "custody"> {
  custody: CustodyEntry[];
  custodyVerification?: { valid: boolean; brokenAt: number | null };
  /** Stored inline by the platform (downloadable) vs. registered external reference. */
  inline?: boolean;
}

/** GET /investigations/:id */
export interface InvestigationDetail extends Investigation {
  organizationName?: string | null;
  incident?: Incident | null;
  timeline: TimelineEntry[];
  notes: InvestigationNote[];
  tasks: InvestigationTask[];
  evidence: EvidenceView[];
}

export interface CreateInvestigationInput {
  organizationId?: string;
  incidentId?: string;
  title: string;
  hypothesis?: string;
  leadId?: string;
}

export interface UpdateInvestigationInput {
  title?: string;
  status?: InvestigationStatus;
  leadId?: string | null;
  hypothesis?: string | null;
}

export interface CreateTaskInput {
  title: string;
  description?: string;
  assigneeId?: string;
  dueAt?: string;
}

export interface UpdateTaskInput {
  title?: string;
  description?: string | null;
  status?: TaskStatus;
  assigneeId?: string | null;
  dueAt?: string | null;
}

/** POST /investigations/:id/evidence — inline bytes, or a registered external artifact. */
export type AddEvidenceInput = { name: string; kind: EvidenceKind; tags: string[]; note?: string } & (
  | { contentBase64: string }
  | { sha256: string; sizeBytes: number; storageRef: string }
);

export const CUSTODY_ACTIONS = ["accessed", "analyzed", "transferred", "exported", "verified", "sealed", "returned"] as const;
export type CustodyAction = (typeof CUSTODY_ACTIONS)[number];

// ─── Inventory ──────────────────────────────────────────────────────────────

export interface AssetFilters {
  organizationId?: string | null;
  q?: string;
  kind?: AssetKind[];
  criticality?: Criticality[];
  internetFacing?: boolean;
  minRisk?: number;
  sort?: "risk" | "name" | "recent";
  limit?: number;
  cursor?: string;
}

/** GET /assets/:id — the asset plus related records the principal may read (null = no permission). */
export interface AssetDetail extends Asset {
  agents?: Agent[];
  vulnerabilities?: Vulnerability[] | null;
  alerts?: Alert[] | null;
  incidents?: Incident[] | null;
}

export interface AgentFilters {
  organizationId?: string | null;
  q?: string;
  status?: AgentStatus[];
  platform?: Agent["platform"];
  antivirusStatus?: Agent["antivirusStatus"];
  limit?: number;
  cursor?: string;
}

export interface IdentityView extends Identity {
  enabled?: boolean;
}

export interface IdentityFilters {
  organizationId?: string | null;
  q?: string;
  provider?: string;
  kind?: IdentityView["kind"][];
  privileged?: boolean;
  mfa?: boolean;
  minRisk?: number;
  sort?: "risk" | "principal" | "recent";
  limit?: number;
  cursor?: string;
}

/** What an identity can reach in the Security Graph. */
export interface IdentityAccess {
  kind: string;
  assetId: string | null;
  label: string;
  criticality: string | null;
}

export interface IdentityDetail extends IdentityView {
  alerts?: Alert[] | null;
  access?: IdentityAccess[] | null;
}

// ─── SIEM: events & detections ──────────────────────────────────────────────

export interface EventSearchParams {
  organizationId?: string | null;
  /** Bloody query syntax (field:value, AND/OR/NOT, wildcards, ranges). */
  q: string;
  /** Relative window ("15m", "24h", "7d"…) or absolute bounds. */
  range: TimeRange;
  limit?: number;
}

export type TimeRange = { preset: TimeRangePreset } | { from: string; to: string };
export type TimeRangePreset = "15m" | "1h" | "4h" | "24h" | "7d" | "30d" | "90d";

export interface EventSearchResult {
  items: CanonicalEvent[];
  nextCursor: string | null;
  total?: number;
  truncated?: boolean;
}

export type DetectionKind = "sigma" | "threshold" | "sequence" | "yara" | "suricata" | "custom";

export interface DetectionRule {
  id: string;
  organizationId: string | null;
  name: string;
  description: string | null;
  kind: DetectionKind;
  severity: Severity;
  enabled: boolean;
  version: number;
  /** Rule source (Sigma YAML for kind "sigma"). */
  source: string;
  attack: AttackTechnique[];
  tags?: string[];
  createdAt?: string;
  updatedAt: string;
  lastMatchedAt?: string | null;
  matches24h?: number | null;
}

export interface UpsertDetectionInput {
  name: string;
  description?: string | null;
  kind: DetectionKind;
  severity: Severity;
  enabled: boolean;
  source: string;
  organizationId: string | null;
  tags?: string[];
}

export interface DetectionTestInput {
  /** Test the editor's current source instead of the saved version. */
  source?: string;
  lookbackHours: number;
}

export interface DetectionTestResult {
  valid: boolean;
  errors: string[];
  matched: number;
  scanned?: number | null;
  events: CanonicalEvent[];
}

// ─── Security Graph & attack paths ─────────────────────────────────────────

export interface GraphSearchParams {
  q: string;
  kinds?: NodeKind[];
  limit?: number;
  organizationId?: string | null;
}

export interface NeighborParams {
  depth?: number;
  direction?: "in" | "out" | "both";
  limit?: number;
}

/** One entry of the greedy "fix this to break N paths" remediation ranking. */
export interface RemediationPriorityView {
  nodeId?: string;
  edgeId?: string;
  action: string;
  pathsBroken: number;
  marginalPathsBroken?: number;
  riskReduced?: number;
  rank?: number | null;
  effort?: "low" | "medium" | "high";
  category?: string;
}

export interface AttackPathSummaryView {
  totalPaths: number;
  targetsAtRisk?: number;
  entryPoints?: number;
  maxRiskScore?: number;
  shortestPathLength?: number | null;
  fixesToBreakAll?: number;
  topRemediation?: string | null;
  truncated?: boolean;
}

export interface AttackPathResult {
  paths: AttackPath[];
  remediations: RemediationPriorityView[];
  summary: AttackPathSummaryView | null;
}

// ─── Exposure & vulnerabilities ─────────────────────────────────────────────

export interface VulnerabilityFilters {
  organizationId?: string | null;
  q?: string;
  severity?: Severity[];
  status?: Vulnerability["status"][];
  knownExploited?: boolean;
  assetId?: string;
  sort?: "risk" | "cvss" | "epss" | "sla" | "recent";
  limit?: number;
  cursor?: string;
}

export interface VulnerabilityView extends Vulnerability {
  assetName?: string | null;
  /** Risk-acceptance exception (status "accepted"). */
  exceptionReason?: string | null;
  exceptionExpiresAt?: string | null;
}

export interface UpdateVulnerabilityInput {
  status: Vulnerability["status"];
  reason?: string;
  /** Exception expiry for status "accepted". */
  expiresAt?: string | null;
}

export interface ExposureComponent {
  key: string;
  label: string;
  /** 0–100 exposure (higher is worse). */
  score: number;
  findings?: number | null;
  module?: ModuleKey | null;
}

/** GET /exposure/summary — unified, explained exposure score. */
export interface ExposureSummary {
  score: number;
  severity?: Severity;
  summary?: string | null;
  likelihood?: number | null;
  impact?: number | null;
  factors?: RiskFactor[];
  modelVersion?: string | null;
  components?: ExposureComponent[];
  generatedAt?: string;
}

// ─── Threat intelligence ────────────────────────────────────────────────────

export interface IndicatorFilters {
  organizationId?: string | null;
  q?: string;
  type?: IndicatorType[];
  severity?: Severity[];
  limit?: number;
  cursor?: string;
}

export interface CreateIndicatorInput {
  organizationId: string | null;
  type: IndicatorType;
  value: string;
  confidence: number;
  severity: Severity;
  source: string;
  threatActor?: string | null;
  malware?: string | null;
  campaign?: string | null;
  tags: string[];
  expiresAt?: string | null;
}

/** GET /intel/matches — an indicator observed in this environment. */
export interface IntelMatch {
  id: string;
  indicatorId: string;
  indicator?: Indicator | null;
  organizationId: string;
  matchedAt: string;
  entityKind: string;
  entityId: string | null;
  entityLabel?: string | null;
  field?: string | null;
  eventId?: string | null;
  incidentId?: string | null;
  value?: string | null;
}

export interface IntelMatchFilters {
  organizationId?: string | null;
  indicatorId?: string;
  incidentId?: string;
  limit?: number;
  cursor?: string;
}

// ─── SOAR ───────────────────────────────────────────────────────────────────

export interface UpsertPlaybookInput {
  name: string;
  description: string | null;
  organizationId: string | null;
  enabled: boolean;
  trigger: Playbook["trigger"];
  conditions: Playbook["conditions"];
  steps: Playbook["steps"];
}

// ─── AI SOC ─────────────────────────────────────────────────────────────────

export type AiContextKind = "incident" | "investigation" | "asset" | "identity" | "indicator" | "alert" | "none";

export interface AiConversationSummary {
  id: string;
  title: string | null;
  organizationId: string | null;
  context?: { kind: AiContextKind; id?: string } | null;
  providerId?: string | null;
  model?: string | null;
  createdAt: string;
  updatedAt: string;
  messageCount?: number | null;
}

export interface AiThreadMessage {
  seq: number;
  at: string | null;
  message: AiMessage;
}

export interface AiConversationDetail {
  conversation: AiConversationSummary;
  messages: AiThreadMessage[];
  actions: AiActionRecord[];
}

/** POST /ai/chat */
export interface AiChatResult {
  conversationId: string;
  providerId: string | null;
  model: string | null;
  answer: string;
  finishReason: string | null;
  actions: AiActionRecord[];
  maxToolTier: AiToolTier | null;
  fallbackUsed: boolean;
}

/** POST /ai/providers/:id/test */
export interface AiProviderTestResult {
  ok: boolean;
  latencyMs: number | null;
  message: string | null;
  models: string[];
}

// ─── Integrations ───────────────────────────────────────────────────────────

export type IntegrationStatus = "healthy" | "degraded" | "error" | "pending" | "disabled" | "unknown";

/** GET /integrations — a configured engine connection. Credentials are never returned. */
export interface IntegrationView {
  id: string;
  organizationId: string | null;
  /** ENGINES[].key */
  engine: string;
  name: string;
  endpoint: string | null;
  enabled: boolean;
  hasCredential: boolean;
  status: IntegrationStatus;
  lastSyncAt: string | null;
  lastError: string | null;
  config?: Record<string, unknown>;
  eventsLast24h?: number | null;
  createdAt?: string;
  updatedAt?: string;
}

/** POST /integrations — `credential` is write-only (stored in the secret store). */
export interface CreateIntegrationInput {
  engine: string;
  name: string;
  organizationId: string | null;
  endpoint: string | null;
  credential?: string;
  enabled: boolean;
  config?: Record<string, unknown>;
}

export interface IntegrationSyncResult {
  status?: string;
  message?: string;
}

// ─── Settings: API keys, audit, teams, users ───────────────────────────────

export interface ApiKeyView {
  id: string;
  name: string;
  prefix: string;
  organizationId: string | null;
  roles: RoleBinding[];
  createdBy: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  expiresAt: string | null;
  revokedAt: string | null;
  active: boolean;
}

export interface CreateApiKeyInput {
  name: string;
  organizationId: string | null;
  roles: RoleKey[];
  expiresInDays?: number;
}

/** POST /api-keys — the full key is returned exactly once. */
export interface CreateApiKeyResult {
  apiKey: ApiKeyView;
  key: string;
}

export interface AuditRecord {
  id: string;
  seq: number;
  at: string;
  organizationId: string | null;
  actor: { kind: string; id: string | null; label: string | null };
  action: string;
  target: { kind: string | null; id: string | null } | null;
  outcome: "success" | "denied" | "failure" | string;
  ip: string | null;
  userAgent: string | null;
  requestId: string | null;
  details: Record<string, unknown>;
  hash: string;
  prevHash: string | null;
}

export interface AuditFilters {
  organizationId?: string | null;
  action?: string;
  actorKind?: "user" | "service" | "system" | "anonymous";
  actorId?: string;
  targetKind?: string;
  targetId?: string;
  outcome?: ("success" | "denied" | "failure")[];
  requestId?: string;
  from?: string;
  to?: string;
  limit?: number;
}

export interface AuditVerifyResult {
  intact: boolean;
  firstBrokenSeq: number | null;
  records: number;
  headSeq: number | null;
  headHash: string | null;
  verifiedAt: string;
}

export interface TeamView {
  id: string;
  organizationId: string | null;
  name: string;
  description: string | null;
  createdAt: string;
  members: { userId: string; email: string; displayName: string | null; memberRole: string }[];
  bindings: RoleBinding[];
}

export interface CreateUserInput {
  email: string;
  displayName?: string | null;
  title?: string | null;
  organizationId?: string | null;
  roles: RoleBinding[];
}

export interface UpdateUserInput {
  displayName?: string | null;
  title?: string | null;
  status?: "active" | "disabled";
}
