import type {
  Account,
  Alert,
  Asset,
  Entitlement,
  Identity,
  Incident,
  IncidentStatus,
  NotificationChannelKind,
  Organization,
  PlanKey,
  Principal,
  ReportFormat,
  ReportType,
  ResponseActionStatus,
  RiskAssessment,
  RoleBinding,
  Severity,
} from "@bloody/contracts";

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
  severity?: Severity[];
  limit?: number;
  cursor?: string;
}

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
