import type {
  Agent,
  Alert,
  Asset,
  AttackPath,
  CanonicalEvent,
  EdgeKind,
  Evidence,
  GraphNode,
  Identity,
  Incident,
  IncidentStatus,
  Indicator,
  IndicatorType,
  Investigation,
  NotificationChannel,
  Playbook,
  ReportType,
  ResponseActionKey,
  ResponseActionRecord,
  RiskAssessment,
  Severity,
  Subgraph,
  TimelineEntry,
  Vulnerability,
} from "@bloody/contracts";
import type { SocScope } from "./types.js";

/**
 * Port between the AI SOC and Bloody's data plane. The API implements it on top of its
 * repositories (Postgres with RLS, OpenSearch, the Security Graph, Risk/Attack-Path engines).
 *
 * Contract for implementers:
 *  - every method MUST scope queries to `scope.tenantId` (and `scope.organizationId`) — the
 *    scope is derived from the authenticated principal, never from model output;
 *  - entities outside the scope MUST be reported as not found (`null` / empty), never leaked;
 *  - results should honour the requested limits (the gateway truncates oversize results anyway).
 */

export interface IncidentDetail {
  incident: Incident;
  alerts: Alert[];
  investigations: Investigation[];
  timeline: TimelineEntry[];
}

export interface AssetDetail {
  asset: Asset;
  risk: RiskAssessment | null;
  vulnerabilities: Vulnerability[];
  agent: Agent | null;
  identities: Identity[];
  openIncidents: Incident[];
}

export interface IdentityDetail {
  identity: Identity;
  risk: RiskAssessment | null;
  groups: string[];
  recentAuthentications: CanonicalEvent[];
  openIncidents: Incident[];
}

export interface InvestigationDetail {
  investigation: Investigation;
  timeline: TimelineEntry[];
  evidence: Evidence[];
}

export interface IncidentFilter {
  status?: IncidentStatus[];
  severity?: Severity[];
  query?: string;
  assetId?: string;
  identityId?: string;
  since?: string;
  limit: number;
}

export interface AlertFilter {
  incidentId?: string;
  assetId?: string;
  identityId?: string;
  severityAtLeast?: Severity;
  since: string;
  limit: number;
}

export interface EventSearchInput {
  /** Bloody search syntax (field:value, AND/OR/NOT, wildcards) evaluated by the event store. */
  query: string;
  from: string;
  to: string;
  limit: number;
  fields?: string[];
}

export interface EventSearchResult {
  events: CanonicalEvent[];
  total: number;
  truncated: boolean;
}

export interface GraphNeighborsInput {
  nodeId: string;
  depth: number;
  direction: "out" | "in" | "both";
  edgeKinds?: EdgeKind[];
  limit: number;
}

export interface BlastRadiusResult extends Subgraph {
  /** Ids of crown-jewel / high-criticality nodes reachable from the start node. */
  crownJewels: string[];
}

export interface IntelSearchInput {
  value?: string;
  type?: IndicatorType;
  query?: string;
  includeMatches: boolean;
  limit: number;
}

export interface IntelMatch {
  indicatorId: string;
  type: IndicatorType;
  value: string;
  entity: { kind: string; id: string; label: string };
  lastSeenAt: string;
  incidentId: string | null;
}

export interface IntelSearchResult {
  indicators: Indicator[];
  matches: IntelMatch[];
}

export interface AttackPathQuery {
  assetId?: string;
  nodeId?: string;
  toCrownJewelsOnly: boolean;
  limit: number;
}

export type RiskEntityKind = "asset" | "identity" | "incident" | "vulnerability";

export interface HuntInput {
  hypothesis: string;
  query: string;
  language: "bloody_ql" | "sigma";
  from: string;
  to: string;
  limit: number;
  attack: string[];
}

export interface HuntResult {
  queryExecuted: string;
  hits: CanonicalEvent[];
  total: number;
  truncated: boolean;
  /** Optional top-N aggregations computed by the store (e.g. by host, user, process). */
  aggregations: Record<string, Array<{ key: string; count: number }>>;
}

export interface RuleValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
  /** Matches when replayed against recent telemetry (when the engine supports it). */
  testMatches?: number;
}

export interface ReportDataInput {
  type: ReportType;
  periodDays: number;
  incidentId?: string;
  focus?: string;
}

export interface ReportData {
  type: ReportType;
  organizationName: string | null;
  period: { from: string; to: string };
  /** Report-ready aggregates produced by @bloody/reporting / engines (metrics, trends, top-N). */
  metrics: Record<string, unknown>;
}

export interface SubmitResponseActionInput {
  action: ResponseActionKey;
  target: { kind: "asset" | "identity" | "indicator" | "incident"; id: string; label?: string };
  incidentId?: string;
  parameters: Record<string, unknown>;
  reason: string;
  requestedVia: "ai";
  aiActionId: string;
}

export interface InvestigationNoteInput {
  investigationId: string;
  title: string;
  body: string;
  refs: string[];
  author: { kind: "ai"; onBehalfOf: string; conversationId: string; aiActionId: string };
}

export interface SendNotificationInput {
  channelIds: string[];
  subject: string;
  body: string;
  incidentId?: string;
  aiGenerated: true;
  aiActionId: string;
}

export interface SocDataPort {
  getIncident(scope: SocScope, id: string, opts: { includeAlerts: boolean; includeTimeline: boolean }): Promise<IncidentDetail | null>;
  listIncidents(scope: SocScope, filter: IncidentFilter): Promise<Incident[]>;
  getAlert(scope: SocScope, id: string): Promise<Alert | null>;
  listAlerts(scope: SocScope, filter: AlertFilter): Promise<Alert[]>;
  searchEvents(scope: SocScope, input: EventSearchInput): Promise<EventSearchResult>;
  graphNeighbors(scope: SocScope, input: GraphNeighborsInput): Promise<Subgraph>;
  graphBlastRadius(scope: SocScope, input: { nodeId: string; maxDepth: number; limit: number }): Promise<BlastRadiusResult>;
  graphSearch(scope: SocScope, input: { query: string; limit: number }): Promise<GraphNode[]>;
  getAsset(scope: SocScope, id: string): Promise<AssetDetail | null>;
  getIdentity(scope: SocScope, id: string): Promise<IdentityDetail | null>;
  getInvestigation(scope: SocScope, id: string): Promise<InvestigationDetail | null>;
  searchIntel(scope: SocScope, input: IntelSearchInput): Promise<IntelSearchResult>;
  getAttackPaths(scope: SocScope, input: AttackPathQuery): Promise<AttackPath[]>;
  getRiskAssessment(scope: SocScope, input: { entityKind: RiskEntityKind; id: string }): Promise<RiskAssessment | null>;
  runHunt(scope: SocScope, input: HuntInput): Promise<HuntResult>;
  listVulnerabilities(scope: SocScope, input: { assetId?: string; limit: number }): Promise<Vulnerability[]>;
  /** Compile/validate a detection rule with the Detection Engine. Never deploys it. */
  validateDetectionRule(scope: SocScope, input: { format: "sigma"; content: string }): Promise<RuleValidation>;
  getReportData(scope: SocScope, input: ReportDataInput): Promise<ReportData>;
  listPlaybooks(scope: SocScope, input: { action?: ResponseActionKey }): Promise<Playbook[]>;
  /** Hand an approved AI response action to SOAR (creates a ResponseActionRecord, requestedVia "ai"). */
  submitResponseAction(scope: SocScope, input: SubmitResponseActionInput): Promise<ResponseActionRecord>;
  addInvestigationNote(scope: SocScope, input: InvestigationNoteInput): Promise<TimelineEntry>;
  listNotificationChannels(scope: SocScope): Promise<NotificationChannel[]>;
  sendNotification(scope: SocScope, input: SendNotificationInput): Promise<{ deliveryId: string; channels: number; status: string }>;
}
