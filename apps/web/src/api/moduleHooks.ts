import { useInfiniteQuery, useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import type {
  Agent,
  AiActionRecord,
  AiChatRequest,
  AiProviderConfig,
  Alert,
  Asset,
  CanonicalEvent,
  GraphNode,
  Indicator,
  Page,
  Playbook,
  Subgraph,
  UpsertAiProviderInput,
} from "@bloody/contracts";
import { useMemo } from "react";
import { api, type ApiError, type QueryParams } from "./client";
import {
  toAttackPathResult,
  toChatResult,
  toConversationDetail,
  toConversationList,
  toEventSearchResult,
  toExposureSummary,
  toGraphNodes,
  toProviderTestResult,
  toSubgraph,
} from "./normalize";
import { keepPreviousWithinOrg, orgKey, toArray, toPage, useScope, withoutOrg } from "./queryUtils";
import type {
  AddEvidenceInput,
  AgentFilters,
  AiChatResult,
  AiConversationDetail,
  AiConversationSummary,
  AiProviderTestResult,
  ApiKeyView,
  AssetFilters,
  AttackPathResult,
  AuditFilters,
  AuditRecord,
  AuditVerifyResult,
  CreateApiKeyInput,
  CreateApiKeyResult,
  CreateIndicatorInput,
  CreateIntegrationInput,
  CreateInvestigationInput,
  CreateTaskInput,
  CreateUserInput,
  CustodyAction,
  DetectionRule,
  DetectionTestInput,
  DetectionTestMatch,
  DetectionTestResult,
  DetectionVersion,
  EventSearchParams,
  EventSearchResult,
  EvidenceView,
  ExposureSummary,
  GraphSearchParams,
  IdentityDetail,
  IdentityFilters,
  IdentityView,
  IndicatorFilters,
  IntegrationSyncResult,
  IntegrationView,
  IntelMatch,
  IntelMatchFilters,
  InvestigationDetail,
  InvestigationFilters,
  InvestigationNote,
  InvestigationSummary,
  InvestigationTask,
  NeighborParams,
  TeamView,
  UpdateInvestigationInput,
  UpdateTaskInput,
  UpdateUserInput,
  UpdateVulnerabilityInput,
  UpsertDetectionInput,
  UpsertPlaybookInput,
  UserSummary,
  VulnerabilityFilters,
  VulnerabilityView,
} from "./types";
import { encodeTimeRange, resolveTimeRange } from "../lib/timeRange";

/**
 * Part B hooks: module workspaces over the same data model (docs/ARCHITECTURE.md §5).
 * Re-exported from api/hooks.ts — import them from there.
 */

const enc = encodeURIComponent;

export const moduleKeys = {
  investigations: ["investigations"] as const,
  investigation: (id: string) => ["investigation", id] as const,
  assets: ["assets"] as const,
  agents: ["agents"] as const,
  identities: ["identities"] as const,
  identity: (id: string) => ["identity", id] as const,
  alerts: ["alerts"] as const,
  events: ["events"] as const,
  detections: ["detections"] as const,
  graph: ["graph"] as const,
  attackPaths: ["attack-paths"] as const,
  vulnerabilities: ["vulnerabilities"] as const,
  exposure: ["exposure"] as const,
  indicators: ["intel-indicators"] as const,
  intelMatches: ["intel-matches"] as const,
  playbooks: ["playbooks"] as const,
  aiProviders: ["ai", "providers"] as const,
  aiConversations: ["ai", "conversations"] as const,
  aiConversation: (id: string) => ["ai", "conversation", id] as const,
  integrations: ["integrations"] as const,
  apiKeys: ["api-keys"] as const,
  audit: ["audit"] as const,
  teams: ["teams"] as const,
  users: ["users"] as const,
};

interface ListOptions {
  enabled?: boolean;
  refetchIntervalMs?: number;
  staleTime?: number;
}

/** Org-scoped list query: key `[name, org, filters]`, `organizationId` sent as a query param. */
function useScopedPage<T, F extends { organizationId?: string | null }>(name: string, path: string, filters: F, toQuery: (f: Omit<F, "organizationId">) => QueryParams, options: ListOptions = {}) {
  const orgId = useScope(filters.organizationId);
  const rest = withoutOrg(filters);
  return useQuery<Page<T>, ApiError>({
    queryKey: [name, orgKey(orgId), rest],
    queryFn: async ({ signal }) => toPage(await api.get<Page<T> | T[]>(path, { signal, query: { organizationId: orgId, ...toQuery(rest) } })),
    placeholderData: keepPreviousWithinOrg<Page<T>>(orgId),
    enabled: options.enabled ?? true,
    refetchInterval: options.refetchIntervalMs,
    staleTime: options.staleTime,
  });
}

/** Cursor-paginated variant ("Load more"); `items` flattens every loaded page. */
function useScopedInfinite<T, F extends { organizationId?: string | null }>(name: string, path: string, filters: F, toQuery: (f: Omit<F, "organizationId">) => QueryParams, options: ListOptions = {}) {
  const orgId = useScope(filters.organizationId);
  const rest = withoutOrg(filters);
  const query = useInfiniteQuery<Page<T>, ApiError>({
    queryKey: [name, orgKey(orgId), rest, "infinite"],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ signal, pageParam }) =>
      toPage(await api.get<Page<T> | T[]>(path, { signal, query: { organizationId: orgId, ...toQuery(rest), cursor: pageParam as string | undefined } })),
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    enabled: options.enabled ?? true,
    refetchInterval: options.refetchIntervalMs,
  });
  const items = useMemo(() => (query.data ? query.data.pages.flatMap((p) => p.items) : undefined), [query.data]);
  return { ...query, items };
}

const csv = <T extends string>(v: T[] | undefined) => (v && v.length > 0 ? v : undefined);
const bool = (v: boolean | undefined) => (v === undefined ? undefined : String(v));

// ─── Investigations ─────────────────────────────────────────────────────────

const investigationQuery = (f: Omit<InvestigationFilters, "organizationId">): QueryParams => ({
  incidentId: f.incidentId,
  status: csv(f.status),
  q: f.q?.trim() || undefined,
  limit: f.limit ?? 200,
  cursor: f.cursor,
});

export function useInvestigations(filters: InvestigationFilters = {}, options: ListOptions = {}) {
  return useScopedPage<InvestigationSummary, InvestigationFilters>("investigations", "/investigations", filters, investigationQuery, options);
}

export function useInvestigation(id: string | null | undefined) {
  return useQuery<InvestigationDetail, ApiError>({
    queryKey: moduleKeys.investigation(id ?? ""),
    queryFn: async ({ signal }) => {
      const raw = await api.get<InvestigationDetail>(`/investigations/${enc(id!)}`, { signal });
      return { ...raw, timeline: raw.timeline ?? [], notes: raw.notes ?? [], tasks: raw.tasks ?? [], evidence: raw.evidence ?? [] };
    },
    enabled: Boolean(id),
  });
}

function invalidateInvestigation(qc: QueryClient, id?: string) {
  if (id) void qc.invalidateQueries({ queryKey: moduleKeys.investigation(id) });
  void qc.invalidateQueries({ queryKey: moduleKeys.investigations });
}

export function useCreateInvestigation() {
  const qc = useQueryClient();
  return useMutation<InvestigationSummary, ApiError, CreateInvestigationInput>({
    mutationFn: (input) => api.post<InvestigationSummary>("/investigations", input),
    onSuccess: () => {
      invalidateInvestigation(qc);
      void qc.invalidateQueries({ queryKey: ["incidents"] });
      void qc.invalidateQueries({ queryKey: ["incident"] });
    },
  });
}

export function useUpdateInvestigation(id: string) {
  const qc = useQueryClient();
  return useMutation<InvestigationSummary, ApiError, UpdateInvestigationInput>({
    mutationFn: (patch) => api.patch<InvestigationSummary>(`/investigations/${enc(id)}`, patch),
    onSuccess: () => invalidateInvestigation(qc, id),
  });
}

export function useAddInvestigationNote(id: string) {
  const qc = useQueryClient();
  return useMutation<InvestigationNote, ApiError, { body: string; visibility: "internal" | "customer" }>({
    mutationFn: (input) => api.post<InvestigationNote>(`/investigations/${enc(id)}/notes`, input),
    onSuccess: () => invalidateInvestigation(qc, id),
  });
}

export function useCreateInvestigationTask(id: string) {
  const qc = useQueryClient();
  return useMutation<InvestigationTask, ApiError, CreateTaskInput>({
    mutationFn: (input) => api.post<InvestigationTask>(`/investigations/${enc(id)}/tasks`, input),
    onSuccess: () => invalidateInvestigation(qc, id),
  });
}

export function useUpdateInvestigationTask(id: string) {
  const qc = useQueryClient();
  return useMutation<InvestigationTask, ApiError, { taskId: string; patch: UpdateTaskInput }>({
    mutationFn: ({ taskId, patch }) => api.patch<InvestigationTask>(`/investigations/${enc(id)}/tasks/${enc(taskId)}`, patch),
    onSuccess: () => invalidateInvestigation(qc, id),
  });
}

export function useAddEvidence(id: string) {
  const qc = useQueryClient();
  return useMutation<EvidenceView, ApiError, AddEvidenceInput>({
    mutationFn: (input) => api.post<EvidenceView>(`/investigations/${enc(id)}/evidence`, input),
    onSuccess: () => invalidateInvestigation(qc, id),
  });
}

export function useAppendCustody(id: string) {
  const qc = useQueryClient();
  return useMutation<EvidenceView, ApiError, { evidenceId: string; action: CustodyAction; note?: string }>({
    mutationFn: ({ evidenceId, action, note }) => api.post<EvidenceView>(`/investigations/${enc(id)}/evidence/${enc(evidenceId)}/custody`, note ? { action, note } : { action }),
    onSuccess: () => invalidateInvestigation(qc, id),
  });
}

/** Download inline evidence; the server appends an "accessed:downloaded" custody entry. */
export function useDownloadEvidence(id: string) {
  const qc = useQueryClient();
  return useMutation<{ blob: Blob; filename: string | null }, ApiError, { evidenceId: string }>({
    mutationFn: ({ evidenceId }) => api.download(`/investigations/${enc(id)}/evidence/${enc(evidenceId)}/content`),
    onSuccess: () => invalidateInvestigation(qc, id),
  });
}

// ─── Inventory: assets, agents, identities ──────────────────────────────────

const assetQuery = (f: Omit<AssetFilters, "organizationId">): QueryParams => ({
  q: f.q?.trim() || undefined,
  kind: csv(f.kind),
  criticality: csv(f.criticality),
  internetFacing: bool(f.internetFacing),
  minRisk: f.minRisk,
  sort: f.sort,
  limit: f.limit ?? 200,
});

export function useAssets(filters: AssetFilters = {}, options: ListOptions = {}) {
  return useScopedInfinite<Asset, AssetFilters>("assets", "/assets", filters, assetQuery, options);
}

const agentQuery = (f: Omit<AgentFilters, "organizationId">): QueryParams => ({
  q: f.q?.trim() || undefined,
  status: csv(f.status),
  platform: f.platform,
  antivirusStatus: f.antivirusStatus,
  limit: f.limit ?? 500,
});

export function useAgents(filters: AgentFilters = {}, options: ListOptions = {}) {
  return useScopedInfinite<Agent, AgentFilters>("agents", "/agents", filters, agentQuery, options);
}

const identityQuery = (f: Omit<IdentityFilters, "organizationId">): QueryParams => ({
  q: f.q?.trim() || undefined,
  provider: f.provider,
  kind: csv(f.kind),
  privileged: bool(f.privileged),
  mfa: bool(f.mfa),
  minRisk: f.minRisk,
  sort: f.sort,
  limit: f.limit ?? 500,
});

export function useIdentities(filters: IdentityFilters = {}, options: ListOptions = {}) {
  return useScopedInfinite<IdentityView, IdentityFilters>("identities", "/identities", filters, identityQuery, options);
}

export function useIdentity(id: string | null | undefined) {
  return useQuery<IdentityDetail, ApiError>({
    queryKey: moduleKeys.identity(id ?? ""),
    queryFn: ({ signal }) => api.get<IdentityDetail>(`/identities/${enc(id!)}`, { signal }),
    enabled: Boolean(id),
  });
}

// ─── Alerts (triage) ────────────────────────────────────────────────────────

/** GET /alerts/:id — the alert plus its contributing events (null without event:read). */
export function useAlert(id: string | null | undefined) {
  return useQuery<Alert & { events?: CanonicalEvent[] | null }, ApiError>({
    queryKey: ["alert", id ?? ""],
    queryFn: ({ signal }) => api.get<Alert & { events?: CanonicalEvent[] | null }>(`/alerts/${enc(id!)}`, { signal }),
    enabled: Boolean(id),
  });
}

export function useUpdateAlert() {
  const qc = useQueryClient();
  return useMutation<Alert, ApiError, { id: string; status: "new" | "triaged" | "suppressed" | "false_positive"; reason?: string }>({
    mutationFn: ({ id, status, reason }) => api.patch<Alert>(`/alerts/${enc(id)}`, reason ? { status, reason } : { status }),
    onSuccess: (_res, vars) => {
      void qc.invalidateQueries({ queryKey: moduleKeys.alerts });
      void qc.invalidateQueries({ queryKey: ["alert", vars.id] });
      void qc.invalidateQueries({ queryKey: ["command-center"] });
    },
  });
}

// ─── SIEM: event search & detections ───────────────────────────────────────

/** GET /events/search — Bloody query syntax over normalized events, cursor paginated. */
export function useEventSearch(params: EventSearchParams, options: { enabled?: boolean } = {}) {
  const orgId = useScope(params.organizationId);
  const q = params.q.trim();
  const range = encodeTimeRange(params.range);
  const limit = params.limit ?? 200;
  const query = useInfiniteQuery<EventSearchResult, ApiError>({
    queryKey: ["events", orgKey(orgId), q, range, limit],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ signal, pageParam }) => {
      const { from, to } = resolveTimeRange(params.range);
      return toEventSearchResult(await api.get<unknown>("/events/search", { signal, query: { organizationId: orgId, q, from, to, limit, cursor: pageParam as string | undefined } }));
    },
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    enabled: options.enabled ?? true,
    staleTime: 15_000,
  });
  const items = useMemo(() => (query.data ? query.data.pages.flatMap((p) => p.items) : undefined), [query.data]);
  const first = query.data?.pages[0];
  return { ...query, items, total: first?.total, truncated: first?.truncated ?? false };
}

export function useDetections(filters: { organizationId?: string | null; q?: string; enabled?: boolean } = {}, options: ListOptions = {}) {
  return useScopedPage<DetectionRule, typeof filters>(
    "detections",
    "/detections",
    filters,
    (f) => ({ q: f.q?.trim() || undefined, enabled: bool(f.enabled), limit: 500 }),
    options,
  );
}

export function useSaveDetection() {
  const qc = useQueryClient();
  return useMutation<DetectionRule, ApiError, { id?: string; input: UpsertDetectionInput }>({
    mutationFn: ({ id, input }) => (id ? api.patch<DetectionRule>(`/detections/${enc(id)}`, input) : api.post<DetectionRule>("/detections", input)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.detections }),
  });
}

function toDetectionTestResult(raw: unknown): DetectionTestResult {
  const rec = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const replay = (typeof rec.replay === "object" && rec.replay !== null ? rec.replay : {}) as Record<string, unknown>;
  const strings = (v: unknown) => (Array.isArray(v) ? v.map(String) : []);
  const matches = Array.isArray(replay.matches)
    ? replay.matches
        .filter((m): m is Record<string, unknown> => typeof m === "object" && m !== null)
        .map((m, i) => ({
          id: typeof m.id === "string" ? m.id : `match-${i}`,
          title: typeof m.title === "string" ? m.title : "Match",
          severity: typeof m.severity === "string" ? (m.severity as DetectionTestMatch["severity"]) : null,
          explanation: typeof m.explanation === "string" ? m.explanation : null,
          eventIds: strings(m.eventIds),
        }))
    : [];
  const matched = typeof rec.matched === "number" ? rec.matched : typeof replay.matched === "number" ? replay.matched : matches.length;
  const scanned = typeof rec.scanned === "number" ? rec.scanned : typeof replay.scanned === "number" ? replay.scanned : null;
  return {
    valid: rec.valid !== false,
    errors: strings(rec.errors),
    warnings: strings(rec.warnings),
    matched,
    scanned,
    truncated: replay.truncated === true,
    events: toEventSearchResult(rec.events ?? []).items,
    matches,
  };
}

/** Test a saved rule (optionally with the editor's unsaved source) or a draft (no id). */
export function useTestDetection() {
  return useMutation<DetectionTestResult, ApiError, { id?: string; input: DetectionTestInput }>({
    mutationFn: async ({ id, input }) => toDetectionTestResult(await api.post<unknown>(id ? `/detections/${enc(id)}/test` : "/detections/test", input)),
  });
}

export function useDetectionVersions(id: string | null | undefined) {
  return useQuery<DetectionVersion[], ApiError>({
    queryKey: ["detections", "versions", id ?? ""],
    queryFn: async ({ signal }) => toArray(await api.get<Page<DetectionVersion> | DetectionVersion[]>(`/detections/${enc(id!)}/versions`, { signal })),
    enabled: Boolean(id),
  });
}

export function useRollbackDetection() {
  const qc = useQueryClient();
  return useMutation<DetectionRule, ApiError, { id: string; version: number }>({
    mutationFn: ({ id, version }) => api.post<DetectionRule>(`/detections/${enc(id)}/rollback`, { version }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.detections }),
  });
}

/** Delete a custom rule, or remove an override to revert to the built-in version. */
export function useDeleteDetection() {
  const qc = useQueryClient();
  return useMutation<void, ApiError, string>({
    mutationFn: (id) => api.delete<void>(`/detections/${enc(id)}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.detections }),
  });
}

// ─── Security Graph & attack paths ─────────────────────────────────────────

export function useGraphSearch(params: GraphSearchParams, options: { enabled?: boolean } = {}) {
  const orgId = useScope(params.organizationId);
  const q = params.q.trim();
  return useQuery<GraphNode[], ApiError>({
    queryKey: ["graph", orgKey(orgId), "search", q, params.kinds ?? [], params.limit ?? 25],
    queryFn: async ({ signal }) =>
      toGraphNodes(await api.get<unknown>("/graph/search", { signal, query: { q, organizationId: orgId, kind: csv(params.kinds), limit: params.limit ?? 25 } })),
    enabled: (options.enabled ?? true) && q.length >= 2,
    staleTime: 30_000,
  });
}

function neighborsKey(orgId: string | null, nodeId: string, p: NeighborParams) {
  return ["graph", orgKey(orgId), "neighbors", nodeId, p.depth ?? 1, p.direction ?? "both", p.limit ?? 50] as const;
}

async function getNeighbors(nodeId: string, p: NeighborParams, signal?: AbortSignal): Promise<Subgraph> {
  return toSubgraph(
    await api.get<unknown>(`/graph/node/${enc(nodeId)}/neighbors`, { signal, query: { depth: p.depth ?? 1, direction: p.direction ?? "both", limit: p.limit ?? 50 } }),
  );
}

export function useGraphNeighbors(nodeId: string | null | undefined, params: NeighborParams = {}) {
  const orgId = useScope(undefined);
  return useQuery<Subgraph, ApiError>({
    queryKey: neighborsKey(orgId, nodeId ?? "", params),
    queryFn: ({ signal }) => getNeighbors(nodeId!, params, signal),
    enabled: Boolean(nodeId),
    staleTime: 30_000,
  });
}

/** Imperative neighbor expansion for the graph explorer (shares the query cache). */
export function useNeighborFetcher() {
  const qc = useQueryClient();
  const orgId = useScope(undefined);
  return (nodeId: string, params: NeighborParams = {}) =>
    qc.fetchQuery({ queryKey: neighborsKey(orgId, nodeId, params), queryFn: ({ signal }) => getNeighbors(nodeId, params, signal), staleTime: 30_000 });
}

export function useIncidentGraph(incidentId: string | null | undefined) {
  return useQuery<Subgraph, ApiError>({
    queryKey: ["graph", "incident", incidentId ?? ""],
    queryFn: async ({ signal }) => toSubgraph(await api.get<unknown>(`/incidents/${enc(incidentId!)}/graph`, { signal })),
    enabled: Boolean(incidentId),
  });
}

export function useAttackPaths(filters: { organizationId?: string | null; targetId?: string; limit?: number } = {}, options: { enabled?: boolean } = {}) {
  const orgId = useScope(filters.organizationId);
  return useQuery<AttackPathResult, ApiError>({
    queryKey: ["attack-paths", orgKey(orgId), filters.targetId ?? null, filters.limit ?? 200],
    queryFn: async ({ signal }) =>
      toAttackPathResult(await api.get<unknown>("/attack-paths", { signal, query: { organizationId: orgId, targetId: filters.targetId, limit: filters.limit ?? 200 } })),
    placeholderData: keepPreviousWithinOrg<AttackPathResult>(orgId),
    enabled: options.enabled ?? true,
    staleTime: 60_000,
  });
}

// ─── Exposure & vulnerabilities ─────────────────────────────────────────────

const vulnQuery = (f: Omit<VulnerabilityFilters, "organizationId">): QueryParams => ({
  q: f.q?.trim() || undefined,
  severity: csv(f.severity),
  status: csv(f.status),
  knownExploited: bool(f.knownExploited),
  assetId: f.assetId,
  overdue: bool(f.overdue),
  internetFacing: bool(f.internetFacing),
  priority: csv(f.priority),
  sort: f.sort ?? "risk",
  limit: f.limit ?? 500,
});

export function useVulnerabilities(filters: VulnerabilityFilters = {}, options: ListOptions = {}) {
  return useScopedInfinite<VulnerabilityView, VulnerabilityFilters>("vulnerabilities", "/vulnerabilities", filters, vulnQuery, options);
}

export function useUpdateVulnerability() {
  const qc = useQueryClient();
  return useMutation<VulnerabilityView, ApiError, { id: string; input: UpdateVulnerabilityInput }>({
    mutationFn: ({ id, input }) => api.patch<VulnerabilityView>(`/vulnerabilities/${enc(id)}`, input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: moduleKeys.vulnerabilities });
      void qc.invalidateQueries({ queryKey: moduleKeys.exposure });
    },
  });
}

export function useExposureSummary(options: { organizationId?: string | null; enabled?: boolean } = {}) {
  const orgId = useScope(options.organizationId);
  return useQuery<ExposureSummary, ApiError>({
    queryKey: ["exposure", orgKey(orgId)],
    queryFn: async ({ signal }) => toExposureSummary(await api.get<unknown>("/exposure/summary", { signal, query: { organizationId: orgId } })),
    placeholderData: keepPreviousWithinOrg<ExposureSummary>(orgId),
    enabled: options.enabled ?? true,
    staleTime: 60_000,
  });
}

// ─── Threat intelligence ────────────────────────────────────────────────────

const indicatorQuery = (f: Omit<IndicatorFilters, "organizationId">): QueryParams => ({
  q: f.q?.trim() || undefined,
  type: csv(f.type),
  severity: csv(f.severity),
  limit: f.limit ?? 500,
});

export function useIndicators(filters: IndicatorFilters = {}, options: ListOptions = {}) {
  return useScopedInfinite<Indicator, IndicatorFilters>("intel-indicators", "/intel/indicators", filters, indicatorQuery, options);
}

export function useCreateIndicator() {
  const qc = useQueryClient();
  return useMutation<Indicator, ApiError, CreateIndicatorInput>({
    mutationFn: (input) => api.post<Indicator>("/intel/indicators", input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["intel-indicators"] });
      void qc.invalidateQueries({ queryKey: ["intel-matches"] });
    },
  });
}

export function useIntelMatches(filters: IntelMatchFilters = {}, options: ListOptions = {}) {
  return useScopedPage<IntelMatch, IntelMatchFilters>(
    "intel-matches",
    "/intel/matches",
    filters,
    (f) => ({ indicatorId: f.indicatorId, incidentId: f.incidentId, limit: f.limit ?? 500 }),
    options,
  );
}

// ─── SOAR playbooks ─────────────────────────────────────────────────────────

export function usePlaybooks(options: ListOptions & { organizationId?: string | null } = {}) {
  return useScopedPage<Playbook, { organizationId?: string | null }>("playbooks", "/playbooks", { organizationId: options.organizationId }, () => ({ limit: 500 }), options);
}

export function useSavePlaybook() {
  const qc = useQueryClient();
  return useMutation<Playbook, ApiError, { id?: string; input: UpsertPlaybookInput }>({
    mutationFn: ({ id, input }) => (id ? api.patch<Playbook>(`/playbooks/${enc(id)}`, input) : api.post<Playbook>("/playbooks", input)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.playbooks }),
  });
}

// ─── AI SOC ─────────────────────────────────────────────────────────────────

/** Providers visible to the principal (tenant defaults + per-organization overrides). */
export function useAiProviders(options: { enabled?: boolean } = {}) {
  return useQuery<AiProviderConfig[], ApiError>({
    queryKey: moduleKeys.aiProviders,
    queryFn: async ({ signal }) => toArray(await api.get<Page<AiProviderConfig> | AiProviderConfig[]>("/ai/providers", { signal })),
    enabled: options.enabled ?? true,
    staleTime: 60_000,
  });
}

export function useSaveAiProvider() {
  const qc = useQueryClient();
  return useMutation<AiProviderConfig, ApiError, { id?: string; input: Partial<UpsertAiProviderInput> }>({
    mutationFn: ({ id, input }) => (id ? api.patch<AiProviderConfig>(`/ai/providers/${enc(id)}`, input) : api.post<AiProviderConfig>("/ai/providers", input)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.aiProviders }),
  });
}

export function useDeleteAiProvider() {
  const qc = useQueryClient();
  return useMutation<void, ApiError, string>({
    mutationFn: (id) => api.delete<void>(`/ai/providers/${enc(id)}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.aiProviders }),
  });
}

export function useTestAiProvider() {
  return useMutation<AiProviderTestResult, ApiError, string>({
    mutationFn: async (id) => toProviderTestResult(await api.post<unknown>(`/ai/providers/${enc(id)}/test`)),
  });
}

export function useAiConversations(options: { enabled?: boolean } = {}) {
  const orgId = useScope(undefined);
  return useQuery<AiConversationSummary[], ApiError>({
    queryKey: ["ai", "conversations", orgKey(orgId)],
    queryFn: async ({ signal }) => toConversationList(await api.get<unknown>("/ai/conversations", { signal, query: { organizationId: orgId, limit: 100 } })),
    enabled: options.enabled ?? true,
  });
}

export function useAiConversation(id: string | null | undefined) {
  return useQuery<AiConversationDetail, ApiError>({
    queryKey: moduleKeys.aiConversation(id ?? ""),
    queryFn: async ({ signal }) => toConversationDetail(await api.get<unknown>(`/ai/conversations/${enc(id!)}`, { signal }), id!),
    enabled: Boolean(id),
  });
}

export function useAiChat() {
  const qc = useQueryClient();
  return useMutation<AiChatResult, ApiError, AiChatRequest>({
    mutationFn: async (input) => toChatResult(await api.post<unknown>("/ai/chat", input)),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: moduleKeys.aiConversations });
      if (res.conversationId) void qc.invalidateQueries({ queryKey: moduleKeys.aiConversation(res.conversationId) });
      if (res.actions.some((a) => a.status === "pending_approval")) void qc.invalidateQueries({ queryKey: ["response-actions"] });
    },
  });
}

function useAiDecision(decision: "approve" | "reject") {
  const qc = useQueryClient();
  return useMutation<AiActionRecord | unknown, ApiError, { id: string; conversationId?: string; reason?: string }>({
    mutationFn: ({ id, reason }) => api.post<unknown>(`/ai/actions/${enc(id)}/${decision}`, decision === "reject" ? { reason: reason ?? "Rejected by analyst" } : {}),
    onSuccess: (_res, vars) => {
      if (vars.conversationId) void qc.invalidateQueries({ queryKey: moduleKeys.aiConversation(vars.conversationId) });
      void qc.invalidateQueries({ queryKey: ["response-actions"] });
    },
  });
}
export const useApproveAiAction = () => useAiDecision("approve");
export const useRejectAiAction = () => useAiDecision("reject");

// ─── Integrations ───────────────────────────────────────────────────────────

export function useIntegrations(options: ListOptions = {}) {
  const orgId = useScope(undefined);
  return useQuery<IntegrationView[], ApiError>({
    queryKey: ["integrations", orgKey(orgId)],
    queryFn: async ({ signal }) => toArray(await api.get<Page<IntegrationView> | IntegrationView[]>("/integrations", { signal, query: { organizationId: orgId } })),
    enabled: options.enabled ?? true,
    refetchInterval: options.refetchIntervalMs ?? 60_000,
    placeholderData: keepPreviousWithinOrg<IntegrationView[]>(orgId),
  });
}

export function useCreateIntegration() {
  const qc = useQueryClient();
  return useMutation<IntegrationView, ApiError, CreateIntegrationInput>({
    mutationFn: (input) => api.post<IntegrationView>("/integrations", input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.integrations }),
  });
}

export function useSyncIntegration() {
  const qc = useQueryClient();
  return useMutation<IntegrationSyncResult, ApiError, string>({
    mutationFn: (id) => api.post<IntegrationSyncResult>(`/integrations/${enc(id)}/sync`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.integrations }),
  });
}

// ─── Settings: API keys, audit, teams, users ───────────────────────────────

export function useApiKeys(options: { enabled?: boolean } = {}) {
  return useQuery<ApiKeyView[], ApiError>({
    queryKey: moduleKeys.apiKeys,
    queryFn: async ({ signal }) => toArray(await api.get<Page<ApiKeyView> | ApiKeyView[]>("/api-keys", { signal })),
    enabled: options.enabled ?? true,
  });
}

export function useCreateApiKey() {
  const qc = useQueryClient();
  return useMutation<CreateApiKeyResult, ApiError, CreateApiKeyInput>({
    mutationFn: (input) => api.post<CreateApiKeyResult>("/api-keys", input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.apiKeys }),
  });
}

export function useRevokeApiKey() {
  const qc = useQueryClient();
  return useMutation<void, ApiError, string>({
    mutationFn: (id) => api.delete<void>(`/api-keys/${enc(id)}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.apiKeys }),
  });
}

const auditQuery = (f: Omit<AuditFilters, "organizationId">): QueryParams => ({
  action: f.action?.trim() || undefined,
  actorKind: f.actorKind,
  actorId: f.actorId?.trim() || undefined,
  targetKind: f.targetKind?.trim() || undefined,
  targetId: f.targetId?.trim() || undefined,
  outcome: csv(f.outcome),
  requestId: f.requestId?.trim() || undefined,
  from: f.from,
  to: f.to,
  limit: f.limit ?? 100,
});

export function useAuditLog(filters: AuditFilters = {}, options: ListOptions = {}) {
  return useScopedInfinite<AuditRecord, AuditFilters>("audit", "/audit", filters, auditQuery, options);
}

export function useVerifyAudit() {
  return useMutation<AuditVerifyResult, ApiError, void>({
    mutationFn: () => api.get<AuditVerifyResult>("/audit/verify"),
  });
}

export function useTeams(options: { enabled?: boolean } = {}) {
  return useQuery<TeamView[], ApiError>({
    queryKey: moduleKeys.teams,
    queryFn: async ({ signal }) => toArray(await api.get<Page<TeamView> | TeamView[]>("/teams", { signal })),
    enabled: options.enabled ?? true,
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation<UserSummary, ApiError, CreateUserInput>({
    mutationFn: (input) => api.post<UserSummary>("/users", input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.users }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation<UserSummary, ApiError, { id: string; patch: UpdateUserInput }>({
    mutationFn: ({ id, patch }) => api.patch<UserSummary>(`/users/${enc(id)}`, patch),
    onSuccess: () => void qc.invalidateQueries({ queryKey: moduleKeys.users }),
  });
}
