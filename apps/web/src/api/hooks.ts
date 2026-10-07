import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";
import {
  ACTIVE_INCIDENT_STATUSES,
  REPORT_TYPES,
  type Alert,
  type AutomationRule,
  type CommandCenterSummary,
  type CreateOrganizationInput,
  type Escalation,
  type Incident,
  type ModuleKey,
  type MsspOverview,
  type NotificationChannel,
  type Organization,
  type Page,
  type ReportSchedule,
  type ResponseActionRecord,
  type ResponseActionRequest,
  type RiskAssessment,
  type Asset,
  type Severity,
  type UpdateIncidentInput,
} from "@bloody/contracts";
import { useMemo } from "react";
import { api, type ApiError, type DownloadResult } from "./client";
import type {
  AlertFilters,
  BillingUsage,
  CreateAutomationRuleInput,
  CreateNotificationChannelInput,
  CreateReportScheduleInput,
  EntitlementView,
  EscalationFilters,
  GenerateReportRequest,
  IncidentDetail,
  IncidentFilters,
  LoginRequest,
  LoginResponse,
  MeResponse,
  NotificationItem,
  OidcStartResponse,
  ReportTypeInfo,
  ResponseActionFilters,
  SearchHit,
  UserSummary,
} from "./types";
import { useCurrentOrganizationId } from "../app/orgScope";
import { hrefForEntity } from "../lib/entityLinks";

/**
 * React Query hooks over the `/api/v1` surface (docs/ARCHITECTURE.md §5).
 *
 * Every tenant-data key includes the organization scope, so switching organization never shows
 * the previous organization's cached data. The whole cache is cleared on logout / 401.
 * Hooks that accept `organizationId` default to the currently selected organization
 * (`undefined` → current scope, `null` → all organizations).
 */

const ALL = "all";
const orgKey = (orgId: string | null) => orgId ?? ALL;

export const queryKeys = {
  me: ["auth", "me"] as const,
  organizations: ["organizations"] as const,
  organization: (id: string) => ["organizations", id] as const,
  commandCenter: (orgId: string | null, windowDays: number) => ["command-center", orgKey(orgId), windowDays] as const,
  msspOverview: ["mssp", "overview"] as const,
  incidents: (orgId: string | null, filters: Omit<IncidentFilters, "organizationId">) => ["incidents", orgKey(orgId), filters] as const,
  incidentsRoot: ["incidents"] as const,
  incident: (id: string) => ["incident", id] as const,
  alerts: (orgId: string | null, filters: Omit<AlertFilters, "organizationId">) => ["alerts", orgKey(orgId), filters] as const,
  escalations: (orgId: string | null, filters: Omit<EscalationFilters, "organizationId">) => ["escalations", orgKey(orgId), filters] as const,
  escalationsRoot: ["escalations"] as const,
  search: (orgId: string | null, q: string) => ["search", orgKey(orgId), q] as const,
  entitlements: ["entitlements"] as const,
  responseActions: (orgId: string | null, filters: Omit<ResponseActionFilters, "organizationId">) =>
    ["response-actions", orgKey(orgId), filters] as const,
  responseActionsRoot: ["response-actions"] as const,
  users: ["users"] as const,
  asset: (id: string) => ["asset", id] as const,
  assetRisk: (id: string) => ["risk", "asset", id] as const,
  notificationChannels: ["notification-channels"] as const,
  automations: ["automations"] as const,
  reportTypes: ["reports", "types"] as const,
  reportSchedules: (orgId: string | null) => ["reports", "schedules", orgKey(orgId)] as const,
  billingUsage: ["billing", "usage"] as const,
};

function useScope(explicit: string | null | undefined): string | null {
  const current = useCurrentOrganizationId();
  return explicit === undefined ? current : explicit;
}

function withoutOrg<T extends { organizationId?: string | null }>(filters: T): Omit<T, "organizationId"> {
  const { organizationId: _ignored, ...rest } = filters;
  return rest;
}

/** Lists may come back as Page<T> or (from simpler endpoints) a bare array. */
export function toPage<T>(raw: Page<T> | T[] | null | undefined): Page<T> {
  if (!raw) return { items: [], nextCursor: null };
  if (Array.isArray(raw)) return { items: raw, nextCursor: null, total: raw.length };
  return { items: raw.items ?? [], nextCursor: raw.nextCursor ?? null, ...(raw.total !== undefined ? { total: raw.total } : {}) };
}

function toArray<T>(raw: Page<T> | T[] | null | undefined): T[] {
  return toPage(raw).items;
}

// ─── Auth & session ─────────────────────────────────────────────────────────

export function useMe() {
  return useQuery<MeResponse, ApiError>({
    queryKey: queryKeys.me,
    queryFn: ({ signal }) => api.get<MeResponse>("/auth/me", { signal, skipAuthRedirect: true }),
    staleTime: 5 * 60_000,
    retry: (count, error) => error.status >= 500 && count < 2,
  });
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation<LoginResponse, ApiError, LoginRequest>({
    mutationFn: (input) => api.post<LoginResponse>("/auth/login", input, { skipAuthRedirect: true }),
    onSuccess: (res) => {
      if (!res?.mfaRequired) {
        qc.clear();
        void qc.invalidateQueries({ queryKey: queryKeys.me });
      }
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation<void, ApiError, void>({
    mutationFn: () => api.post<void>("/auth/logout", undefined, { skipAuthRedirect: true }),
    // Always drop cached tenant data, even if the server call fails (expired session etc.).
    onSettled: () => qc.clear(),
  });
}

export function useOidcStart() {
  return useMutation<OidcStartResponse, ApiError, { returnTo: string }>({
    mutationFn: ({ returnTo }) =>
      api.get<OidcStartResponse>("/auth/oidc/start", { query: { returnTo }, skipAuthRedirect: true }),
  });
}

// ─── Organizations ──────────────────────────────────────────────────────────

export function useOrganizations() {
  return useQuery<Organization[], ApiError>({
    queryKey: queryKeys.organizations,
    queryFn: async ({ signal }) => toArray(await api.get<Page<Organization> | Organization[]>("/organizations", { signal, query: { limit: 500 } })),
    staleTime: 60_000,
  });
}

export function useOrganization(id: string | null | undefined) {
  return useQuery<Organization, ApiError>({
    queryKey: queryKeys.organization(id ?? ""),
    queryFn: ({ signal }) => api.get<Organization>(`/organizations/${encodeURIComponent(id!)}`, { signal }),
    enabled: Boolean(id),
  });
}

export function useCreateOrganization() {
  const qc = useQueryClient();
  return useMutation<Organization, ApiError, CreateOrganizationInput>({
    mutationFn: (input) => api.post<Organization>("/organizations", input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.organizations });
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      void qc.invalidateQueries({ queryKey: queryKeys.msspOverview });
    },
  });
}

export function useUpdateOrganization(id: string) {
  const qc = useQueryClient();
  return useMutation<Organization, ApiError, Partial<Pick<Organization, "name" | "retentionDays" | "parentOrganizationId">>>({
    mutationFn: (patch) => api.patch<Organization>(`/organizations/${encodeURIComponent(id)}`, patch),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.organizations });
      void qc.invalidateQueries({ queryKey: queryKeys.me });
    },
  });
}

// ─── Command Center & MSSP ──────────────────────────────────────────────────

export function useCommandCenterSummary(windowDays = 90, options: { organizationId?: string | null; refetchIntervalMs?: number } = {}) {
  const orgId = useScope(options.organizationId);
  return useQuery<CommandCenterSummary, ApiError>({
    queryKey: queryKeys.commandCenter(orgId, windowDays),
    queryFn: ({ signal }) =>
      api.get<CommandCenterSummary>("/command-center/summary", { signal, query: { organizationId: orgId, windowDays } }),
    refetchInterval: options.refetchIntervalMs ?? 60_000,
    placeholderData: keepPreviousData,
  });
}

export function useMsspOverview(options: { enabled?: boolean } = {}) {
  return useQuery<MsspOverview, ApiError>({
    queryKey: queryKeys.msspOverview,
    queryFn: ({ signal }) => api.get<MsspOverview>("/mssp/overview", { signal }),
    refetchInterval: 60_000,
    enabled: options.enabled ?? true,
  });
}

// ─── Incidents ──────────────────────────────────────────────────────────────

function incidentQuery(orgId: string | null, f: Omit<IncidentFilters, "organizationId">) {
  return {
    organizationId: orgId,
    severity: f.severity,
    status: f.status,
    q: f.q?.trim() || undefined,
    assigneeId: f.assigneeId,
    limit: f.limit ?? 100,
    cursor: f.cursor,
  };
}

export function useIncidents(filters: IncidentFilters = {}, options: { enabled?: boolean } = {}) {
  const orgId = useScope(filters.organizationId);
  const rest = withoutOrg(filters);
  return useQuery<Page<Incident>, ApiError>({
    queryKey: queryKeys.incidents(orgId, rest),
    queryFn: async ({ signal }) =>
      toPage(await api.get<Page<Incident> | Incident[]>("/incidents", { signal, query: incidentQuery(orgId, rest) })),
    placeholderData: keepPreviousData,
    enabled: options.enabled ?? true,
  });
}

/** Cursor-paginated incidents for list pages ("Load more"). */
export function useInfiniteIncidents(filters: IncidentFilters = {}) {
  const orgId = useScope(filters.organizationId);
  const rest = withoutOrg(filters);
  return useInfiniteQuery<Page<Incident>, ApiError>({
    queryKey: [...queryKeys.incidents(orgId, rest), "infinite"],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ signal, pageParam }) =>
      toPage(
        await api.get<Page<Incident> | Incident[]>("/incidents", {
          signal,
          query: incidentQuery(orgId, { ...rest, cursor: pageParam as string | undefined }),
        }),
      ),
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
}

/**
 * Active incidents with per-severity endpoint / identity involvement, derived from the
 * incident list. `complete` is false when there are more active incidents than one page —
 * callers must then not present the breakdown as exhaustive.
 */
export function useActiveIncidentBreakdown(enabled: boolean) {
  const query = useIncidents({ status: ACTIVE_INCIDENT_STATUSES, limit: 500 }, { enabled });
  const breakdown = useMemo(() => {
    if (!query.data) return null;
    const active = query.data.items.filter((i) => ACTIVE_INCIDENT_STATUSES.includes(i.status));
    const empty = () => ({ endpoint: 0, identity: 0 });
    const out: Record<"critical" | "high" | "lowMedium", { endpoint: number; identity: number }> = {
      critical: empty(),
      high: empty(),
      lowMedium: empty(),
    };
    for (const inc of active) {
      const bucket = inc.severity === "critical" ? out.critical : inc.severity === "high" ? out.high : out.lowMedium;
      if (inc.assetIds.length > 0) bucket.endpoint += 1;
      if (inc.identityIds.length > 0) bucket.identity += 1;
    }
    return { ...out, complete: query.data.nextCursor === null };
  }, [query.data]);
  return { ...query, breakdown };
}

export function useIncident(id: string | null | undefined) {
  return useQuery<IncidentDetail, ApiError>({
    queryKey: queryKeys.incident(id ?? ""),
    queryFn: ({ signal }) => api.get<IncidentDetail>(`/incidents/${encodeURIComponent(id!)}`, { signal }),
    enabled: Boolean(id),
  });
}

export function invalidateIncidentData(qc: QueryClient, id?: string) {
  if (id) void qc.invalidateQueries({ queryKey: queryKeys.incident(id) });
  void qc.invalidateQueries({ queryKey: queryKeys.incidentsRoot });
  void qc.invalidateQueries({ queryKey: ["command-center"] });
  void qc.invalidateQueries({ queryKey: queryKeys.msspOverview });
}

export function useUpdateIncident(id: string) {
  const qc = useQueryClient();
  return useMutation<IncidentDetail, ApiError, UpdateIncidentInput>({
    mutationFn: (patch) => api.patch<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`, patch),
    onSuccess: (updated) => {
      qc.setQueryData<IncidentDetail>(queryKeys.incident(id), (prev) => (prev ? { ...prev, ...updated } : updated));
      invalidateIncidentData(qc, id);
    },
  });
}

// ─── Alerts ─────────────────────────────────────────────────────────────────

export function useAlerts(filters: AlertFilters = {}, options: { enabled?: boolean } = {}) {
  const orgId = useScope(filters.organizationId);
  const rest = withoutOrg(filters);
  return useQuery<Page<Alert>, ApiError>({
    queryKey: queryKeys.alerts(orgId, rest),
    queryFn: async ({ signal }) =>
      toPage(
        await api.get<Page<Alert> | Alert[]>("/alerts", {
          signal,
          query: { organizationId: orgId, incidentId: rest.incidentId, severity: rest.severity, limit: rest.limit ?? 100, cursor: rest.cursor },
        }),
      ),
    enabled: options.enabled ?? true,
  });
}

// ─── Escalations ────────────────────────────────────────────────────────────

export function useEscalations(filters: EscalationFilters = {}, options: { enabled?: boolean; refetchIntervalMs?: number } = {}) {
  const orgId = useScope(filters.organizationId);
  const rest = withoutOrg(filters);
  return useQuery<Page<Escalation>, ApiError>({
    queryKey: queryKeys.escalations(orgId, rest),
    queryFn: async ({ signal }) => {
      const page = toPage(
        await api.get<Page<Escalation> | Escalation[]>("/escalations", {
          signal,
          query: { organizationId: orgId, status: rest.status, limit: rest.limit ?? 200, cursor: rest.cursor },
        }),
      );
      // Defensive client-side filter in case the endpoint ignores `status`.
      if (rest.status && rest.status.length > 0) page.items = page.items.filter((e) => rest.status!.includes(e.status));
      return page;
    },
    enabled: options.enabled ?? true,
    refetchInterval: options.refetchIntervalMs,
    placeholderData: keepPreviousData,
  });
}

function useEscalationTransition(action: "acknowledge" | "resolve") {
  const qc = useQueryClient();
  return useMutation<Escalation, ApiError, { id: string; note?: string }>({
    mutationFn: ({ id, note }) => api.post<Escalation>(`/escalations/${encodeURIComponent(id)}/${action}`, note ? { note } : {}),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.escalationsRoot });
      void qc.invalidateQueries({ queryKey: ["command-center"] });
    },
  });
}

export const useAcknowledgeEscalation = () => useEscalationTransition("acknowledge");
export const useResolveEscalation = () => useEscalationTransition("resolve");

// ─── Global search ──────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : typeof value === "number" ? String(value) : undefined;
}
const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

function toHit(raw: unknown, groupKind?: string): SearchHit | null {
  if (!isRecord(raw)) return null;
  const id = str(raw.id) ?? str(raw.key);
  if (!id) return null;
  const kind = str(raw.kind) ?? str(raw.type) ?? groupKind ?? "entity";
  const title = str(raw.title) ?? str(raw.label) ?? str(raw.name) ?? str(raw.value) ?? id;
  const severity = typeof raw.severity === "string" && (SEVERITIES as readonly string[]).includes(raw.severity) ? (raw.severity as Severity) : null;
  const href = str(raw.href) ?? str(raw.url);
  return {
    kind,
    id,
    title,
    subtitle: str(raw.subtitle) ?? str(raw.description) ?? null,
    organizationId: str(raw.organizationId) ?? null,
    organizationName: str(raw.organizationName) ?? null,
    severity,
    href: href && href.startsWith("/") && !href.startsWith("//") ? href : hrefForEntity(kind, id),
  };
}

/** Accepts `{items}`, `{results}`, `{hits}`, `{groups:[{kind, items}]}` or a bare array. */
export function normalizeSearchResponse(raw: unknown): SearchHit[] {
  let list: { item: unknown; kind?: string }[] = [];
  if (Array.isArray(raw)) list = raw.map((item) => ({ item }));
  else if (isRecord(raw)) {
    const flat = raw.items ?? raw.results ?? raw.hits;
    if (Array.isArray(flat)) list = flat.map((item) => ({ item }));
    else if (Array.isArray(raw.groups)) {
      for (const group of raw.groups) {
        if (isRecord(group) && Array.isArray(group.items)) {
          const kind = str(group.kind) ?? str(group.type);
          for (const item of group.items) list.push({ item, ...(kind ? { kind } : {}) });
        }
      }
    }
  }
  return list.map(({ item, kind }) => toHit(item, kind)).filter((h): h is SearchHit => h !== null);
}

export function useGlobalSearch(q: string, options: { organizationId?: string | null; minLength?: number } = {}) {
  const orgId = useScope(options.organizationId);
  const term = q.trim();
  return useQuery<SearchHit[], ApiError>({
    queryKey: queryKeys.search(orgId, term),
    queryFn: async ({ signal }) =>
      normalizeSearchResponse(await api.get<unknown>("/search", { signal, query: { q: term, organizationId: orgId, limit: 25 } })),
    enabled: term.length >= (options.minLength ?? 2),
    staleTime: 15_000,
    placeholderData: keepPreviousData,
  });
}

// ─── Entitlements & billing ─────────────────────────────────────────────────

export function useEntitlements() {
  return useQuery<EntitlementView[], ApiError>({
    queryKey: queryKeys.entitlements,
    queryFn: async ({ signal }) => toArray(await api.get<Page<EntitlementView> | EntitlementView[]>("/entitlements", { signal })),
    staleTime: 60_000,
  });
}

export function useStartTrial() {
  const qc = useQueryClient();
  return useMutation<EntitlementView, ApiError, ModuleKey>({
    mutationFn: (module) => api.post<EntitlementView>(`/entitlements/${encodeURIComponent(module)}/trial`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.entitlements });
      void qc.invalidateQueries({ queryKey: queryKeys.me });
    },
  });
}

export function useBillingUsage(options: { enabled?: boolean } = {}) {
  return useQuery<BillingUsage, ApiError>({
    queryKey: queryKeys.billingUsage,
    queryFn: ({ signal }) => api.get<BillingUsage>("/billing/usage", { signal }),
    enabled: options.enabled ?? true,
  });
}

// ─── Users ──────────────────────────────────────────────────────────────────

export function useUsers(options: { enabled?: boolean } = {}) {
  return useQuery<UserSummary[], ApiError>({
    queryKey: queryKeys.users,
    queryFn: async ({ signal }) => toArray(await api.get<Page<UserSummary> | UserSummary[]>("/users", { signal, query: { limit: 500 } })),
    staleTime: 5 * 60_000,
    enabled: options.enabled ?? true,
  });
}

// ─── Assets & risk ──────────────────────────────────────────────────────────

export function useAsset(id: string | null | undefined) {
  return useQuery<Asset, ApiError>({
    queryKey: queryKeys.asset(id ?? ""),
    queryFn: ({ signal }) => api.get<Asset>(`/assets/${encodeURIComponent(id!)}`, { signal }),
    enabled: Boolean(id),
    staleTime: 60_000,
  });
}

export function useAssetRisk(id: string | null | undefined) {
  return useQuery<RiskAssessment, ApiError>({
    queryKey: queryKeys.assetRisk(id ?? ""),
    queryFn: ({ signal }) => api.get<RiskAssessment>(`/risk/assets/${encodeURIComponent(id!)}`, { signal }),
    enabled: Boolean(id),
  });
}

// ─── Response actions (SOAR) ────────────────────────────────────────────────

export function useResponseActions(filters: ResponseActionFilters = {}, options: { enabled?: boolean; refetchIntervalMs?: number } = {}) {
  const orgId = useScope(filters.organizationId);
  const rest = withoutOrg(filters);
  return useQuery<Page<ResponseActionRecord>, ApiError>({
    queryKey: queryKeys.responseActions(orgId, rest),
    queryFn: async ({ signal }) => {
      const page = toPage(
        await api.get<Page<ResponseActionRecord> | ResponseActionRecord[]>("/response/actions", {
          signal,
          query: { organizationId: orgId, incidentId: rest.incidentId, status: rest.status, limit: rest.limit ?? 100 },
        }),
      );
      if (rest.status && rest.status.length > 0) page.items = page.items.filter((a) => rest.status!.includes(a.status));
      if (rest.incidentId) page.items = page.items.filter((a) => a.incidentId === rest.incidentId);
      return page;
    },
    enabled: options.enabled ?? true,
    refetchInterval: options.refetchIntervalMs,
  });
}

export function useRequestResponseAction() {
  const qc = useQueryClient();
  return useMutation<ResponseActionRecord, ApiError, ResponseActionRequest>({
    mutationFn: (input) => api.post<ResponseActionRecord>("/response/actions", input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.responseActionsRoot }),
  });
}

function useResponseDecision(decision: "approve" | "reject") {
  const qc = useQueryClient();
  return useMutation<ResponseActionRecord, ApiError, { id: string; comment?: string }>({
    mutationFn: ({ id, comment }) =>
      api.post<ResponseActionRecord>(`/response/actions/${encodeURIComponent(id)}/${decision}`, comment ? { comment } : {}),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.responseActionsRoot }),
  });
}
export const useApproveResponseAction = () => useResponseDecision("approve");
export const useRejectResponseAction = () => useResponseDecision("reject");

// ─── Notifications, automations & reporting ─────────────────────────────────

export function useNotificationChannels(options: { enabled?: boolean } = {}) {
  return useQuery<NotificationChannel[], ApiError>({
    queryKey: queryKeys.notificationChannels,
    queryFn: async ({ signal }) =>
      toArray(await api.get<Page<NotificationChannel> | NotificationChannel[]>("/notifications/channels", { signal })),
    enabled: options.enabled ?? true,
    staleTime: 60_000,
  });
}

export function useCreateNotificationChannel() {
  const qc = useQueryClient();
  return useMutation<NotificationChannel, ApiError, CreateNotificationChannelInput>({
    mutationFn: (input) => api.post<NotificationChannel>("/notifications/channels", input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.notificationChannels }),
  });
}

export function useTestNotificationChannel() {
  return useMutation<{ ok: boolean; message?: string }, ApiError, string>({
    mutationFn: (id) => api.post<{ ok: boolean; message?: string }>(`/notifications/channels/${encodeURIComponent(id)}/test`),
  });
}

export function useAutomationRules(options: { enabled?: boolean } = {}) {
  return useQuery<AutomationRule[], ApiError>({
    queryKey: queryKeys.automations,
    queryFn: async ({ signal }) => toArray(await api.get<Page<AutomationRule> | AutomationRule[]>("/automations", { signal })),
    enabled: options.enabled ?? true,
    staleTime: 60_000,
  });
}

export function useCreateAutomationRule() {
  const qc = useQueryClient();
  return useMutation<AutomationRule, ApiError, CreateAutomationRuleInput>({
    mutationFn: (input) => api.post<AutomationRule>("/automations", input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.automations }),
  });
}

/** Report types the API can generate; falls back to the contract catalogue if the endpoint is absent. */
export function useReportTypes() {
  return useQuery<ReportTypeInfo[], ApiError>({
    queryKey: queryKeys.reportTypes,
    queryFn: async ({ signal }) => {
      const raw = await api.get<Page<ReportTypeInfo> | ReportTypeInfo[]>("/reports/types", { signal });
      const list = toArray(raw);
      return list.length > 0 ? list : REPORT_TYPES.map((r) => ({ ...r }));
    },
    staleTime: 10 * 60_000,
  });
}

export function useReportSchedules(options: { organizationId?: string | null; enabled?: boolean } = {}) {
  const orgId = useScope(options.organizationId);
  return useQuery<ReportSchedule[], ApiError>({
    queryKey: queryKeys.reportSchedules(orgId),
    queryFn: async ({ signal }) =>
      toArray(await api.get<Page<ReportSchedule> | ReportSchedule[]>("/reports/schedules", { signal, query: { organizationId: orgId } })),
    enabled: options.enabled ?? true,
  });
}

export function useCreateReportSchedule() {
  const qc = useQueryClient();
  return useMutation<ReportSchedule, ApiError, CreateReportScheduleInput>({
    mutationFn: (input) => api.post<ReportSchedule>("/reports/schedules", input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["reports", "schedules"] }),
  });
}

export function useGenerateReport() {
  return useMutation<DownloadResult, ApiError, GenerateReportRequest>({
    mutationFn: (input) => api.download("/reports/generate", { method: "POST", body: input }),
  });
}

/**
 * Actionable items for the notification bell, aggregated from real endpoints:
 * open escalations, response actions awaiting approval, and newly created incidents.
 * Sources the principal cannot read are skipped (never errored).
 */
export function useNotificationFeed(access: { escalations: boolean; approvals: boolean; incidents: boolean }) {
  const escalations = useEscalations({ status: ["open"], limit: 25 }, { enabled: access.escalations, refetchIntervalMs: 60_000 });
  const approvals = useResponseActions({ status: ["pending_approval"], limit: 25 }, { enabled: access.approvals, refetchIntervalMs: 60_000 });
  const incidents = useIncidents({ status: ["new"], limit: 25 }, { enabled: access.incidents });

  const items = useMemo<NotificationItem[]>(() => {
    const out: NotificationItem[] = [];
    const now = Date.now();
    for (const e of escalations.data?.items ?? []) {
      const overdue = new Date(e.dueAt).getTime() < now;
      out.push({
        id: `escalation:${e.id}`,
        kind: "escalation",
        title: e.title,
        detail: overdue ? "Escalation overdue — customer action required" : "Escalation awaiting action",
        severity: e.severity,
        organizationId: e.organizationId,
        at: e.createdAt,
        href: hrefForEntity("escalation", e.id),
      });
    }
    for (const a of approvals.data?.items ?? []) {
      out.push({
        id: `approval:${a.id}`,
        kind: "approval",
        title: `Approval required: ${a.action.replace(/_/g, " ")}${a.target.label ? ` · ${a.target.label}` : ""}`,
        detail: `Requested via ${a.requestedVia} — ${a.reason}`,
        severity: "high",
        organizationId: a.organizationId,
        at: a.createdAt,
        href: `/soar/approvals?id=${encodeURIComponent(a.id)}`,
      });
    }
    for (const i of incidents.data?.items ?? []) {
      if (i.status !== "new") continue;
      out.push({
        id: `incident:${i.id}`,
        kind: "incident",
        title: `#${i.number} ${i.title}`,
        detail: "New incident reported",
        severity: i.severity,
        organizationId: i.organizationId,
        at: i.detectedAt,
        href: hrefForEntity("incident", i.id),
      });
    }
    return out.sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
  }, [escalations.data, approvals.data, incidents.data]);

  return {
    items,
    isLoading: escalations.isLoading || approvals.isLoading || incidents.isLoading,
    isError: escalations.isError && approvals.isError && incidents.isError,
    refetch: () => {
      void escalations.refetch();
      void approvals.refetch();
      void incidents.refetch();
    },
  };
}
