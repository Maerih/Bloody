import { ENGINES, EXCLUDED_KEYED_SERVICES, OPEN_INTEL_SOURCES, type ResponseActionKey } from "@bloody/contracts";
import {
  CoPilotClient,
  CoPilotSync,
  EngineClient,
  createMispClient,
  createOpenCtiClient,
  createVelociraptorResponse,
  createWazuhActiveResponse,
  createWazuhApiClient,
  createWebhookBlockConnector,
  mispHealthCheck,
  openCtiHealthCheck,
  pullMispIndicators,
  pullOpenCtiIndicators,
  wazuhHealthCheck,
  type AdapterRegistry,
  type EngineClientOptions,
  type FetchLike as EngineFetch,
  type HealthCheckResult,
  type HostResolver as EngineHostResolver,
  type ResponseExecutionRequest,
  type ResponseExecutionResult,
} from "@bloody/adapters";
import { z } from "zod";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, badRequest } from "../http/errors.js";
import type { PipelineLogger } from "../pipeline/analytics.js";
import type { Row } from "../repo/mappers.js";
import { persistCoPilotPlan, type CoPilotSyncSummary } from "./copilot-sync.js";
import type { DomainEventBus } from "./domain-events.js";
import type { IntelService, UpsertSummary } from "./intel.js";
import type { InventoryService } from "./inventory.js";
import type { SecretStore } from "./secret-store.js";

/**
 * Engine integrations: configuration (credentials in the secret store, never returned), health
 * probes, pull synchronisation (SOCFortress CoPilot, MISP, OpenCTI) and response connectors
 * (Wazuh active response, Velociraptor collections, signed firewall/DNS block webhook). Engines
 * are reached only through their network APIs via `@bloody/adapters` with the SSRF guard.
 */

export const EXTRA_INTEGRATION_KINDS = [
  { key: "webhook_block", name: "Firewall / DNS block relay (signed webhook)", layer: "response", role: "Blocks IPs and domains through a customer-operated relay that verifies Bloody's HMAC signature", license: "Proprietary relay contract", licenseRisk: "low", mode: "network_api", powers: ["soar"], core: false, homepage: "" },
] as const;

export const INTEGRATION_KINDS: string[] = [...ENGINES.map((e) => e.key), ...EXTRA_INTEGRATION_KINDS.map((e) => e.key)];

type Capability = "health" | "sync" | "response" | "ingest";
const CAPABILITIES: Record<string, Capability[]> = {
  wazuh: ["health", "response", "ingest"],
  velociraptor: ["response", "ingest"],
  misp: ["health", "sync"],
  opencti: ["health", "sync"],
  copilot: ["health", "sync", "ingest"],
  webhook_block: ["response"],
};

const Common = z.object({
  /** Plain http is refused unless explicitly allowed (on-prem relays without TLS). */
  allowHttp: z.boolean().default(false),
  allowLoopback: z.boolean().default(false),
});

const CONFIG_SCHEMAS: Record<string, z.ZodTypeAny> = {
  wazuh: Common.extend({
    username: z.string().min(1).max(200),
    activeResponse: z
      .object({
        blockIpCommand: z.string().max(64).optional(),
        disableAccountCommand: z.string().max(64).optional(),
        isolateCommand: z.string().max(64).optional(),
        releaseCommand: z.string().max(64).optional(),
        killProcessCommand: z.string().max(64).optional(),
        quarantineFileCommand: z.string().max(64).optional(),
        allowAllAgents: z.boolean().optional(),
      })
      .strict()
      .default({}),
  }).strict(),
  velociraptor: Common.extend({
    response: z
      .object({
        killProcessArtifact: z.string().max(200).optional(),
        quarantineFileArtifact: z.string().max(200).optional(),
        evidenceArtifactAllowList: z.array(z.string().max(200)).max(50).optional(),
        yaraArtifact: z.string().max(200).optional(),
      })
      .strict()
      .default({}),
  }).strict(),
  misp: Common.extend({
    last: z.string().regex(/^\d{1,4}[mhdw]$/).default("7d"),
    tags: z.array(z.string().max(200)).max(50).optional(),
    types: z.array(z.string().max(100)).max(50).optional(),
    publishedOnly: z.boolean().default(true),
  }).strict(),
  opencti: Common.extend({ pageSize: z.number().int().min(1).max(5000).default(500), includeRevoked: z.boolean().default(true) }).strict(),
  copilot: Common.extend({
    username: z.string().min(1).max(200),
    portal: z.enum(["main", "customer"]).default("main"),
    customerCodes: z.array(z.string().min(1).max(100)).max(1000).optional(),
    organizationOverrides: z.record(z.string().uuid()).optional(),
    minWazuhVersion: z.string().regex(/^\d+\.\d+(\.\d+)?$/).optional(),
    staleAfterHours: z.number().int().min(1).max(24 * 30).optional(),
  }).strict(),
  webhook_block: Common.extend({ path: z.string().startsWith("/").max(200).default("/block"), protectedValues: z.array(z.string().max(255)).max(500).default([]) }).strict(),
};
const DEFAULT_CONFIG = Common.extend({}).passthrough();

const CREDENTIAL_REQUIRED = new Set(["wazuh", "misp", "opencti", "copilot", "webhook_block", "velociraptor"]);
const ENDPOINT_REQUIRED = new Set(["wazuh", "misp", "opencti", "copilot", "webhook_block", "velociraptor"]);

export function validateIntegrationConfig(kind: string, config: unknown): Record<string, unknown> {
  const schema = CONFIG_SCHEMAS[kind] ?? DEFAULT_CONFIG;
  const r = schema.safeParse(config ?? {});
  if (!r.success) throw new HttpError(400, "invalid_integration_config", `Invalid ${kind} configuration`, r.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })));
  return r.data as Record<string, unknown>;
}

export function validateEndpoint(kind: string, endpoint: string | null, config: Record<string, unknown>): void {
  if (!endpoint) {
    if (ENDPOINT_REQUIRED.has(kind)) throw badRequest(`${kind} integrations require an endpoint (base URL of the engine API)`);
    return;
  }
  let u: URL;
  try {
    u = new URL(endpoint);
  } catch {
    throw badRequest("endpoint must be an absolute URL");
  }
  if (u.username || u.password) throw badRequest("Credentials must not be embedded in the endpoint URL — use the credential field");
  if (u.protocol !== "https:" && !(u.protocol === "http:" && config.allowHttp === true)) throw badRequest("endpoint must use https (set config.allowHttp for plain-http on-prem relays)");
}

export function capabilitiesOf(kind: string): Capability[] {
  return CAPABILITIES[kind] ?? ["ingest"];
}

export interface IntegrationView {
  id: string;
  organizationId: string | null;
  kind: string;
  engine: string;
  name: string;
  endpoint: string | null;
  enabled: boolean;
  hasCredential: boolean;
  status: string;
  health: unknown;
  lastSyncAt: string | null;
  lastEventAt: string | null;
  lastError: string | null;
  lastSyncReport: unknown;
  config: Record<string, unknown>;
  capabilities: Capability[];
  createdAt: string;
  updatedAt: string;
}

export function toIntegrationView(r: Row): IntegrationView {
  const kind = String(r.kind);
  return {
    id: String(r.id),
    organizationId: (r.organization_id as string | null) ?? null,
    kind,
    engine: kind,
    name: String(r.name),
    endpoint: (r.endpoint as string | null) ?? null,
    enabled: Boolean(r.enabled),
    hasCredential: typeof r.credential_ref === "string" && r.credential_ref.length > 0,
    status: String(r.status),
    health: r.health ?? {},
    lastSyncAt: (r.last_sync_at as string | null) ?? null,
    lastEventAt: (r.last_event_at as string | null) ?? null,
    lastError: (r.last_error as string | null) ?? null,
    lastSyncReport: r.last_sync_report ?? null,
    config: (r.config as Record<string, unknown>) ?? {},
    capabilities: capabilitiesOf(kind),
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
}

export interface IntegrationServiceDeps {
  db: Database;
  secretStore: SecretStore;
  inventory: InventoryService;
  intel: IntelService;
  events: DomainEventBus;
  adapters: AdapterRegistry;
  fetch: EngineFetch;
  resolveHost: EngineHostResolver | false | undefined;
  allowPrivateNetworks: boolean;
  log: PipelineLogger;
  now: () => number;
  onSynced?: (tenantId: string) => void;
}

export interface SyncOutcome {
  kind: string;
  status: "succeeded" | "failed";
  message: string;
  startedAt: string;
  finishedAt: string;
  copilot?: CoPilotSyncSummary;
  intel?: UpsertSummary & { pages: number };
  error?: { code: string; message: string };
}

export class IntegrationService {
  constructor(private readonly deps: IntegrationServiceDeps) {}

  catalog() {
    const adapterKeys = new Set(this.deps.adapters.list().map((a) => a.key));
    return {
      engines: [...ENGINES, ...EXTRA_INTEGRATION_KINDS].map((e) => ({
        ...e,
        capabilities: capabilitiesOf(e.key),
        ingestAdapter: adapterKeys.has(e.key) ? `/api/v1/ingest/${e.key}` : null,
        credentialRequired: CREDENTIAL_REQUIRED.has(e.key),
        endpointRequired: ENDPOINT_REQUIRED.has(e.key),
      })),
      adapters: this.deps.adapters.catalog(),
      openIntelSources: OPEN_INTEL_SOURCES,
      excludedKeyedServices: EXCLUDED_KEYED_SERVICES,
    };
  }

  private async secret(tenantId: string, row: Row): Promise<string> {
    const ref = row.credential_ref as string | null;
    if (!ref) throw new HttpError(409, "credential_missing", `The ${String(row.kind)} integration has no credential configured`);
    const value = await this.deps.db.withTenant(tenantId, (tx) => this.deps.secretStore.resolve(tx, tenantId, ref));
    if (value === null) throw new HttpError(409, "credential_missing", "The integration credential could not be found in the secret store");
    return value;
  }

  private base(row: Row): Omit<EngineClientOptions, "engine" | "auth"> {
    const cfg = (row.config as Record<string, unknown>) ?? {};
    return {
      baseUrl: String(row.endpoint),
      fetch: this.deps.fetch,
      urlPolicy: { allowPrivateNetworks: this.deps.allowPrivateNetworks, allowLoopback: this.deps.allowPrivateNetworks && cfg.allowLoopback === true, allowHttp: cfg.allowHttp === true },
      ...(this.deps.resolveHost !== undefined ? { resolveHost: this.deps.resolveHost } : {}),
      timeoutMs: 20_000,
    };
  }

  async copilotClient(tenantId: string, row: Row): Promise<CoPilotClient> {
    const cfg = CONFIG_SCHEMAS.copilot!.parse(row.config) as { username: string; portal: "main" | "customer" };
    return new CoPilotClient({ ...this.base(row), username: cfg.username, password: await this.secret(tenantId, row), portal: cfg.portal });
  }

  /** Live probe of the engine API; stores the result on the integration. */
  async health(tenantId: string, row: Row): Promise<HealthCheckResult> {
    const kind = String(row.kind);
    let result: HealthCheckResult;
    const started = this.deps.now();
    try {
      switch (kind) {
        case "wazuh": {
          const cfg = row.config as { username: string };
          result = await wazuhHealthCheck(createWazuhApiClient({ ...this.base(row), username: cfg.username, password: await this.secret(tenantId, row) }));
          break;
        }
        case "misp":
          result = await mispHealthCheck(createMispClient({ ...this.base(row), apiKey: await this.secret(tenantId, row) }));
          break;
        case "opencti":
          result = await openCtiHealthCheck(createOpenCtiClient({ ...this.base(row), token: await this.secret(tenantId, row) }));
          break;
        case "copilot":
          result = await (await this.copilotClient(tenantId, row)).healthCheck();
          break;
        default: {
          // Stream / file-drop sources: health is data freshness.
          const last = (row.last_event_at as string | null) ?? null;
          const age = last ? this.deps.now() - Date.parse(last) : null;
          result = {
            engine: kind,
            status: age === null ? "degraded" : age < 3_600_000 ? "healthy" : age < 24 * 3_600_000 ? "degraded" : "unhealthy",
            ok: age !== null && age < 24 * 3_600_000,
            checkedAt: new Date(this.deps.now()).toISOString(),
            latencyMs: 0,
            details: { lastEventAt: last ?? "never", probe: "data freshness (no engine API probe for this source)" },
          };
        }
      }
    } catch (err) {
      result = {
        engine: kind,
        status: "unhealthy",
        ok: false,
        checkedAt: new Date(this.deps.now()).toISOString(),
        latencyMs: this.deps.now() - started,
        error: { code: err instanceof HttpError ? err.code : ((err as { code?: string }).code ?? "error"), message: err instanceof Error ? err.message.slice(0, 300) : "health check failed" },
      };
    }
    const status = !row.enabled ? "disabled" : result.status === "unhealthy" ? "failing" : result.status;
    await this.deps.db.withTenant(tenantId, (tx) =>
      tx.query("UPDATE integrations SET status = $2, health = $3::jsonb, last_error = $4 WHERE id = $1", [row.id, status, JSON.stringify(result), result.error?.message ?? null]),
    );
    return result;
  }

  /** Pull synchronisation (CoPilot → organizations/assets/agents/alerts/incidents; MISP/OpenCTI → indicators). */
  async sync(tenantId: string, row: Row, actor: string): Promise<SyncOutcome> {
    const kind = String(row.kind);
    if (!capabilitiesOf(kind).includes("sync")) throw new HttpError(400, "sync_not_supported", `${kind} integrations do not support pull synchronisation (data arrives through /ingest/${kind})`);
    if (!row.enabled) throw new HttpError(409, "integration_disabled", "The integration is disabled");
    const startedAt = new Date(this.deps.now()).toISOString();
    const nowIso = () => new Date(this.deps.now()).toISOString();
    const state = (row.sync_state as Record<string, unknown>) ?? {};
    try {
      let outcome: SyncOutcome;
      if (kind === "copilot") {
        const cfg = CONFIG_SCHEMAS.copilot!.parse(row.config) as z.infer<(typeof CONFIG_SCHEMAS)["copilot"]> & { customerCodes?: string[]; organizationOverrides?: Record<string, string>; minWazuhVersion?: string; staleAfterHours?: number };
        const client = await this.copilotClient(tenantId, row);
        const { plan } = await new CoPilotSync(client, {
          tenantId,
          integrationId: String(row.id),
          ...(cfg.organizationOverrides ? { organizationOverrides: cfg.organizationOverrides } : {}),
          ...(cfg.minWazuhVersion ? { minWazuhVersion: cfg.minWazuhVersion } : {}),
          ...(cfg.staleAfterHours ? { staleAfterHours: cfg.staleAfterHours } : {}),
          snapshot: { ...(cfg.customerCodes ? { customerCodes: cfg.customerCodes } : {}), now: () => new Date(this.deps.now()) },
        }).run();
        const summary = await this.deps.db.withTenant(tenantId, (tx) =>
          persistCoPilotPlan(tx, { tenantId, integration: row, plan, inventory: this.deps.inventory, events: this.deps.events, actor, now: this.deps.now }),
        );
        summary.afterCommit();
        outcome = { kind, status: "succeeded", message: plan.report.headline, startedAt, finishedAt: nowIso(), copilot: summary.view };
        await this.recordSync(tenantId, row, { ...state, lastPlanAt: plan.source.fetchedAt }, { headline: plan.report.headline, totals: plan.report.totals, created: summary.view.created, updated: summary.view.updated, warnings: summary.view.warnings.length });
      } else {
        const organizationId = (row.organization_id as string | null) ?? null;
        let records;
        let pages = 0;
        let nextState: Record<string, unknown> = state;
        if (kind === "misp") {
          const cfg = CONFIG_SCHEMAS.misp!.parse(row.config) as { last: string; tags?: string[]; types?: string[]; publishedOnly: boolean };
          const since = typeof state.timestamp === "number" ? state.timestamp : undefined;
          const res = await pullMispIndicators(createMispClient({ ...this.base(row), apiKey: await this.secret(tenantId, row) }), { ...(since ? { timestamp: since } : { last: cfg.last }), ...(cfg.tags ? { tags: cfg.tags } : {}), ...(cfg.types ? { types: cfg.types } : {}), ...(cfg.publishedOnly ? { published: true } : {}) }, { now: nowIso() });
          records = res.records;
          pages = res.pages;
          nextState = { ...state, timestamp: Math.floor(this.deps.now() / 1000) };
        } else {
          const cfg = CONFIG_SCHEMAS.opencti!.parse(row.config) as { pageSize: number; includeRevoked: boolean };
          const res = await pullOpenCtiIndicators(createOpenCtiClient({ ...this.base(row), token: await this.secret(tenantId, row) }), { ...(typeof state.since === "string" ? { since: state.since } : {}), pageSize: cfg.pageSize, now: nowIso(), includeRevoked: cfg.includeRevoked });
          records = res.records;
          pages = res.pages;
          nextState = { ...state, since: startedAt };
        }
        const summary = await this.deps.db.withTenant(tenantId, (tx) => this.deps.intel.upsertRecords(tx, tenantId, organizationId, records));
        outcome = { kind, status: "succeeded", message: `${summary.created} new, ${summary.updated} updated, ${summary.revoked} revoked indicator(s) from ${kind}`, startedAt, finishedAt: nowIso(), intel: { ...summary, pages } };
        await this.recordSync(tenantId, row, nextState, { received: summary.received, created: summary.created, updated: summary.updated, revoked: summary.revoked, skipped: summary.skipped.length, pages });
      }
      this.deps.onSynced?.(tenantId);
      return outcome;
    } catch (err) {
      const code = err instanceof HttpError ? err.code : ((err as { code?: string }).code ?? "sync_failed");
      const message = err instanceof Error ? err.message.slice(0, 500) : "sync failed";
      await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE integrations SET status = 'failing', last_error = $2 WHERE id = $1", [row.id, message]));
      if (err instanceof HttpError && err.statusCode < 500 && err.code !== "credential_missing") throw err;
      return { kind, status: "failed", message, startedAt, finishedAt: nowIso(), error: { code, message } };
    }
  }

  private async recordSync(tenantId: string, row: Row, state: Record<string, unknown>, report: Record<string, unknown>): Promise<void> {
    await this.deps.db.withTenant(tenantId, (tx) =>
      tx.query("UPDATE integrations SET last_sync_at = now(), sync_state = $2::jsonb, last_sync_report = $3::jsonb, status = 'healthy', last_error = NULL WHERE id = $1", [row.id, JSON.stringify(state), JSON.stringify(report)]),
    );
  }

  // ─── Response connectors ────────────────────────────────────────────────

  private connectorSet(row: Row, secret: string): { supported: ResponseActionKey[]; execute: (req: ResponseExecutionRequest) => Promise<ResponseExecutionResult> } {
    const kind = String(row.kind);
    const cfg = (row.config as Record<string, unknown>) ?? {};
    switch (kind) {
      case "wazuh": {
        const c = createWazuhActiveResponse((cfg.activeResponse as Parameters<typeof createWazuhActiveResponse>[0]) ?? {});
        const client = createWazuhApiClient({ ...this.base(row), username: String(cfg.username ?? ""), password: secret });
        return { supported: c.supported, execute: (req) => c.execute(req, { client, clock: () => new Date(this.deps.now()) }) };
      }
      case "velociraptor": {
        const c = createVelociraptorResponse((cfg.response as Parameters<typeof createVelociraptorResponse>[0]) ?? {});
        const client = new EngineClient({ ...this.base(row), engine: "velociraptor", auth: { kind: "bearer", token: secret } });
        return { supported: c.supported, execute: (req) => c.execute(req, { client, clock: () => new Date(this.deps.now()) }) };
      }
      case "webhook_block": {
        const c = createWebhookBlockConnector({ secret, path: String(cfg.path ?? "/block"), protectedValues: (cfg.protectedValues as string[]) ?? [], clock: () => new Date(this.deps.now()) });
        const client = new EngineClient({ ...this.base(row), engine: "webhook_block" });
        return { supported: c.supported, execute: (req) => c.execute(req, { client, clock: () => new Date(this.deps.now()) }) };
      }
      default:
        return { supported: [], execute: () => Promise.reject(new Error(`${kind} has no response connector`)) };
    }
  }

  /** Static capability of a connector kind (without building clients). */
  static supports(kind: string, config: Record<string, unknown>, action: ResponseActionKey): boolean {
    try {
      if (kind === "wazuh") return createWazuhActiveResponse((config.activeResponse as Parameters<typeof createWazuhActiveResponse>[0]) ?? {}).supported.includes(action);
      if (kind === "velociraptor") return createVelociraptorResponse((config.response as Parameters<typeof createVelociraptorResponse>[0]) ?? {}).supported.includes(action);
      if (kind === "webhook_block") return action === "block_ip" || action === "block_domain";
    } catch {
      return false;
    }
    return false;
  }

  /** The first enabled integration of the organization (then tenant-wide) able to run the action. */
  async connectorFor(tx: Queryable, tenantId: string, organizationId: string, action: ResponseActionKey): Promise<{ integration: Row; execute: (req: ResponseExecutionRequest) => Promise<ResponseExecutionResult> } | null> {
    const { rows } = await tx.query<Row>(
      `SELECT * FROM integrations WHERE enabled AND kind IN ('wazuh', 'velociraptor', 'webhook_block') AND (organization_id = $1 OR organization_id IS NULL)
       ORDER BY (organization_id IS NULL), created_at`,
      [organizationId],
    );
    for (const row of rows) {
      if (!IntegrationService.supports(String(row.kind), (row.config as Record<string, unknown>) ?? {}, action)) continue;
      const ref = row.credential_ref as string | null;
      if (!ref) continue;
      const secret = await this.deps.secretStore.resolve(tx, tenantId, ref);
      if (!secret) continue;
      const set = this.connectorSet(row, secret);
      if (!set.supported.includes(action)) continue;
      return { integration: row, execute: set.execute };
    }
    return null;
  }

  /** Actions with a configured connector, per organization (response catalog). */
  async availableActions(tx: Queryable, organizationId: string | null): Promise<Map<ResponseActionKey, string[]>> {
    const { rows } = await tx.query<Row>(
      `SELECT id, kind, name, config FROM integrations WHERE enabled AND credential_ref IS NOT NULL AND kind IN ('wazuh', 'velociraptor', 'webhook_block') ${organizationId ? "AND (organization_id = $1 OR organization_id IS NULL)" : ""}`,
      organizationId ? [organizationId] : [],
    );
    const out = new Map<ResponseActionKey, string[]>();
    for (const r of rows) {
      for (const a of ["isolate_endpoint", "release_endpoint", "kill_process", "quarantine_file", "block_ip", "block_domain", "disable_identity", "collect_evidence", "run_yara_scan"] as ResponseActionKey[]) {
        if (IntegrationService.supports(String(r.kind), (r.config as Record<string, unknown>) ?? {}, a)) out.set(a, [...(out.get(a) ?? []), String(r.name)]);
      }
    }
    return out;
  }
}
