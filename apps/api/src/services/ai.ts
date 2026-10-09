import type { AiProviderConfig, AiProviderKind, AiToolTier, Principal } from "@bloody/contracts";
import {
  AiAbortError,
  AiAccessDeniedError,
  AiConfigError,
  AiError,
  AiNotFoundError,
  AiOrchestrator,
  AiPolicyError,
  AiProviderError,
  AiQuotaExceededError,
  DefaultAiProviderRegistry,
  createProvider,
  testProviderConnection,
  SsrfBlockedError,
  ToolGateway,
  createStandardSocTools,
  type AiApprovalRequest,
  type AnyToolDefinition,
  type AiApprovalTicket,
  type AiAuditEvent,
  type AiAuditSink,
  type AiQuotaGuard,
  type AiUsageMeter,
  type AiUsageRecord,
  type ApprovalSink,
  type FetchLike,
  type HealthStatus,
  type HostResolver,
  type QuotaDecision,
  type SocDataPort,
  type ToolInvocationResult,
} from "@bloody/ai";
import type { ApprovalGate, ApprovalRequest } from "@bloody/automation";
import type { ResponseActionKey } from "@bloody/contracts";
import { writeAudit } from "../audit/audit.js";
import type { Database } from "../db/pool.js";
import { HttpError } from "../http/errors.js";
import type { PipelineLogger } from "../pipeline/analytics.js";
import type { Row } from "../repo/mappers.js";
import { PgConversationStore } from "./ai-store.js";
import type { QuotaService } from "./commercial.js";
import type { DomainEventBus } from "./domain-events.js";
import { approvalHttpError, type ResponseService } from "./response.js";
import type { SecretStore } from "./secret-store.js";

/**
 * AI SOC composition: tenant-scoped provider registry (configs in `ai_providers`, API keys in the
 * secret store), the ToolGateway (tiers, RBAC, approvals, audit) over the Postgres SocDataPort,
 * the orchestrator, conversation persistence, usage metering and the plan's daily AI quota.
 *
 * Approvals: an AI tool at or above `require_approval` is queued through the same ApprovalGate as
 * every other dangerous action (no self-approval, response:approve, expiry, audit); response
 * actions requested by the AI also get a `response_actions` row so the SOAR queue shows them.
 * Approving runs the tool through the gateway (which re-checks four-eyes and arguments).
 */

export function toProviderConfig(r: Row): AiProviderConfig {
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: (r.organization_id as string | null) ?? null,
    name: String(r.name),
    kind: r.kind as AiProviderKind,
    endpoint: (r.endpoint as string | null) ?? null,
    model: String(r.model),
    credentialRef: (r.credential_ref as string | null) ?? null,
    hasCredential: typeof r.credential_ref === "string" && r.credential_ref.length > 0,
    contextWindow: Number(r.context_window),
    temperature: Number(r.temperature),
    maxOutputTokens: Number(r.max_output_tokens),
    systemPolicy: (r.system_policy as string | null) ?? null,
    maxToolTier: r.max_tool_tier as AiToolTier,
    isDefault: Boolean(r.is_default),
    fallbackProviderId: (r.fallback_provider_id as string | null) ?? null,
    retentionDays: Number(r.retention_days),
    redactSensitive: Boolean(r.redact_sensitive),
    allowCloudData: Boolean(r.allow_cloud_data),
    enabled: Boolean(r.enabled),
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
}

/** API view: the credential reference never leaves the server, only `hasCredential`. */
export function providerView(c: AiProviderConfig) {
  const { credentialRef: _ref, ...rest } = c;
  return rest;
}

/** Map `@bloody/ai` errors onto the API error model. */
export function aiHttpError(err: unknown): unknown {
  if (err instanceof HttpError || !(err instanceof AiError)) return err;
  const details = err.details;
  if (err instanceof AiQuotaExceededError) return new HttpError(429, "quota_exceeded", err.message, details);
  if (err instanceof AiAccessDeniedError) return new HttpError(403, err.code, err.message, details);
  if (err instanceof AiNotFoundError) return new HttpError(404, err.code, err.message, details);
  if (err instanceof SsrfBlockedError) return new HttpError(400, "unsafe_endpoint", err.message, details);
  if (err instanceof AiConfigError) return new HttpError(409, err.code, err.message, details);
  if (err instanceof AiPolicyError) return new HttpError(422, err.code, err.message, details);
  if (err instanceof AiAbortError) return new HttpError(503, "aborted", err.message);
  if (err instanceof AiProviderError) return new HttpError(err.code === "rate_limited" ? 429 : 502, `provider_${err.code}`, err.message, { providerKind: err.providerKind, providerId: err.providerId, retryable: err.retryable });
  if (err.code === "invalid_request") return new HttpError(400, "invalid_request", err.message, details);
  if (err.code === "invalid_state") return new HttpError(409, "invalid_state", err.message, details);
  return new HttpError(422, err.code, err.message, details);
}

/** Response action a queued AI tool maps to in the approval queue. */
function approvalActionFor(req: AiApprovalRequest): ResponseActionKey {
  if (req.tool === "request_response_action" && typeof req.arguments.action === "string") return req.arguments.action as ResponseActionKey;
  if (req.tool === "send_notification") return "send_email";
  return "notify_analyst";
}

export interface AiServiceDeps {
  db: Database;
  secretStore: SecretStore;
  quota: QuotaService;
  gate: ApprovalGate;
  responses: ResponseService;
  port: SocDataPort;
  events: DomainEventBus;
  fetch: FetchLike;
  /** DNS check of provider endpoints (false disables — tests only). */
  hostResolver?: HostResolver | false | undefined;
  allowPrivateEndpoints: boolean;
  log: PipelineLogger;
  now: () => number;
}

export class AiService {
  readonly store: PgConversationStore;
  readonly registry: DefaultAiProviderRegistry;
  readonly gateway: ToolGateway;
  readonly orchestrator: AiOrchestrator;
  readonly audit: AiAuditSink;
  readonly tools: AnyToolDefinition[];

  constructor(private readonly deps: AiServiceDeps) {
    const clock = { now: () => new Date(deps.now()) };
    this.store = new PgConversationStore(deps.db, deps.now);
    this.audit = { record: (e) => this.recordAudit(e) };
    this.registry = new DefaultAiProviderRegistry({
      configs: { listProviders: (tenantId) => this.listProviders(tenantId) },
      secrets: deps.secretStore.aiResolver(),
      fetch: deps.fetch,
      settings: { get: (tenantId) => this.settings(tenantId) },
      ...(deps.hostResolver !== undefined ? { hostResolver: deps.hostResolver } : {}),
      onFallback: (scope, event) => deps.log.warn({ tenantId: scope.tenantId, event }, "AI provider fallback"),
    });
    const approvals: ApprovalSink = { requestApproval: (req) => this.requestApproval(req) };
    this.tools = createStandardSocTools(deps.port);
    this.gateway = new ToolGateway(this.tools, { approvals, audit: this.audit, clock });
    const usage: AiUsageMeter = { record: (r) => this.meter(r) };
    const quota: AiQuotaGuard = { consume: (input) => this.consume(input) };
    this.orchestrator = new AiOrchestrator({
      providers: this.registry,
      gateway: this.gateway,
      soc: deps.port,
      store: this.store,
      audit: this.audit,
      usage,
      quota,
      clock,
      organizationName: (tenantId, orgId) => deps.db.withTenant(tenantId, async (tx) => (await tx.query<{ name: string }>("SELECT name FROM organizations WHERE id = $1", [orgId])).rows[0]?.name ?? null),
      onBackgroundError: (err, where) => deps.log.warn({ where, err: err instanceof Error ? err.message : String(err) }, "AI background write failed"),
    });
    deps.responses.attachAi(
      (principal, actionId, decision, comment) => (decision === "approve" ? this.approve(principal, actionId, comment).then(() => undefined) : this.reject(principal, actionId, comment ?? "rejected").then(() => undefined)),
      (approval) => this.onApprovalClosed(approval),
    );
  }

  async listProviders(tenantId: string): Promise<AiProviderConfig[]> {
    return this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM ai_providers ORDER BY name")).rows.map(toProviderConfig));
  }

  async settings(tenantId: string): Promise<{ allowPrivateEndpoints: boolean }> {
    const v = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<{ v: unknown }>("SELECT settings->'ai'->'allowPrivateEndpoints' AS v FROM accounts WHERE id = $1", [tenantId])).rows[0]?.v);
    return { allowPrivateEndpoints: this.deps.allowPrivateEndpoints || v === true };
  }

  // ─── Injected sinks ──────────────────────────────────────────────────────

  private async recordAudit(e: AiAuditEvent): Promise<void> {
    const outcome = e.decision === "denied" || e.action.endsWith(".denied") ? "denied" : e.action.endsWith(".failed") ? "failure" : "success";
    await this.deps.db.withTenant(e.tenantId, (tx) =>
      writeAudit(
        tx,
        {
          tenantId: e.tenantId,
          actorKind: e.actor.kind === "ai" ? "system" : e.actor.kind,
          actorId: e.actor.kind === "ai" ? `ai:${e.actor.id}` : e.actor.id,
          actorLabel: e.actor.email ?? (e.actor.kind === "ai" ? "AI SOC analyst" : null),
          ip: null,
          userAgent: null,
          requestId: e.requestId ?? null,
        },
        {
          action: e.action,
          organizationId: e.organizationId,
          targetKind: e.actionId ? "ai_action" : e.conversationId ? "ai_conversation" : "ai",
          targetId: e.actionId ?? e.conversationId ?? null,
          outcome,
          details: {
            tool: e.tool,
            tier: e.tier,
            risk: e.risk,
            decision: e.decision,
            status: e.status,
            code: e.code,
            reason: e.reason,
            onBehalfOf: e.onBehalfOf,
            providerId: e.providerId,
            model: e.model,
            durationMs: e.durationMs,
            arguments: e.arguments,
            metadata: e.metadata,
          },
        },
      ),
    );
  }

  private async meter(r: AiUsageRecord): Promise<void> {
    await this.deps.db.withTenant(r.tenantId, async (tx) => {
      await this.deps.quota.meter(tx, r.tenantId, r.organizationId, "ai.calls", 1);
      await this.deps.quota.meter(tx, r.tenantId, r.organizationId, "ai.tokens.input", r.inputTokens);
      await this.deps.quota.meter(tx, r.tenantId, r.organizationId, "ai.tokens.output", r.outputTokens);
      if (r.egress === "cloud") await this.deps.quota.meter(tx, r.tenantId, r.organizationId, "ai.calls.cloud", 1);
    });
  }

  private async consume(input: { tenantId: string; organizationId: string | null; units: number }): Promise<QuotaDecision> {
    const d = await this.deps.quota.consumeAi(input.tenantId, input.units);
    return { allowed: d.allowed, limit: d.limit, used: d.used, remaining: Math.max(0, d.limit - d.used), resetsAt: d.resetsAt };
  }

  /** ApprovalSink: queue an AI tool call for a human decision. */
  private async requestApproval(req: AiApprovalRequest): Promise<AiApprovalTicket> {
    const requestedBy = { kind: "ai" as const, id: `ai:${req.conversationId}`, onBehalfOf: req.requestedBy.id };
    let approvalId: string;
    let expiresAt: string | null = null;
    let responseActionId: string | null = null;
    if (req.tool === "request_response_action") {
      const a = req.arguments as { action: ResponseActionKey; target: { kind: "asset" | "identity" | "indicator" | "incident"; id: string; label?: string }; incidentId?: string; parameters?: Record<string, unknown>; reason: string };
      const view = await this.deps.responses.request(
        {
          tenantId: req.tenantId,
          organizationId: req.organizationId,
          action: a.action,
          incidentId: a.incidentId ?? null,
          target: a.target,
          parameters: a.parameters ?? {},
          reason: a.reason,
          requestedBy,
          via: "ai",
          aiActionId: req.actionId,
          conversationId: req.conversationId,
          forceApproval: true,
        },
        { tenantId: req.tenantId, actorKind: "system", actorId: `ai:${req.conversationId}`, actorLabel: "AI SOC analyst", ip: null, userAgent: null, requestId: null },
      );
      if (!view.approvalId) throw new AiError("approval_unavailable", "The response action could not be queued for approval");
      approvalId = view.approvalId;
      responseActionId = view.id;
      expiresAt = (await this.deps.gate.get(req.tenantId, approvalId))?.expiresAt ?? null;
    } else {
      const approval = await this.deps.gate.request({
        tenantId: req.tenantId,
        organizationId: req.organizationId,
        kind: "ai_action",
        action: approvalActionFor(req),
        forced: true,
        reason: `${req.summary} — ${req.reason}`.slice(0, 2000),
        subject: { conversationId: req.conversationId, target: { kind: "ai_action", id: req.actionId, label: req.tool } },
        parameters: { tool: req.tool, arguments: req.arguments },
        requestedBy,
      });
      approvalId = approval.id;
      expiresAt = approval.expiresAt;
      this.deps.events.publish({
        tenantId: req.tenantId,
        organizationId: req.organizationId,
        event: "response.pending_approval",
        occurredAt: new Date(this.deps.now()).toISOString(),
        severity: req.risk === "high" ? "high" : "medium",
        subject: { kind: "ai_action", id: req.actionId, label: req.summary.slice(0, 200) },
        dedupKey: `approval:${approval.id}`,
        data: { approvalId: approval.id, risk: req.risk, tool: req.tool, requestedVia: "ai", action: { action: req.tool } },
      });
    }
    // Pre-create the action record with its approval link (the orchestrator upserts it afterwards).
    await this.deps.db.withTenant(req.tenantId, (tx) =>
      tx.query(
        `INSERT INTO ai_actions (id, tenant_id, organization_id, conversation_id, tool, tier, arguments, status, requested_by, at, approval_id, response_action_id, provider_id, risk)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'pending_approval', $8, $9, $10, $11, $12, $13)
         ON CONFLICT (id) DO UPDATE SET approval_id = EXCLUDED.approval_id, response_action_id = EXCLUDED.response_action_id`,
        [req.actionId, req.tenantId, req.organizationId, req.conversationId, req.tool, req.tier, JSON.stringify(req.arguments), req.requestedBy.id, req.requestedAt, approvalId, responseActionId, req.providerId, req.risk],
      ),
    );
    return { approvalId, expiresAt };
  }

  /** Live provider test (SSRF-checked health check, then model listing). The key is never returned. */
  async testProvider(cfg: AiProviderConfig): Promise<{ health: HealthStatus; models: Array<{ id: string; name?: string; contextWindow?: number }>; modelsError: string | null }> {
    const secret = cfg.credentialRef ? await this.deps.db.withTenant(cfg.tenantId, (tx) => this.deps.secretStore.resolve(tx, cfg.tenantId, cfg.credentialRef!)) : null;
    const { allowPrivateEndpoints } = await this.settings(cfg.tenantId);
    const runtime = { allowPrivateEndpoints, timeoutMs: 20_000, maxRetries: 0, governance: false as const };
    const health = await testProviderConnection(cfg, secret, this.deps.fetch, { ...runtime, ...(this.deps.hostResolver ? { hostResolver: this.deps.hostResolver } : {}) });
    let models: Array<{ id: string; name?: string; contextWindow?: number }> = [];
    let modelsError: string | null = null;
    if (health.ok || health.modelsListed !== null) {
      try {
        const listed = await createProvider(cfg, secret, this.deps.fetch, runtime).listModels();
        models = listed.slice(0, 500).map((m) => ({ id: m.id, ...(m.name ? { name: m.name } : {}), ...(m.contextWindow ? { contextWindow: m.contextWindow } : {}) }));
      } catch (err) {
        modelsError = err instanceof Error ? err.message.slice(0, 300) : "model listing failed";
      }
    }
    return { health, models, modelsError };
  }

  /** Approval expired / cancelled outside the AI flow: close the AI action too. */
  private async onApprovalClosed(approval: ApprovalRequest): Promise<void> {
    if (approval.status !== "expired" && approval.status !== "cancelled") return;
    await this.deps.db.withTenant(approval.tenantId, (tx) =>
      tx.query("UPDATE ai_actions SET status = 'rejected', result = $2::jsonb WHERE approval_id = $1 AND status = 'pending_approval'", [approval.id, JSON.stringify({ reason: `approval ${approval.status}` })]),
    );
  }

  private async approvalOf(tenantId: string, actionId: string): Promise<{ approvalId: string | null; organizationId: string } | null> {
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<{ approval_id: string | null; organization_id: string }>("SELECT approval_id, organization_id FROM ai_actions WHERE id = $1", [actionId]);
      return rows[0] ? { approvalId: rows[0].approval_id, organizationId: rows[0].organization_id } : null;
    });
  }

  /**
   * Approve an AI action: the ApprovalGate decides (human, response:approve, no self-approval,
   * expiry, distinct approvers), then the gateway executes the tool.
   */
  async approve(principal: Principal, actionId: string, comment?: string): Promise<ToolInvocationResult | { status: "pending_approval"; approvals: number; required: number }> {
    const link = /^[0-9a-f-]{36}$/i.test(actionId) ? await this.approvalOf(principal.tenantId, actionId) : null;
    if (!link) throw new HttpError(404, "not_found", "AI action not found");
    if (link.approvalId) {
      let decided: ApprovalRequest;
      try {
        decided = await this.deps.gate.approve(principal.tenantId, link.approvalId, principal, comment);
      } catch (err) {
        throw approvalHttpError(err);
      }
      if (decided.status === "pending") return { status: "pending_approval", approvals: decided.approvals.length, required: decided.requiredApprovals };
    }
    try {
      return await this.orchestrator.approveAction({ approver: principal, actionId });
    } catch (err) {
      throw aiHttpError(err);
    }
  }

  async reject(principal: Principal, actionId: string, reason: string) {
    const link = /^[0-9a-f-]{36}$/i.test(actionId) ? await this.approvalOf(principal.tenantId, actionId) : null;
    if (!link) throw new HttpError(404, "not_found", "AI action not found");
    if (link.approvalId) {
      try {
        await this.deps.gate.reject(principal.tenantId, link.approvalId, principal, reason);
      } catch (err) {
        throw approvalHttpError(err);
      }
    }
    try {
      return await this.orchestrator.rejectAction({ approver: principal, actionId, reason });
    } catch (err) {
      throw aiHttpError(err);
    }
  }
}
