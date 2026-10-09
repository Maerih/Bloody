import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { AiChatRequest, AiProviderKind, AiToolTier, UpsertAiProviderInput, Uuid, type AiProviderConfig } from "@bloody/contracts";
import { assertSafeEndpoint, classifyEgress, describeTools, listProviderCatalog, resolveEndpoint } from "@bloody/ai";
import { recordAudit } from "../audit/audit.js";
import { actorId, assertRecordAccess, canAnywhere, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { badRequest, notFound, toHttpError } from "../http/errors.js";
import { IdParam, Limit } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { aiHttpError, providerView, toProviderConfig } from "../services/ai.js";
import { toAiAction } from "../services/ai-store.js";
import { loadOne, parse } from "./util.js";

const PatchProvider = z
  .object({
    name: z.string().trim().min(1).max(120),
    kind: AiProviderKind,
    model: z.string().min(1).max(200),
    endpoint: z.string().url().nullable(),
    /** Write-only. A string replaces the stored key; null removes it. */
    apiKey: z.string().min(1).max(4000).nullable(),
    contextWindow: z.number().int().min(512).max(2_000_000),
    temperature: z.number().min(0).max(2),
    maxOutputTokens: z.number().int().min(16).max(200_000),
    systemPolicy: z.string().max(20_000).nullable(),
    maxToolTier: AiToolTier,
    isDefault: z.boolean(),
    fallbackProviderId: Uuid.nullable(),
    retentionDays: z.number().int().min(0).max(3650),
    redactSensitive: z.boolean(),
    allowCloudData: z.boolean(),
    enabled: z.boolean(),
  })
  .partial()
  .strict();

const ConversationsQuery = z.object({ organizationId: Uuid.optional(), scope: z.enum(["mine", "all"]).default("mine"), limit: Limit(100, 25), cursor: z.string().optional() });
const ActionsQuery = z.object({ organizationId: Uuid.optional(), status: z.enum(["completed", "pending_approval", "approved", "rejected", "denied", "failed"]).optional(), limit: Limit(200, 50) });

/** ai:configure in the provider's scope (tenant-wide for tenant providers). */
function requireConfigure(request: FastifyRequest, organizationId: string | null) {
  return requirePermission(request, "ai:configure", organizationId);
}

async function checkFallback(tx: Queryable, organizationId: string | null, fallbackId: string | null | undefined, selfId: string | null): Promise<void> {
  if (!fallbackId) return;
  if (fallbackId === selfId) throw badRequest("A provider cannot fall back to itself");
  const { rows } = await tx.query<{ organization_id: string | null }>("SELECT organization_id FROM ai_providers WHERE id = $1", [fallbackId]);
  if (!rows[0]) throw badRequest("fallbackProviderId does not reference a provider of this tenant");
  if (rows[0].organization_id !== null && rows[0].organization_id !== organizationId) throw badRequest("The fallback provider belongs to another organization");
}

/**
 * AI SOC: provider configuration (keys go to the secret store and are never returned), provider
 * tests, chat (JSON or Server-Sent Events), conversations and the AI action approval queue.
 */
export async function aiRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const aiModule = { module: "ai_soc" as const };

  const endpointCheck = async (tenantId: string, kind: AiProviderConfig["kind"], endpoint: string | null) => {
    const resolved = resolveEndpoint({ kind, endpoint });
    if (!resolved) return;
    const { allowPrivateEndpoints } = await s.ai.settings(tenantId);
    try {
      assertSafeEndpoint(resolved, { allowPrivate: allowPrivateEndpoints, requireHttps: classifyEgress(kind, resolved) === "cloud" });
    } catch (err) {
      throw aiHttpError(err);
    }
  };

  // ─── Providers ────────────────────────────────────────────────────────────
  app.get("/ai/providers/catalog", { config: aiModule }, async (request) => {
    requireAuth(request);
    return { items: listProviderCatalog() };
  });

  app.get("/ai/tools", { config: aiModule }, async (request) => {
    requireAuth(request);
    return { items: describeTools(s.ai.tools) };
  });

  app.get("/ai/providers", { config: aiModule }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional() }), request.query);
    const orgs = resolveOrgFilter(request, canAnywhere(auth.principal, "ai:configure") ? "ai:configure" : "ai:use", q.organizationId);
    const all = await s.ai.listProviders(auth.tenantId);
    const visible = all.filter((c) => c.organizationId === null || orgs === null || orgs.includes(c.organizationId));
    return { items: visible.map(providerView), nextCursor: null };
  });

  app.post("/ai/providers", { config: { ...aiModule, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(UpsertAiProviderInput, request.body);
    const organizationId = body.organizationId ?? null;
    requireConfigure(request, organizationId);
    await endpointCheck(auth.tenantId, body.kind, body.endpoint ?? null);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (organizationId) await loadOne(tx, "organizations", organizationId, "Organization");
      await checkFallback(tx, organizationId, body.fallbackProviderId, null);
      const credentialRef = body.apiKey ? (await s.secretStore.put(tx, auth.tenantId, { value: body.apiKey, name: `AI provider ${body.name}`, purpose: "ai.provider", organizationId, createdBy: actorId(auth) })).ref : null;
      if (body.isDefault) await tx.query("UPDATE ai_providers SET is_default = false WHERE organization_id IS NOT DISTINCT FROM $1 AND is_default", [organizationId]);
      const { rows } = await tx.query<Row>(
        `INSERT INTO ai_providers (tenant_id, organization_id, name, kind, endpoint, model, credential_ref, context_window, temperature, max_output_tokens, system_policy,
                                   max_tool_tier, is_default, fallback_provider_id, retention_days, redact_sensitive, allow_cloud_data, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING *`,
        [
          auth.tenantId,
          organizationId,
          body.name,
          body.kind,
          body.endpoint ?? null,
          body.model,
          credentialRef,
          body.contextWindow,
          body.temperature,
          body.maxOutputTokens,
          body.systemPolicy ?? null,
          body.maxToolTier,
          body.isDefault,
          body.fallbackProviderId ?? null,
          body.retentionDays,
          body.redactSensitive,
          body.allowCloudData,
          body.enabled,
        ],
      );
      const cfg = toProviderConfig(rows[0]!);
      await recordAudit(tx, request, {
        action: "ai_provider.created",
        organizationId,
        targetKind: "ai_provider",
        targetId: cfg.id,
        details: { name: cfg.name, kind: cfg.kind, model: cfg.model, endpoint: cfg.endpoint, maxToolTier: cfg.maxToolTier, hasCredential: cfg.hasCredential, allowCloudData: cfg.allowCloudData },
      });
      return cfg;
    });
    return reply.status(201).send(providerView(created));
  });

  const loadProvider = async (tenantId: string, request: FastifyRequest, id: string, permission: "ai:configure" | "ai:use" = "ai:configure") => {
    const row = await s.db.withTenant(tenantId, (tx) => loadOne(tx, "ai_providers", id, "AI provider"));
    const cfg = toProviderConfig(row);
    if (cfg.organizationId) assertRecordAccess(request, permission, cfg.organizationId, "AI provider");
    else resolveOrgFilter(request, permission, undefined);
    return cfg;
  };

  app.get("/ai/providers/:id", { config: aiModule }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return providerView(await loadProvider(auth.tenantId, request, id, "ai:use"));
  });

  app.patch("/ai/providers/:id", { config: { ...aiModule, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(PatchProvider, request.body);
    if (Object.keys(body).length === 0) throw badRequest("Nothing to update");
    const cur = await loadProvider(auth.tenantId, request, id);
    requireConfigure(request, cur.organizationId);
    const kind = body.kind ?? cur.kind;
    const endpoint = body.endpoint !== undefined ? body.endpoint : cur.endpoint;
    if (body.kind !== undefined || body.endpoint !== undefined) await endpointCheck(auth.tenantId, kind, endpoint);
    const updated = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.fallbackProviderId !== undefined) await checkFallback(tx, cur.organizationId, body.fallbackProviderId, id);
      let credentialRef = cur.credentialRef;
      let releasedRef: string | null = null;
      if (typeof body.apiKey === "string") {
        if (credentialRef) await s.secretStore.replace(tx, auth.tenantId, credentialRef, body.apiKey);
        else credentialRef = (await s.secretStore.put(tx, auth.tenantId, { value: body.apiKey, name: `AI provider ${body.name ?? cur.name}`, purpose: "ai.provider", organizationId: cur.organizationId, createdBy: actorId(auth) })).ref;
      } else if (body.apiKey === null && credentialRef) {
        releasedRef = credentialRef;
        credentialRef = null;
      }
      if (body.isDefault) await tx.query("UPDATE ai_providers SET is_default = false WHERE organization_id IS NOT DISTINCT FROM $1 AND is_default AND id <> $2", [cur.organizationId, id]);
      const next = { ...cur, ...body, kind, endpoint, credentialRef };
      const { rows } = await tx.query<Row>(
        `UPDATE ai_providers SET name = $2, kind = $3, endpoint = $4, model = $5, credential_ref = $6, context_window = $7, temperature = $8, max_output_tokens = $9,
                system_policy = $10, max_tool_tier = $11, is_default = $12, fallback_provider_id = $13, retention_days = $14, redact_sensitive = $15, allow_cloud_data = $16, enabled = $17
         WHERE id = $1 RETURNING *`,
        [id, next.name, next.kind, next.endpoint, next.model, next.credentialRef, next.contextWindow, next.temperature, next.maxOutputTokens, next.systemPolicy, next.maxToolTier, next.isDefault, next.fallbackProviderId, next.retentionDays, next.redactSensitive, next.allowCloudData, next.enabled],
      );
      if (releasedRef) await s.secretStore.delete(tx, releasedRef);
      const fields = Object.keys(body).map((k) => (k === "apiKey" ? (body.apiKey === null ? "apiKey(removed)" : "apiKey(replaced)") : k));
      await recordAudit(tx, request, { action: "ai_provider.updated", organizationId: cur.organizationId, targetKind: "ai_provider", targetId: id, details: { fields } });
      return toProviderConfig(rows[0]!);
    });
    return providerView(updated);
  });

  app.delete("/ai/providers/:id", { config: { ...aiModule, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const cur = await loadProvider(auth.tenantId, request, id);
    requireConfigure(request, cur.organizationId);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await tx.query("DELETE FROM ai_providers WHERE id = $1", [id]);
      if (cur.credentialRef) await s.secretStore.delete(tx, cur.credentialRef);
      await recordAudit(tx, request, { action: "ai_provider.deleted", organizationId: cur.organizationId, targetKind: "ai_provider", targetId: id, details: { name: cur.name, kind: cur.kind } });
    });
    return reply.status(204).send();
  });

  /** Live provider test: SSRF-checked health check + model listing. Never echoes the key. */
  app.post("/ai/providers/:id/test", { config: { ...aiModule, audit: "ai_provider.tested" } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const cfg = await loadProvider(auth.tenantId, request, id);
    requireConfigure(request, cfg.organizationId);
    request.auditState.organizationId = cfg.organizationId;
    request.auditState.targetKind = "ai_provider";
    const { health, models, modelsError } = await s.ai.testProvider(cfg);
    request.auditState.details = { ok: health.ok, latencyMs: health.latencyMs, code: health.error?.code ?? null };
    return { providerId: id, health, models, modelsError };
  });

  // ─── Chat ─────────────────────────────────────────────────────────────────
  app.post("/ai/chat", { config: { ...aiModule, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(AiChatRequest, request.body);
    requirePermission(request, "ai:use", body.organizationId);
    // The orchestrator audits every turn (ai.chat.completed / denied / failed).
    request.auditState.recorded = true;
    const accept = String(request.headers.accept ?? "");
    if (accept.includes("text/event-stream")) {
      const abort = new AbortController();
      request.raw.on("close", () => abort.abort());
      reply.hijack();
      const raw = reply.raw;
      raw.writeHead(200, { ...(reply.getHeaders() as Record<string, string>), "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store", connection: "keep-alive", "x-accel-buffering": "no" });
      const send = (event: string, data: unknown) => {
        if (!raw.writableEnded) raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      };
      try {
        await s.ai.orchestrator.run({ principal: auth.principal, request: body, signal: abort.signal, requestId: request.id, onEvent: (e) => send(e.type, e) });
      } catch (err) {
        const http = toHttpError(aiHttpError(err));
        send("error", { error: { code: http.code, message: http.message, requestId: request.id } });
      } finally {
        raw.end();
      }
      return reply;
    }
    try {
      return await s.ai.orchestrator.run({ principal: auth.principal, request: body, requestId: request.id });
    } catch (err) {
      throw aiHttpError(err);
    }
  });

  // ─── Conversations ────────────────────────────────────────────────────────
  app.get("/ai/conversations", { config: aiModule }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(ConversationsQuery, request.query);
    if (q.organizationId) resolveOrgFilter(request, "ai:use", q.organizationId);
    if (q.scope === "all") {
      // Reviewers (audit:read) may list every analyst's conversations of an organization.
      if (!q.organizationId) throw badRequest("scope=all requires organizationId");
      requirePermission(request, "audit:read", q.organizationId);
    }
    const page = await s.ai.store.list(auth.tenantId, {
      ...(q.organizationId ? { organizationId: q.organizationId } : {}),
      ...(q.scope === "mine" ? { principalId: auth.principal.id } : {}),
      limit: q.limit,
      ...(q.cursor ? { cursor: q.cursor } : {}),
    });
    return page;
  });

  app.get("/ai/conversations/:id", { config: aiModule }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    try {
      return await s.ai.orchestrator.getConversation(auth.principal, id);
    } catch (err) {
      throw aiHttpError(err);
    }
  });

  // ─── AI action approvals ──────────────────────────────────────────────────
  app.get("/ai/actions", { config: aiModule }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(ActionsQuery, request.query);
    const orgs = resolveOrgFilter(request, "ai:use", q.organizationId);
    const params: unknown[] = [];
    const where = ["TRUE"];
    if (orgs) where.push(`a.organization_id = ANY($${params.push(orgs)}::uuid[])`);
    if (q.status) where.push(`a.status = $${params.push(q.status)}`);
    params.push(q.limit);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT a.*, c.title AS conversation_title FROM ai_actions a JOIN ai_conversations c ON c.id = a.conversation_id
         WHERE ${where.join(" AND ")} ORDER BY a.at DESC LIMIT $${params.length}`,
        params,
      ),
    );
    return {
      items: rows.map((r) => ({ ...toAiAction(r), organizationId: String(r.organization_id), approvalId: (r.approval_id as string | null) ?? null, responseActionId: (r.response_action_id as string | null) ?? null, risk: (r.risk as string | null) ?? null, conversationTitle: (r.conversation_title as string | null) ?? null })),
      nextCursor: null,
    };
  });

  app.post("/ai/actions/:id/approve", { config: { ...aiModule, audit: "ai.action.approve" } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(z.object({ comment: z.string().trim().max(2000).optional() }).strict(), request.body ?? {});
    const found = await s.ai.store.getAction(auth.tenantId, id);
    if (!found) throw notFound("AI action");
    assertRecordAccess(request, "ai:use", found.organizationId, "AI action");
    requirePermission(request, "response:approve", found.organizationId);
    request.auditState.organizationId = found.organizationId;
    request.auditState.targetKind = "ai_action";
    return s.ai.approve(auth.principal, id, body.comment);
  });

  app.post("/ai/actions/:id/reject", { config: { ...aiModule, audit: "ai.action.reject" } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(z.object({ reason: z.string().trim().min(3).max(2000) }).strict(), request.body);
    const found = await s.ai.store.getAction(auth.tenantId, id);
    if (!found) throw notFound("AI action");
    assertRecordAccess(request, "ai:use", found.organizationId, "AI action");
    requirePermission(request, "response:approve", found.organizationId);
    request.auditState.organizationId = found.organizationId;
    request.auditState.targetKind = "ai_action";
    return s.ai.reject(auth.principal, id, body.reason);
  });
}
