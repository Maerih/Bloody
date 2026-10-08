import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { AutomationEvent, NotificationChannelKind, PlaybookCondition, Uuid, principalCan, type Permission } from "@bloody/contracts";
import { AutomationRuleEngine, DEFAULT_RULE_TEMPLATES, AutomationError } from "@bloody/automation";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, forbidden, notFound } from "../http/errors.js";
import { IdParam, Limit, decodeCursor } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { NotificationService, channelView, toChannel, toRule } from "../services/notifications.js";
import { QueryBool, keysetClause, loadOne, orderBy, pageRows, parse, type KeysetSort } from "./util.js";

const ChannelBody = z
  .object({
    name: z.string().trim().min(1).max(200),
    kind: NotificationChannelKind,
    organizationId: Uuid.nullable().default(null),
    config: z.record(z.unknown()).default({}),
    enabled: z.boolean().default(true),
  })
  .strict();
const ChannelPatch = z.object({ name: z.string().trim().min(1).max(200).optional(), config: z.record(z.unknown()).optional(), enabled: z.boolean().optional() }).strict();

const RuleBody = z
  .object({
    name: z.string().trim().min(1).max(200),
    organizationId: Uuid.nullable().default(null),
    event: AutomationEvent,
    conditions: z.array(PlaybookCondition).max(20).default([]),
    channelIds: z.array(Uuid).max(20).default([]),
    template: z.object({ subject: z.string().min(1).max(300), body: z.string().min(1).max(20_000) }).optional(),
    throttleMinutes: z.number().int().min(0).max(10_080).default(0),
    enabled: z.boolean().default(true),
  })
  .strict();
const RulePatch = z
  .object({
    name: z.string().trim().min(1).max(200).optional(),
    conditions: z.array(PlaybookCondition).max(20).optional(),
    channelIds: z.array(Uuid).max(20).optional(),
    template: z.object({ subject: z.string().min(1).max(300), body: z.string().min(1).max(20_000) }).optional(),
    throttleMinutes: z.number().int().min(0).max(10_080).optional(),
    enabled: z.boolean().optional(),
  })
  .strict();

const BellQuery = z.object({ unread: QueryBool.optional(), limit: Limit(200, 50), cursor: z.string().optional() });
const BELL_SORT: KeysetSort = { expr: "n.created_at", dir: "desc", cast: "timestamptz" };

const MANAGE: Permission[] = ["settings:write", "playbook:write"];

/** Channel / rule management: settings:write or playbook:write in the scope (tenant-wide scope for tenant-wide items). */
function requireManage(request: FastifyRequest, organizationId: string | null): void {
  const auth = requireAuth(request);
  if (auth.boundOrganizationId !== null && organizationId !== auth.boundOrganizationId) throw forbidden("This API key is restricted to its organization");
  if (!MANAGE.some((p) => principalCan(auth.principal, p, organizationId))) {
    request.auditState.details = { deniedPermission: MANAGE.join("|"), organizationId };
    throw forbidden(`Missing permission settings:write or playbook:write${organizationId ? " for this organization" : " (tenant-wide)"}`);
  }
}

function inScope(orgs: string[] | null, organizationId: string | null): boolean {
  return organizationId === null || orgs === null || orgs.includes(organizationId);
}

export async function notificationRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  // ─── Channels ──────────────────────────────────────────────────────────────
  app.get("/notifications/channels", async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional(), kind: NotificationChannelKind.optional() }), request.query);
    const orgs = resolveOrgFilter(request, "playbook:read", q.organizationId);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT * FROM notification_channels WHERE ${orgs ? "(organization_id IS NULL OR organization_id = ANY($1::uuid[]))" : "TRUE"} ${q.kind ? `AND kind = $${orgs ? 2 : 1}` : ""} ORDER BY name`,
        [...(orgs ? [orgs] : []), ...(q.kind ? [q.kind] : [])],
      ),
    );
    return { items: rows.map((r) => channelView({ ...toChannel(r), createdAt: String(r.created_at), updatedAt: String(r.updated_at) })), nextCursor: null, kinds: s.notifications.registry.kinds() };
  });

  app.post("/notifications/channels", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(ChannelBody, request.body);
    requireManage(request, body.organizationId);
    const res = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.organizationId) await loadOne(tx, "organizations", body.organizationId, "Organization");
      const prepared = await s.notifications.prepareConfig(tx, auth.tenantId, { kind: body.kind, organizationId: body.organizationId, name: body.name, config: body.config }, null, actorId(auth));
      const { rows } = await tx.query<Row>(
        "INSERT INTO notification_channels (tenant_id, organization_id, name, kind, config, enabled) VALUES ($1, $2, $3, $4, $5::jsonb, $6) RETURNING *",
        [auth.tenantId, body.organizationId, body.name, body.kind, JSON.stringify(prepared.config), body.enabled],
      );
      const channel = toChannel(rows[0]!);
      await recordAudit(tx, request, { action: "notification_channel.created", organizationId: body.organizationId, targetKind: "notification_channel", targetId: channel.id, details: { kind: body.kind, name: body.name } });
      return { channel: channelView({ ...channel, createdAt: String(rows[0]!.created_at), updatedAt: String(rows[0]!.updated_at) }), generatedSecret: prepared.generatedSecret };
    });
    // A generated webhook signing secret is returned exactly once so the receiver can verify signatures.
    return reply.status(201).send({ ...res.channel, ...(res.generatedSecret ? { signingSecret: res.generatedSecret } : {}) });
  });

  app.get("/notifications/channels/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const orgs = resolveOrgFilter(request, "playbook:read", undefined);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "notification_channels", id, "Notification channel");
      if (!inScope(orgs, (row.organization_id as string | null) ?? null)) throw notFound("Notification channel");
      return channelView({ ...toChannel(row), createdAt: String(row.created_at), updatedAt: String(row.updated_at) });
    });
  });

  app.patch("/notifications/channels/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(ChannelPatch, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "notification_channels", id, "Notification channel");
      const cur = toChannel(row);
      requireManage(request, cur.organizationId);
      let config = cur.config;
      let released: string[] = [];
      if (body.config) {
        const prepared = await s.notifications.prepareConfig(tx, auth.tenantId, { kind: cur.kind, organizationId: cur.organizationId, name: body.name ?? cur.name, config: body.config }, cur, actorId(auth));
        config = prepared.config;
        released = prepared.releasedRefs;
      }
      const { rows } = await tx.query<Row>("UPDATE notification_channels SET name = $2, config = $3::jsonb, enabled = $4 WHERE id = $1 RETURNING *", [id, body.name ?? cur.name, JSON.stringify(config), body.enabled ?? cur.enabled]);
      for (const ref of released) await s.secretStore.delete(tx, ref);
      await recordAudit(tx, request, { action: "notification_channel.updated", organizationId: cur.organizationId, targetKind: "notification_channel", targetId: id, details: { fields: Object.keys(body), configKeys: body.config ? Object.keys(body.config) : [] } });
      return channelView({ ...toChannel(rows[0]!), createdAt: String(rows[0]!.created_at), updatedAt: String(rows[0]!.updated_at) });
    });
  });

  app.delete("/notifications/channels/:id", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const cur = toChannel(await loadOne(tx, "notification_channels", id, "Notification channel"));
      requireManage(request, cur.organizationId);
      await tx.query("UPDATE automation_rules SET channel_ids = array_remove(channel_ids, $1::uuid) WHERE $1::uuid = ANY(channel_ids)", [id]);
      await tx.query("UPDATE report_schedules SET channel_ids = array_remove(channel_ids, $1::uuid) WHERE $1::uuid = ANY(channel_ids)", [id]);
      await tx.query("DELETE FROM notification_channels WHERE id = $1", [id]);
      for (const ref of NotificationService.refsOf(cur.config)) await s.secretStore.delete(tx, ref);
      await recordAudit(tx, request, { action: "notification_channel.deleted", organizationId: cur.organizationId, targetKind: "notification_channel", targetId: id, details: { kind: cur.kind, name: cur.name } });
    });
    return reply.status(204).send();
  });

  app.post("/notifications/channels/:id/test", { config: { audit: "notification_channel.tested" } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const channel = await s.db.withTenant(auth.tenantId, async (tx) => toChannel(await loadOne(tx, "notification_channels", id, "Notification channel")));
    requireManage(request, channel.organizationId);
    request.auditState.organizationId = channel.organizationId;
    request.auditState.targetKind = "notification_channel";
    try {
      const res = await s.notifications.registry.test(channel, { requestedBy: auth.principal.email ?? auth.principal.id, now: new Date(s.now()) });
      request.auditState.details = { kind: channel.kind, ok: true };
      return { ok: true, channelId: id, kind: channel.kind, message: res.detail ?? "Test notification delivered", providerMessageId: res.providerMessageId ?? null, warnings: res.warnings ?? [] };
    } catch (err) {
      const code = err instanceof AutomationError ? err.code : "delivery_failed";
      request.auditState.details = { kind: channel.kind, ok: false, code };
      return { ok: false, channelId: id, kind: channel.kind, code, message: err instanceof Error ? err.message.slice(0, 500) : "delivery failed" };
    }
  });

  // ─── Automation rules ─────────────────────────────────────────────────────
  app.get("/automations/templates", async (request) => {
    requireAuth(request);
    return { items: Object.values(DEFAULT_RULE_TEMPLATES) };
  });

  app.get("/automations", async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional(), event: AutomationEvent.optional() }), request.query);
    const orgs = resolveOrgFilter(request, "playbook:read", q.organizationId);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT * FROM automation_rules WHERE ${orgs ? "(organization_id IS NULL OR organization_id = ANY($1::uuid[]))" : "TRUE"} ${q.event ? `AND event = $${orgs ? 2 : 1}` : ""} ORDER BY name`,
        [...(orgs ? [orgs] : []), ...(q.event ? [q.event] : [])],
      ),
    );
    return { items: rows.map((r) => ({ ...toRule(r), createdAt: r.created_at, updatedAt: r.updated_at })), nextCursor: null };
  });

  const checkChannels = async (tx: { query: (sql: string, p: unknown[]) => Promise<{ rows: Row[] }> }, organizationId: string | null, channelIds: string[]) => {
    if (channelIds.length === 0) return;
    const { rows } = await tx.query("SELECT id, organization_id FROM notification_channels WHERE id = ANY($1::uuid[])", [channelIds]);
    const found = new Map(rows.map((r) => [String(r.id), (r.organization_id as string | null) ?? null]));
    for (const cid of channelIds) {
      if (!found.has(cid)) throw new HttpError(400, "invalid_channel", `Channel ${cid} does not exist`);
      const org = found.get(cid)!;
      // A rule may use tenant-wide channels and channels of its own organization only.
      if (org !== null && org !== organizationId) throw new HttpError(400, "invalid_channel", `Channel ${cid} belongs to another organization`);
    }
  };

  app.post("/automations", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(RuleBody, request.body);
    requireManage(request, body.organizationId);
    const template = body.template ?? { subject: DEFAULT_RULE_TEMPLATES[body.event].subject, body: DEFAULT_RULE_TEMPLATES[body.event].body };
    const issues = AutomationRuleEngine.validateRule({ event: body.event, conditions: body.conditions, template, channelIds: body.channelIds, throttleMinutes: body.throttleMinutes });
    if (issues.length > 0) throw new HttpError(400, "invalid_rule", "Invalid automation rule", issues);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.organizationId) await loadOne(tx, "organizations", body.organizationId, "Organization");
      await checkChannels(tx, body.organizationId, body.channelIds);
      const { rows } = await tx.query<Row>(
        `INSERT INTO automation_rules (tenant_id, organization_id, name, event, conditions, channel_ids, template, throttle_minutes, enabled)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::uuid[], $7::jsonb, $8, $9) RETURNING *`,
        [auth.tenantId, body.organizationId, body.name, body.event, JSON.stringify(body.conditions), body.channelIds, JSON.stringify(template), body.throttleMinutes, body.enabled],
      );
      const rule = toRule(rows[0]!);
      await recordAudit(tx, request, { action: "automation_rule.created", organizationId: body.organizationId, targetKind: "automation_rule", targetId: rule.id, details: { event: body.event, channels: body.channelIds.length } });
      return rule;
    });
    return reply.status(201).send(created);
  });

  app.patch("/automations/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(RulePatch, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const cur = toRule(await loadOne(tx, "automation_rules", id, "Automation rule"));
      requireManage(request, cur.organizationId);
      const next = { ...cur, ...body };
      const issues = AutomationRuleEngine.validateRule(next);
      if (issues.length > 0) throw new HttpError(400, "invalid_rule", "Invalid automation rule", issues);
      if (body.channelIds) await checkChannels(tx, cur.organizationId, body.channelIds);
      const { rows } = await tx.query<Row>(
        "UPDATE automation_rules SET name = $2, conditions = $3::jsonb, channel_ids = $4::uuid[], template = $5::jsonb, throttle_minutes = $6, enabled = $7 WHERE id = $1 RETURNING *",
        [id, next.name, JSON.stringify(next.conditions), next.channelIds, JSON.stringify(next.template), next.throttleMinutes, next.enabled],
      );
      await recordAudit(tx, request, { action: "automation_rule.updated", organizationId: cur.organizationId, targetKind: "automation_rule", targetId: id, details: { fields: Object.keys(body) } });
      return toRule(rows[0]!);
    });
  });

  app.delete("/automations/:id", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const cur = toRule(await loadOne(tx, "automation_rules", id, "Automation rule"));
      requireManage(request, cur.organizationId);
      await tx.query("DELETE FROM automation_rules WHERE id = $1", [id]);
      await recordAudit(tx, request, { action: "automation_rule.deleted", organizationId: cur.organizationId, targetKind: "automation_rule", targetId: id, details: { event: cur.event, name: cur.name } });
    });
    return reply.status(204).send();
  });

  /** Render a rule against a sample event (rule editor preview); nothing is sent. */
  app.post("/automations/preview", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const body = parse(
      z.object({ event: AutomationEvent, template: z.object({ subject: z.string().min(1).max(300), body: z.string().min(1).max(20_000) }), data: z.record(z.unknown()).default({}), organizationId: Uuid.nullable().default(null) }).strict(),
      request.body,
    );
    request.auditState.recorded = true;
    const rendered = s.notifications.engine.render({ template: body.template }, {
      tenantId: auth.tenantId,
      organizationId: body.organizationId,
      event: body.event,
      occurredAt: new Date(s.now()).toISOString(),
      subject: { kind: "preview", id: "preview" },
      data: body.data,
    });
    return rendered;
  });

  // ─── In-app notifications (Command Center bell) ──────────────────────────
  const visibility = (auth: ReturnType<typeof requireAuth>, params: unknown[]): string => {
    const tenantRoles = [...new Set(auth.principal.bindings.filter((b) => b.organizationId === null).map((b) => b.role))];
    const orgBindings = auth.principal.bindings.filter((b) => b.organizationId !== null);
    const me = params.push(auth.principal.id);
    const tr = params.push(tenantRoles);
    const or = params.push(orgBindings.map((b) => b.role));
    const oo = params.push(orgBindings.map((b) => b.organizationId));
    const scope = tenantRoles.length > 0 ? "TRUE" : `(n.organization_id IS NULL OR n.organization_id = ANY($${oo}::uuid[]))`;
    return `(${scope} AND ($${me}::uuid = ANY(n.recipient_user_ids) OR n.recipient_roles && $${tr}::text[]
             OR EXISTS (SELECT 1 FROM unnest($${or}::text[], $${oo}::uuid[]) b(role, org) WHERE b.role = ANY(n.recipient_roles) AND (n.organization_id IS NULL OR b.org = n.organization_id))))`;
  };

  app.get("/notifications", async (request) => {
    const auth = requireAuth(request);
    const q = parse(BellQuery, request.query);
    if (auth.principal.kind !== "user") return { items: [], nextCursor: null, unread: 0 };
    const params: unknown[] = [];
    const where = [visibility(auth, params)];
    const me = params.push(auth.principal.id);
    if (q.unread) where.push(`NOT ($${me}::uuid = ANY(n.read_by))`);
    const unreadWhere = [...where, `NOT ($${me}::uuid = ANY(n.read_by))`];
    const countParams = [...params];
    where.push(keysetClause(BELL_SORT, "n.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        `SELECT n.*, n.created_at AS sort_key, ($${me}::uuid = ANY(n.read_by)) AS is_read FROM notifications n WHERE ${where.join(" AND ")} ORDER BY ${orderBy(BELL_SORT, "n.id")} LIMIT $${params.length}`,
        params,
      );
      const unread = await tx.query<{ n: number }>(`SELECT count(*)::int AS n FROM notifications n WHERE ${unreadWhere.join(" AND ")} AND n.created_at > now() - interval '30 days'`, countParams);
      const page = pageRows(rows, q.limit, (r) => ({
        id: String(r.id),
        organizationId: (r.organization_id as string | null) ?? null,
        event: String(r.event),
        severity: String(r.severity),
        title: String(r.title),
        body: String(r.body),
        facts: r.facts,
        link: r.link ?? null,
        source: String(r.source),
        subject: r.subject_kind ? { kind: String(r.subject_kind), id: String(r.subject_id) } : null,
        read: Boolean(r.is_read),
        createdAt: String(r.created_at),
      }));
      return { ...page, unread: unread.rows[0]?.n ?? 0 };
    });
  });

  app.post("/notifications/:id/read", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    request.auditState.recorded = true;
    const params: unknown[] = [id];
    const vis = visibility(auth, params);
    await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query(`UPDATE notifications n SET read_by = array_append(read_by, $${params.push(auth.principal.id)}::uuid) WHERE n.id = $1 AND ${vis} AND NOT ($${params.length}::uuid = ANY(n.read_by))`, params),
    );
    return reply.status(204).send();
  });

  app.post("/notifications/read-all", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    request.auditState.recorded = true;
    const params: unknown[] = [];
    const vis = visibility(auth, params);
    const me = params.push(auth.principal.id);
    const res = await s.db.withTenant(auth.tenantId, (tx) => tx.query(`UPDATE notifications n SET read_by = array_append(read_by, $${me}::uuid) WHERE ${vis} AND NOT ($${me}::uuid = ANY(n.read_by))`, params));
    return { marked: res.rowCount ?? 0 };
  });

  // ─── Dead letters ─────────────────────────────────────────────────────────
  app.get("/notifications/dead-letters", async (request) => {
    const auth = requireAuth(request);
    requireManage(request, null);
    const q = parse(z.object({ status: z.enum(["pending", "redriven", "discarded"]).optional(), limit: Limit(500, 100) }), request.query);
    const items = await s.notifications.deadLetters.list(auth.tenantId, { ...(q.status ? { status: q.status } : {}), limit: q.limit });
    return { items, nextCursor: null };
  });

  for (const action of ["redrive", "discard"] as const) {
    app.post(`/notifications/dead-letters/:id/${action}`, { config: { audit: `notification.dead_letter_${action}` } }, async (request) => {
      const auth = requireAuth(request);
      const { id } = parse(IdParam, request.params);
      requireManage(request, null);
      const actor = { kind: auth.principal.kind === "user" ? ("user" as const) : ("service" as const), id: auth.principal.id };
      try {
        if (action === "redrive") return await s.notifications.engine.redrive(auth.tenantId, id, actor);
        await s.notifications.engine.discardDeadLetter(auth.tenantId, id, actor);
        return { discarded: true };
      } catch (err) {
        if (err instanceof AutomationError) throw new HttpError(err.code === "not_found" ? 404 : 409, err.code, err.message);
        throw err;
      }
    });
  }

}
