import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { CreateOrganizationInput, PlanKey, Uuid, type Playbook } from "@bloody/contracts";
import { DEFAULT_RULE_TEMPLATES, resolveEffectivePlaybooks } from "@bloody/automation";
import { recordAudit } from "../audit/audit.js";
import { actorId, assertRecordAccess, canGrantRole, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest, forbidden, notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { toOrganization, type Row } from "../repo/mappers.js";
import { INTEGRATION_KINDS, toIntegrationView, validateEndpoint, validateIntegrationConfig } from "../services/integrations.js";
import { playbookView, toPlaybook } from "../services/soar.js";
import { loadOne, parse } from "./util.js";

const SOC_ROLES = ["soc_analyst_t1", "soc_analyst_t2", "threat_hunter", "incident_responder", "security_engineer"] as const;
const SocRole = z.enum(SOC_ROLES);

const ProvisionBody = CreateOrganizationInput.extend({
  plan: PlanKey.nullable().optional(),
  industry: z.string().trim().max(100).nullable().optional(),
  mrr: z.number().min(0).max(1_000_000_000).optional(),
  externalRef: z.string().trim().max(200).nullable().optional(),
  admin: z.object({ email: z.string().trim().toLowerCase().email().max(320), displayName: z.string().trim().max(200).optional() }).strict(),
  /** Additional customer-side read-only users (customer portal). */
  viewers: z.array(z.object({ email: z.string().trim().toLowerCase().email().max(320), displayName: z.string().trim().max(200).optional() }).strict()).max(50).default([]),
  /** Analysts assigned to the customer (existing users of the tenant). */
  analysts: z.array(z.object({ userId: Uuid, role: SocRole.default("soc_analyst_t2") }).strict()).max(50).default([]),
  /** Engine integrations to create for the customer (credentials go to the secret store). */
  integrations: z
    .array(
      z
        .object({
          kind: z.string().refine((k) => INTEGRATION_KINDS.includes(k), "unknown integration kind"),
          name: z.string().trim().min(1).max(200),
          endpoint: z.string().trim().url().max(2048).nullable().optional(),
          config: z.record(z.unknown()).default({}),
          credential: z.string().min(1).max(16_384).optional(),
        })
        .strict(),
    )
    .max(20)
    .default([]),
  /** Default customer notifications (in-app channel + rules for new incidents and escalations). */
  defaultNotifications: z.boolean().default(true),
  /** Global MSSP playbooks to switch off for this customer (disabled same-name overrides). */
  disableGlobalPlaybooks: z.array(Uuid).max(100).default([]),
}).strict();

const AssignBody = z.object({ userId: Uuid, role: SocRole.default("soc_analyst_t2"), primary: z.boolean().default(false) }).strict();

const OverrideBody = z
  .object({
    organizationId: Uuid,
    enabled: z.boolean().optional(),
    conditions: z.array(z.unknown()).max(50).optional(),
    steps: z.array(z.unknown()).min(1).max(50).optional(),
    description: z.string().max(4000).nullable().optional(),
  })
  .strict();

/**
 * MSSP administration: customer provisioning (organization + customer admin invite + default
 * notifications + integrations + analyst assignment + playbook opt-outs, in one transaction),
 * analyst assignment per customer, and the global-playbook / per-customer-override matrix.
 */
export async function msspAdminRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.post("/mssp/customers", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(ProvisionBody, request.body);
    requirePermission(request, "org:write", null);
    requirePermission(request, "user:write", null);
    if (body.plan !== undefined || body.mrr !== undefined) requirePermission(request, "billing:write", null);
    if (body.integrations.length > 0) requirePermission(request, "integration:write", null);
    if (body.disableGlobalPlaybooks.length > 0) requirePermission(request, "playbook:write", null);
    for (const a of body.analysts) if (!canGrantRole(auth.principal, a.role, null)) throw forbidden(`You cannot grant the ${a.role} role`);
    const emails = [body.admin.email, ...body.viewers.map((v) => v.email)];
    if (new Set(emails).size !== emails.length) throw badRequest("Duplicate e-mail addresses");
    const integrationConfigs = body.integrations.map((i) => {
      const config = validateIntegrationConfig(i.kind, i.config);
      validateEndpoint(i.kind, i.endpoint ?? null, config);
      return { ...i, config };
    });

    const result = await s.db.withTenant(auth.tenantId, async (tx) => {
      await s.quota.assertCapacity(tx, auth.tenantId, "organizations", 1);
      if (body.parentOrganizationId) await loadOne(tx, "organizations", body.parentOrganizationId, "Parent organization");
      const existing = await tx.query("SELECT 1 FROM users WHERE email = ANY($1::text[])", [emails]);
      if ((existing.rowCount ?? 0) > 0) throw new HttpError(409, "user_exists", "A user with one of these e-mail addresses already exists in this tenant");
      const added = 1 + body.viewers.length;
      await s.quota.assertCapacity(tx, auth.tenantId, "users", added);
      const orgRes = await tx.query<Row>(
        `INSERT INTO organizations (tenant_id, parent_organization_id, name, slug, retention_days, plan, industry, mrr, status, external_source, external_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'onboarding', $9, $10) RETURNING *`,
        [auth.tenantId, body.parentOrganizationId ?? null, body.name, body.slug, body.retentionDays, body.plan ?? null, body.industry ?? null, body.mrr ?? 0, body.externalRef ? "api" : null, body.externalRef ?? null],
      );
      const org = toOrganization(orgRes.rows[0]!);
      const grantor = auth.principal.kind === "user" ? auth.principal.id : null;

      // Customer admin (invited until a password is set or they sign in through SSO) + viewers.
      const invite = async (email: string, displayName: string | undefined, role: "org_admin" | "customer_viewer") => {
        const { rows } = await tx.query<{ id: string }>("INSERT INTO users (tenant_id, organization_id, email, display_name, status) VALUES ($1, $2, $3, $4, 'invited') RETURNING id", [auth.tenantId, org.id, email, displayName ?? null]);
        await tx.query("INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id, created_by) VALUES ($1, 'user', $2, $3, $4, $5)", [auth.tenantId, rows[0]!.id, role, org.id, grantor]);
        return { id: rows[0]!.id, email, role, status: "invited" as const };
      };
      const admin = await invite(body.admin.email, body.admin.displayName, "org_admin");
      const viewers = [];
      for (const v of body.viewers) viewers.push(await invite(v.email, v.displayName, "customer_viewer"));

      // Analyst assignment: org-scoped SOC bindings for existing tenant users.
      const analysts = [];
      for (const a of body.analysts) {
        const { rows } = await tx.query<{ id: string; status: string }>("SELECT id, status FROM users WHERE id = $1", [a.userId]);
        if (!rows[0] || rows[0].status === "disabled") throw badRequest(`Analyst ${a.userId} is not an active user of this tenant`);
        await tx.query(
          `INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id, created_by) VALUES ($1, 'user', $2, $3, $4, $5)
           ON CONFLICT (tenant_id, principal_kind, principal_id, role, org_key(organization_id)) DO NOTHING`,
          [auth.tenantId, a.userId, a.role, org.id, grantor],
        );
        analysts.push({ userId: a.userId, role: a.role });
      }
      await tx.query("UPDATE organizations SET settings = jsonb_set(settings, '{assignedAnalysts}', $2::jsonb) WHERE id = $1", [org.id, JSON.stringify(analysts.map((a, i) => ({ ...a, primary: i === 0 })))]);

      // Default notifications: an in-app channel for the customer's admins and viewers + SOC, and
      // rules for new high/critical incidents and escalations awaiting the customer.
      const channels = [];
      const automations = [];
      if (body.defaultNotifications) {
        const ch = await tx.query<{ id: string }>(
          "INSERT INTO notification_channels (tenant_id, organization_id, name, kind, config, enabled) VALUES ($1, $2, $3, 'in_app', $4::jsonb, true) RETURNING id",
          [auth.tenantId, org.id, `${body.name} portal`, JSON.stringify({ userIds: [], roles: ["org_admin", "customer_viewer", "ciso"] })],
        );
        channels.push({ id: ch.rows[0]!.id, kind: "in_app", name: `${body.name} portal` });
        for (const [event, conditions] of [
          ["incident.created", [{ field: "severity", op: "in", value: ["high", "critical"] }]],
          ["escalation.created", []],
        ] as const) {
          const t = DEFAULT_RULE_TEMPLATES[event];
          const r = await tx.query<{ id: string }>(
            `INSERT INTO automation_rules (tenant_id, organization_id, name, event, conditions, channel_ids, template, throttle_minutes, enabled)
             VALUES ($1, $2, $3, $4, $5::jsonb, $6::uuid[], $7::jsonb, 15, true) RETURNING id`,
            [auth.tenantId, org.id, `${t.name} (${body.name})`, event, JSON.stringify(conditions), [ch.rows[0]!.id], JSON.stringify({ subject: t.subject, body: t.body })],
          );
          automations.push({ id: r.rows[0]!.id, event });
        }
      }

      // Integrations (credentials sealed in the secret store).
      const integrations = [];
      for (const i of integrationConfigs) {
        const ref = i.credential ? (await s.secretStore.put(tx, auth.tenantId, { value: i.credential, name: `${i.kind} integration ${i.name}`, purpose: `integration.${i.kind}`, organizationId: org.id, createdBy: actorId(auth) })).ref : null;
        const { rows } = await tx.query<Row>(
          "INSERT INTO integrations (tenant_id, organization_id, kind, name, endpoint, config, credential_ref, enabled, status) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, true, 'pending') RETURNING *",
          [auth.tenantId, org.id, i.kind, i.name, i.endpoint ?? null, JSON.stringify(i.config), ref],
        );
        integrations.push(toIntegrationView(rows[0]!));
      }

      // Global playbooks apply automatically; opted-out ones get a disabled same-name override.
      const disabled = [];
      for (const pid of body.disableGlobalPlaybooks) {
        const { rows } = await tx.query<Row>("SELECT * FROM playbooks WHERE id = $1 AND organization_id IS NULL", [pid]);
        if (!rows[0]) throw badRequest(`Global playbook ${pid} not found`);
        const g = toPlaybook(rows[0]);
        const created = await s.playbooks.create(tx, auth.tenantId, { organizationId: org.id, name: g.name, description: g.description, enabled: false, trigger: g.trigger, conditions: g.conditions, steps: g.steps }, actorId(auth), "disabled at customer provisioning");
        disabled.push({ globalPlaybookId: pid, overrideId: created.playbook.id, name: g.name });
      }
      const all = (await tx.query<Row>("SELECT * FROM playbooks WHERE organization_id IS NULL OR organization_id = $1", [org.id])).rows.map(toPlaybook);
      const effective = resolveEffectivePlaybooks(all, auth.tenantId, org.id).map((e) => ({ id: e.playbook.id, name: e.playbook.name, enabled: e.playbook.enabled, source: e.source }));

      await tx.query("UPDATE organizations SET status = 'active' WHERE id = $1", [org.id]);
      await recordAudit(tx, request, {
        action: "mssp.customer_provisioned",
        organizationId: org.id,
        targetKind: "organization",
        targetId: org.id,
        details: { name: org.name, slug: org.slug, admin: body.admin.email, viewers: body.viewers.length, analysts: analysts.length, integrations: integrations.map((i) => i.kind), channels: channels.length, playbooksDisabled: disabled.length },
      });
      return { organization: { ...org, status: "active" }, admin, viewers, analysts, channels, automations, integrations, playbooks: { effective, disabled } };
    });
    return reply.status(201).send(result);
  });

  // ─── Analyst assignment ──────────────────────────────────────────────────
  app.get("/mssp/customers/:id/analysts", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    assertRecordAccess(request, "user:read", id, "Organization");
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const org = await loadOne(tx, "organizations", id, "Organization");
      const assigned = ((org.settings as { assignedAnalysts?: Array<{ userId: string; role: string; primary?: boolean }> } | null)?.assignedAnalysts ?? []).filter((a) => typeof a.userId === "string");
      const { rows } = await tx.query<Row>(
        `SELECT u.id, u.email, u.display_name, u.status, rb.role, rb.organization_id FROM role_bindings rb JOIN users u ON u.id = rb.principal_id
         WHERE rb.principal_kind = 'user' AND rb.role = ANY($2::text[]) AND (rb.organization_id = $1 OR rb.organization_id IS NULL) ORDER BY lower(u.email)`,
        [id, [...SOC_ROLES]],
      );
      const byUser = new Map<string, { userId: string; email: string; displayName: string | null; status: string; roles: Array<{ role: string; scope: "organization" | "tenant" }>; assigned: boolean; primary: boolean }>();
      for (const r of rows) {
        const key = String(r.id);
        const a = assigned.find((x) => x.userId === key);
        const cur = byUser.get(key) ?? { userId: key, email: String(r.email), displayName: (r.display_name as string | null) ?? null, status: String(r.status), roles: [], assigned: Boolean(a), primary: Boolean(a?.primary) };
        cur.roles.push({ role: String(r.role), scope: r.organization_id ? "organization" : "tenant" });
        byUser.set(key, cur);
      }
      return { organizationId: id, items: [...byUser.values()].sort((x, y) => Number(y.assigned) - Number(x.assigned) || x.email.localeCompare(y.email)) };
    });
  });

  app.post("/mssp/customers/:id/analysts", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(AssignBody, request.body);
    requirePermission(request, "user:write", id);
    if (!canGrantRole(auth.principal, body.role, id)) throw forbidden(`You cannot grant the ${body.role} role`);
    const out = await s.db.withTenant(auth.tenantId, async (tx) => {
      const org = await loadOne(tx, "organizations", id, "Organization");
      const { rows } = await tx.query<{ status: string }>("SELECT status FROM users WHERE id = $1", [body.userId]);
      if (!rows[0] || rows[0].status === "disabled") throw badRequest("The analyst must be an active user of this tenant");
      await tx.query(
        `INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id, created_by) VALUES ($1, 'user', $2, $3, $4, $5)
         ON CONFLICT (tenant_id, principal_kind, principal_id, role, org_key(organization_id)) DO NOTHING`,
        [auth.tenantId, body.userId, body.role, id, auth.principal.kind === "user" ? auth.principal.id : null],
      );
      const current = ((org.settings as { assignedAnalysts?: Array<{ userId: string; role: string; primary?: boolean }> } | null)?.assignedAnalysts ?? []).filter((a) => a.userId !== body.userId);
      const next = [...current.map((a) => (body.primary ? { ...a, primary: false } : a)), { userId: body.userId, role: body.role, primary: body.primary || current.length === 0 }];
      await tx.query("UPDATE organizations SET settings = jsonb_set(settings, '{assignedAnalysts}', $2::jsonb) WHERE id = $1", [id, JSON.stringify(next)]);
      await recordAudit(tx, request, { action: "mssp.analyst_assigned", organizationId: id, targetKind: "user", targetId: body.userId, details: { role: body.role, primary: body.primary } });
      return { organizationId: id, analysts: next };
    });
    return reply.status(201).send(out);
  });

  app.delete("/mssp/customers/:id/analysts/:userId", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id, userId } = parse(z.object({ id: Uuid, userId: Uuid }), request.params);
    requirePermission(request, "user:write", id);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const org = await loadOne(tx, "organizations", id, "Organization");
      const removed = await tx.query("DELETE FROM role_bindings WHERE principal_kind = 'user' AND principal_id = $1 AND organization_id = $2 AND role = ANY($3::text[])", [userId, id, [...SOC_ROLES]]);
      const current = ((org.settings as { assignedAnalysts?: Array<{ userId: string }> } | null)?.assignedAnalysts ?? []).filter((a) => a.userId !== userId);
      await tx.query("UPDATE organizations SET settings = jsonb_set(settings, '{assignedAnalysts}', $2::jsonb) WHERE id = $1", [id, JSON.stringify(current)]);
      await recordAudit(tx, request, { action: "mssp.analyst_unassigned", organizationId: id, targetKind: "user", targetId: userId, details: { bindingsRemoved: removed.rowCount ?? 0 } });
    });
    return reply.status(204).send();
  });

  // ─── Global playbooks & per-customer overrides ───────────────────────────
  app.get("/mssp/playbooks", { config: { module: "soar" } }, async (request) => {
    const auth = requireAuth(request);
    const orgs = resolveOrgFilter(request, "playbook:read", undefined);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const orgRows = (orgs ? await tx.query<Row>("SELECT id, name FROM organizations WHERE id = ANY($1::uuid[]) ORDER BY lower(name)", [orgs]) : await tx.query<Row>("SELECT id, name FROM organizations ORDER BY lower(name)")).rows;
      const pbRows = (await tx.query<Row>("SELECT * FROM playbooks ORDER BY name")).rows;
      const all = pbRows.map(toPlaybook);
      const globals = pbRows.filter((r) => r.organization_id === null);
      const items = globals.map((g) => {
        const key = String(g.name).trim().toLowerCase();
        return {
          ...playbookView(g),
          organizations: orgRows.map((o) => {
            const eff = resolveEffectivePlaybooks(all, auth.tenantId, String(o.id)).find((e) => e.playbook.name.trim().toLowerCase() === key);
            return {
              organizationId: String(o.id),
              organizationName: String(o.name),
              source: eff?.source ?? "global",
              playbookId: eff?.playbook.id ?? String(g.id),
              enabled: eff?.playbook.enabled ?? Boolean(g.enabled),
              version: eff?.playbook.version ?? Number(g.version),
            };
          }),
        };
      });
      return { items, organizations: orgRows.map((o) => ({ id: String(o.id), name: String(o.name) })) };
    });
  });

  /** Create (or update) a customer override of a global playbook by copying it with changes. */
  app.post("/mssp/playbooks/:id/overrides", { config: { module: "soar", audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(OverrideBody, request.body);
    requirePermission(request, "playbook:write", body.organizationId);
    const res = await s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM playbooks WHERE id = $1", [id]);
      if (!rows[0]) throw notFound("Playbook");
      if (rows[0].organization_id !== null) throw badRequest("Only global playbooks can be overridden");
      await loadOne(tx, "organizations", body.organizationId, "Organization");
      const g = toPlaybook(rows[0]);
      const draft = {
        organizationId: body.organizationId,
        name: g.name,
        description: body.description !== undefined ? body.description : g.description,
        enabled: body.enabled ?? g.enabled,
        trigger: g.trigger,
        conditions: (body.conditions as Playbook["conditions"] | undefined) ?? g.conditions,
        steps: (body.steps as Playbook["steps"] | undefined) ?? g.steps,
      };
      const existing = (await tx.query<Row>("SELECT id FROM playbooks WHERE organization_id = $1 AND lower(name) = lower($2)", [body.organizationId, g.name])).rows[0];
      if (existing) {
        const out = await s.playbooks.update(tx, String(existing.id), draft, actorId(auth), { comment: "override updated" });
        await recordAudit(tx, request, { action: "playbook.override_updated", organizationId: body.organizationId, targetKind: "playbook", targetId: String(existing.id), details: { globalPlaybookId: id, changed: out.changed } });
        return { created: false, playbook: out.playbook, warnings: out.warnings };
      }
      const out = await s.playbooks.create(tx, auth.tenantId, draft, actorId(auth), `override of global playbook ${id}`);
      await recordAudit(tx, request, { action: "playbook.override_created", organizationId: body.organizationId, targetKind: "playbook", targetId: out.playbook.id, details: { globalPlaybookId: id, enabled: draft.enabled } });
      return { created: true, playbook: out.playbook, warnings: out.warnings };
    });
    return reply.status(res.created ? 201 : 200).send({ ...res.playbook, overridesGlobal: id, warnings: res.warnings });
  });

}
