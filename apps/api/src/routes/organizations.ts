import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { CreateOrganizationInput, PLANS, PlanKey, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest } from "../http/errors.js";
import { IdParam, Limit, decodeCursor, likePattern } from "../http/params.js";
import { toOrganization, type Row } from "../repo/mappers.js";
import { loadAccountPlan } from "../services/entitlements.js";
import { keysetClause, loadOne, orderBy, pageRows, parse } from "./util.js";

const ORG_STATUS = z.enum(["active", "onboarding", "suspended", "offboarded"]);

const CreateOrgBody = CreateOrganizationInput.extend({
  plan: PlanKey.nullable().optional(),
  industry: z.string().trim().max(100).nullable().optional(),
  mrr: z.number().min(0).max(1_000_000_000).optional(),
  status: ORG_STATUS.optional(),
  externalRef: z.string().trim().max(200).nullable().optional(),
}).strict();

const PatchOrgBody = z
  .object({
    name: z.string().trim().min(1).max(200),
    retentionDays: z.number().int().min(1).max(3650),
    parentOrganizationId: Uuid.nullable(),
    plan: PlanKey.nullable(),
    industry: z.string().trim().max(100).nullable(),
    mrr: z.number().min(0).max(1_000_000_000),
    status: ORG_STATUS,
  })
  .partial()
  .strict();

const ListQuery = z.object({
  q: z.string().trim().max(200).optional(),
  parentOrganizationId: Uuid.optional(),
  status: ORG_STATUS.optional(),
  limit: Limit(500, 100),
  cursor: z.string().optional(),
});

const SORT = { expr: "lower(o.name)", dir: "asc" as const, cast: "text" };

/**
 * Organizations (customers / business units) of the caller's tenant. Creating organizations
 * and changing commercial fields (plan, MRR) are tenant-level operations; delegated org
 * admins may edit their own organization's settings.
 */
export async function organizationRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/organizations", async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "org:read", undefined);
    const params: unknown[] = [];
    const where: string[] = [];
    if (orgs) {
      params.push(orgs);
      where.push(`o.id = ANY($${params.length}::uuid[])`);
    }
    if (q.q) {
      params.push(likePattern(q.q));
      where.push(`(o.name ILIKE $${params.length} OR o.slug ILIKE $${params.length})`);
    }
    if (q.parentOrganizationId) {
      params.push(q.parentOrganizationId);
      where.push(`o.parent_organization_id = $${params.length}`);
    }
    if (q.status) {
      params.push(q.status);
      where.push(`o.status = $${params.length}`);
    }
    where.push(keysetClause(SORT, "o.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(`SELECT o.*, ${SORT.expr} AS sort_key FROM organizations o WHERE ${where.join(" AND ")} ORDER BY ${orderBy(SORT, "o.id")} LIMIT $${params.length}`, params),
    );
    return pageRows(rows, q.limit, toOrganization);
  });

  app.post("/organizations", { config: { audit: false } }, async (request, reply) => {
    const auth = requirePermission(request, "org:write", null);
    const body = parse(CreateOrgBody, request.body);
    if (body.plan !== undefined || body.mrr !== undefined) requirePermission(request, "billing:write", null);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      const account = await loadAccountPlan(tx, auth.tenantId);
      const limit = PLANS[account.plan].limits.organizations;
      const count = await tx.query<{ n: number }>("SELECT count(*)::int AS n FROM organizations WHERE status <> 'offboarded'");
      if ((count.rows[0]?.n ?? 0) >= limit) {
        throw new HttpError(402, "quota_exceeded", `The ${PLANS[account.plan].name} plan allows ${limit} organization(s); upgrade to add more`, { limit, plan: account.plan });
      }
      if (body.parentOrganizationId) await loadOne(tx, "organizations", body.parentOrganizationId, "Parent organization");
      const { rows } = await tx.query<Row>(
        `INSERT INTO organizations (tenant_id, parent_organization_id, name, slug, retention_days, plan, industry, mrr, status, external_source, external_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
        [
          auth.tenantId,
          body.parentOrganizationId ?? null,
          body.name,
          body.slug,
          body.retentionDays,
          body.plan ?? null,
          body.industry ?? null,
          body.mrr ?? 0,
          body.status ?? "active",
          body.externalRef ? "api" : null,
          body.externalRef ?? null,
        ],
      );
      const org = toOrganization(rows[0]!);
      await recordAudit(tx, request, { action: "organization.created", organizationId: org.id, targetKind: "organization", targetId: org.id, details: { name: org.name, slug: org.slug, parentOrganizationId: org.parentOrganizationId } });
      return org;
    });
    return reply.status(201).send(created);
  });

  app.get("/organizations/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const org = toOrganization(await loadOne(tx, "organizations", id, "Organization"));
      assertRecordAccess(request, "org:read", org.id, "Organization");
      const { rows } = await tx.query<Row>(
        `SELECT (SELECT count(*)::int FROM assets WHERE organization_id = $1) AS assets,
                (SELECT count(*)::int FROM agents WHERE organization_id = $1) AS agents,
                (SELECT count(*)::int FROM identities WHERE organization_id = $1) AS identities,
                (SELECT count(*)::int FROM incidents WHERE organization_id = $1 AND status IN ('new', 'triage', 'investigating', 'contained')) AS active_incidents,
                (SELECT count(*)::int FROM users WHERE organization_id = $1) AS users,
                (SELECT count(*)::int FROM organizations WHERE parent_organization_id = $1) AS children`,
        [id],
      );
      const st = rows[0] ?? {};
      return { ...org, stats: { assets: st.assets ?? 0, agents: st.agents ?? 0, identities: st.identities ?? 0, activeIncidents: st.active_incidents ?? 0, users: st.users ?? 0, childOrganizations: st.children ?? 0 } };
    });
  });

  app.patch("/organizations/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const patch = parse(PatchOrgBody, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const before = toOrganization(await loadOne(tx, "organizations", id, "Organization"));
      assertRecordAccess(request, "org:read", id, "Organization");
      requirePermission(request, "org:write", id);
      if (patch.plan !== undefined || patch.mrr !== undefined) requirePermission(request, "billing:write", null);
      if (patch.parentOrganizationId !== undefined || patch.status !== undefined) requirePermission(request, "org:write", null);
      if (patch.parentOrganizationId) {
        if (patch.parentOrganizationId === id) throw badRequest("An organization cannot be its own parent");
        await loadOne(tx, "organizations", patch.parentOrganizationId, "Parent organization");
        const cycle = await tx.query(
          `WITH RECURSIVE anc AS (
             SELECT id, parent_organization_id, 1 AS depth FROM organizations WHERE id = $1
             UNION ALL
             SELECT o.id, o.parent_organization_id, anc.depth + 1 FROM organizations o JOIN anc ON o.id = anc.parent_organization_id WHERE anc.depth < 64)
           SELECT 1 FROM anc WHERE id = $2 LIMIT 1`,
          [patch.parentOrganizationId, id],
        );
        if ((cycle.rowCount ?? 0) > 0) throw badRequest("Moving the organization there would create a cycle");
      }
      const sets: string[] = [];
      const params: unknown[] = [id];
      const set = (col: string, v: unknown) => {
        params.push(v);
        sets.push(`${col} = $${params.length}`);
      };
      if (patch.name !== undefined) set("name", patch.name);
      if (patch.retentionDays !== undefined) set("retention_days", patch.retentionDays);
      if (patch.parentOrganizationId !== undefined) set("parent_organization_id", patch.parentOrganizationId);
      if (patch.plan !== undefined) set("plan", patch.plan);
      if (patch.industry !== undefined) set("industry", patch.industry);
      if (patch.mrr !== undefined) set("mrr", patch.mrr);
      if (patch.status !== undefined) set("status", patch.status);
      if (sets.length === 0) return before;
      const { rows } = await tx.query<Row>(`UPDATE organizations SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, params);
      const after = toOrganization(rows[0]!);
      const changed = Object.fromEntries(Object.keys(patch).map((k) => [k, { from: (before as unknown as Record<string, unknown>)[k] ?? null, to: (after as unknown as Record<string, unknown>)[k] ?? null }]));
      await recordAudit(tx, request, { action: "organization.updated", organizationId: id, targetKind: "organization", targetId: id, details: { changed } });
      return after;
    });
  });
}
