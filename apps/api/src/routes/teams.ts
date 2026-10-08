import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { RoleKey, Uuid, type RoleBinding } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { canGrantRole, orgScopeFor, requireAuth, requirePermission } from "../auth/rbac.js";
import type { AuthContext } from "../auth/types.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { forbidden, notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { parse } from "./util.js";

const CreateTeamBody = z
  .object({
    name: z.string().trim().min(1).max(200),
    organizationId: Uuid.nullable().optional(),
    description: z.string().trim().max(2000).nullable().optional(),
  })
  .strict();
const PatchTeamBody = z.object({ name: z.string().trim().min(1).max(200), description: z.string().trim().max(2000).nullable() }).partial().strict();
const MemberBody = z.object({ userId: Uuid, memberRole: z.enum(["member", "lead"]).default("member") }).strict();
const Binding = z.object({ role: RoleKey, organizationId: Uuid.nullable() }).strict();
const MemberParams = z.object({ id: Uuid, userId: Uuid });

export interface TeamView {
  id: string;
  tenantId: string;
  organizationId: string | null;
  name: string;
  description: string | null;
  createdAt: string;
  members: Array<{ userId: string; email: string; displayName: string | null; memberRole: string }>;
  bindings: RoleBinding[];
}

async function teamViews(tx: Queryable, teams: Row[]): Promise<TeamView[]> {
  const ids = teams.map((t) => String(t.id));
  if (ids.length === 0) return [];
  const members = await tx.query<{ team_id: string; user_id: string; email: string; display_name: string | null; member_role: string }>(
    "SELECT m.team_id, m.user_id, u.email, u.display_name, m.member_role FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = ANY($1::uuid[]) ORDER BY u.email",
    [ids],
  );
  const bindings = await tx.query<{ principal_id: string; role: string; organization_id: string | null }>(
    "SELECT principal_id, role, organization_id FROM role_bindings WHERE principal_kind = 'team' AND principal_id = ANY($1::uuid[]) ORDER BY role",
    [ids],
  );
  return teams.map((t) => ({
    id: String(t.id),
    tenantId: String(t.tenant_id),
    organizationId: (t.organization_id as string | null) ?? null,
    name: String(t.name),
    description: (t.description as string | null) ?? null,
    createdAt: String(t.created_at),
    members: members.rows.filter((m) => m.team_id === t.id).map((m) => ({ userId: m.user_id, email: m.email, displayName: m.display_name, memberRole: m.member_role })),
    bindings: bindings.rows
      .filter((b) => b.principal_id === t.id)
      .flatMap((b) => {
        const role = RoleKey.safeParse(b.role);
        return role.success ? [{ role: role.data, organizationId: b.organization_id }] : [];
      }),
  }));
}

function assertCanGrant(auth: AuthContext, binding: RoleBinding): void {
  if (!canGrantRole(auth.principal, binding.role, binding.organizationId)) {
    throw forbidden(`You cannot grant role ${binding.role}${binding.organizationId ? " for this organization" : " tenant-wide"}`, "role_escalation");
  }
}

/**
 * Teams group users (e.g. a customer-specific analyst pod). Team role bindings apply to every
 * member, so adding a member is treated as granting the team's roles: the caller must be able
 * to grant each of them.
 */
export async function teamRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  async function loadTeam(tx: Queryable, auth: AuthContext, id: string): Promise<Row> {
    const { rows } = await tx.query<Row>("SELECT * FROM teams WHERE id = $1", [id]);
    const team = rows[0];
    if (!team) throw notFound("Team");
    const scope = orgScopeFor(auth, "user:read");
    const org = (team.organization_id as string | null) ?? null;
    const visible = scope === "all" || (org !== null && scope.includes(org));
    if (!visible) throw notFound("Team");
    return team;
  }

  async function teamBindings(tx: Queryable, teamId: string): Promise<RoleBinding[]> {
    const { rows } = await tx.query<{ role: string; organization_id: string | null }>("SELECT role, organization_id FROM role_bindings WHERE principal_kind = 'team' AND principal_id = $1", [teamId]);
    return rows.flatMap((r) => {
      const role = RoleKey.safeParse(r.role);
      return role.success ? [{ role: role.data, organizationId: r.organization_id }] : [];
    });
  }

  app.get("/teams", async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional() }), request.query);
    const scope = orgScopeFor(auth, "user:read");
    if (scope !== "all" && scope.length === 0) throw forbidden("Missing permission user:read");
    const params: unknown[] = [];
    const where: string[] = [];
    if (scope !== "all") {
      params.push(scope);
      where.push(`organization_id = ANY($${params.length}::uuid[])`);
    }
    if (q.organizationId) {
      params.push(q.organizationId);
      where.push(`organization_id = $${params.length}`);
    }
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(`SELECT * FROM teams ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY lower(name), id LIMIT 500`, params);
      return { items: await teamViews(tx, rows), nextCursor: null };
    });
  });

  app.post("/teams", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateTeamBody, request.body);
    requirePermission(request, "team:write", body.organizationId ?? null);
    const team = await s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("INSERT INTO teams (tenant_id, organization_id, name, description) VALUES ($1, $2, $3, $4) RETURNING *", [
        auth.tenantId,
        body.organizationId ?? null,
        body.name,
        body.description ?? null,
      ]);
      const view = (await teamViews(tx, rows))[0]!;
      await recordAudit(tx, request, { action: "team.created", organizationId: view.organizationId, targetKind: "team", targetId: view.id, details: { name: view.name } });
      return view;
    });
    return reply.status(201).send(team);
  });

  app.patch("/teams/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const patch = parse(PatchTeamBody, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const team = await loadTeam(tx, auth, id);
      requirePermission(request, "team:write", (team.organization_id as string | null) ?? null);
      const { rows } = await tx.query<Row>("UPDATE teams SET name = coalesce($2, name), description = CASE WHEN $4 THEN $3 ELSE description END WHERE id = $1 RETURNING *", [
        id,
        patch.name ?? null,
        patch.description ?? null,
        patch.description !== undefined,
      ]);
      await recordAudit(tx, request, { action: "team.updated", organizationId: (team.organization_id as string | null) ?? null, targetKind: "team", targetId: id, details: { changed: Object.keys(patch) } });
      return (await teamViews(tx, rows))[0];
    });
  });

  app.delete("/teams/:id", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const team = await loadTeam(tx, auth, id);
      requirePermission(request, "team:write", (team.organization_id as string | null) ?? null);
      for (const b of await teamBindings(tx, id)) assertCanGrant(auth, b);
      await tx.query("DELETE FROM role_bindings WHERE principal_kind = 'team' AND principal_id = $1", [id]);
      await tx.query("DELETE FROM teams WHERE id = $1", [id]);
      await recordAudit(tx, request, { action: "team.deleted", organizationId: (team.organization_id as string | null) ?? null, targetKind: "team", targetId: id, details: { name: team.name } });
    });
    return reply.status(204).send();
  });

  app.post("/teams/:id/members", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(MemberBody, request.body);
    const view = await s.db.withTenant(auth.tenantId, async (tx) => {
      const team = await loadTeam(tx, auth, id);
      requirePermission(request, "team:write", (team.organization_id as string | null) ?? null);
      for (const b of await teamBindings(tx, id)) assertCanGrant(auth, b);
      const user = await tx.query<Row>("SELECT id, status FROM users WHERE id = $1", [body.userId]);
      if (!user.rows[0]) throw notFound("User");
      await tx.query(
        `INSERT INTO team_members (team_id, user_id, tenant_id, organization_id, member_role) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (team_id, user_id) DO UPDATE SET member_role = EXCLUDED.member_role`,
        [id, body.userId, auth.tenantId, team.organization_id ?? null, body.memberRole],
      );
      await recordAudit(tx, request, { action: "team.member_added", organizationId: (team.organization_id as string | null) ?? null, targetKind: "team", targetId: id, details: { userId: body.userId, memberRole: body.memberRole } });
      const { rows } = await tx.query<Row>("SELECT * FROM teams WHERE id = $1", [id]);
      return (await teamViews(tx, rows))[0];
    });
    return reply.status(201).send(view);
  });

  app.delete("/teams/:id/members/:userId", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id, userId } = parse(MemberParams, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const team = await loadTeam(tx, auth, id);
      requirePermission(request, "team:write", (team.organization_id as string | null) ?? null);
      const res = await tx.query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2", [id, userId]);
      if ((res.rowCount ?? 0) === 0) throw notFound("Team member");
      await recordAudit(tx, request, { action: "team.member_removed", organizationId: (team.organization_id as string | null) ?? null, targetKind: "team", targetId: id, details: { userId } });
    });
    return reply.status(204).send();
  });

  app.post("/teams/:id/roles", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const binding = parse(Binding, request.body);
    const view = await s.db.withTenant(auth.tenantId, async (tx) => {
      const team = await loadTeam(tx, auth, id);
      const teamOrg = (team.organization_id as string | null) ?? null;
      requirePermission(request, "team:write", teamOrg);
      requirePermission(request, "user:write", binding.organizationId);
      if (teamOrg !== null && binding.organizationId !== teamOrg) throw forbidden("An organization team can only hold roles for its own organization");
      assertCanGrant(auth, binding);
      await tx.query(
        `INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id, created_by) VALUES ($1, 'team', $2, $3, $4, $5)
         ON CONFLICT (tenant_id, principal_kind, principal_id, role, org_key(organization_id)) DO NOTHING`,
        [auth.tenantId, id, binding.role, binding.organizationId, auth.principal.kind === "user" ? auth.principal.id : null],
      );
      await recordAudit(tx, request, { action: "team.role_granted", organizationId: binding.organizationId, targetKind: "team", targetId: id, details: binding });
      const { rows } = await tx.query<Row>("SELECT * FROM teams WHERE id = $1", [id]);
      return (await teamViews(tx, rows))[0];
    });
    return reply.status(201).send(view);
  });

  app.delete("/teams/:id/roles", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const q = parse(z.object({ role: RoleKey, organizationId: Uuid.optional() }), request.query);
    const binding: RoleBinding = { role: q.role, organizationId: q.organizationId ?? null };
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const team = await loadTeam(tx, auth, id);
      requirePermission(request, "team:write", (team.organization_id as string | null) ?? null);
      assertCanGrant(auth, binding);
      const res = await tx.query("DELETE FROM role_bindings WHERE principal_kind = 'team' AND principal_id = $1 AND role = $2 AND organization_id IS NOT DISTINCT FROM $3", [id, binding.role, binding.organizationId]);
      if ((res.rowCount ?? 0) === 0) throw notFound("Role binding");
      await recordAudit(tx, request, { action: "team.role_revoked", organizationId: binding.organizationId, targetKind: "team", targetId: id, details: binding });
    });
    return reply.status(204).send();
  });
}
