import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { RoleKey, Uuid, type RoleBinding } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { canGrantRole, orgScopeFor, requireAuth, requirePermission } from "../auth/rbac.js";
import type { AuthContext } from "../auth/types.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { HttpError, badRequest, forbidden, notFound } from "../http/errors.js";
import { IdParam, Limit, decodeCursor, likePattern } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { hashPassword, passwordPolicyErrors, PASSWORD_MAX_LENGTH } from "../security/passwords.js";
import { keysetClause, orderBy, pageRows, parse } from "./util.js";

const Binding = z.object({ role: RoleKey, organizationId: Uuid.nullable() });
const Email = z
  .string()
  .trim()
  .toLowerCase()
  .max(320)
  .regex(/^[^@\s]+@[^@\s]+\.[^@\s]+$/, "must be an e-mail address");

const CreateUserBody = z
  .object({
    email: Email,
    displayName: z.string().trim().min(1).max(200).nullable().optional(),
    title: z.string().trim().max(200).nullable().optional(),
    organizationId: Uuid.nullable().optional(),
    password: z.string().min(1).max(PASSWORD_MAX_LENGTH).optional(),
    roles: z.array(Binding).max(25).default([]),
  })
  .strict();

const PatchUserBody = z
  .object({
    displayName: z.string().trim().min(1).max(200).nullable(),
    title: z.string().trim().max(200).nullable(),
    status: z.enum(["active", "disabled"]),
  })
  .partial()
  .strict();

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  q: z.string().trim().max(200).optional(),
  status: z.enum(["active", "invited", "disabled"]).optional(),
  limit: Limit(500, 100),
  cursor: z.string().optional(),
});

const SORT = { expr: "u.email", dir: "asc" as const, cast: "text" };

export interface UserView {
  id: string;
  tenantId: string;
  organizationId: string | null;
  email: string;
  displayName: string | null;
  title: string | null;
  status: string;
  disabled: boolean;
  mfaEnabled: boolean;
  lastLoginAt: string | null;
  locked: boolean;
  createdAt: string;
  updatedAt: string;
  bindings: RoleBinding[];
  teams: Array<{ id: string; name: string; memberRole: string }>;
}

function toUserView(r: Row, bindings: RoleBinding[], teams: UserView["teams"], now: number): UserView {
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: (r.organization_id as string | null) ?? null,
    email: String(r.email),
    displayName: (r.display_name as string | null) ?? null,
    title: (r.title as string | null) ?? null,
    status: String(r.status),
    disabled: r.status === "disabled",
    mfaEnabled: Boolean(r.mfa_enabled),
    lastLoginAt: (r.last_login_at as string | null) ?? null,
    locked: typeof r.locked_until === "string" && Date.parse(r.locked_until) > now,
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
    bindings,
    teams,
  };
}

async function bindingsAndTeams(tx: Queryable, userIds: string[]): Promise<{ bindings: Map<string, RoleBinding[]>; teams: Map<string, UserView["teams"]> }> {
  const bindings = new Map<string, RoleBinding[]>();
  const teams = new Map<string, UserView["teams"]>();
  if (userIds.length === 0) return { bindings, teams };
  const b = await tx.query<{ principal_id: string; role: string; organization_id: string | null }>(
    "SELECT principal_id, role, organization_id FROM role_bindings WHERE principal_kind = 'user' AND principal_id = ANY($1::uuid[]) ORDER BY role, organization_id NULLS FIRST",
    [userIds],
  );
  for (const r of b.rows) {
    const role = RoleKey.safeParse(r.role);
    if (!role.success) continue;
    const list = bindings.get(r.principal_id) ?? [];
    list.push({ role: role.data, organizationId: r.organization_id });
    bindings.set(r.principal_id, list);
  }
  const t = await tx.query<{ user_id: string; id: string; name: string; member_role: string }>(
    "SELECT m.user_id, t.id, t.name, m.member_role FROM team_members m JOIN teams t ON t.id = m.team_id WHERE m.user_id = ANY($1::uuid[]) ORDER BY lower(t.name)",
    [userIds],
  );
  for (const r of t.rows) {
    const list = teams.get(r.user_id) ?? [];
    list.push({ id: r.id, name: r.name, memberRole: r.member_role });
    teams.set(r.user_id, list);
  }
  return { bindings, teams };
}

/** SQL predicate: users visible to an org-scoped administrator (home org or a binding in scope). */
function userScopeClause(scope: "all" | string[], params: unknown[], alias = "u"): string {
  if (scope === "all") return "TRUE";
  params.push(scope);
  const p = `$${params.length}::uuid[]`;
  return `(${alias}.organization_id = ANY(${p}) OR EXISTS (SELECT 1 FROM role_bindings rb WHERE rb.principal_kind = 'user' AND rb.principal_id = ${alias}.id AND rb.organization_id = ANY(${p})))`;
}

/**
 * Scopes an administrator must hold `user:write` in to manage a user: tenant level for staff
 * (no home org or any tenant-wide binding), otherwise every organization the user belongs to.
 */
export function requiredAdminScopes(user: { organization_id: string | null }, bindings: RoleBinding[]): Array<string | null> {
  if (user.organization_id === null || bindings.some((b) => b.organizationId === null)) return [null];
  return [...new Set([user.organization_id, ...bindings.map((b) => b.organizationId as string)])];
}

export async function loadManagedUser(tx: Queryable, auth: AuthContext, userId: string): Promise<{ row: Row; bindings: RoleBinding[] }> {
  const params: unknown[] = [userId];
  const scope = orgScopeFor(auth, "user:read");
  if (scope !== "all" && scope.length === 0) throw forbidden("Missing permission user:read");
  const { rows } = await tx.query<Row>(`SELECT u.* FROM users u WHERE u.id = $1 AND ${userScopeClause(scope, params)}`, params);
  const row = rows[0];
  if (!row) throw notFound("User");
  const { bindings } = await bindingsAndTeams(tx, [userId]);
  return { row, bindings: bindings.get(userId) ?? [] };
}

function assertCanAdminister(request: FastifyRequest, user: Row, bindings: RoleBinding[]): void {
  for (const scope of requiredAdminScopes({ organization_id: (user.organization_id as string | null) ?? null }, bindings)) requirePermission(request, "user:write", scope);
}

function assertCanGrant(request: FastifyRequest, auth: AuthContext, binding: RoleBinding): void {
  requirePermission(request, "user:write", binding.organizationId);
  if (!canGrantRole(auth.principal, binding.role, binding.organizationId)) {
    throw forbidden(`You cannot grant role ${binding.role}${binding.organizationId ? " for this organization" : " tenant-wide"} (it carries permissions you do not hold)`, "role_escalation");
  }
}

/** Users, their role bindings and team memberships (tenant-scoped, delegated by organization). */
export async function userRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/users", async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const scope = orgScopeFor(auth, "user:read");
    if (scope !== "all" && scope.length === 0) throw forbidden("Missing permission user:read");
    if (q.organizationId && scope !== "all" && !scope.includes(q.organizationId)) throw forbidden("Missing permission user:read for this organization");
    const params: unknown[] = [];
    const where = [userScopeClause(q.organizationId ? [q.organizationId] : scope, params)];
    if (q.q) {
      params.push(likePattern(q.q));
      where.push(`(u.email ILIKE $${params.length} OR u.display_name ILIKE $${params.length})`);
    }
    if (q.status) {
      params.push(q.status);
      where.push(`u.status = $${params.length}`);
    }
    where.push(keysetClause(SORT, "u.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(`SELECT u.*, ${SORT.expr} AS sort_key FROM users u WHERE ${where.join(" AND ")} ORDER BY ${orderBy(SORT, "u.id")} LIMIT $${params.length}`, params);
      const ids = rows.slice(0, q.limit).map((r) => String(r.id));
      const extra = await bindingsAndTeams(tx, ids);
      const now = s.now();
      return pageRows(rows, q.limit, (r) => toUserView(r, extra.bindings.get(String(r.id)) ?? [], extra.teams.get(String(r.id)) ?? [], now));
    });
  });

  app.get("/users/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { row } = await loadManagedUser(tx, auth, id);
      const extra = await bindingsAndTeams(tx, [id]);
      return toUserView(row, extra.bindings.get(id) ?? [], extra.teams.get(id) ?? [], s.now());
    });
  });

  app.post("/users", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateUserBody, request.body);
    for (const b of body.roles) assertCanGrant(request, auth, b);
    requirePermission(request, "user:write", body.organizationId ?? null);
    if (body.password) {
      const errors = passwordPolicyErrors(body.password, body.email);
      if (errors.length > 0) throw new HttpError(400, "weak_password", "The password does not meet the password policy", errors);
    }
    const hash = body.password ? await hashPassword(body.password) : null;
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        "INSERT INTO users (tenant_id, organization_id, email, display_name, title, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
        [auth.tenantId, body.organizationId ?? null, body.email, body.displayName ?? null, body.title ?? null, hash ? "active" : "invited"],
      );
      const user = rows[0]!;
      if (hash) await tx.query("INSERT INTO user_credentials (user_id, tenant_id, organization_id, password_hash) VALUES ($1, $2, $3, $4)", [user.id, auth.tenantId, body.organizationId ?? null, hash]);
      for (const b of body.roles) {
        await tx.query(
          `INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id, created_by) VALUES ($1, 'user', $2, $3, $4, $5)
           ON CONFLICT (tenant_id, principal_kind, principal_id, role, org_key(organization_id)) DO NOTHING`,
          [auth.tenantId, user.id, b.role, b.organizationId, auth.principal.kind === "user" ? auth.principal.id : null],
        );
      }
      await recordAudit(tx, request, { action: "user.created", organizationId: body.organizationId ?? null, targetKind: "user", targetId: String(user.id), details: { email: body.email, roles: body.roles, status: user.status } });
      const extra = await bindingsAndTeams(tx, [String(user.id)]);
      return toUserView(user, extra.bindings.get(String(user.id)) ?? [], [], s.now());
    });
    return reply.status(201).send(created);
  });

  app.patch("/users/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const patch = parse(PatchUserBody, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { row, bindings } = await loadManagedUser(tx, auth, id);
      if (id === auth.principal.id && patch.status === "disabled") throw badRequest("You cannot disable your own account");
      if (id !== auth.principal.id || patch.status !== undefined) assertCanAdminister(request, row, bindings);
      const sets: string[] = [];
      const params: unknown[] = [id];
      const set = (col: string, v: unknown) => {
        params.push(v);
        sets.push(`${col} = $${params.length}`);
      };
      if (patch.displayName !== undefined) set("display_name", patch.displayName);
      if (patch.title !== undefined) set("title", patch.title);
      if (patch.status !== undefined) {
        if (patch.status === "active" && row.status === "invited") throw badRequest("Invited users become active when a password is set");
        set("status", patch.status);
      }
      let updated = row;
      if (sets.length > 0) {
        const res = await tx.query<Row>(`UPDATE users SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, params);
        updated = res.rows[0]!;
      }
      if (patch.status === "disabled") await tx.query("UPDATE sessions SET revoked_at = now(), revoked_reason = 'user_disabled' WHERE user_id = $1 AND revoked_at IS NULL", [id]);
      await recordAudit(tx, request, { action: patch.status === "disabled" ? "user.disabled" : "user.updated", organizationId: (row.organization_id as string | null) ?? null, targetKind: "user", targetId: id, details: { changed: Object.keys(patch) } });
      const extra = await bindingsAndTeams(tx, [id]);
      return toUserView(updated, extra.bindings.get(id) ?? [], extra.teams.get(id) ?? [], s.now());
    });
  });

  // POST /users/:id/password — administrative password (re)set; activates invited users.
  app.post("/users/:id/password", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const { password } = parse(z.object({ password: z.string().min(1).max(PASSWORD_MAX_LENGTH) }).strict(), request.body);
    const target = await s.db.withTenant(auth.tenantId, async (tx) => {
      const { row, bindings } = await loadManagedUser(tx, auth, id);
      assertCanAdminister(request, row, bindings);
      return row;
    });
    const errors = passwordPolicyErrors(password, String(target.email));
    if (errors.length > 0) throw new HttpError(400, "weak_password", "The password does not meet the password policy", errors);
    const hash = await hashPassword(password);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await tx.query(
        `INSERT INTO user_credentials (user_id, tenant_id, organization_id, password_hash) VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, password_changed_at = now()`,
        [id, auth.tenantId, target.organization_id ?? null, hash],
      );
      await tx.query("UPDATE users SET status = CASE WHEN status = 'invited' THEN 'active' ELSE status END, failed_login_count = 0, locked_until = NULL WHERE id = $1", [id]);
      await tx.query("UPDATE sessions SET revoked_at = now(), revoked_reason = 'password_reset' WHERE user_id = $1 AND revoked_at IS NULL", [id]);
      await recordAudit(tx, request, { action: "user.password_reset", organizationId: (target.organization_id as string | null) ?? null, targetKind: "user", targetId: id });
    });
    return reply.status(204).send();
  });

  // POST /users/:id/roles { role, organizationId } — grant (only roles the caller could hold itself).
  app.post("/users/:id/roles", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const binding = parse(Binding.strict(), request.body);
    if (id === auth.principal.id) throw forbidden("You cannot change your own role bindings", "self_modification");
    assertCanGrant(request, auth, binding);
    const view = await s.db.withTenant(auth.tenantId, async (tx) => {
      await loadManagedUser(tx, auth, id);
      await tx.query(
        `INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id, created_by) VALUES ($1, 'user', $2, $3, $4, $5)
         ON CONFLICT (tenant_id, principal_kind, principal_id, role, org_key(organization_id)) DO NOTHING`,
        [auth.tenantId, id, binding.role, binding.organizationId, auth.principal.kind === "user" ? auth.principal.id : null],
      );
      await recordAudit(tx, request, { action: "user.role_granted", organizationId: binding.organizationId, targetKind: "user", targetId: id, details: binding });
      const extra = await bindingsAndTeams(tx, [id]);
      const { rows } = await tx.query<Row>("SELECT * FROM users WHERE id = $1", [id]);
      return toUserView(rows[0]!, extra.bindings.get(id) ?? [], extra.teams.get(id) ?? [], s.now());
    });
    return reply.status(201).send(view);
  });

  // DELETE /users/:id/roles?role=&organizationId= — revoke one binding.
  app.delete("/users/:id/roles", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const q = parse(z.object({ role: RoleKey, organizationId: Uuid.optional() }), request.query);
    const binding: RoleBinding = { role: q.role, organizationId: q.organizationId ?? null };
    if (id === auth.principal.id) throw forbidden("You cannot change your own role bindings", "self_modification");
    assertCanGrant(request, auth, binding);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await loadManagedUser(tx, auth, id);
      const res = await tx.query("DELETE FROM role_bindings WHERE principal_kind = 'user' AND principal_id = $1 AND role = $2 AND organization_id IS NOT DISTINCT FROM $3", [id, binding.role, binding.organizationId]);
      if ((res.rowCount ?? 0) === 0) throw notFound("Role binding");
      await recordAudit(tx, request, { action: "user.role_revoked", organizationId: binding.organizationId, targetKind: "user", targetId: id, details: binding });
    });
    return reply.status(204).send();
  });

}
