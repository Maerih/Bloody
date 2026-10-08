import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { RoleKey, Uuid, type RoleBinding } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { canGrantRole, orgScopeFor, requireAuth, requirePermission } from "../auth/rbac.js";
import { AuthService } from "../auth/service.js";
import type { AppServices } from "../context.js";
import { forbidden, notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { parse } from "./util.js";

const CreateKeyBody = z
  .object({
    name: z.string().trim().min(1).max(200),
    /** Bind the key to one organization (recommended for ingestion keys). null = tenant-wide. */
    organizationId: Uuid.nullable().default(null),
    roles: z.array(RoleKey).min(1).max(10).default(["api_service"]),
    expiresInDays: z.number().int().min(1).max(730).optional(),
  })
  .strict();

export interface ApiKeyView {
  id: string;
  name: string;
  prefix: string;
  organizationId: string | null;
  roles: RoleBinding[];
  createdBy: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  expiresAt: string | null;
  revokedAt: string | null;
  active: boolean;
}

function toView(r: Row, roles: RoleBinding[], now: number): ApiKeyView {
  const expiresAt = (r.expires_at as string | null) ?? null;
  const revokedAt = (r.revoked_at as string | null) ?? null;
  return {
    id: String(r.id),
    name: String(r.name),
    prefix: String(r.prefix),
    organizationId: (r.organization_id as string | null) ?? null,
    roles,
    createdBy: (r.created_by as string | null) ?? null,
    createdAt: String(r.created_at),
    lastUsedAt: (r.last_used_at as string | null) ?? null,
    lastUsedIp: (r.last_used_ip as string | null) ?? null,
    expiresAt,
    revokedAt,
    active: revokedAt === null && (expiresAt === null || Date.parse(expiresAt) > now),
  };
}

/**
 * Service API keys (`bk_<prefix>_<secret>`). Only the sha256 of the key is stored; the full key
 * is returned exactly once at creation. Keys may be bound to one organization and carry only
 * roles the creator could grant itself.
 */
export async function apiKeyRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/api-keys", async (request) => {
    const auth = requireAuth(request);
    const scope = orgScopeFor(auth, "apikey:write");
    if (scope !== "all" && scope.length === 0) throw forbidden("Missing permission apikey:write");
    const params: unknown[] = [];
    let where = "TRUE";
    if (scope !== "all") {
      params.push(scope);
      where = `organization_id = ANY($1::uuid[])`;
    }
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(`SELECT * FROM api_keys WHERE ${where} ORDER BY created_at DESC, id LIMIT 500`, params);
      const ids = rows.map((r) => String(r.id));
      const b = ids.length
        ? await tx.query<{ principal_id: string; role: string; organization_id: string | null }>(
            "SELECT principal_id, role, organization_id FROM role_bindings WHERE principal_kind = 'api_key' AND principal_id = ANY($1::uuid[])",
            [ids],
          )
        : { rows: [] };
      const now = s.now();
      return {
        items: rows.map((r) =>
          toView(
            r,
            b.rows.filter((x) => x.principal_id === r.id).flatMap((x) => {
              const role = RoleKey.safeParse(x.role);
              return role.success ? [{ role: role.data, organizationId: x.organization_id }] : [];
            }),
            now,
          ),
        ),
        nextCursor: null,
      };
    });
  });

  app.post("/api-keys", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateKeyBody, request.body);
    requirePermission(request, "apikey:write", body.organizationId);
    for (const role of body.roles) {
      if (!canGrantRole(auth.principal, role, body.organizationId)) throw forbidden(`You cannot grant role ${role} to an API key`, "role_escalation");
    }
    const generated = AuthService.generateApiKey();
    const expiresAt = body.expiresInDays ? new Date(s.now() + body.expiresInDays * 86_400_000).toISOString() : null;
    const view = await s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        "INSERT INTO api_keys (tenant_id, organization_id, name, prefix, key_hash, created_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        [auth.tenantId, body.organizationId, body.name, generated.prefix, generated.hash, auth.principal.kind === "user" ? auth.principal.id : null, expiresAt],
      );
      const key = rows[0]!;
      for (const role of new Set(body.roles)) {
        await tx.query("INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id, created_by) VALUES ($1, 'api_key', $2, $3, $4, $5)", [
          auth.tenantId,
          key.id,
          role,
          body.organizationId,
          auth.principal.kind === "user" ? auth.principal.id : null,
        ]);
      }
      await recordAudit(tx, request, { action: "apikey.created", organizationId: body.organizationId, targetKind: "api_key", targetId: String(key.id), details: { name: body.name, prefix: generated.prefix, roles: body.roles, expiresAt } });
      return toView(key, [...new Set(body.roles)].map((role) => ({ role, organizationId: body.organizationId })), s.now());
    });
    void reply.status(201);
    // The secret is shown exactly once.
    return { apiKey: view, key: generated.key };
  });

  app.delete("/api-keys/:id", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM api_keys WHERE id = $1", [id]);
      const key = rows[0];
      if (!key) throw notFound("API key");
      const scope = orgScopeFor(auth, "apikey:write");
      const org = (key.organization_id as string | null) ?? null;
      if (scope !== "all" && (org === null || !scope.includes(org))) throw notFound("API key");
      requirePermission(request, "apikey:write", org);
      await tx.query("UPDATE api_keys SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1", [id]);
      await recordAudit(tx, request, { action: "apikey.revoked", organizationId: org, targetKind: "api_key", targetId: id, details: { prefix: key.prefix } });
    });
    return reply.status(204).send();
  });
}
