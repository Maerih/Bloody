import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { AgentStatus, AssetKind, Criticality, IdentityKind, UpsertAssetInput, Uuid, principalCan } from "@bloody/contracts";
import { markAudited, recordAudit } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { badRequest, notFound } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor, likePattern } from "../http/params.js";
import { toAgent, toAlert, toAsset, toIdentity, toIncident, toVulnerability, type Row } from "../repo/mappers.js";
import { QueryBool, keysetClause, loadOne, orderBy, pageRows, parse, type KeysetSort } from "./util.js";

/** Effective agent status: a "protected"/"outdated" agent silent for 24 h is unresponsive. */
export const AGENT_STATUS_SQL = (alias = "ag") =>
  `CASE WHEN ${alias}.status IN ('protected', 'outdated') AND ${alias}.last_checkin_at IS NOT NULL AND ${alias}.last_checkin_at < now() - interval '24 hours' THEN 'unresponsive' ELSE ${alias}.status END`;

const ASSET_SORTS: Record<string, KeysetSort> = {
  risk: { expr: "coalesce(a.risk_score, -1)", dir: "desc", cast: "numeric" },
  name: { expr: "lower(a.name)", dir: "asc", cast: "text" },
  recent: { expr: "coalesce(a.last_seen_at, a.created_at)", dir: "desc", cast: "timestamptz" },
};

const AssetListQuery = z.object({
  organizationId: Uuid.optional(),
  q: z.string().trim().max(200).optional(),
  kind: csvOf(AssetKind).optional(),
  criticality: csvOf(Criticality).optional(),
  internetFacing: QueryBool.optional(),
  source: z.enum(["manual", "discovered", "integration", "agent"]).optional(),
  minRisk: z.coerce.number().min(0).max(100).optional(),
  sort: z.enum(["risk", "name", "recent"]).default("risk"),
  limit: Limit(500, 50),
  cursor: z.string().optional(),
});

const CreateAssetBody = UpsertAssetInput.extend({
  organizationId: Uuid,
  ipAddresses: z.array(z.string().ip()).max(64).default([]),
  tags: z.array(z.string().trim().min(1).max(64)).max(64).default([]),
}).strict();

const PatchAssetBody = z
  .object({
    kind: AssetKind,
    name: z.string().trim().min(1).max(300),
    hostname: z.string().trim().min(1).max(255).nullable(),
    ipAddresses: z.array(z.string().ip()).max(64),
    os: z.string().trim().max(200).nullable(),
    criticality: Criticality,
    internetFacing: z.boolean(),
    tags: z.array(z.string().trim().min(1).max(64)).max(64),
    owner: z.string().trim().max(200).nullable(),
  })
  .partial()
  .strict();

const AgentListQuery = z.object({
  organizationId: Uuid.optional(),
  q: z.string().trim().max(200).optional(),
  status: csvOf(AgentStatus).optional(),
  platform: z.enum(["windows", "macos", "linux"]).optional(),
  antivirusStatus: z.enum(["protected", "unhealthy", "unmanaged", "incompatible"]).optional(),
  limit: Limit(500, 100),
  cursor: z.string().optional(),
});

const UpsertAgentBody = z
  .object({
    organizationId: Uuid,
    hostname: z.string().trim().min(1).max(255),
    platform: z.enum(["windows", "macos", "linux"]),
    version: z.string().trim().min(1).max(100),
    engine: z.string().trim().min(1).max(100),
    status: AgentStatus.default("protected"),
    antivirusStatus: z.enum(["protected", "unhealthy", "unmanaged", "incompatible"]).default("unmanaged"),
    firewallEnabled: z.boolean().default(false),
    lastCheckinAt: z.string().datetime({ offset: true }).optional(),
    os: z.string().trim().max(200).optional(),
    ipAddresses: z.array(z.string().ip()).max(16).optional(),
    externalRef: z.string().trim().max(200).optional(),
  })
  .strict();

const IDENTITY_SORTS: Record<string, KeysetSort> = {
  risk: { expr: "coalesce(i.risk_score, -1)", dir: "desc", cast: "numeric" },
  principal: { expr: "lower(i.principal)", dir: "asc", cast: "text" },
  recent: { expr: "coalesce(i.last_activity_at, i.created_at)", dir: "desc", cast: "timestamptz" },
};

const IdentityListQuery = z.object({
  organizationId: Uuid.optional(),
  q: z.string().trim().max(200).optional(),
  provider: z.string().trim().max(100).optional(),
  kind: csvOf(IdentityKind).optional(),
  privileged: QueryBool.optional(),
  mfa: QueryBool.optional(),
  minRisk: z.coerce.number().min(0).max(100).optional(),
  sort: z.enum(["risk", "principal", "recent"]).default("risk"),
  limit: Limit(500, 50),
  cursor: z.string().optional(),
});

const UpsertIdentityBody = z
  .object({
    organizationId: Uuid,
    kind: IdentityKind.default("user"),
    provider: z.string().trim().min(1).max(100),
    principal: z.string().trim().min(1).max(500),
    displayName: z.string().trim().max(300).nullable().optional(),
    privileged: z.boolean().default(false),
    mfaEnabled: z.boolean().default(false),
    enabled: z.boolean().default(true),
    lastActivityAt: z.string().datetime({ offset: true }).nullable().optional(),
  })
  .strict();

const PatchIdentityBody = z
  .object({ displayName: z.string().trim().max(300).nullable(), privileged: z.boolean(), mfaEnabled: z.boolean(), enabled: z.boolean() })
  .partial()
  .strict();

/**
 * `status` is the effective health (silent agents become "unresponsive"); `reportedStatus` is
 * what the agent itself last reported.
 */
function agentView(r: Row, effectiveStatus?: unknown) {
  const effective = effectiveStatus ?? r.effective_status ?? r.status;
  return { ...toAgent({ ...r, status: effective }), reportedStatus: String(r.status) };
}

async function graphAccessForIdentity(tx: Queryable, identityId: string) {
  const { rows } = await tx.query<{ kind: string; asset_id: string | null; label: string; criticality: string | null }>(
    `SELECT e.kind, a.props->>'assetId' AS asset_id, a.label, a.props->>'criticality' AS criticality
     FROM graph_nodes i JOIN graph_edges e ON e.from_id = i.id AND e.kind IN ('admin_of', 'has_access_to', 'owns', 'logged_into')
     JOIN graph_nodes a ON a.id = e.to_id
     WHERE i.props->>'identityId' = $1 ORDER BY e.kind, a.label LIMIT 200`,
    [identityId],
  );
  return rows.map((r) => ({ relation: r.kind, assetId: r.asset_id, label: r.label, criticality: r.criticality }));
}

/** Assets, agents and identities — the inventory every detection, score and path builds on. */
export async function inventoryRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  // ─── Assets ──────────────────────────────────────────────────────────────

  app.get("/assets", async (request) => {
    const auth = requireAuth(request);
    const q = parse(AssetListQuery, request.query);
    const orgs = resolveOrgFilter(request, "asset:read", q.organizationId);
    const sort = ASSET_SORTS[q.sort]!;
    const params: unknown[] = [];
    const where: string[] = [];
    if (orgs) {
      params.push(orgs);
      where.push(`a.organization_id = ANY($${params.length}::uuid[])`);
    }
    if (q.q) {
      params.push(likePattern(q.q));
      const p = `$${params.length}`;
      params.push(q.q);
      where.push(`(a.name ILIKE ${p} OR a.hostname ILIKE ${p} OR $${params.length} = ANY(a.ip_addresses) OR EXISTS (SELECT 1 FROM unnest(a.tags) t WHERE t ILIKE ${p}))`);
    }
    if (q.kind?.length) {
      params.push(q.kind);
      where.push(`a.kind = ANY($${params.length}::text[])`);
    }
    if (q.criticality?.length) {
      params.push(q.criticality);
      where.push(`a.criticality = ANY($${params.length}::text[])`);
    }
    if (q.internetFacing !== undefined) {
      params.push(q.internetFacing);
      where.push(`a.internet_facing = $${params.length}`);
    }
    if (q.source) {
      params.push(q.source);
      where.push(`a.source = $${params.length}`);
    }
    if (q.minRisk !== undefined) {
      params.push(q.minRisk);
      where.push(`a.risk_score >= $${params.length}`);
    }
    where.push(keysetClause(sort, "a.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(`SELECT a.*, ${sort.expr} AS sort_key FROM assets a WHERE ${where.join(" AND ")} ORDER BY ${orderBy(sort, "a.id")} LIMIT $${params.length}`, params),
    );
    return pageRows(rows, q.limit, toAsset);
  });

  app.post("/assets", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateAssetBody, request.body);
    requirePermission(request, "asset:write", body.organizationId);
    const asset = await s.db.withTenant(auth.tenantId, async (tx) => {
      await loadOne(tx, "organizations", body.organizationId, "Organization");
      const created = await s.inventory.createAsset(tx, auth.tenantId, body.organizationId, { ...body, source: "manual" });
      await recordAudit(tx, request, { action: "asset.created", organizationId: body.organizationId, targetKind: "asset", targetId: created.id, details: { name: created.name, kind: created.kind, criticality: created.criticality } });
      return created;
    });
    s.attackPaths.invalidate(auth.tenantId);
    return reply.status(201).send(asset);
  });

  app.get("/assets/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const asset = toAsset(await loadOne(tx, "assets", id, "Asset"));
      assertRecordAccess(request, "asset:read", asset.organizationId, "Asset");
      const p = auth.principal;
      const org = asset.organizationId;
      const agents = await tx.query<Row>(`SELECT ag.*, ${AGENT_STATUS_SQL()} AS effective_status FROM agents ag WHERE ag.asset_id = $1 ORDER BY ag.updated_at DESC`, [id]);
      const vulns = principalCan(p, "vuln:read", org)
        ? (await tx.query<Row>("SELECT * FROM vulnerabilities WHERE asset_id = $1 AND status IN ('open', 'in_remediation', 'accepted') ORDER BY risk_score DESC NULLS LAST, id LIMIT 50", [id])).rows.map(toVulnerability)
        : null;
      const alerts = principalCan(p, "alert:read", org) ? (await tx.query<Row>("SELECT * FROM alerts WHERE asset_id = $1 ORDER BY last_seen_at DESC LIMIT 20", [id])).rows.map(toAlert) : null;
      const incidents = principalCan(p, "incident:read", org)
        ? (await tx.query<Row>("SELECT * FROM incidents WHERE $1 = ANY(asset_ids) ORDER BY detected_at DESC LIMIT 20", [id])).rows.map(toIncident)
        : null;
      return { ...asset, agents: agents.rows.map((r) => agentView(r)), vulnerabilities: vulns, alerts, incidents };
    });
  });

  app.patch("/assets/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const patch = parse(PatchAssetBody, request.body);
    const updated = await s.db.withTenant(auth.tenantId, async (tx) => {
      const before = toAsset(await loadOne(tx, "assets", id, "Asset"));
      assertRecordAccess(request, "asset:read", before.organizationId, "Asset");
      requirePermission(request, "asset:write", before.organizationId);
      const after = await s.inventory.updateAsset(tx, auth.tenantId, id, patch);
      if (!after) throw notFound("Asset");
      await recordAudit(tx, request, {
        action: "asset.updated",
        organizationId: before.organizationId,
        targetKind: "asset",
        targetId: id,
        details: { changed: Object.fromEntries(Object.keys(patch).map((k) => [k, { from: (before as unknown as Record<string, unknown>)[k] ?? null, to: (after as unknown as Record<string, unknown>)[k] ?? null }])) },
      });
      return after;
    });
    s.attackPaths.invalidate(auth.tenantId);
    return updated;
  });

  // ─── Agents ──────────────────────────────────────────────────────────────

  app.get("/agents", async (request) => {
    const auth = requireAuth(request);
    const q = parse(AgentListQuery, request.query);
    const orgs = resolveOrgFilter(request, "asset:read", q.organizationId);
    const sort: KeysetSort = { expr: "lower(ag.hostname)", dir: "asc", cast: "text" };
    const params: unknown[] = [];
    const where: string[] = [];
    if (orgs) {
      params.push(orgs);
      where.push(`ag.organization_id = ANY($${params.length}::uuid[])`);
    }
    if (q.q) {
      params.push(likePattern(q.q));
      where.push(`ag.hostname ILIKE $${params.length}`);
    }
    if (q.status?.length) {
      params.push(q.status);
      where.push(`${AGENT_STATUS_SQL()} = ANY($${params.length}::text[])`);
    }
    if (q.platform) {
      params.push(q.platform);
      where.push(`ag.platform = $${params.length}`);
    }
    if (q.antivirusStatus) {
      params.push(q.antivirusStatus);
      where.push(`ag.antivirus_status = $${params.length}`);
    }
    where.push(keysetClause(sort, "ag.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT ag.*, ${AGENT_STATUS_SQL()} AS effective_status, ${sort.expr} AS sort_key FROM agents ag WHERE ${where.join(" AND ")} ORDER BY ${orderBy(sort, "ag.id")} LIMIT $${params.length}`,
        params,
      ),
    );
    return pageRows(rows, q.limit, (r) => agentView(r));
  });

  // POST /agents — register / heartbeat an agent (upsert by org + hostname + engine).
  app.post("/agents", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(UpsertAgentBody, request.body);
    requirePermission(request, "asset:write", body.organizationId);
    const checkin = body.lastCheckinAt ?? new Date(s.now()).toISOString();
    const { agent, created } = await s.db.withTenant(auth.tenantId, async (tx) => {
      await loadOne(tx, "organizations", body.organizationId, "Organization");
      const assets = await s.inventory.resolveOrDiscoverHosts(tx, auth.tenantId, body.organizationId, [{ hostname: body.hostname, os: body.os, ips: body.ipAddresses, lastSeenAt: checkin }]);
      const assetId = [...assets.values()][0] ?? null;
      const { rows } = await tx.query<Row & { inserted: boolean }>(
        `INSERT INTO agents (tenant_id, organization_id, asset_id, hostname, platform, version, engine, status, last_checkin_at, antivirus_status, firewall_enabled, external_source, external_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (tenant_id, organization_id, lower(hostname), engine) DO UPDATE SET
           asset_id = coalesce(EXCLUDED.asset_id, agents.asset_id), platform = EXCLUDED.platform, version = EXCLUDED.version, status = EXCLUDED.status,
           last_checkin_at = GREATEST(agents.last_checkin_at, EXCLUDED.last_checkin_at), antivirus_status = EXCLUDED.antivirus_status,
           firewall_enabled = EXCLUDED.firewall_enabled, external_ref = coalesce(EXCLUDED.external_ref, agents.external_ref)
         RETURNING *, (xmax = 0) AS inserted`,
        [
          auth.tenantId,
          body.organizationId,
          assetId,
          body.hostname,
          body.platform,
          body.version,
          body.engine,
          body.status,
          checkin,
          body.antivirusStatus,
          body.firewallEnabled,
          body.externalRef ? body.engine : null,
          body.externalRef ?? null,
        ],
      );
      const row = rows[0]!;
      if (assetId) {
        await tx.query("UPDATE assets SET source = CASE WHEN source = 'discovered' THEN 'agent' ELSE source END WHERE id = $1", [assetId]);
        const asset = toAsset(await loadOne(tx, "assets", assetId, "Asset"));
        await s.inventory.syncAssetGraph(tx, auth.tenantId, asset);
        await s.inventory.scoreAsset(tx, auth.tenantId, assetId);
      }
      if (row.inserted) {
        await recordAudit(tx, request, { action: "agent.registered", organizationId: body.organizationId, targetKind: "agent", targetId: String(row.id), details: { hostname: body.hostname, engine: body.engine, version: body.version } });
      } else {
        markAudited(tx, request); // heartbeats are not audited individually
      }
      const eff = await tx.query<{ s: string }>(`SELECT ${AGENT_STATUS_SQL()} AS s FROM agents ag WHERE ag.id = $1`, [row.id]);
      return { agent: agentView(row, eff.rows[0]?.s), created: Boolean(row.inserted) };
    });
    return reply.status(created ? 201 : 200).send(agent);
  });

  // ─── Identities ──────────────────────────────────────────────────────────

  app.get("/identities", async (request) => {
    const auth = requireAuth(request);
    const q = parse(IdentityListQuery, request.query);
    const orgs = resolveOrgFilter(request, "identity:read", q.organizationId);
    const sort = IDENTITY_SORTS[q.sort]!;
    const params: unknown[] = [];
    const where: string[] = [];
    if (orgs) {
      params.push(orgs);
      where.push(`i.organization_id = ANY($${params.length}::uuid[])`);
    }
    if (q.q) {
      params.push(likePattern(q.q));
      where.push(`(i.principal ILIKE $${params.length} OR i.display_name ILIKE $${params.length})`);
    }
    if (q.provider) {
      params.push(q.provider.toLowerCase());
      where.push(`lower(i.provider) = $${params.length}`);
    }
    if (q.kind?.length) {
      params.push(q.kind);
      where.push(`i.kind = ANY($${params.length}::text[])`);
    }
    if (q.privileged !== undefined) {
      params.push(q.privileged);
      where.push(`i.privileged = $${params.length}`);
    }
    if (q.mfa !== undefined) {
      params.push(q.mfa);
      where.push(`i.mfa_enabled = $${params.length}`);
    }
    if (q.minRisk !== undefined) {
      params.push(q.minRisk);
      where.push(`i.risk_score >= $${params.length}`);
    }
    where.push(keysetClause(sort, "i.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(`SELECT i.*, ${sort.expr} AS sort_key FROM identities i WHERE ${where.join(" AND ")} ORDER BY ${orderBy(sort, "i.id")} LIMIT $${params.length}`, params),
    );
    return pageRows(rows, q.limit, toIdentity);
  });

  app.get("/identities/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const identity = toIdentity(await loadOne(tx, "identities", id, "Identity"));
      assertRecordAccess(request, "identity:read", identity.organizationId, "Identity");
      const alerts = principalCan(auth.principal, "alert:read", identity.organizationId)
        ? (await tx.query<Row>("SELECT * FROM alerts WHERE identity_id = $1 ORDER BY last_seen_at DESC LIMIT 20", [id])).rows.map(toAlert)
        : null;
      const access = principalCan(auth.principal, "graph:read", identity.organizationId) ? await graphAccessForIdentity(tx, id) : null;
      return { ...identity, alerts, access };
    });
  });

  // Identity inventory writes (directory / IdP sync) use the inventory permission asset:write.
  app.post("/identities", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(UpsertIdentityBody, request.body);
    requirePermission(request, "asset:write", body.organizationId);
    const identity = await s.db.withTenant(auth.tenantId, async (tx) => {
      await loadOne(tx, "organizations", body.organizationId, "Organization");
      const view = await s.inventory.upsertIdentity(tx, auth.tenantId, body.organizationId, body, "api");
      await recordAudit(tx, request, { action: "identity.upserted", organizationId: body.organizationId, targetKind: "identity", targetId: view.id, details: { provider: view.provider, principal: view.principal, privileged: view.privileged, mfaEnabled: view.mfaEnabled } });
      return view;
    });
    s.attackPaths.invalidate(auth.tenantId);
    return reply.status(201).send(identity);
  });

  app.patch("/identities/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const patch = parse(PatchIdentityBody, request.body);
    if (Object.keys(patch).length === 0) throw badRequest("Nothing to update");
    const updated = await s.db.withTenant(auth.tenantId, async (tx) => {
      const before = toIdentity(await loadOne(tx, "identities", id, "Identity"));
      assertRecordAccess(request, "identity:read", before.organizationId, "Identity");
      requirePermission(request, "asset:write", before.organizationId);
      const view = await s.inventory.upsertIdentity(tx, auth.tenantId, before.organizationId, {
        kind: before.kind,
        provider: before.provider,
        principal: before.principal,
        displayName: patch.displayName !== undefined ? patch.displayName : before.displayName,
        privileged: patch.privileged ?? before.privileged,
        mfaEnabled: patch.mfaEnabled ?? before.mfaEnabled,
        enabled: patch.enabled ?? before.enabled,
        lastActivityAt: before.lastActivityAt,
      });
      await recordAudit(tx, request, { action: "identity.updated", organizationId: before.organizationId, targetKind: "identity", targetId: id, details: { changed: patch } });
      return view;
    });
    s.attackPaths.invalidate(auth.tenantId);
    return updated;
  });
}
