import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Severity, Uuid } from "@bloody/contracts";
import { BufferingSink, narrateRisk, type ExplainedRiskAssessment } from "@bloody/engines";
import { recordAudit } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter, actorId } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { badRequest, notFound } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor, likePattern } from "../http/params.js";
import { toAsset, toVulnerability, type Row } from "../repo/mappers.js";
import { ENRICHMENT_SOURCES, publishKev, type EnrichmentSource } from "../services/enrichment.js";
import { keysetClause, loadOne, orderBy, pageRows, parse, QueryBool, type KeysetSort } from "./util.js";

const VulnStatus = z.enum(["open", "in_remediation", "accepted", "mitigated", "resolved"]);
const Priority = z.enum(["P1", "P2", "P3", "P4"]);

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  assetId: Uuid.optional(),
  q: z.string().trim().max(200).optional(),
  severity: csvOf(Severity).optional(),
  status: csvOf(VulnStatus).optional(),
  priority: csvOf(Priority).optional(),
  knownExploited: QueryBool.optional(),
  overdue: QueryBool.optional(),
  internetFacing: QueryBool.optional(),
  sort: z.enum(["risk", "cvss", "epss", "sla", "recent"]).default("risk"),
  limit: Limit(500, 100),
  cursor: z.string().optional(),
});

const SORTS: Record<string, KeysetSort> = {
  risk: { expr: "coalesce(v.risk_score, 0)", dir: "desc", cast: "numeric" },
  cvss: { expr: "coalesce(v.cvss, 0)", dir: "desc", cast: "numeric" },
  epss: { expr: "coalesce(v.epss, 0)", dir: "desc", cast: "numeric" },
  sla: { expr: "coalesce(v.sla_due_at, 'infinity'::timestamptz)", dir: "asc", cast: "timestamptz" },
  recent: { expr: "v.last_seen_at", dir: "desc", cast: "timestamptz" },
};

const UpsertBody = z
  .object({
    assetId: Uuid,
    cve: z.string().trim().regex(/^CVE-\d{4}-\d{4,}$/i).nullable().optional(),
    title: z.string().trim().min(1).max(500),
    cvss: z.number().min(0).max(10).nullable().optional(),
    epss: z.number().min(0).max(1).nullable().optional(),
    knownExploited: z.boolean().optional(),
    severity: Severity.optional(),
    patchAvailable: z.boolean().optional(),
    source: z.string().trim().min(1).max(100).default("manual"),
  })
  .strict();

const PatchBody = z
  .object({
    status: VulnStatus,
    reason: z.string().trim().min(3).max(2000).optional(),
    /** Risk-acceptance exception expiry (status "accepted"). */
    expiresAt: z.string().datetime({ offset: true }).nullable().optional(),
  })
  .strict();

function toView(r: Row) {
  return {
    ...toVulnerability(r),
    assetName: (r.asset_name as string | null) ?? null,
    assetCriticality: (r.asset_criticality as string | null) ?? null,
    internetFacing: r.asset_internet_facing === undefined ? null : Boolean(r.asset_internet_facing),
    organizationName: (r.organization_name as string | null) ?? null,
    kev: r.kev ?? null,
    epssPercentile: r.epss_percentile === null || r.epss_percentile === undefined ? null : Number(r.epss_percentile),
    enrichment: r.enrichment ?? null,
    enrichedAt: (r.enriched_at as string | null) ?? null,
    exceptionReason: (r.exception_reason as string | null) ?? null,
    exceptionExpiresAt: (r.exception_expires_at as string | null) ?? null,
    overdue: r.sla_due_at !== null && r.sla_due_at !== undefined && ["open", "in_remediation"].includes(String(r.status)) && Date.parse(String(r.sla_due_at)) < Date.now(),
    firstSeenAt: String(r.first_seen_at),
    lastSeenAt: String(r.last_seen_at),
    resolvedAt: (r.resolved_at as string | null) ?? null,
    source: String(r.source),
  };
}

/**
 * Vulnerability management with risk-based prioritization: every finding carries the Risk
 * Engine's explained priority (P1–P4, SLA, recommended action); KEV / EPSS evidence comes from
 * the enrichment job.
 */
export async function vulnerabilityRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const vuln = { module: "vuln" as const };
  const BASE = `SELECT v.*, a.name AS asset_name, a.criticality AS asset_criticality, a.internet_facing AS asset_internet_facing, o.name AS organization_name
                FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id JOIN organizations o ON o.id = v.organization_id`;

  app.get("/vulnerabilities", { config: vuln }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "vuln:read", q.organizationId);
    const sort = SORTS[q.sort]!;
    const params: unknown[] = [];
    const where: string[] = [orgs ? `v.organization_id = ANY($${params.push(orgs)}::uuid[])` : "TRUE"];
    if (q.assetId) where.push(`v.asset_id = $${params.push(q.assetId)}`);
    if (q.q) where.push(`(v.cve ILIKE $${params.push(likePattern(q.q))} OR v.title ILIKE $${params.length} OR a.name ILIKE $${params.length})`);
    if (q.severity?.length) where.push(`v.severity = ANY($${params.push(q.severity)}::text[])`);
    where.push(q.status?.length ? `v.status = ANY($${params.push(q.status)}::text[])` : "v.status IN ('open', 'in_remediation', 'accepted')");
    if (q.priority?.length) where.push(`v.priority = ANY($${params.push(q.priority)}::text[])`);
    if (q.knownExploited !== undefined) where.push(`v.known_exploited = $${params.push(q.knownExploited)}`);
    if (q.overdue === true) where.push("v.sla_due_at < now() AND v.status IN ('open', 'in_remediation')");
    if (q.internetFacing !== undefined) where.push(`a.internet_facing = $${params.push(q.internetFacing)}`);
    where.push(keysetClause(sort, "v.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(`${BASE.replace("SELECT v.*,", `SELECT v.*, ${sort.expr} AS sort_key,`)} WHERE ${where.join(" AND ")} ORDER BY ${orderBy(sort, "v.id")} LIMIT $${params.length}`, params),
    );
    return pageRows(rows, q.limit, toView);
  });

  app.get("/vulnerabilities/summary", { config: vuln }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional() }), request.query);
    const orgs = resolveOrgFilter(request, "vuln:read", q.organizationId);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT count(*)::int AS open,
                count(*) FILTER (WHERE v.priority = 'P1')::int AS p1, count(*) FILTER (WHERE v.priority = 'P2')::int AS p2,
                count(*) FILTER (WHERE v.priority = 'P3')::int AS p3, count(*) FILTER (WHERE v.priority = 'P4')::int AS p4,
                count(*) FILTER (WHERE v.severity = 'critical')::int AS critical, count(*) FILTER (WHERE v.severity = 'high')::int AS high,
                count(*) FILTER (WHERE v.known_exploited)::int AS known_exploited,
                count(*) FILTER (WHERE v.known_exploited AND a.internet_facing)::int AS kev_internet_facing,
                count(*) FILTER (WHERE v.sla_due_at < now())::int AS overdue,
                count(*) FILTER (WHERE v.patch_available)::int AS patch_available,
                count(DISTINCT v.asset_id)::int AS affected_assets,
                max(v.enriched_at) AS last_enriched_at
         FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id
         WHERE ${orgs ? "v.organization_id = ANY($1::uuid[]) AND" : ""} v.status IN ('open', 'in_remediation')`,
        orgs ? [orgs] : [],
      ),
    );
    const r = rows[0]!;
    return {
      open: r.open,
      byPriority: { P1: r.p1, P2: r.p2, P3: r.p3, P4: r.p4 },
      bySeverity: { critical: r.critical, high: r.high },
      knownExploited: r.known_exploited,
      knownExploitedOnInternetFacing: r.kev_internet_facing,
      overdueSla: r.overdue,
      patchAvailable: r.patch_available,
      affectedAssets: r.affected_assets,
      lastEnrichedAt: r.last_enriched_at ?? null,
      enrichmentEnabled: s.enrichment.enabled,
    };
  });

  app.get("/vulnerabilities/enrichment", { config: vuln }, async (request) => {
    const auth = requireAuth(request);
    resolveOrgFilter(request, "vuln:read", undefined);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) => tx.query<Row>("SELECT * FROM enrichment_runs ORDER BY started_at DESC LIMIT 20"));
    return {
      enabled: s.enrichment.enabled,
      sources: ENRICHMENT_SOURCES,
      allowedHosts: s.config.enrichment.allowedHosts,
      runs: rows.map((r) => ({ id: String(r.id), sources: r.sources, status: r.status, stats: r.stats, error: r.error ?? null, requestedBy: r.requested_by ?? null, startedAt: r.started_at, finishedAt: r.finished_at ?? null })),
    };
  });

  app.post("/vulnerabilities/enrichment", { config: { ...vuln, audit: "vulnerability.enrichment_run" } }, async (request) => {
    const auth = requireAuth(request);
    const body = parse(z.object({ sources: z.array(z.enum(["cisa_kev", "first_epss"])).min(1).max(2).default(["cisa_kev", "first_epss"]) }).strict(), request.body ?? {});
    // Enrichment re-prioritizes the whole tenant: tenant-level permission.
    requirePermission(request, "vuln:write", null);
    const result = await s.enrichment.run(auth.tenantId, { sources: body.sources as EnrichmentSource[], requestedBy: actorId(auth) });
    request.auditState.targetKind = "enrichment_run";
    request.auditState.targetId = result.runId;
    request.auditState.details = { sources: body.sources, status: result.status, updated: result.stats.updated, newlyKnownExploited: result.stats.newlyKnownExploited };
    return result;
  });

  app.get("/vulnerabilities/:id", { config: vuln }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(`${BASE} WHERE v.id = $1`, [id]);
      if (!rows[0]) throw notFound("Vulnerability");
      const view = toView(rows[0]);
      assertRecordAccess(request, "vuln:read", view.organizationId, "Vulnerability");
      const asset = toAsset(await loadOne(tx, "assets", view.assetId, "Asset"));
      const risk = view.risk as (ExplainedRiskAssessment & { priority?: string; slaDays?: number; recommendedAction?: string; rationale?: string }) | null;
      return { ...view, asset, narrative: risk ? narrateRisk(risk, { audience: "analyst", subject: `${view.cve ?? view.title} on ${asset.name}` }) : null };
    });
  });

  app.post("/vulnerabilities", { config: { ...vuln, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(UpsertBody, request.body);
    const sink = new BufferingSink();
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      const asset = toAsset(await loadOne(tx, "assets", body.assetId, "Asset"));
      assertRecordAccess(request, "asset:read", asset.organizationId, "Asset");
      requirePermission(request, "vuln:write", asset.organizationId);
      const v = await s.inventory.upsertVulnerability(
        tx,
        auth.tenantId,
        {
          assetId: body.assetId,
          cve: body.cve ?? null,
          title: body.title,
          cvss: body.cvss ?? null,
          epss: body.epss ?? null,
          knownExploited: body.knownExploited ?? false,
          ...(body.severity ? { severity: body.severity } : {}),
          patchAvailable: body.patchAvailable ?? false,
          source: body.source,
        },
        sink,
      );
      await recordAudit(tx, request, { action: "vulnerability.upserted", organizationId: asset.organizationId, targetKind: "vulnerability", targetId: v.id, details: { cve: v.cve, priority: v.priority, assetId: asset.id } });
      const { rows } = await tx.query<Row>(`${BASE} WHERE v.id = $1`, [v.id]);
      return toView(rows[0]!);
    });
    for (const n of sink.drain()) if (n.type === "vulnerability.kev_detected") publishKev(s.domainEvents, n, "api");
    s.attackPaths.invalidate(auth.tenantId);
    return reply.status(201).send(created);
  });

  app.patch("/vulnerabilities/:id", { config: { ...vuln, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(PatchBody, request.body);
    if (body.status === "accepted" && !body.reason) throw badRequest("A justification (reason) is required to accept a risk");
    if (body.expiresAt && Date.parse(body.expiresAt) <= s.now()) throw badRequest("expiresAt must be in the future");
    const updated = await s.db.withTenant(auth.tenantId, async (tx) => {
      const cur = await loadOne(tx, "vulnerabilities", id, "Vulnerability");
      const v = toVulnerability(cur);
      assertRecordAccess(request, "vuln:read", v.organizationId, "Vulnerability");
      requirePermission(request, "vuln:write", v.organizationId);
      await s.inventory.upsertVulnerability(tx, auth.tenantId, {
        assetId: v.assetId,
        cve: v.cve,
        title: v.title,
        cvss: v.cvss,
        epss: v.epss,
        knownExploited: v.knownExploited,
        severity: v.severity,
        status: body.status,
        patchAvailable: v.patchAvailable,
        slaDueAt: v.slaDueAt,
        source: String(cur.source),
        firstSeenAt: String(cur.first_seen_at),
      });
      await tx.query("UPDATE vulnerabilities SET exception_reason = $2, exception_expires_at = $3 WHERE id = $1", [
        id,
        body.status === "accepted" ? body.reason : null,
        body.status === "accepted" ? (body.expiresAt ?? null) : null,
      ]);
      await recordAudit(tx, request, { action: "vulnerability.status_changed", organizationId: v.organizationId, targetKind: "vulnerability", targetId: id, details: { from: v.status, to: body.status, reason: body.reason ?? null, exceptionExpiresAt: body.expiresAt ?? null } });
      const { rows } = await tx.query<Row>(`${BASE} WHERE v.id = $1`, [id]);
      return toView(rows[0]!);
    });
    s.attackPaths.invalidate(auth.tenantId);
    return updated;
  });
}
