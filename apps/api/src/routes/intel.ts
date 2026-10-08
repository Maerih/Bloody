import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { IndicatorType, Severity, Uuid } from "@bloody/contracts";
import { parseMispAttributes, parseStixBundle } from "@bloody/adapters";
import { recordAudit } from "../audit/audit.js";
import { assertRecordAccess, canAnywhere, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest, forbidden } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor, likePattern } from "../http/params.js";
import { toIndicator, type Row } from "../repo/mappers.js";
import { keysetClause, loadOne, orderBy, pageRows, parse, QueryBool, type KeysetSort } from "./util.js";

const Tlp = z.enum(["clear", "green", "amber", "amber+strict", "red"]);

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  q: z.string().trim().max(200).optional(),
  type: csvOf(IndicatorType).optional(),
  severity: csvOf(Severity).optional(),
  source: z.string().trim().max(200).optional(),
  tag: z.string().trim().max(100).optional(),
  active: QueryBool.optional(),
  sort: z.enum(["recent", "confidence", "severity"]).default("recent"),
  limit: Limit(500, 100),
  cursor: z.string().optional(),
});

const SORTS: Record<string, KeysetSort> = {
  recent: { expr: "i.last_seen_at", dir: "desc", cast: "timestamptz" },
  confidence: { expr: "i.confidence::numeric", dir: "desc", cast: "numeric" },
  severity: { expr: "(CASE i.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)::numeric * 1000 + i.confidence", dir: "desc", cast: "numeric" },
};

const CreateBody = z
  .object({
    organizationId: Uuid.nullable().default(null),
    type: IndicatorType,
    value: z.string().trim().min(1).max(2048),
    confidence: z.number().int().min(0).max(100).default(70),
    severity: Severity.default("medium"),
    source: z.string().trim().min(1).max(200).default("manual"),
    threatActor: z.string().trim().max(200).nullable().optional(),
    malware: z.string().trim().max(200).nullable().optional(),
    campaign: z.string().trim().max(200).nullable().optional(),
    tags: z.array(z.string().trim().min(1).max(100)).max(50).default([]),
    expiresAt: z.string().datetime({ offset: true }).nullable().optional(),
    description: z.string().max(4000).nullable().optional(),
    tlp: Tlp.nullable().optional(),
    retroHunt: z.boolean().default(false),
  })
  .strict();

const PatchBody = z
  .object({
    confidence: z.number().int().min(0).max(100).optional(),
    severity: Severity.optional(),
    threatActor: z.string().trim().max(200).nullable().optional(),
    malware: z.string().trim().max(200).nullable().optional(),
    campaign: z.string().trim().max(200).nullable().optional(),
    tags: z.array(z.string().trim().min(1).max(100)).max(50).optional(),
    expiresAt: z.string().datetime({ offset: true }).nullable().optional(),
    description: z.string().max(4000).nullable().optional(),
    tlp: Tlp.nullable().optional(),
    revoked: z.boolean().optional(),
  })
  .strict();

const ImportBody = z
  .object({
    format: z.enum(["stix", "misp"]),
    organizationId: Uuid.nullable().default(null),
    /** Source label stored on every record (defaults to the feed's own). */
    source: z.string().trim().min(1).max(200).optional(),
    /** STIX 2.1 bundle / MISP restSearch JSON (object, or the JSON text). */
    payload: z.unknown(),
    retroHunt: z.boolean().default(false),
    lookbackDays: z.number().int().min(1).max(90).default(30),
  })
  .strict();

const MatchesQuery = z.object({
  organizationId: Uuid.optional(),
  indicatorId: Uuid.optional(),
  incidentId: Uuid.optional(),
  assetId: Uuid.optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  limit: Limit(500, 100),
  cursor: z.string().optional(),
});

const RetroBody = z
  .object({ organizationId: Uuid.optional(), indicatorIds: z.array(Uuid).max(1000).optional(), lookbackDays: z.number().int().min(1).max(90).default(30) })
  .strict();

const MATCH_SORT: KeysetSort = { expr: "m.matched_at", dir: "desc", cast: "timestamptz" };

export function toIndicatorView(r: Row) {
  return {
    ...toIndicator(r),
    description: (r.description as string | null) ?? null,
    tlp: (r.tlp as string | null) ?? null,
    attack: Array.isArray(r.attack) ? r.attack : [],
    scoring: Array.isArray(r.scoring) ? r.scoring : [],
    revoked: Boolean(r.revoked),
    externalRef: (r.external_ref as string | null) ?? null,
    active: !r.revoked && (r.expires_at === null || Date.parse(String(r.expires_at)) > Date.now()),
    ...(r.matches !== undefined ? { matches: Number(r.matches) } : {}),
  };
}

function toMatchView(r: Row) {
  return {
    id: String(r.id),
    indicatorId: String(r.indicator_id),
    indicator: { type: r.type, value: r.ind_value, severity: r.severity, confidence: Number(r.confidence), source: r.source, threatActor: (r.threat_actor as string | null) ?? null },
    organizationId: String(r.organization_id),
    organizationName: (r.organization_name as string | null) ?? null,
    matchedAt: String(r.matched_at),
    eventTime: String(r.event_time),
    entityKind: r.asset_id ? "asset" : "event",
    entityId: r.asset_id ? String(r.asset_id) : String(r.event_id),
    entityLabel: (r.asset_name as string | null) ?? String(r.observed_value),
    field: String(r.field),
    eventId: String(r.event_id),
    alertId: (r.alert_id as string | null) ?? null,
    incidentId: (r.incident_id as string | null) ?? null,
    value: String(r.observed_value),
  };
}

/** Indicators are tenant-wide (organizationId null) or organization-scoped. */
function requireIntelWrite(request: Parameters<typeof requirePermission>[0], organizationId: string | null): void {
  requirePermission(request, "intel:write", organizationId);
}

export async function intelRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const cti = { module: "cti" as const };

  app.get("/intel/indicators", { config: cti }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "intel:read", q.organizationId);
    const sort = SORTS[q.sort]!;
    const params: unknown[] = [];
    const where: string[] = [orgs ? `(i.organization_id IS NULL OR i.organization_id = ANY($${params.push(orgs)}::uuid[]))` : "TRUE"];
    if (q.q) where.push(`(i.value ILIKE $${params.push(likePattern(q.q))} OR i.threat_actor ILIKE $${params.length} OR i.malware ILIKE $${params.length} OR i.campaign ILIKE $${params.length})`);
    if (q.type?.length) where.push(`i.type = ANY($${params.push(q.type)}::text[])`);
    if (q.severity?.length) where.push(`i.severity = ANY($${params.push(q.severity)}::text[])`);
    if (q.source) where.push(`i.source = $${params.push(q.source)}`);
    if (q.tag) where.push(`$${params.push(q.tag)} = ANY(i.tags)`);
    if (q.active === true) where.push("NOT i.revoked AND (i.expires_at IS NULL OR i.expires_at > now())");
    if (q.active === false) where.push("(i.revoked OR i.expires_at <= now())");
    where.push(keysetClause(sort, "i.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT i.*, ${sort.expr} AS sort_key, (SELECT count(*) FROM indicator_matches m WHERE m.indicator_id = i.id) AS matches
         FROM indicators i WHERE ${where.join(" AND ")} ORDER BY ${orderBy(sort, "i.id")} LIMIT $${params.length}`,
        params,
      ),
    );
    return pageRows(rows, q.limit, toIndicatorView);
  });

  app.get("/intel/indicators/:id", { config: cti }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "indicators", id, "Indicator");
      if (row.organization_id) assertRecordAccess(request, "intel:read", String(row.organization_id), "Indicator");
      else if (!canAnywhere(auth.principal, "intel:read")) throw forbidden("Missing permission intel:read");
      const orgs = resolveOrgFilter(request, "intel:read", undefined);
      const params: unknown[] = [id];
      const { rows } = await tx.query<Row>(
        `SELECT m.*, i.type, i.value AS ind_value, i.severity, i.confidence, i.source, i.threat_actor, a.name AS asset_name, al.incident_id, o.name AS organization_name
         FROM indicator_matches m JOIN indicators i ON i.id = m.indicator_id JOIN organizations o ON o.id = m.organization_id
         LEFT JOIN assets a ON a.id = m.asset_id LEFT JOIN alerts al ON al.id = m.alert_id
         WHERE m.indicator_id = $1 ${orgs ? `AND m.organization_id = ANY($${params.push(orgs)}::uuid[])` : ""}
         ORDER BY m.matched_at DESC LIMIT 25`,
        params,
      );
      return { ...toIndicatorView(row), recentMatches: rows.map(toMatchView) };
    });
  });

  app.post("/intel/indicators", { config: { ...cti, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateBody, request.body);
    requireIntelWrite(request, body.organizationId);
    if (body.expiresAt && Date.parse(body.expiresAt) <= s.now()) throw badRequest("expiresAt must be in the future");
    const row = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.organizationId) await loadOne(tx, "organizations", body.organizationId, "Organization");
      const r = await s.inventory.upsertIndicator(tx, auth.tenantId, {
        organizationId: body.organizationId,
        type: body.type,
        value: body.value,
        confidence: body.confidence,
        severity: body.severity,
        source: body.source,
        threatActor: body.threatActor ?? null,
        malware: body.malware ?? null,
        campaign: body.campaign ?? null,
        tags: body.tags,
        expiresAt: body.expiresAt ?? null,
      });
      const upd = await tx.query<Row>("UPDATE indicators SET description = $2, tlp = $3, revoked = false WHERE id = $1 RETURNING *", [r.id, body.description ?? null, body.tlp ?? null]);
      await recordAudit(tx, request, { action: "intel.indicator_created", organizationId: body.organizationId, targetKind: "indicator", targetId: String(r.id), details: { type: body.type, source: body.source, severity: body.severity } });
      return upd.rows[0]!;
    });
    const view = toIndicatorView(row);
    const retroHunt = body.retroHunt ? await s.intel.retroHunt(auth.tenantId, resolveOrgFilter(request, "intel:read", body.organizationId ?? undefined), { indicatorIds: [view.id], lookbackDays: 30, actor: auth.principal.id }) : null;
    return reply.status(201).send({ ...view, ...(retroHunt ? { retroHunt } : {}) });
  });

  app.patch("/intel/indicators/:id", { config: { ...cti, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(PatchBody, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "indicators", id, "Indicator");
      if (row.organization_id) assertRecordAccess(request, "intel:read", String(row.organization_id), "Indicator");
      requireIntelWrite(request, (row.organization_id as string | null) ?? null);
      const sets: string[] = [];
      const params: unknown[] = [id];
      const set = (col: string, v: unknown) => sets.push(`${col} = $${params.push(v)}`);
      if (body.confidence !== undefined) set("confidence", body.confidence);
      if (body.severity !== undefined) set("severity", body.severity);
      if (body.threatActor !== undefined) set("threat_actor", body.threatActor);
      if (body.malware !== undefined) set("malware", body.malware);
      if (body.campaign !== undefined) set("campaign", body.campaign);
      if (body.tags !== undefined) set("tags", body.tags);
      if (body.expiresAt !== undefined) set("expires_at", body.expiresAt);
      if (body.description !== undefined) set("description", body.description);
      if (body.tlp !== undefined) set("tlp", body.tlp);
      if (body.revoked !== undefined) set("revoked", body.revoked);
      if (sets.length === 0) return toIndicatorView(row);
      const upd = await tx.query<Row>(`UPDATE indicators SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, params);
      await recordAudit(tx, request, { action: "intel.indicator_updated", organizationId: (row.organization_id as string | null) ?? null, targetKind: "indicator", targetId: id, details: { fields: Object.keys(body) } });
      return toIndicatorView(upd.rows[0]!);
    });
  });

  // Indicators are revoked, not deleted: their match history stays explainable.
  app.delete("/intel/indicators/:id", { config: { ...cti, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "indicators", id, "Indicator");
      if (row.organization_id) assertRecordAccess(request, "intel:read", String(row.organization_id), "Indicator");
      requireIntelWrite(request, (row.organization_id as string | null) ?? null);
      await tx.query("UPDATE indicators SET revoked = true, expires_at = LEAST(coalesce(expires_at, now()), now()) WHERE id = $1", [id]);
      await recordAudit(tx, request, { action: "intel.indicator_revoked", organizationId: (row.organization_id as string | null) ?? null, targetKind: "indicator", targetId: id, details: { type: row.type, source: row.source } });
    });
    return reply.status(204).send();
  });

  app.post("/intel/indicators/import", { config: { ...cti, audit: false }, bodyLimit: 32 * 1024 * 1024 }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(ImportBody, request.body);
    requireIntelWrite(request, body.organizationId);
    let payload: unknown = body.payload;
    if (typeof payload === "string") {
      try {
        payload = JSON.parse(payload);
      } catch {
        throw badRequest("payload must be JSON (STIX 2.1 bundle or MISP restSearch response)");
      }
    }
    const nowIso = new Date(s.now()).toISOString();
    const parsed = body.format === "stix" ? parseStixBundle(payload, { now: nowIso, ...(body.source ? { source: body.source } : {}) }) : parseMispAttributes(payload, { now: nowIso });
    if (parsed.records.length === 0 && parsed.skipped.length === 0) throw new HttpError(422, "empty_feed", `No indicators found in the ${body.format.toUpperCase()} payload`);
    if (parsed.records.length > 50_000) throw new HttpError(413, "feed_too_large", "At most 50 000 indicators per import");
    const summary = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.organizationId) await loadOne(tx, "organizations", body.organizationId, "Organization");
      const res = await s.intel.upsertRecords(tx, auth.tenantId, body.organizationId, parsed.records, body.source ? { sourceOverride: body.source } : {});
      await recordAudit(tx, request, {
        action: "intel.imported",
        organizationId: body.organizationId,
        targetKind: "intel_feed",
        targetId: body.format,
        details: { format: body.format, received: res.received, created: res.created, updated: res.updated, revoked: res.revoked, skipped: res.skipped.length + parsed.skipped.length },
      });
      return res;
    });
    const retroHunt = body.retroHunt && summary.indicatorIds.length > 0 ? await s.intel.retroHunt(auth.tenantId, resolveOrgFilter(request, "intel:read", body.organizationId ?? undefined), { indicatorIds: summary.indicatorIds, lookbackDays: body.lookbackDays, actor: auth.principal.id }) : null;
    return reply.status(201).send({
      format: body.format,
      received: summary.received,
      created: summary.created,
      updated: summary.updated,
      revoked: summary.revoked,
      skipped: [...parsed.skipped, ...summary.skipped].slice(0, 200),
      skippedCount: parsed.skipped.length + summary.skipped.length,
      retroHunt,
    });
  });

  app.get("/intel/matches", { config: cti }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(MatchesQuery, request.query);
    const orgs = resolveOrgFilter(request, "intel:read", q.organizationId);
    const params: unknown[] = [];
    const where: string[] = [orgs ? `m.organization_id = ANY($${params.push(orgs)}::uuid[])` : "TRUE"];
    if (q.indicatorId) where.push(`m.indicator_id = $${params.push(q.indicatorId)}`);
    if (q.incidentId) where.push(`al.incident_id = $${params.push(q.incidentId)}`);
    if (q.assetId) where.push(`m.asset_id = $${params.push(q.assetId)}`);
    if (q.from) where.push(`m.matched_at >= $${params.push(q.from)}`);
    if (q.to) where.push(`m.matched_at < $${params.push(q.to)}`);
    where.push(keysetClause(MATCH_SORT, "m.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT m.*, m.matched_at AS sort_key, i.type, i.value AS ind_value, i.severity, i.confidence, i.source, i.threat_actor, a.name AS asset_name, al.incident_id, o.name AS organization_name
         FROM indicator_matches m JOIN indicators i ON i.id = m.indicator_id JOIN organizations o ON o.id = m.organization_id
         LEFT JOIN assets a ON a.id = m.asset_id LEFT JOIN alerts al ON al.id = m.alert_id
         WHERE ${where.join(" AND ")} ORDER BY ${orderBy(MATCH_SORT, "m.id")} LIMIT $${params.length}`,
        params,
      ),
    );
    return pageRows(rows, q.limit, toMatchView);
  });

  const retroHunt = async (request: Parameters<typeof requireAuth>[0]) => {
    const auth = requireAuth(request);
    const body = parse(RetroBody, request.body ?? {});
    const orgs = resolveOrgFilter(request, "intel:read", body.organizationId);
    // Recording matches is a write in the organizations hunted.
    if (orgs) for (const o of orgs) requirePermission(request, "intel:write", o);
    else requirePermission(request, "intel:write", null);
    const result = await s.intel.retroHunt(auth.tenantId, orgs, { ...(body.indicatorIds ? { indicatorIds: body.indicatorIds } : {}), lookbackDays: body.lookbackDays, actor: auth.principal.id });
    request.auditState.details = { lookbackDays: body.lookbackDays, matches: result.matches, indicators: result.indicators };
    request.auditState.organizationId = body.organizationId ?? null;
    return result;
  };
  app.post("/intel/retro-hunt", { config: { ...cti, audit: "intel.retro_hunt" } }, (request) => retroHunt(request));
  app.post("/intel/matches/retro-hunt", { config: { ...cti, audit: "intel.retro_hunt" } }, (request) => retroHunt(request));

  app.get("/intel/sources", { config: cti }, async (request) => {
    const auth = requireAuth(request);
    const orgs = resolveOrgFilter(request, "intel:read", undefined);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT source, count(*)::int AS indicators, count(*) FILTER (WHERE NOT revoked AND (expires_at IS NULL OR expires_at > now()))::int AS active,
                max(updated_at) AS last_updated_at, count(DISTINCT type)::int AS types
         FROM indicators WHERE ${orgs ? "(organization_id IS NULL OR organization_id = ANY($1::uuid[]))" : "TRUE"} GROUP BY source ORDER BY indicators DESC`,
        orgs ? [orgs] : [],
      ),
    );
    return { items: rows.map((r) => ({ source: String(r.source), indicators: Number(r.indicators), active: Number(r.active), types: Number(r.types), lastUpdatedAt: r.last_updated_at })) };
  });

}
