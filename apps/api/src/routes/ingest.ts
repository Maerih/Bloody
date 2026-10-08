import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { Uuid } from "@bloody/contracts";
import { requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest, forbidden, notFound } from "../http/errors.js";
import type { IngestOutcome } from "../pipeline/ingest.js";
import { loadOne, parse } from "./util.js";

const MAX_REJECTIONS_IN_RESPONSE = 100;

const BatchBody = z.union([
  z.array(z.unknown()),
  z
    .object({
      organizationId: Uuid.optional(),
      events: z.array(z.unknown()),
    })
    .strict(),
]);
const OrgQuery = z.object({ organizationId: Uuid.optional(), integrationId: Uuid.optional(), sensorId: z.string().trim().max(200).optional() });
const AdapterParams = z.object({ adapter: z.string().regex(/^[a-z0-9_]{2,40}$/, "unknown adapter") });

/**
 * Resolve the target organization of an ingest call: org-bound API keys always write to their
 * own organization; otherwise the caller names one it holds `event:ingest` for.
 */
function resolveIngestOrg(request: FastifyRequest, explicit: string | undefined): string {
  const auth = requireAuth(request);
  if (auth.boundOrganizationId) {
    if (explicit && explicit !== auth.boundOrganizationId) throw forbidden("This API key may only ingest into its own organization");
    requirePermission(request, "event:ingest", auth.boundOrganizationId);
    return auth.boundOrganizationId;
  }
  if (!explicit) throw badRequest("organizationId is required (or use an organization-bound API key)");
  requirePermission(request, "event:ingest", explicit);
  return explicit;
}

function summarize(outcome: IngestOutcome) {
  return {
    ...outcome,
    rejected: outcome.rejected.slice(0, MAX_REJECTIONS_IN_RESPONSE),
    rejectedCount: outcome.rejected.length,
  };
}

/**
 * Ingest: canonical events (`POST /ingest/events`) and raw engine payloads normalized by the
 * adapter registry (`POST /ingest/:adapter`, e.g. wazuh, zeek, suricata, falco…). Events are
 * stored, metered and published to the data fabric; the analytics pipeline consumes them.
 */
export async function ingestRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  // Gzip / binary engine exports (adapters decompress and split records themselves).
  app.addContentTypeParser(["application/gzip", "application/octet-stream"], { parseAs: "buffer" }, (_req, body, done) => done(null, body));

  const limits = { bodyLimit: s.config.ingest.bodyLimitBytes };

  app.post("/ingest/events", { ...limits, config: { audit: "ingest.events" } }, async (request, reply) => {
    const auth = requireAuth(request);
    const q = parse(OrgQuery, request.query);
    const body = parse(BatchBody, request.body);
    const events = Array.isArray(body) ? body : body.events;
    const organizationId = resolveIngestOrg(request, (Array.isArray(body) ? undefined : body.organizationId) ?? q.organizationId);
    if (events.length === 0) throw badRequest("The batch contains no events");
    if (events.length > s.config.ingest.maxBatch) throw new HttpError(413, "batch_too_large", `A batch may contain at most ${s.config.ingest.maxBatch} events`, { max: s.config.ingest.maxBatch, received: events.length });
    await s.db.withTenant(auth.tenantId, (tx) => loadOne(tx, "organizations", organizationId, "Organization"));
    const outcome = await s.ingest.ingest(auth.tenantId, organizationId, events, auth.method === "api_key" ? `api_key:${auth.principal.displayName ?? auth.principal.id}`.slice(0, 64) : "api");
    request.auditState.organizationId = organizationId;
    request.auditState.targetKind = "ingest_batch";
    request.auditState.targetId = outcome.batchId;
    request.auditState.details = { received: outcome.received, accepted: outcome.accepted, duplicates: outcome.duplicates, rejected: outcome.rejected.length };
    return reply.status(202).send(summarize(outcome));
  });

  app.post("/ingest/:adapter", { ...limits, config: { audit: "ingest.adapter" } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { adapter } = parse(AdapterParams, request.params);
    if (!s.adapters.has(adapter)) throw new HttpError(404, "unknown_adapter", `No adapter is registered for "${adapter}"`, { available: s.adapters.list().map((a) => a.key) });
    const q = parse(OrgQuery, request.query);
    const organizationId = resolveIngestOrg(request, q.organizationId);
    if (request.body === undefined || request.body === null || (typeof request.body === "string" && request.body.trim() === "")) throw badRequest("Empty payload");
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await loadOne(tx, "organizations", organizationId, "Organization");
      if (q.integrationId) {
        const res = await tx.query("SELECT 1 FROM integrations WHERE id = $1 AND (organization_id IS NULL OR organization_id = $2)", [q.integrationId, organizationId]);
        if ((res.rowCount ?? 0) === 0) throw notFound("Integration");
      }
    });
    const receivedAt = new Date(s.now()).toISOString();
    let normalized;
    try {
      normalized = s.adapters.ingest(adapter, request.body, {
        receivedAt,
        idNamespace: auth.tenantId,
        maxRecords: s.config.ingest.maxBatch,
        ...(q.integrationId ? { integrationId: q.integrationId } : {}),
        ...(q.sensorId ? { sensorId: q.sensorId } : {}),
      });
    } catch (err) {
      throw new HttpError(400, "unparseable_payload", `The ${adapter} adapter could not read the payload: ${err instanceof Error ? err.message.slice(0, 300) : "invalid input"}`);
    }
    const { result, report } = normalized;
    const outcome = result.events.length > 0 ? await s.ingest.ingest(auth.tenantId, organizationId, result.events, adapter) : null;
    if (q.integrationId && outcome && outcome.accepted > 0) {
      await s.db.withTenant(auth.tenantId, (tx) => tx.query("UPDATE integrations SET last_event_at = now() WHERE id = $1", [q.integrationId]));
    }
    request.auditState.organizationId = organizationId;
    request.auditState.targetKind = "ingest_batch";
    if (outcome) request.auditState.targetId = outcome.batchId;
    request.auditState.details = { adapter, records: result.records, events: result.events.length, accepted: outcome?.accepted ?? 0, rejected: result.rejected.length, health: report.health.status };
    return reply.status(202).send({
      adapter: result.adapter,
      adapterVersion: result.adapterVersion,
      normalization: {
        records: result.records,
        events: result.events.length,
        rejected: result.rejected.length,
        skipped: result.skipped.length,
        truncated: result.truncated,
        rejections: report.rejections,
        skips: report.skips,
      },
      report: { headline: report.headline, health: report.health, totals: report.totals, bySeverity: report.bySeverity, attack: report.attack.slice(0, 20), window: report.window },
      ingest: outcome ? summarize(outcome) : null,
    });
  });
}
