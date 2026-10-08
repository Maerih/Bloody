import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Uuid } from "@bloody/contracts";
import { requireAuth, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { badRequest } from "../http/errors.js";
import { EventFilter, resolveRange } from "../services/event-search.js";
import { QueryBool, parse } from "./util.js";

const Common = {
  organizationId: Uuid.optional(),
  q: z.string().max(4000).optional(),
  text: z.string().trim().max(500).optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  range: z.string().regex(/^\d{1,4}[mhd]$/).optional(),
  order: z.enum(["desc", "asc"]).default("desc"),
  cursor: z.string().max(500).optional(),
};

const GetQuery = z.object({
  ...Common,
  /** JSON-encoded structured filters `[{field, op, value}]` (query builder). */
  filters: z.string().max(20_000).optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(100),
  count: QueryBool.optional(),
  aggs: z.string().max(500).optional(),
});

const PostBody = z
  .object({
    ...Common,
    filters: z.array(EventFilter).max(50).default([]),
    limit: z.number().int().min(1).max(1000).default(100),
    count: z.boolean().default(false),
    aggs: z.array(z.string().max(200)).max(8).default([]),
  })
  .strict();

function parseFilters(raw: string | undefined): EventFilter[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw badRequest("filters must be a JSON array of {field, op, value}");
  }
  const r = z.array(EventFilter).max(50).safeParse(parsed);
  if (!r.success) throw badRequest("filters must be a JSON array of {field, op, value}", r.error.issues.slice(0, 10));
  return r.data;
}

/**
 * SIEM event search: Bloody query language (`q`), structured filters, full text over the event
 * message, time range (absolute or relative `range`), keyset pagination and optional top-N
 * aggregations. Tenant-scoped by RLS and limited to the caller's organizations.
 */
export async function eventRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const run = async (tenantId: string, orgs: string[] | null, input: {
    q?: string | undefined;
    text?: string | undefined;
    filters: EventFilter[];
    from?: string | undefined;
    to?: string | undefined;
    range?: string | undefined;
    order: "asc" | "desc";
    cursor?: string | undefined;
    limit: number;
    count: boolean;
    aggs: string[];
  }) => {
    const range = resolveRange(input, s.now());
    const base = { q: input.q, text: input.text, filters: input.filters, from: range.from, to: range.to, order: input.order };
    const result = await s.eventSearch.search(tenantId, orgs, { ...base, limit: input.limit, cursor: input.cursor }, { count: input.count });
    const aggregations = input.aggs.length > 0 ? await s.eventSearch.aggregate(tenantId, orgs, base, input.aggs) : undefined;
    return { ...result, ...(aggregations ? { aggregations } : {}) };
  };

  app.get("/events/search", { config: { module: "siem" } }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(GetQuery, request.query);
    const orgs = resolveOrgFilter(request, "event:read", q.organizationId);
    return run(auth.tenantId, orgs, {
      q: q.q,
      text: q.text,
      filters: parseFilters(q.filters),
      from: q.from,
      to: q.to,
      range: q.range,
      order: q.order,
      cursor: q.cursor,
      limit: q.limit,
      count: q.count ?? false,
      aggs: q.aggs ? q.aggs.split(",").map((a) => a.trim()).filter(Boolean) : [],
    });
  });

  // POST variant for long structured queries (no audit row: it is a read).
  app.post("/events/search", { config: { module: "siem", audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const body = parse(PostBody, request.body);
    const orgs = resolveOrgFilter(request, "event:read", body.organizationId);
    request.auditState.recorded = true;
    return run(auth.tenantId, orgs, body);
  });
}
