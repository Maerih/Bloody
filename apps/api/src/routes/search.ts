import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Uuid, type Permission, type Severity } from "@bloody/contracts";
import { orgScopeFor, requireAuth } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { Limit, csvOf, likePattern } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { parse } from "./util.js";

const KINDS = ["incident", "alert", "investigation", "asset", "identity", "vulnerability", "indicator", "observable"] as const;
type SearchKind = (typeof KINDS)[number];

const PERMISSION: Record<SearchKind, Permission> = {
  incident: "incident:read",
  alert: "alert:read",
  investigation: "investigation:read",
  asset: "asset:read",
  identity: "identity:read",
  vulnerability: "vuln:read",
  indicator: "intel:read",
  observable: "graph:read",
};

/** Security Graph node kinds searchable as observables / threat context. */
const OBSERVABLE_NODE_KINDS = ["ip", "domain", "url", "hash", "certificate", "threat_actor", "malware", "campaign", "cloud_asset", "application", "saas_app", "process", "file"];

const Query = z.object({
  q: z.string().trim().min(2).max(200),
  organizationId: Uuid.optional(),
  kinds: csvOf(z.enum(KINDS)).optional(),
  limit: Limit(50, 25),
});

export interface SearchHitView {
  kind: string;
  id: string;
  title: string;
  subtitle: string | null;
  organizationId: string | null;
  organizationName: string | null;
  severity: Severity | null;
  /** 0 = exact match, 1 = prefix, 2 = contains — lower is better. */
  match: number;
  at: string | null;
}

interface KindQuery {
  sql: (orgClause: string, p: { exact: string; prefix: string; contains: string; num: string }) => string;
  map: (r: Row) => Omit<SearchHitView, "match" | "organizationName"> & { organizationName?: string | null };
  /** Tenant-shared rows (organization_id NULL) are visible to anyone holding the permission. */
  sharedRows?: boolean;
}

const sev = (v: unknown): Severity | null => (typeof v === "string" && ["info", "low", "medium", "high", "critical"].includes(v) ? (v as Severity) : null);
const str = (v: unknown): string | null => (v === null || v === undefined ? null : String(v));

const MATCH = (cols: string[], p: { exact: string; prefix: string }) =>
  `(CASE WHEN ${cols.map((c) => `lower(${c}) = ${p.exact}`).join(" OR ")} THEN 0 WHEN ${cols.map((c) => `${c} ILIKE ${p.prefix}`).join(" OR ")} THEN 1 ELSE 2 END)`;

const QUERIES: Record<SearchKind, KindQuery> = {
  incident: {
    sql: (org, p) => `SELECT i.id, i.title, i.number, i.severity, i.status, i.organization_id, o.name AS org_name, i.detected_at AS at,
        CASE WHEN i.number::text = ${p.num} THEN 0 ELSE ${MATCH(["i.title"], p)} END AS match
      FROM incidents i JOIN organizations o ON o.id = i.organization_id
      WHERE ${org} AND i.merged_into IS NULL AND (i.title ILIKE ${p.contains} OR i.number::text = ${p.num})`,
    map: (r) => ({ kind: "incident", id: String(r.id), title: `#${String(r.number)} ${String(r.title)}`, subtitle: `Incident · ${String(r.status)}`, organizationId: str(r.organization_id), severity: sev(r.severity), at: str(r.at) }),
  },
  alert: {
    sql: (org, p) => `SELECT a.id, a.title, a.rule_id, a.severity, a.status, a.organization_id, o.name AS org_name, a.last_seen_at AS at, ${MATCH(["a.title", "a.rule_id"], p)} AS match
      FROM alerts a JOIN organizations o ON o.id = a.organization_id
      WHERE ${org} AND (a.title ILIKE ${p.contains} OR a.rule_id ILIKE ${p.contains})`,
    map: (r) => ({ kind: "alert", id: String(r.id), title: String(r.title), subtitle: `Alert · ${str(r.rule_id) ?? "detection"} · ${String(r.status)}`, organizationId: str(r.organization_id), severity: sev(r.severity), at: str(r.at) }),
  },
  investigation: {
    sql: (org, p) => `SELECT v.id, v.title, v.status, v.organization_id, o.name AS org_name, v.updated_at AS at, ${MATCH(["v.title"], p)} AS match
      FROM investigations v JOIN organizations o ON o.id = v.organization_id
      WHERE ${org} AND (v.title ILIKE ${p.contains} OR v.hypothesis ILIKE ${p.contains})`,
    map: (r) => ({ kind: "investigation", id: String(r.id), title: String(r.title), subtitle: `Investigation · ${String(r.status)}`, organizationId: str(r.organization_id), severity: null, at: str(r.at) }),
  },
  asset: {
    sql: (org, p) => `SELECT a.id, a.name, a.hostname, a.kind, a.criticality, a.ip_addresses, a.risk_score, a.organization_id, o.name AS org_name, a.last_seen_at AS at,
        CASE WHEN lower(${p.exact}) = ANY(a.ip_addresses) THEN 0 ELSE ${MATCH(["a.name", "a.hostname"], p)} END AS match
      FROM assets a JOIN organizations o ON o.id = a.organization_id
      WHERE ${org} AND (a.name ILIKE ${p.contains} OR a.hostname ILIKE ${p.contains} OR ${p.exact} = ANY(a.ip_addresses)
        OR EXISTS (SELECT 1 FROM unnest(a.ip_addresses) ip WHERE ip LIKE ${p.prefix}))`,
    map: (r) => ({
      kind: "asset",
      id: String(r.id),
      title: String(r.name),
      subtitle: [String(r.kind).replace("_", " "), str(r.hostname), (r.ip_addresses as string[] | null)?.[0] ?? null, r.criticality === "crown_jewel" ? "crown jewel" : null].filter(Boolean).join(" · "),
      organizationId: str(r.organization_id),
      severity: r.risk_score === null ? null : Number(r.risk_score) >= 90 ? "critical" : Number(r.risk_score) >= 70 ? "high" : Number(r.risk_score) >= 40 ? "medium" : "low",
      at: str(r.at),
    }),
  },
  identity: {
    sql: (org, p) => `SELECT i.id, i.principal, i.display_name, i.provider, i.kind, i.privileged, i.risk_score, i.organization_id, o.name AS org_name, i.last_activity_at AS at,
        ${MATCH(["i.principal", "i.display_name"], p)} AS match
      FROM identities i JOIN organizations o ON o.id = i.organization_id
      WHERE ${org} AND (i.principal ILIKE ${p.contains} OR i.display_name ILIKE ${p.contains})`,
    map: (r) => ({
      kind: "identity",
      id: String(r.id),
      title: String(r.display_name ?? r.principal),
      subtitle: [String(r.principal), String(r.provider), r.privileged ? "privileged" : null].filter(Boolean).join(" · "),
      organizationId: str(r.organization_id),
      severity: r.risk_score === null ? null : Number(r.risk_score) >= 90 ? "critical" : Number(r.risk_score) >= 70 ? "high" : Number(r.risk_score) >= 40 ? "medium" : "low",
      at: str(r.at),
    }),
  },
  vulnerability: {
    sql: (org, p) => `SELECT v.id, v.cve, v.title, v.severity, v.status, v.known_exploited, v.organization_id, o.name AS org_name, a.name AS asset_name, v.last_seen_at AS at,
        ${MATCH(["v.cve", "v.title"], p)} AS match
      FROM vulnerabilities v JOIN organizations o ON o.id = v.organization_id JOIN assets a ON a.id = v.asset_id
      WHERE ${org} AND (v.cve ILIKE ${p.contains} OR v.title ILIKE ${p.contains})`,
    map: (r) => ({
      kind: "vulnerability",
      id: String(r.id),
      title: r.cve ? `${String(r.cve)} — ${String(r.title)}` : String(r.title),
      subtitle: [`on ${String(r.asset_name)}`, String(r.status), r.known_exploited ? "known exploited (KEV)" : null].filter(Boolean).join(" · "),
      organizationId: str(r.organization_id),
      severity: sev(r.severity),
      at: str(r.at),
    }),
  },
  indicator: {
    sharedRows: true,
    sql: (org, p) => `SELECT x.id, x.type, x.value, x.severity, x.source, x.threat_actor, x.malware, x.campaign, x.organization_id, o.name AS org_name, x.last_seen_at AS at,
        ${MATCH(["x.value", "x.threat_actor", "x.malware", "x.campaign"], p)} AS match
      FROM indicators x LEFT JOIN organizations o ON o.id = x.organization_id
      WHERE ${org} AND (x.value ILIKE ${p.contains} OR x.threat_actor ILIKE ${p.contains} OR x.malware ILIKE ${p.contains} OR x.campaign ILIKE ${p.contains})`,
    map: (r) => ({
      kind: "indicator",
      id: String(r.id),
      title: String(r.value),
      subtitle: [`${String(r.type)} indicator`, str(r.threat_actor), str(r.malware), str(r.campaign), `source ${String(r.source)}`].filter(Boolean).join(" · "),
      organizationId: str(r.organization_id),
      organizationName: r.organization_id ? str(r.org_name) : "All organizations",
      severity: sev(r.severity),
      at: str(r.at),
    }),
  },
  observable: {
    sharedRows: true,
    sql: (org, p) => `SELECT g.id, g.kind, g.key, g.label, g.organization_id, o.name AS org_name, g.updated_at AS at, ${MATCH(["g.key", "g.label"], p)} AS match
      FROM graph_nodes g LEFT JOIN organizations o ON o.id = g.organization_id
      WHERE ${org} AND g.kind = ANY('{${OBSERVABLE_NODE_KINDS.join(",")}}'::text[]) AND (g.key ILIKE ${p.contains} OR g.label ILIKE ${p.contains})`,
    map: (r) => ({
      kind: String(r.kind),
      id: String(r.id),
      title: String(r.label),
      subtitle: `${String(r.kind).replace("_", " ")} in the Security Graph`,
      organizationId: str(r.organization_id),
      organizationName: r.organization_id ? str(r.org_name) : "All organizations",
      severity: null,
      at: str(r.at),
    }),
  },
};

async function searchKind(tx: Queryable, kind: SearchKind, term: string, orgs: "all" | string[], limit: number): Promise<SearchHitView[]> {
  const spec = QUERIES[kind];
  // Placeholders are bound lazily so a query only declares the parameters it references.
  const params: unknown[] = [];
  const bound = new Map<string, string>();
  const ph = (key: string, value: unknown): string => {
    let placeholder = bound.get(key);
    if (!placeholder) {
      params.push(value);
      placeholder = `$${params.length}`;
      bound.set(key, placeholder);
    }
    return placeholder;
  };
  const p = {
    get exact() {
      return ph("exact", term.toLowerCase());
    },
    get prefix() {
      return ph("prefix", likePattern(term, "prefix"));
    },
    get contains() {
      return ph("contains", likePattern(term));
    },
    get num() {
      return ph("num", term.replace(/^(#|inc-)/i, ""));
    },
  };
  const alias = { incident: "i", alert: "a", investigation: "v", asset: "a", identity: "i", vulnerability: "v", indicator: "x", observable: "g" }[kind];
  let orgClause = "TRUE";
  if (orgs !== "all") {
    const o = ph("orgs", orgs);
    orgClause = spec.sharedRows ? `(${alias}.organization_id = ANY(${o}::uuid[]) OR ${alias}.organization_id IS NULL)` : `${alias}.organization_id = ANY(${o}::uuid[])`;
  }
  const body = spec.sql(orgClause, p);
  const sql = `${body} ORDER BY match, at DESC NULLS LAST LIMIT ${ph("limit", limit)}`;
  const { rows } = await tx.query<Row>(sql, params);
  return rows.map((r) => {
    const hit = spec.map(r);
    return { ...hit, organizationName: hit.organizationName !== undefined ? hit.organizationName : str(r.org_name), match: Number(r.match ?? 2) };
  });
}

/**
 * GET /search?q= — tenant- and permission-aware global search. Each entity kind is searched
 * only within the organizations where the caller holds that kind's read permission.
 */
export async function searchRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/search", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(Query, request.query);
    const kinds = q.kinds?.length ? q.kinds : [...KINDS];
    const plan: Array<{ kind: SearchKind; orgs: "all" | string[] }> = [];
    for (const kind of kinds) {
      let scope = orgScopeFor(auth, PERMISSION[kind]);
      if (q.organizationId) {
        if (scope !== "all" && !scope.includes(q.organizationId)) continue;
        scope = [q.organizationId];
      }
      if (scope !== "all" && scope.length === 0) continue;
      plan.push({ kind, orgs: scope });
    }
    const results = await s.db.withTenant(auth.tenantId, async (tx) => {
      const out: SearchHitView[] = [];
      for (const p of plan) out.push(...(await searchKind(tx, p.kind, q.q, p.orgs, q.limit)));
      return out;
    });
    const priority: Record<string, number> = { incident: 0, asset: 1, identity: 2, alert: 3, indicator: 4, vulnerability: 5, investigation: 6 };
    const items = results
      .sort((a, b) => a.match - b.match || (priority[a.kind] ?? 9) - (priority[b.kind] ?? 9) || (b.at ?? "").localeCompare(a.at ?? ""))
      .slice(0, q.limit);
    const byKind: Record<string, number> = {};
    for (const r of results) byKind[r.kind] = (byKind[r.kind] ?? 0) + 1;
    return { query: q.q, items, total: results.length, byKind, searchedKinds: plan.map((p) => p.kind) };
  });
}
