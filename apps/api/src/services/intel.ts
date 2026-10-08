import type { IndicatorType, Severity } from "@bloody/contracts";
import type { IndicatorRecord } from "@bloody/adapters";
import type { Database, Queryable } from "../db/pool.js";
import type { Row } from "../repo/mappers.js";
import type { DomainEventBus } from "./domain-events.js";
import type { InventoryService } from "./inventory.js";

/**
 * Threat-intelligence write path and retro-hunting.
 *
 *  - Indicator records from any source (manual, STIX bundle, MISP, OpenCTI) are upserted by
 *    their natural key (type, value, source, organization) through the inventory service, so the
 *    Security Graph stays in sync; upstream revocations deactivate the stored copy.
 *  - Retro-hunt matches active indicators against stored events (observable columns, document
 *    paths and the event's own extracted indicators) and records hits in `indicator_matches`
 *    (idempotent). New hits re-score the touched assets and raise `indicator.matched`.
 */

export interface UpsertSummary {
  received: number;
  created: number;
  updated: number;
  revoked: number;
  skipped: Array<{ ref: string; reason: string }>;
  indicatorIds: string[];
}

export interface RetroHuntResult {
  since: string;
  indicators: number;
  matches: number;
  byOrganization: Record<string, number>;
  byType: Record<string, number>;
  assetsRescored: number;
  truncated: boolean;
}

/** Event field patterns per indicator type: SQL predicate (e = events, i = indicator) + field label. */
const MATCHERS: Array<{ types: IndicatorType[]; field: string; observed: string; predicate: string }> = [
  { types: ["ip"], field: "network.srcIp", observed: "e.src_ip", predicate: "e.src_ip = i.value" },
  { types: ["ip"], field: "network.dstIp", observed: "e.dst_ip", predicate: "e.dst_ip = i.value" },
  { types: ["domain"], field: "network.dnsQuery", observed: "e.dns_query", predicate: "(lower(e.dns_query) = i.value OR lower(e.dns_query) LIKE '%.' || i.value)" },
  { types: ["domain"], field: "network.httpHost", observed: "e.doc #>> '{network,httpHost}'", predicate: "(lower(e.doc #>> '{network,httpHost}') = i.value OR lower(e.doc #>> '{network,httpHost}') LIKE '%.' || i.value)" },
  { types: ["domain"], field: "network.tlsSni", observed: "e.doc #>> '{network,tlsSni}'", predicate: "lower(e.doc #>> '{network,tlsSni}') = i.value" },
  { types: ["url"], field: "network.httpUrl", observed: "e.doc #>> '{network,httpUrl}'", predicate: "lower(e.doc #>> '{network,httpUrl}') = lower(i.value)" },
  { types: ["sha256"], field: "file.sha256", observed: "e.file_sha256", predicate: "lower(e.file_sha256) = i.value" },
  { types: ["sha256"], field: "process.hashSha256", observed: "e.doc #>> '{process,hashSha256}'", predicate: "lower(e.doc #>> '{process,hashSha256}') = i.value" },
  { types: ["md5"], field: "file.md5", observed: "e.doc #>> '{file,md5}'", predicate: "lower(e.doc #>> '{file,md5}') = i.value" },
  { types: ["email"], field: "user.email", observed: "e.doc #>> '{user,email}'", predicate: "lower(e.doc #>> '{user,email}') = i.value" },
  { types: ["ja3"], field: "network.ja3", observed: "e.doc #>> '{network,ja3}'", predicate: "lower(e.doc #>> '{network,ja3}') = i.value" },
  {
    types: ["ip", "domain", "url", "sha256", "sha1", "md5", "email", "cve", "ja3", "user_agent"],
    field: "indicators",
    observed: "i.value",
    predicate: "e.doc->'indicators' @> jsonb_build_array(jsonb_build_object('type', i.type, 'value', i.value))",
  },
];

export const RETRO_HUNT_MAX_MATCHES = 5000;

export class IntelService {
  constructor(
    private readonly db: Database,
    private readonly inventory: InventoryService,
    private readonly events: DomainEventBus,
    private readonly now: () => number,
  ) {}

  /** Upsert adapter indicator records into one scope (organization or tenant-wide). */
  async upsertRecords(tx: Queryable, tenantId: string, organizationId: string | null, records: IndicatorRecord[], opts: { sourceOverride?: string } = {}): Promise<UpsertSummary> {
    const summary: UpsertSummary = { received: records.length, created: 0, updated: 0, revoked: 0, skipped: [], indicatorIds: [] };
    const before = Number((await tx.query<{ n: string }>("SELECT count(*)::text AS n FROM indicators")).rows[0]?.n ?? 0);
    for (const r of records) {
      const source = (opts.sourceOverride ?? r.source).slice(0, 200);
      if (r.revoked) {
        const res = await tx.query(
          `UPDATE indicators SET revoked = true, expires_at = LEAST(coalesce(expires_at, now()), now())
           WHERE NOT revoked AND ((external_ref = $1) OR (type = $2 AND value = lower($3) AND source = $4 AND organization_id IS NOT DISTINCT FROM $5::uuid))`,
          [r.externalRef, r.type, r.value, source, organizationId],
        );
        summary.revoked += res.rowCount ?? 0;
        continue;
      }
      if (r.expiresAt && Date.parse(r.expiresAt) <= this.now()) {
        summary.skipped.push({ ref: r.externalRef, reason: "already expired" });
        continue;
      }
      await tx.query("SAVEPOINT intel_record");
      try {
        const row = await this.inventory.upsertIndicator(tx, tenantId, {
          organizationId,
          type: r.type,
          value: r.value,
          confidence: Math.max(0, Math.min(100, Math.round(r.confidence))),
          severity: r.severity,
          source,
          threatActor: r.threatActor,
          malware: r.malware,
          campaign: r.campaign,
          tags: r.tags.slice(0, 50),
          firstSeenAt: r.firstSeenAt,
          lastSeenAt: r.lastSeenAt,
          expiresAt: r.expiresAt,
        });
        await tx.query(
          `UPDATE indicators SET external_ref = $2, description = $3, tlp = $4, attack = $5::jsonb, scoring = $6::jsonb, revoked = false WHERE id = $1`,
          [row.id, r.externalRef.slice(0, 500), r.description, r.tlp, JSON.stringify(r.attack), JSON.stringify(r.scoring.slice(0, 20))],
        );
        await tx.query("RELEASE SAVEPOINT intel_record");
        summary.indicatorIds.push(String(row.id));
      } catch (err) {
        await tx.query("ROLLBACK TO SAVEPOINT intel_record");
        summary.skipped.push({ ref: r.externalRef, reason: err instanceof Error ? err.message.slice(0, 200) : "rejected" });
      }
    }
    const after = Number((await tx.query<{ n: string }>("SELECT count(*)::text AS n FROM indicators")).rows[0]?.n ?? 0);
    summary.created = Math.max(0, after - before);
    summary.updated = Math.max(0, summary.indicatorIds.length - summary.created);
    return summary;
  }

  /**
   * Match active indicators against stored events of the last `lookbackDays` (bounded), only in
   * the given organizations (null = all). Idempotent: hits already recorded are not counted.
   */
  async retroHunt(tenantId: string, orgs: string[] | null, opts: { indicatorIds?: string[]; lookbackDays: number; actor?: string }): Promise<RetroHuntResult> {
    const since = new Date(this.now() - opts.lookbackDays * 86_400_000).toISOString();
    const result: RetroHuntResult = { since, indicators: 0, matches: 0, byOrganization: {}, byType: {}, assetsRescored: 0, truncated: false };
    const touched = await this.db.withTenant(tenantId, async (tx) => {
      const params: unknown[] = [since];
      const indWhere = ["NOT i.revoked", "(i.expires_at IS NULL OR i.expires_at > now())"];
      if (opts.indicatorIds?.length) indWhere.push(`i.id = ANY($${params.push(opts.indicatorIds)}::uuid[])`);
      let eventOrg = "";
      if (orgs) {
        const p = params.push(orgs);
        indWhere.push(`(i.organization_id IS NULL OR i.organization_id = ANY($${p}::uuid[]))`);
        eventOrg = `AND e.organization_id = ANY($${p}::uuid[])`;
      }
      const counted = await tx.query<{ n: string }>(`SELECT count(*)::text AS n FROM indicators i WHERE ${indWhere.join(" AND ")} AND $1::timestamptz IS NOT NULL`, params);
      result.indicators = Number(counted.rows[0]?.n ?? 0);
      const assets = new Set<string>();
      for (const m of MATCHERS) {
        if (result.matches >= RETRO_HUNT_MAX_MATCHES) {
          result.truncated = true;
          break;
        }
        const remaining = RETRO_HUNT_MAX_MATCHES - result.matches;
        const typeParam = params.length + 1;
        const limitParam = params.length + 2;
        const { rows } = await tx.query<{ organization_id: string; type: string; asset_id: string | null; indicator_id: string }>(
          `WITH hits AS (
             SELECT e.tenant_id, e.organization_id, i.id AS indicator_id, i.type, e.id AS event_id, e.occurred_at, ${m.observed} AS observed,
                    (SELECT a.id FROM assets a WHERE a.organization_id = e.organization_id AND e.asset_hostname IS NOT NULL
                       AND split_part(lower(a.hostname), '.', 1) = split_part(lower(e.asset_hostname), '.', 1) LIMIT 1) AS asset_id
             FROM events e JOIN indicators i ON ${m.predicate} AND (i.organization_id IS NULL OR i.organization_id = e.organization_id)
             WHERE e.occurred_at >= $1::timestamptz ${eventOrg} AND ${indWhere.join(" AND ")} AND i.type = ANY($${typeParam}::text[])
             LIMIT $${limitParam}
           )
           INSERT INTO indicator_matches (tenant_id, organization_id, indicator_id, event_id, asset_id, observed_value, field, event_time)
           SELECT tenant_id, organization_id, indicator_id, event_id, asset_id, left(coalesce(observed, ''), 2048), $${limitParam + 1}, occurred_at FROM hits
           ON CONFLICT (tenant_id, indicator_id, event_id, field) DO NOTHING
           RETURNING organization_id, (SELECT type FROM indicators WHERE id = indicator_id) AS type, asset_id, indicator_id`,
          [...params, m.types, remaining, m.field],
        );
        for (const r of rows) {
          result.matches++;
          result.byOrganization[r.organization_id] = (result.byOrganization[r.organization_id] ?? 0) + 1;
          result.byType[r.type] = (result.byType[r.type] ?? 0) + 1;
          if (r.asset_id) assets.add(r.asset_id);
        }
      }
      if (result.matches > 0) {
        await tx.query(
          `UPDATE indicators SET last_seen_at = now() WHERE id IN (SELECT DISTINCT indicator_id FROM indicator_matches WHERE matched_at > now() - interval '5 minutes')`,
        );
        for (const id of assets) await this.inventory.scoreAsset(tx, tenantId, id);
      }
      return assets;
    });
    result.assetsRescored = touched.size;
    for (const [organizationId, n] of Object.entries(result.byOrganization)) {
      this.events.publish({
        tenantId,
        organizationId,
        event: "indicator.matched",
        occurredAt: new Date(this.now()).toISOString(),
        severity: "high",
        subject: { kind: "organization", id: organizationId },
        dedupKey: `retro-hunt:${organizationId}:${new Date(this.now()).toISOString().slice(0, 13)}`,
        data: { matches: n, source: "retro_hunt", since, byType: result.byType },
        ...(opts.actor ? { initiatedBy: { kind: "user" as const, id: opts.actor } } : {}),
      });
    }
    return result;
  }
}

export function indicatorSeverityRank(s: Severity): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s];
}

export type { Row };
