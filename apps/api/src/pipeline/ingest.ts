import { randomUUID } from "node:crypto";
import { BCE_SCHEMA_VERSION, CanonicalEvent, IngestEvent, type CanonicalEvent as CanonicalEventT } from "@bloody/contracts";
import type { Database, Queryable } from "../db/pool.js";
import type { Metrics } from "../metrics.js";
import { TOPICS, type EventBus } from "./event-bus.js";

/**
 * Ingest service: validation → server-side tenancy → durable storage → data fabric.
 *
 *  - Each record is validated against the contract `IngestEvent`; invalid records are rejected
 *    individually with zod issues (the rest of the batch is accepted).
 *  - Ids are kept when supplied (adapters derive deterministic ids per tenant) so redelivery
 *    is idempotent: an already-stored (tenant, id, time) is reported as a duplicate and NOT
 *    re-published to the pipeline.
 *  - tenantId/organizationId always come from the authenticated principal, never the body.
 */

export interface IngestRejection {
  index: number;
  errors: Array<{ path: string; message: string }>;
}

export interface IngestOutcome {
  batchId: string;
  organizationId: string;
  received: number;
  accepted: number;
  duplicates: number;
  rejected: IngestRejection[];
  eventIds: string[];
}

export interface IngestBatchMessage {
  batchId: string;
  tenantId: string;
  organizationId: string;
  source: string;
  receivedAt: string;
  events: CanonicalEventT[];
}

const PUBLISH_CHUNK = 1000;

export class IngestService {
  constructor(
    private readonly db: Database,
    private readonly bus: EventBus,
    private readonly metrics: Metrics,
    private readonly opts: { maxBatch: number; maxEventAgeDays: number },
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** Validate + assign tenancy. Pure (no I/O) so the adapter path can reuse it. */
  prepare(tenantId: string, organizationId: string, records: readonly unknown[], receivedAt: string): { events: CanonicalEventT[]; rejected: IngestRejection[] } {
    const events: CanonicalEventT[] = [];
    const rejected: IngestRejection[] = [];
    const nowMs = this.now();
    const oldest = nowMs - this.opts.maxEventAgeDays * 86_400_000;
    const newest = nowMs + 5 * 60_000; // tolerate 5 minutes of sensor clock skew
    const seen = new Set<string>();
    records.forEach((raw, index) => {
      // Custom API producers may omit provenance; the platform then records itself as the adapter.
      const withProvenance =
        raw && typeof raw === "object" && !Array.isArray(raw) && (raw as Record<string, unknown>).provenance === undefined
          ? { ...(raw as Record<string, unknown>), provenance: { adapter: "api", adapterVersion: "1", receivedAt } }
          : raw;
      const parsed = IngestEvent.safeParse(withProvenance);
      if (!parsed.success) {
        rejected.push({ index, errors: parsed.error.issues.slice(0, 20).map((i) => ({ path: i.path.join("."), message: i.message })) });
        return;
      }
      const ts = Date.parse(parsed.data.timestamp);
      if (ts < oldest || ts > newest) {
        rejected.push({ index, errors: [{ path: "timestamp", message: ts > newest ? "timestamp is in the future" : `timestamp is older than ${this.opts.maxEventAgeDays} days` }] });
        return;
      }
      const id = parsed.data.id ?? randomUUID();
      if (seen.has(id)) {
        rejected.push({ index, errors: [{ path: "id", message: "duplicate id within the batch" }] });
        return;
      }
      seen.add(id);
      const candidate = {
        ...parsed.data,
        schemaVersion: BCE_SCHEMA_VERSION,
        id,
        tenantId,
        organizationId,
        timestamp: new Date(ts).toISOString(),
        provenance: parsed.data.provenance,
      };
      const full = CanonicalEvent.safeParse(candidate);
      if (!full.success) {
        rejected.push({ index, errors: full.error.issues.slice(0, 20).map((i) => ({ path: i.path.join("."), message: i.message })) });
        return;
      }
      events.push(full.data);
    });
    return { events, rejected };
  }

  async ingest(tenantId: string, organizationId: string, records: readonly unknown[], source: string): Promise<IngestOutcome> {
    const receivedAt = new Date(this.now()).toISOString();
    const batchId = randomUUID();
    const { events, rejected } = this.prepare(tenantId, organizationId, records, receivedAt);
    const inserted = events.length === 0 ? new Set<string>() : await this.db.withTenant(tenantId, (tx) => this.store(tx, tenantId, organizationId, events));
    const fresh = events.filter((e) => inserted.has(e.id));
    if (fresh.length > 0) {
      for (let i = 0; i < fresh.length; i += PUBLISH_CHUNK) {
        const message: IngestBatchMessage = { batchId, tenantId, organizationId, source, receivedAt, events: fresh.slice(i, i + PUBLISH_CHUNK) };
        await this.bus.publish(TOPICS.eventsIngested, tenantId, message);
      }
      this.metrics.ingestBatches.inc({ source });
    }
    this.metrics.ingestEvents.inc({ result: "accepted", source }, fresh.length);
    this.metrics.ingestEvents.inc({ result: "duplicate", source }, events.length - fresh.length);
    this.metrics.ingestEvents.inc({ result: "rejected", source }, rejected.length);
    return { batchId, organizationId, received: records.length, accepted: fresh.length, duplicates: events.length - fresh.length, rejected, eventIds: fresh.map((e) => e.id) };
  }

  /** Bulk insert (unnest of column arrays: ~30 parameters regardless of batch size). */
  private async store(tx: Queryable, tenantId: string, organizationId: string, events: CanonicalEventT[]): Promise<Set<string>> {
    const months = new Set(events.map((e) => e.timestamp.slice(0, 7)));
    for (const m of months) await tx.query("SELECT ensure_events_partition($1::timestamptz)", [`${m}-01T00:00:00Z`]);
    const col = <T>(f: (e: CanonicalEventT) => T) => events.map(f);
    const { rows } = await tx.query<{ id: string }>(
      `INSERT INTO events (tenant_id, organization_id, id, occurred_at, received_at, category, event_type, action, outcome, severity, risk,
                           source_kind, source_product, sensor_id, integration_id, asset_hostname, user_name, identity_principal,
                           src_ip, dst_ip, dns_query, process_name, file_sha256, detection_rule, attack_ids, doc)
       SELECT $1::uuid, $2::uuid, u.id, u.occurred_at, u.received_at, u.category, u.event_type, u.action, u.outcome, u.severity, u.risk,
              u.source_kind, u.source_product, u.sensor_id, u.integration_id, u.asset_hostname, u.user_name, u.identity_principal,
              u.src_ip, u.dst_ip, u.dns_query, u.process_name, u.file_sha256, u.detection_rule,
              CASE WHEN u.attack_ids = '' THEN '{}'::text[] ELSE string_to_array(u.attack_ids, ',') END, u.doc
       FROM unnest($3::uuid[], $4::timestamptz[], $5::timestamptz[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::numeric[],
                   $12::text[], $13::text[], $14::text[], $15::uuid[], $16::text[], $17::text[], $18::text[],
                   $19::text[], $20::text[], $21::text[], $22::text[], $23::text[], $24::text[], $25::text[], $26::jsonb[])
            AS u(id, occurred_at, received_at, category, event_type, action, outcome, severity, risk,
                 source_kind, source_product, sensor_id, integration_id, asset_hostname, user_name, identity_principal,
                 src_ip, dst_ip, dns_query, process_name, file_sha256, detection_rule, attack_ids, doc)
       ON CONFLICT (tenant_id, id, occurred_at) DO NOTHING
       RETURNING id`,
      [
        tenantId,
        organizationId,
        col((e) => e.id),
        col((e) => e.timestamp),
        col((e) => e.provenance.receivedAt),
        col((e) => e.category),
        col((e) => e.eventType),
        col((e) => e.action ?? null),
        col((e) => e.outcome ?? e.identity?.outcome ?? null),
        col((e) => e.severity),
        col((e) => e.risk ?? null),
        col((e) => e.source.kind),
        col((e) => e.source.product),
        col((e) => e.source.sensorId ?? null),
        col((e) => e.source.integrationId ?? null),
        col((e) => e.asset?.hostname ?? null),
        col((e) => (e.user?.name ? (e.user.domain ? `${e.user.domain}\\${e.user.name}` : e.user.name) : (e.user?.email ?? null))),
        col((e) => e.identity?.principal ?? null),
        col((e) => e.network?.srcIp ?? e.identity?.sourceIp ?? null),
        col((e) => e.network?.dstIp ?? null),
        col((e) => e.network?.dnsQuery ?? null),
        col((e) => e.process?.name ?? (e.process?.path ? e.process.path.split(/[\\/]/).pop() ?? null : null)),
        col((e) => e.file?.sha256 ?? e.process?.hashSha256 ?? null),
        col((e) => e.detection?.ruleName ?? e.detection?.ruleId ?? null),
        col((e) => e.attack.map((t) => t.id).join(",")),
        col((e) => JSON.stringify(e)),
      ],
    );
    await tx.query(
      `INSERT INTO usage_counters (tenant_id, organization_id, metric, period_start, value) VALUES ($1, $2, 'events_ingested', (now() AT TIME ZONE 'UTC')::date, $3)
       ON CONFLICT (tenant_id, org_key(organization_id), metric, period_start) DO UPDATE SET value = usage_counters.value + EXCLUDED.value`,
      [tenantId, organizationId, rows.length],
    );
    return new Set(rows.map((r) => r.id));
  }
}
