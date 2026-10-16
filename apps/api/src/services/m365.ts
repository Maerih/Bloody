import { Resolver } from "node:dns/promises";
import { collectM365, createGraphClient, evaluateM365, GraphError, scoreM365, type DnsResolver } from "@bloody/adapters";
import type { M365Assessment, M365CheckResult, M365Connection, M365ConnectionInput } from "@bloody/contracts";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { SecretStore } from "./secret-store.js";

const iso = (v: unknown) => (v ? new Date(String(v)).toISOString() : null);
export const M365_REASSESS_HOURS = 24;

export function toConnection(r: Row): M365Connection {
  return {
    id: String(r.id),
    organizationId: String(r.organization_id),
    directoryTenantId: String(r.directory_tenant_id),
    clientId: String(r.client_id),
    displayName: (r.display_name as string | null) ?? null,
    status: r.status as M365Connection["status"],
    lastError: (r.last_error as string | null) ?? null,
    lastAssessedAt: iso(r.last_assessed_at),
    lastScore: r.last_score === null || r.last_score === undefined ? null : Number(r.last_score),
    createdAt: iso(r.created_at)!,
  };
}

function toAssessment(r: Row): M365Assessment {
  return {
    id: String(r.id),
    connectionId: String(r.connection_id),
    organizationId: String(r.organization_id),
    tenantName: (r.tenant_name as string | null) ?? null,
    startedAt: iso(r.started_at)!,
    finishedAt: iso(r.finished_at)!,
    score: Number(r.score),
    counts: r.counts as M365Assessment["counts"],
    results: r.results as M365CheckResult[],
  };
}

/** Public DNS lookups for SPF / DKIM / DMARC (short timeouts, a couple of public resolvers as fallback). */
export function systemDnsResolver(): DnsResolver {
  const r = new Resolver({ timeout: 4000, tries: 2 });
  return { resolveTxt: (n) => r.resolveTxt(n), resolveCname: (n) => r.resolveCname(n) };
}

/** Microsoft 365 hardening: read-only Graph connection per organization and its assessments. */
export class M365Service {
  constructor(
    private readonly deps: { db: Database; secrets: SecretStore; fetch: typeof fetch; dns: DnsResolver; now: () => number },
  ) {}

  async connection(tx: Queryable, organizationId: string): Promise<M365Connection | null> {
    const { rows } = await tx.query<Row>("SELECT * FROM m365_connections WHERE organization_id = $1", [organizationId]);
    return rows[0] ? toConnection(rows[0]) : null;
  }

  async latest(tx: Queryable, organizationId: string): Promise<M365Assessment | null> {
    const { rows } = await tx.query<Row>("SELECT * FROM m365_assessments WHERE organization_id = $1 ORDER BY finished_at DESC LIMIT 1", [organizationId]);
    return rows[0] ? toAssessment(rows[0]) : null;
  }

  async history(tx: Queryable, organizationId: string, limit = 30): Promise<Array<{ id: string; finishedAt: string; score: number }>> {
    const { rows } = await tx.query<Row>("SELECT id, finished_at, score FROM m365_assessments WHERE organization_id = $1 ORDER BY finished_at DESC LIMIT $2", [organizationId, limit]);
    return rows.map((r) => ({ id: String(r.id), finishedAt: iso(r.finished_at)!, score: Number(r.score) }));
  }

  /** Save (or replace) the organization's connection; the client secret goes to the sealed store. */
  async connect(tx: Queryable, tenantId: string, input: M365ConnectionInput, actor: string): Promise<M365Connection> {
    const secret = await this.deps.secrets.put(tx, tenantId, { value: input.clientSecret, name: "Microsoft 365 app secret", purpose: "m365.client_secret", organizationId: input.organizationId, createdBy: actor });
    const previous = await tx.query<Row>("SELECT credential_ref FROM m365_connections WHERE organization_id = $1", [input.organizationId]);
    const { rows } = await tx.query<Row>(
      `INSERT INTO m365_connections (tenant_id, organization_id, directory_tenant_id, client_id, credential_ref, status, created_by)
       VALUES ($1, $2, $3, $4, $5, 'pending', $6)
       ON CONFLICT (organization_id) DO UPDATE SET directory_tenant_id = EXCLUDED.directory_tenant_id, client_id = EXCLUDED.client_id,
         credential_ref = EXCLUDED.credential_ref, status = 'pending', last_error = NULL
       RETURNING *`,
      [tenantId, input.organizationId, input.directoryTenantId, input.clientId, secret.ref, actor],
    );
    const old = previous.rows[0]?.credential_ref as string | undefined;
    if (old && old !== secret.ref) await this.deps.secrets.delete(tx, old);
    return toConnection(rows[0]!);
  }

  async disconnect(tx: Queryable, id: string): Promise<M365Connection> {
    const { rows } = await tx.query<Row>("DELETE FROM m365_connections WHERE id = $1 RETURNING *", [id]);
    if (!rows[0]) throw notFound("Microsoft 365 connection");
    await this.deps.secrets.delete(tx, String(rows[0].credential_ref));
    return toConnection(rows[0]);
  }

  /** Read the tenant, grade it, store the assessment. Sign-in failures mark the connection as errored. */
  async assess(tenantId: string, connectionId: string): Promise<M365Assessment> {
    const conn = await this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM m365_connections WHERE id = $1", [connectionId]);
      if (!rows[0]) throw notFound("Microsoft 365 connection");
      const secret = await this.deps.secrets.resolve(tx, tenantId, String(rows[0].credential_ref));
      if (secret === null) throw new HttpError(409, "credential_missing", "The Microsoft 365 app secret is missing — reconnect the tenant");
      return { row: rows[0], secret };
    });
    const started = new Date(this.deps.now()).toISOString();
    const graph = createGraphClient({ directoryTenantId: String(conn.row.directory_tenant_id), clientId: String(conn.row.client_id), clientSecret: conn.secret, fetch: this.deps.fetch, now: this.deps.now });
    try {
      // Fail fast on a bad app registration before collecting everything.
      await graph.get("/organization?$select=id");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE m365_connections SET status = 'error', last_error = $2 WHERE id = $1", [connectionId, message.slice(0, 1000)]));
      throw new HttpError(err instanceof GraphError && err.isPermission ? 400 : 502, "m365_connection_failed", message);
    }
    const snapshot = await collectM365(graph, { dns: this.deps.dns, now: this.deps.now });
    const results = evaluateM365(snapshot);
    const { score, counts } = scoreM365(results);
    const tenantName = snapshot.organization.ok ? snapshot.organization.data.displayName : null;
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        `INSERT INTO m365_assessments (tenant_id, organization_id, connection_id, tenant_name, started_at, finished_at, score, counts, results)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb) RETURNING *`,
        [tenantId, conn.row.organization_id, connectionId, tenantName, started, new Date(this.deps.now()).toISOString(), score, JSON.stringify(counts), JSON.stringify(results)],
      );
      await tx.query("UPDATE m365_connections SET status = 'connected', last_error = NULL, display_name = coalesce($2, display_name), last_assessed_at = now(), last_score = $3 WHERE id = $1", [connectionId, tenantName, score]);
      return toAssessment(rows[0]!);
    });
  }

  /** Scheduler: re-assess every connection not assessed in the last day. */
  async assessDue(tenantId: string): Promise<number> {
    const due = await this.deps.db.withTenant(tenantId, async (tx) =>
      (await tx.query<Row>(`SELECT id FROM m365_connections WHERE status <> 'error' AND (last_assessed_at IS NULL OR last_assessed_at < now() - make_interval(hours => $1))`, [M365_REASSESS_HOURS])).rows,
    );
    let n = 0;
    for (const r of due) {
      try {
        await this.assess(tenantId, String(r.id));
        n++;
      } catch {
        // Recorded on the connection (status / last_error); the next tick tries the others.
      }
    }
    return n;
  }
}
