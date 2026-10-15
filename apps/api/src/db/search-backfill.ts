import path from "node:path";
import { pathToFileURL } from "node:url";
import type { CanonicalEvent } from "@bloody/contracts";
import type pg from "pg";
import type { OpenSearchEventIndex } from "../services/opensearch-events.js";

/**
 * Copy events already stored in Postgres into the search index (enabling OpenSearch on an existing
 * installation, or rebuilding the index). Idempotent: documents are keyed by tenant + event id, so
 * re-running only overwrites. Runs on the privileged connection (all tenants).
 *
 *   pnpm --filter @bloody/api search:backfill [--since 2026-01-01] [--batch 2000]
 */
export async function backfillSearchIndex(opts: {
  pool: pg.Pool;
  index: OpenSearchEventIndex;
  since?: string;
  batch?: number;
  log?: (msg: string) => void;
}): Promise<{ indexed: number }> {
  const batch = Math.min(Math.max(opts.batch ?? 2000, 1), 10_000);
  let cursor: [string, string] | null = null;
  let indexed = 0;
  for (;;) {
    const params: unknown[] = [opts.since ?? "1970-01-01T00:00:00Z", batch];
    let after = "";
    if (cursor) {
      params.push(cursor[0], cursor[1]);
      after = "AND (occurred_at, id) > ($3::timestamptz, $4::uuid)";
    }
    const { rows } = await opts.pool.query<{ tenant_id: string; organization_id: string; id: string; occurred_at: Date | string; doc: CanonicalEvent }>(
      `SELECT tenant_id, organization_id, id, occurred_at, doc FROM events WHERE occurred_at >= $1::timestamptz ${after} ORDER BY occurred_at, id LIMIT $2`,
      params,
    );
    if (rows.length === 0) break;
    const groups = new Map<string, { tenantId: string; organizationId: string; events: CanonicalEvent[] }>();
    for (const r of rows) {
      const key = `${r.tenant_id}/${r.organization_id}`;
      const g = groups.get(key) ?? { tenantId: r.tenant_id, organizationId: r.organization_id, events: [] };
      g.events.push(r.doc);
      groups.set(key, g);
    }
    for (const g of groups.values()) indexed += await opts.index.index(g.tenantId, g.organizationId, g.events);
    const last = rows[rows.length - 1]!;
    cursor = [new Date(last.occurred_at).toISOString(), last.id];
    opts.log?.(`indexed ${indexed} events (up to ${cursor[0]})`);
    if (rows.length < batch) break;
  }
  return { indexed };
}

async function main(): Promise<void> {
  const { loadDotEnv } = await import("../env-file.js");
  loadDotEnv();
  const { loadConfig } = await import("../config.js");
  const { createPool } = await import("./pool.js");
  const { OpenSearchEventIndex } = await import("../services/opensearch-events.js");
  const config = loadConfig();
  if (!config.search.opensearch) throw new Error("OPENSEARCH_URL is not set");
  const arg = (name: string) => {
    const i = process.argv.indexOf(name);
    return i > 0 ? process.argv[i + 1] : undefined;
  };
  const since = arg("--since");
  if (since && Number.isNaN(Date.parse(since))) throw new Error(`--since: invalid date "${since}"`);
  const pool = createPool({ connectionString: config.database.privilegedUrl, max: 2, applicationName: "bloody-search-backfill" });
  try {
    const index = new OpenSearchEventIndex(config.search.opensearch);
    console.log(`bloody search backfill → ${config.search.opensearch.url} (${config.search.opensearch.indexPrefix}-*)`);
    const { indexed } = await backfillSearchIndex({ pool, index, ...(since ? { since } : {}), batch: Number(arg("--batch") ?? 2000), log: (m) => console.log(`  ${m}`) });
    console.log(`done: ${indexed} events indexed`);
  } finally {
    await pool.end();
  }
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
