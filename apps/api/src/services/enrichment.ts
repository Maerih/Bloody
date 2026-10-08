import { maxSeverity, type Severity } from "@bloody/contracts";
import { createEpssClient, createKevClient, enrichCve, fetchEpssScores, fetchKevCatalog, type EpssTable, type FetchLike as EngineFetch, type HostResolver as EngineHostResolver, type KevCatalog } from "@bloody/adapters";
import { BufferingSink, automationEventFor, type EngineNotification } from "@bloody/engines";
import type { EnrichmentConfig } from "../config.js";
import type { Database } from "../db/pool.js";
import { HttpError } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { DomainEventBus } from "./domain-events.js";
import type { InventoryService } from "./inventory.js";

/**
 * Vulnerability enrichment from public, key-less feeds: CISA Known Exploited Vulnerabilities and
 * FIRST EPSS. Behind the FEATURE_VULN_ENRICHMENT flag; outbound requests go only to the
 * allow-listed hosts over https with the SSRF guard (DNS-checked). The KEV catalog is public
 * data and is cached process-wide; EPSS scores are fetched only for the tenant's open CVEs.
 * Enrichment only raises evidence (KEV can turn known-exploited on, never off) and re-scores
 * through the inventory service, which re-prioritizes and emits `vulnerability.kev_detected`.
 */

export type EnrichmentSource = "cisa_kev" | "first_epss";
export const ENRICHMENT_SOURCES: readonly EnrichmentSource[] = ["cisa_kev", "first_epss"];
const KEV_TTL_MS = 6 * 3_600_000;
const MAX_CVES = 5000;

export interface EnrichmentStats {
  vulnerabilitiesScanned: number;
  cves: number;
  updated: number;
  newlyKnownExploited: number;
  epssScored: number;
  severityRaised: number;
  kevCatalog: { entries: number; fetchedAt: string } | null;
}

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export class EnrichmentService {
  private kev: { at: number; catalog: KevCatalog } | null = null;

  constructor(
    private readonly deps: {
      db: Database;
      inventory: InventoryService;
      events: DomainEventBus;
      enabled: boolean;
      config: EnrichmentConfig;
      fetch: EngineFetch;
      resolveHost: EngineHostResolver | false | undefined;
      now: () => number;
    },
  ) {}

  get enabled(): boolean {
    return this.deps.enabled;
  }

  private clientOpts(url: string) {
    const u = new URL(url);
    return {
      baseUrl: u.origin,
      fetch: this.deps.fetch,
      urlPolicy: { allowedHosts: this.deps.config.allowedHosts, allowHttp: false, allowPrivateNetworks: false, allowLoopback: false },
      ...(this.deps.resolveHost !== undefined ? { resolveHost: this.deps.resolveHost } : {}),
      timeoutMs: 60_000,
      retries: 2,
    };
  }

  private async kevCatalog(): Promise<{ catalog: KevCatalog; fetchedAt: number }> {
    if (this.kev && this.deps.now() - this.kev.at < KEV_TTL_MS) return { catalog: this.kev.catalog, fetchedAt: this.kev.at };
    const url = new URL(this.deps.config.kevFeedUrl);
    const catalog = await fetchKevCatalog(createKevClient(this.clientOpts(url.toString())), url.pathname);
    this.kev = { at: this.deps.now(), catalog };
    return { catalog, fetchedAt: this.kev.at };
  }

  private async epss(cves: string[]): Promise<EpssTable> {
    return fetchEpssScores(createEpssClient(this.clientOpts(this.deps.config.epssApiUrl)), cves);
  }

  async run(tenantId: string, opts: { sources: EnrichmentSource[]; requestedBy: string }): Promise<{ runId: string; status: "succeeded" | "failed"; stats: EnrichmentStats; error: string | null }> {
    if (!this.deps.enabled) {
      throw new HttpError(409, "feature_disabled", "Vulnerability enrichment is disabled on this platform (FEATURE_VULN_ENRICHMENT=false)");
    }
    const sources = [...new Set(opts.sources)];
    const runId = await this.deps.db.withTenant(tenantId, async (tx) =>
      String((await tx.query<{ id: string }>("INSERT INTO enrichment_runs (tenant_id, sources, status, requested_by) VALUES ($1, $2, 'running', $3) RETURNING id", [tenantId, sources, opts.requestedBy])).rows[0]!.id),
    );
    const stats: EnrichmentStats = { vulnerabilitiesScanned: 0, cves: 0, updated: 0, newlyKnownExploited: 0, epssScored: 0, severityRaised: 0, kevCatalog: null };
    const notifications: EngineNotification[] = [];
    try {
      const open = await this.deps.db.withTenant(tenantId, async (tx) =>
        (await tx.query<Row>("SELECT * FROM vulnerabilities WHERE cve IS NOT NULL AND status IN ('open', 'in_remediation', 'accepted') ORDER BY risk_score DESC NULLS LAST LIMIT 20000")).rows,
      );
      stats.vulnerabilitiesScanned = open.length;
      const cves = [...new Set(open.map((r) => String(r.cve)))].slice(0, MAX_CVES);
      stats.cves = cves.length;
      const kev = sources.includes("cisa_kev") && cves.length > 0 ? await this.kevCatalog() : null;
      if (kev) stats.kevCatalog = { entries: kev.catalog.entries().length, fetchedAt: new Date(kev.fetchedAt).toISOString() };
      const epss = sources.includes("first_epss") && cves.length > 0 ? await this.epss(cves) : null;
      const sink = new BufferingSink();
      await this.deps.db.withTenant(tenantId, async (tx) => {
        for (const v of open) {
          const cve = String(v.cve);
          const e = enrichCve(cve, { ...(kev ? { kev: kev.catalog } : {}), ...(epss ? { epss } : {}) });
          if (e.epss !== null) stats.epssScored++;
          const knownExploited = Boolean(v.known_exploited) || e.knownExploited;
          const severity = e.severityFloor ? maxSeverity(v.severity as Severity, e.severityFloor) : (v.severity as Severity);
          const epssValue = e.epss ?? (v.epss === null ? null : Number(v.epss));
          const changed = knownExploited !== Boolean(v.known_exploited) || severity !== v.severity || (e.epss !== null && Number(v.epss ?? -1) !== e.epss);
          if (changed) {
            await this.deps.inventory.upsertVulnerability(
              tx,
              tenantId,
              {
                assetId: String(v.asset_id),
                cve,
                title: String(v.title),
                cvss: v.cvss === null ? null : Number(v.cvss),
                epss: epssValue,
                knownExploited,
                severity,
                status: v.status as "open",
                patchAvailable: Boolean(v.patch_available),
                slaDueAt: (v.sla_due_at as string | null) ?? null,
                source: String(v.source),
                firstSeenAt: String(v.first_seen_at),
              },
              sink,
            );
            stats.updated++;
            if (knownExploited && !v.known_exploited) stats.newlyKnownExploited++;
            if (SEV_RANK[severity] > SEV_RANK[v.severity as Severity]) stats.severityRaised++;
          }
          await tx.query(
            "UPDATE vulnerabilities SET kev = coalesce($2::jsonb, kev), epss_percentile = coalesce($3, epss_percentile), enrichment = $4::jsonb, enriched_at = now() WHERE id = $1",
            [v.id, e.kev ? JSON.stringify(e.kev) : null, e.epssPercentile, JSON.stringify({ evidence: e.evidence, severityFloor: e.severityFloor, epssDate: e.epssDate, sources })],
          );
        }
      });
      notifications.push(...sink.drain());
      await this.finish(tenantId, runId, "succeeded", stats, null);
      for (const n of notifications) {
        if (n.type !== "vulnerability.kev_detected" || automationEventFor(n) !== "vulnerability.kev_detected") continue;
        publishKev(this.deps.events, n, "enrichment");
      }
      return { runId, status: "succeeded", stats, error: null };
    } catch (err) {
      const message = err instanceof Error ? err.message.slice(0, 500) : "enrichment failed";
      await this.finish(tenantId, runId, "failed", stats, message);
      return { runId, status: "failed", stats, error: message };
    }
  }

  private async finish(tenantId: string, runId: string, status: "succeeded" | "failed", stats: EnrichmentStats, error: string | null): Promise<void> {
    await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE enrichment_runs SET status = $2, stats = $3::jsonb, error = $4, finished_at = now() WHERE id = $1", [runId, status, JSON.stringify(stats), error]));
  }
}

/** `vulnerability.kev_detected` domain event from the graph's engine notification. */
export function publishKev(events: DomainEventBus, n: Extract<EngineNotification, { type: "vulnerability.kev_detected" }>, source: string): void {
  events.publish({
    tenantId: n.tenantId,
    organizationId: n.organizationId,
    event: "vulnerability.kev_detected",
    occurredAt: n.at,
    severity: n.internetFacing || n.criticality === "crown_jewel" ? "critical" : "high",
    subject: { kind: "asset", id: n.assetNodeId, label: n.assetLabel },
    dedupKey: `kev:${n.cve}:${n.assetNodeId}`,
    data: { cve: n.cve, asset: n.assetLabel, internetFacing: n.internetFacing, criticality: n.criticality, source },
  });
}
