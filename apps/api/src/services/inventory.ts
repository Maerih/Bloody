import type { AssetKind, Criticality, IndicatorType, Severity } from "@bloody/contracts";
import { SecurityGraph, normalizeHostname, normalizeIndicatorValue, type EngineEventSink, type RiskEngine } from "@bloody/engines";
import { badRequest } from "../http/errors.js";
import type { Queryable } from "../db/pool.js";
import { PostgresGraphStore } from "../graph/postgres-store.js";
import { toAsset, toIdentity, toVulnerability, type AssetView, type IdentityView, type Row, type VulnerabilityView } from "../repo/mappers.js";

/**
 * Inventory service: the single write path for assets, identities, vulnerabilities and
 * indicators. Every write is mirrored into the Security Graph (same transaction) and every
 * score is recomputed by the Risk Engine with its explanation stored next to it.
 */

export function graphFor(tx: Queryable, tenantId: string, sink?: EngineEventSink): SecurityGraph {
  return new SecurityGraph({ store: new PostgresGraphStore(tx, tenantId), ...(sink ? { sink } : {}) });
}

export interface AssetInput {
  kind: AssetKind;
  name: string;
  hostname?: string | null | undefined;
  ipAddresses?: string[] | undefined;
  os?: string | null | undefined;
  criticality?: Criticality | undefined;
  internetFacing?: boolean | undefined;
  tags?: string[] | undefined;
  owner?: string | null | undefined;
  source?: "manual" | "discovered" | "integration" | "agent";
  externalSource?: string | null;
  externalRef?: string | null;
  lastSeenAt?: string | null;
}

export interface IdentityInput {
  kind?: "user" | "service_account" | "service_principal" | "machine" | "api_key" | "group" | undefined;
  provider: string;
  principal: string;
  displayName?: string | null | undefined;
  privileged?: boolean | undefined;
  mfaEnabled?: boolean | undefined;
  enabled?: boolean | undefined;
  lastActivityAt?: string | null | undefined;
}

export interface VulnerabilityInput {
  assetId: string;
  cve?: string | null | undefined;
  title: string;
  cvss?: number | null | undefined;
  epss?: number | null | undefined;
  knownExploited?: boolean | undefined;
  severity?: Severity | undefined;
  status?: "open" | "in_remediation" | "accepted" | "mitigated" | "resolved" | undefined;
  patchAvailable?: boolean | undefined;
  slaDueAt?: string | null | undefined;
  source?: string | undefined;
  firstSeenAt?: string | undefined;
}

export interface IndicatorInput {
  organizationId: string | null;
  type: IndicatorType;
  value: string;
  confidence: number;
  severity: Severity;
  source: string;
  threatActor?: string | null | undefined;
  malware?: string | null | undefined;
  campaign?: string | null | undefined;
  tags?: string[] | undefined;
  firstSeenAt?: string | undefined;
  lastSeenAt?: string | undefined;
  expiresAt?: string | null | undefined;
}

function severityFromCvss(cvss: number | null | undefined): Severity {
  if (cvss === null || cvss === undefined) return "medium";
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  if (cvss > 0) return "low";
  return "info";
}

export class InventoryService {
  constructor(
    private readonly risk: RiskEngine,
    private readonly now: () => number = () => Date.now(),
  ) {}

  // ─── Assets ──────────────────────────────────────────────────────────────

  async createAsset(tx: Queryable, tenantId: string, organizationId: string, input: AssetInput): Promise<AssetView> {
    const { rows } = await tx.query<Row>(
      `INSERT INTO assets (tenant_id, organization_id, kind, name, hostname, ip_addresses, os, criticality, internet_facing, tags, owner, source, external_source, external_ref, last_seen_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING *`,
      [
        tenantId,
        organizationId,
        input.kind,
        input.name,
        input.hostname ?? null,
        input.ipAddresses ?? [],
        input.os ?? null,
        input.criticality ?? "medium",
        input.internetFacing ?? false,
        input.tags ?? [],
        input.owner ?? null,
        input.source ?? "manual",
        input.externalSource ?? null,
        input.externalRef ?? null,
        input.lastSeenAt ?? null,
      ],
    );
    const asset = toAsset(rows[0]!);
    await this.syncAssetGraph(tx, tenantId, asset);
    return this.scoreAsset(tx, tenantId, asset.id);
  }

  async updateAsset(tx: Queryable, tenantId: string, assetId: string, patch: Partial<AssetInput>): Promise<AssetView | null> {
    const sets: string[] = [];
    const params: unknown[] = [assetId];
    const set = (col: string, v: unknown) => {
      params.push(v);
      sets.push(`${col} = $${params.length}`);
    };
    if (patch.kind !== undefined) set("kind", patch.kind);
    if (patch.name !== undefined) set("name", patch.name);
    if (patch.hostname !== undefined) set("hostname", patch.hostname);
    if (patch.ipAddresses !== undefined) set("ip_addresses", patch.ipAddresses);
    if (patch.os !== undefined) set("os", patch.os);
    if (patch.criticality !== undefined) set("criticality", patch.criticality);
    if (patch.internetFacing !== undefined) set("internet_facing", patch.internetFacing);
    if (patch.tags !== undefined) set("tags", patch.tags);
    if (patch.owner !== undefined) set("owner", patch.owner);
    if (sets.length === 0) {
      const { rows } = await tx.query<Row>("SELECT * FROM assets WHERE id = $1", [assetId]);
      return rows[0] ? toAsset(rows[0]) : null;
    }
    const { rows } = await tx.query<Row>(`UPDATE assets SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, params);
    if (!rows[0]) return null;
    const asset = toAsset(rows[0]);
    await this.syncAssetGraph(tx, tenantId, asset);
    return this.scoreAsset(tx, tenantId, asset.id);
  }

  async syncAssetGraph(tx: Queryable, tenantId: string, asset: AssetView): Promise<void> {
    const agent = await tx.query<{ status: string; firewall_enabled: boolean }>("SELECT status, firewall_enabled FROM agents WHERE asset_id = $1 ORDER BY updated_at DESC LIMIT 1", [asset.id]);
    const a = agent.rows[0];
    const edr = !a ? false : a.status === "protected" ? "healthy" : a.status === "isolated" ? "healthy" : "degraded";
    await graphFor(tx, tenantId).ingestAsset({
      id: asset.id,
      organizationId: asset.organizationId,
      kind: asset.kind,
      name: asset.name,
      hostname: asset.hostname,
      ipAddresses: asset.ipAddresses,
      os: asset.os,
      criticality: asset.criticality,
      internetFacing: asset.internetFacing,
      tags: asset.tags,
      owner: asset.owner,
      props: { edr, isolated: a?.status === "isolated", firewall: a?.firewall_enabled ?? undefined },
    });
  }

  /** Network reachability (from a scan / firewall policy): asset -can_reach-> target. */
  async setReachability(tx: Queryable, tenantId: string, fromAssetId: string, toAssetIds: string[]): Promise<number> {
    const graph = graphFor(tx, tenantId);
    const ids = [fromAssetId, ...toAssetIds];
    const { rows } = await tx.query<Row>("SELECT * FROM assets WHERE id = ANY($1::uuid[])", [ids]);
    const byId = new Map(rows.map((r) => [String(r.id), toAsset(r)]));
    const from = byId.get(fromAssetId);
    if (!from) return 0;
    const fromNode = await graph.ingestAsset({ id: from.id, organizationId: from.organizationId, name: from.name, hostname: from.hostname });
    let n = 0;
    for (const id of toAssetIds) {
      const to = byId.get(id);
      if (!to || to.organizationId !== from.organizationId || to.id === from.id) continue;
      const toNode = await graph.ingestAsset({ id: to.id, organizationId: to.organizationId, name: to.name, hostname: to.hostname });
      await graph.relate(fromNode.id, "can_reach", toNode.id, { source: "inventory" });
      n++;
    }
    return n;
  }

  /** Resolve event hostnames to assets, registering unknown hosts as discovered assets. */
  async resolveOrDiscoverHosts(
    tx: Queryable,
    tenantId: string,
    organizationId: string,
    hosts: Array<{ hostname: string; os?: string | undefined; ips?: string[] | undefined; lastSeenAt: string }>,
  ): Promise<Map<string, string>> {
    const byKey = new Map<string, { hostname: string; os?: string | undefined; ips?: string[] | undefined; lastSeenAt: string }>();
    for (const h of hosts) {
      const key = normalizeHostname(h.hostname);
      if (!key) continue;
      const prev = byKey.get(key);
      if (!prev || prev.lastSeenAt < h.lastSeenAt) byKey.set(key, { ...h, os: h.os ?? prev?.os, ips: h.ips ?? prev?.ips });
    }
    const out = new Map<string, string>();
    if (byKey.size === 0) return out;
    const keys = [...byKey.keys()];
    const { rows } = await tx.query<{ id: string; key: string }>(
      `SELECT id, split_part(lower(hostname), '.', 1) AS key FROM assets WHERE organization_id = $1 AND hostname IS NOT NULL AND split_part(lower(hostname), '.', 1) = ANY($2::text[])`,
      [organizationId, keys],
    );
    for (const r of rows) out.set(r.key, r.id);
    for (const [key, h] of byKey) {
      if (out.has(key)) {
        await tx.query("UPDATE assets SET last_seen_at = GREATEST(coalesce(last_seen_at, $2), $2) WHERE id = $1", [out.get(key), h.lastSeenAt]);
        continue;
      }
      const os = h.os ?? null;
      const kind: AssetKind = os && /server/i.test(os) ? "server" : "endpoint";
      const ins = await tx.query<Row>(
        `INSERT INTO assets (tenant_id, organization_id, kind, name, hostname, ip_addresses, os, criticality, source, tags, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'medium', 'discovered', ARRAY['discovered'], $8)
         ON CONFLICT (tenant_id, organization_id, lower(hostname)) WHERE hostname IS NOT NULL DO UPDATE SET last_seen_at = GREATEST(assets.last_seen_at, EXCLUDED.last_seen_at)
         RETURNING *`,
        [tenantId, organizationId, kind, h.hostname, h.hostname, (h.ips ?? []).slice(0, 16), os, h.lastSeenAt],
      );
      const asset = toAsset(ins.rows[0]!);
      out.set(key, asset.id);
      await this.syncAssetGraph(tx, tenantId, asset);
    }
    return out;
  }

  async scoreAsset(tx: Queryable, tenantId: string, assetId: string): Promise<AssetView> {
    const { rows } = await tx.query<Row>("SELECT * FROM assets WHERE id = $1", [assetId]);
    const asset = toAsset(rows[0]!);
    const [vulns, alerts, agent, intel, incidents, access] = await Promise.all([
      tx.query<Row>("SELECT cve, title, cvss, epss, known_exploited, severity, status, patch_available FROM vulnerabilities WHERE asset_id = $1 AND status IN ('open', 'in_remediation', 'accepted')", [assetId]),
      tx.query<Row>(
        "SELECT rule_id, title, severity, confidence, source, attack FROM alerts WHERE asset_id = $1 AND status IN ('new', 'triaged', 'promoted') AND last_seen_at > now() - interval '30 days' ORDER BY last_seen_at DESC LIMIT 50",
        [assetId],
      ),
      tx.query<Row>("SELECT status, firewall_enabled FROM agents WHERE asset_id = $1 ORDER BY updated_at DESC LIMIT 1", [assetId]),
      tx.query<Row>(
        `SELECT i.value, i.confidence, i.severity, i.threat_actor, i.campaign FROM indicator_matches m JOIN indicators i ON i.id = m.indicator_id
         WHERE m.asset_id = $1 AND m.matched_at > now() - interval '30 days' GROUP BY i.id LIMIT 20`,
        [assetId],
      ),
      tx.query<{ n: number }>("SELECT count(*)::int AS n FROM incidents WHERE $1 = ANY(asset_ids) AND detected_at > now() - interval '90 days'", [assetId]),
      tx.query<{ principal: string; privileged: boolean }>(
        `SELECT DISTINCT coalesce(f.props->>'principal', f.label) AS principal, coalesce((f.props->>'privileged')::boolean, false) AS privileged
         FROM graph_nodes a JOIN graph_edges e ON e.to_id = a.id AND e.kind IN ('logged_into', 'admin_of', 'has_access_to', 'owns')
         JOIN graph_nodes f ON f.id = e.from_id AND f.kind IN ('identity', 'user', 'service_account')
         WHERE a.props->>'assetId' = $1 LIMIT 100`,
        [assetId],
      ),
    ]);
    const ag = agent.rows[0];
    const assessment = this.risk.scoreAsset({
      asset: { name: asset.name, kind: asset.kind, criticality: asset.criticality, internetFacing: asset.internetFacing },
      vulnerabilities: vulns.rows.map((v) => ({
        cve: (v.cve as string | null) ?? null,
        title: String(v.title),
        cvss: v.cvss === null ? null : Number(v.cvss),
        epss: v.epss === null ? null : Number(v.epss),
        knownExploited: Boolean(v.known_exploited),
        severity: v.severity as Severity,
        status: v.status as "open",
        patchAvailable: Boolean(v.patch_available),
      })),
      identities: access.rows.map((r) => ({ principal: r.principal, privileged: r.privileged })),
      intelMatches: intel.rows.map((r) => ({ value: String(r.value), confidence: Number(r.confidence), severity: r.severity as Severity, threatActor: (r.threat_actor as string | null) ?? null, campaign: (r.campaign as string | null) ?? null })),
      detections: alerts.rows.map((r) => ({ ruleId: (r.rule_id as string | null) ?? null, title: String(r.title), severity: r.severity as Severity, confidence: Number(r.confidence), source: String(r.source), attack: Array.isArray(r.attack) ? (r.attack as never[]) : [] })),
      controls: {
        edr: !ag ? false : ag.status === "protected" || ag.status === "isolated" ? "healthy" : "degraded",
        firewall: ag ? Boolean(ag.firewall_enabled) : false,
        isolated: ag?.status === "isolated",
      },
      history: { incidentsLast90d: incidents.rows[0]?.n ?? 0 },
    });
    const upd = await tx.query<Row>("UPDATE assets SET risk_score = $2, risk = $3::jsonb, risk_updated_at = now() WHERE id = $1 RETURNING *", [assetId, assessment.score, JSON.stringify(assessment)]);
    return toAsset(upd.rows[0]!);
  }

  // ─── Identities ──────────────────────────────────────────────────────────

  async upsertIdentity(tx: Queryable, tenantId: string, organizationId: string, input: IdentityInput, externalSource: string | null = null): Promise<IdentityView> {
    const { rows } = await tx.query<Row>(
      `INSERT INTO identities (tenant_id, organization_id, kind, provider, principal, display_name, privileged, mfa_enabled, enabled, last_activity_at, external_source)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (tenant_id, organization_id, lower(provider), lower(principal)) DO UPDATE SET
         kind = EXCLUDED.kind, display_name = coalesce(EXCLUDED.display_name, identities.display_name),
         privileged = EXCLUDED.privileged, mfa_enabled = EXCLUDED.mfa_enabled, enabled = EXCLUDED.enabled,
         last_activity_at = GREATEST(identities.last_activity_at, EXCLUDED.last_activity_at)
       RETURNING *`,
      [
        tenantId,
        organizationId,
        input.kind ?? "user",
        input.provider,
        input.principal,
        input.displayName ?? null,
        input.privileged ?? false,
        input.mfaEnabled ?? false,
        input.enabled ?? true,
        input.lastActivityAt ?? null,
        externalSource,
      ],
    );
    const identity = toIdentity(rows[0]!);
    await graphFor(tx, tenantId).ingestIdentity({
      id: identity.id,
      organizationId,
      kind: identity.kind,
      provider: identity.provider,
      principal: identity.principal,
      displayName: identity.displayName,
      privileged: identity.privileged,
      mfaEnabled: identity.mfaEnabled,
    });
    return this.scoreIdentity(tx, tenantId, identity.id);
  }

  /** Privileged access mapping (directory / CIEM): identity -admin_of|has_access_to|owns-> asset. */
  async setIdentityAccess(tx: Queryable, tenantId: string, identityId: string, access: Array<{ assetId: string; level: "admin" | "user" | "owner" }>): Promise<number> {
    const graph = graphFor(tx, tenantId);
    const idRow = await tx.query<Row>("SELECT * FROM identities WHERE id = $1", [identityId]);
    if (!idRow.rows[0]) return 0;
    const identity = toIdentity(idRow.rows[0]);
    const node = await graph.ingestIdentity({ id: identity.id, organizationId: identity.organizationId, kind: identity.kind, provider: identity.provider, principal: identity.principal, displayName: identity.displayName, privileged: identity.privileged, mfaEnabled: identity.mfaEnabled });
    const { rows } = await tx.query<Row>("SELECT * FROM assets WHERE id = ANY($1::uuid[]) AND organization_id = $2", [access.map((a) => a.assetId), identity.organizationId]);
    const assets = new Map(rows.map((r) => [String(r.id), toAsset(r)]));
    let n = 0;
    for (const a of access) {
      const asset = assets.get(a.assetId);
      if (!asset) continue;
      const assetNode = await graph.ingestAsset({ id: asset.id, organizationId: asset.organizationId, name: asset.name, hostname: asset.hostname });
      await graph.relate(node.id, a.level === "admin" ? "admin_of" : a.level === "owner" ? "owns" : "has_access_to", assetNode.id, { source: "inventory" });
      n++;
    }
    return n;
  }

  async scoreIdentity(tx: Queryable, tenantId: string, identityId: string): Promise<IdentityView> {
    const { rows } = await tx.query<Row>("SELECT * FROM identities WHERE id = $1", [identityId]);
    const identity = toIdentity(rows[0]!);
    const [alerts, failures, adminOf] = await Promise.all([
      tx.query<Row>("SELECT rule_id, title, severity, confidence, source, attack FROM alerts WHERE identity_id = $1 AND status IN ('new', 'triaged', 'promoted') AND last_seen_at > now() - interval '30 days' LIMIT 50", [identityId]),
      tx.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM events WHERE organization_id = $1 AND lower(identity_principal) = lower($2) AND outcome = 'failure' AND category = 'authentication' AND occurred_at > now() - interval '1 day'",
        [identity.organizationId, identity.principal],
      ),
      tx.query<{ admin: number; crown: number }>(
        `SELECT count(*) FILTER (WHERE e.kind = 'admin_of')::int AS admin,
                count(*) FILTER (WHERE a.props->>'criticality' = 'crown_jewel')::int AS crown
         FROM graph_nodes i JOIN graph_edges e ON e.from_id = i.id AND e.kind IN ('admin_of', 'has_access_to', 'owns', 'logged_into')
         JOIN graph_nodes a ON a.id = e.to_id
         WHERE i.props->>'identityId' = $1`,
        [identityId],
      ),
    ]);
    const assessment = this.risk.scoreIdentity({
      identity: { principal: identity.principal, kind: identity.kind, privileged: identity.privileged, mfaEnabled: identity.mfaEnabled, enabled: identity.enabled, lastActivityAt: identity.lastActivityAt },
      adminOfAssets: adminOf.rows[0]?.admin ?? 0,
      crownJewelAccess: adminOf.rows[0]?.crown ?? 0,
      detections: alerts.rows.map((r) => ({ ruleId: (r.rule_id as string | null) ?? null, title: String(r.title), severity: r.severity as Severity, confidence: Number(r.confidence), source: String(r.source), attack: Array.isArray(r.attack) ? (r.attack as never[]) : [] })),
      signIns: { failures: failures.rows[0]?.n ?? 0 },
      controls: { mfa: identity.mfaEnabled },
    });
    const upd = await tx.query<Row>("UPDATE identities SET risk_score = $2, risk = $3::jsonb, risk_updated_at = now() WHERE id = $1 RETURNING *", [identityId, assessment.score, JSON.stringify(assessment)]);
    return toIdentity(upd.rows[0]!);
  }

  // ─── Vulnerabilities ─────────────────────────────────────────────────────

  async upsertVulnerability(tx: Queryable, tenantId: string, input: VulnerabilityInput, sink?: EngineEventSink): Promise<VulnerabilityView> {
    const assetRow = await tx.query<Row>("SELECT * FROM assets WHERE id = $1", [input.assetId]);
    if (!assetRow.rows[0]) throw badRequest("assetId does not reference an asset of this tenant");
    const asset = toAsset(assetRow.rows[0]);
    const severity = input.severity ?? severityFromCvss(input.cvss);
    const status = input.status ?? "open";
    const priority = this.risk.scoreVulnerability({
      vulnerability: { cve: input.cve ?? null, title: input.title, cvss: input.cvss ?? null, epss: input.epss ?? null, knownExploited: input.knownExploited ?? false, severity, status, patchAvailable: input.patchAvailable ?? false },
      asset: { name: asset.name, criticality: asset.criticality, internetFacing: asset.internetFacing },
    });
    const firstSeen = input.firstSeenAt ?? new Date(this.now()).toISOString();
    const slaDue = input.slaDueAt ?? new Date(Date.parse(firstSeen) + priority.slaDays * 86_400_000).toISOString();
    const { rows } = await tx.query<Row>(
      `INSERT INTO vulnerabilities (tenant_id, organization_id, asset_id, cve, title, cvss, epss, known_exploited, severity, status, patch_available, sla_due_at, priority, risk_score, risk, source, first_seen_at, last_seen_at, resolved_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16, $17, now(), CASE WHEN $10 = 'resolved' THEN now() END)
       ON CONFLICT (tenant_id, asset_id, coalesce(cve, title)) DO UPDATE SET
         title = EXCLUDED.title, cvss = EXCLUDED.cvss, epss = EXCLUDED.epss, known_exploited = EXCLUDED.known_exploited,
         severity = EXCLUDED.severity, status = EXCLUDED.status, patch_available = EXCLUDED.patch_available,
         priority = EXCLUDED.priority, risk_score = EXCLUDED.risk_score, risk = EXCLUDED.risk, last_seen_at = now(),
         resolved_at = CASE WHEN EXCLUDED.status = 'resolved' THEN coalesce(vulnerabilities.resolved_at, now()) ELSE NULL END
       RETURNING *`,
      [
        tenantId,
        asset.organizationId,
        asset.id,
        input.cve ? input.cve.toUpperCase() : null,
        input.title,
        input.cvss ?? null,
        input.epss ?? null,
        input.knownExploited ?? false,
        severity,
        status,
        input.patchAvailable ?? false,
        slaDue,
        priority.priority,
        priority.score,
        JSON.stringify(priority),
        input.source ?? "manual",
        firstSeen,
      ],
    );
    const vuln = toVulnerability(rows[0]!);
    const graph = graphFor(tx, tenantId, sink);
    const assetNode = await graph.ingestAsset({ id: asset.id, organizationId: asset.organizationId, name: asset.name, hostname: asset.hostname, kind: asset.kind, criticality: asset.criticality, internetFacing: asset.internetFacing });
    await graph.ingestVulnerability({
      organizationId: asset.organizationId,
      asset: assetNode.id,
      cve: vuln.cve,
      title: vuln.title,
      cvss: vuln.cvss,
      epss: vuln.epss,
      knownExploited: vuln.knownExploited,
      severity: vuln.severity,
      status: vuln.status,
      patchAvailable: vuln.patchAvailable,
      observedAt: new Date(this.now()).toISOString(),
    });
    await this.scoreAsset(tx, tenantId, asset.id);
    return vuln;
  }

  // ─── Indicators ──────────────────────────────────────────────────────────

  async upsertIndicator(tx: Queryable, tenantId: string, raw: IndicatorInput): Promise<Row> {
    const value = normalizeIndicatorValue(raw.type, raw.value);
    if (value === null) throw badRequest(`Invalid ${raw.type} indicator value`);
    const input = { ...raw, value };
    const { rows } = await tx.query<Row>(
      `INSERT INTO indicators (tenant_id, organization_id, type, value, confidence, severity, source, threat_actor, malware, campaign, tags, first_seen_at, last_seen_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, coalesce($12::timestamptz, now()), coalesce($13::timestamptz, now()), $14)
       ON CONFLICT (tenant_id, org_key(organization_id), type, value, source) DO UPDATE SET
         confidence = EXCLUDED.confidence, severity = EXCLUDED.severity, threat_actor = EXCLUDED.threat_actor, malware = EXCLUDED.malware,
         campaign = EXCLUDED.campaign, tags = EXCLUDED.tags, last_seen_at = GREATEST(indicators.last_seen_at, EXCLUDED.last_seen_at), expires_at = EXCLUDED.expires_at
       RETURNING *`,
      [
        tenantId,
        input.organizationId,
        input.type,
        input.value,
        input.confidence,
        input.severity,
        input.source,
        input.threatActor ?? null,
        input.malware ?? null,
        input.campaign ?? null,
        input.tags ?? [],
        input.firstSeenAt ?? null,
        input.lastSeenAt ?? null,
        input.expiresAt ?? null,
      ],
    );
    await graphFor(tx, tenantId).ingestIndicator({
      organizationId: input.organizationId,
      type: input.type,
      value: input.value,
      confidence: input.confidence,
      severity: input.severity,
      source: input.source,
      threatActor: input.threatActor ?? null,
      malware: input.malware ?? null,
      campaign: input.campaign ?? null,
      ...(input.tags ? { tags: input.tags } : {}),
    });
    return rows[0]!;
  }
}
