import type { ExposureInputs } from "@bloody/engines";
import { inOrder, type Queryable } from "../db/pool.js";

/**
 * Per-organization posture aggregates computed with grouped SQL over the tenant's inventory.
 * They feed the Risk Engine's explainable exposure model (Command Center + MSSP portfolio) and
 * the dashboard counters, so every number on those screens is derived from stored records.
 */
export interface OrgPosture {
  organizationId: string;
  assets: { total: number; internetFacing: number; crownJewels: number; endpoints: number; unmanagedInternetFacing: number };
  vulns: { open: number; critical: number; high: number; knownExploited: number; kevInternetFacing: number; kevCrownJewel: number; highEpss: number; overdueSla: number };
  identities: { total: number; users: number; usersWithMfa: number; privileged: number; privilegedWithoutMfa: number; dormantPrivileged: number; riskyServiceAccounts: number };
  agents: { total: number; protected: number; unresponsive: number; outdated: number; isolated: number; pending: number; edrCoveredAssets: number };
  intel: { matches30d: number; campaigns30d: number };
}

export function emptyPosture(organizationId: string): OrgPosture {
  return {
    organizationId,
    assets: { total: 0, internetFacing: 0, crownJewels: 0, endpoints: 0, unmanagedInternetFacing: 0 },
    vulns: { open: 0, critical: 0, high: 0, knownExploited: 0, kevInternetFacing: 0, kevCrownJewel: 0, highEpss: 0, overdueSla: 0 },
    identities: { total: 0, users: 0, usersWithMfa: 0, privileged: 0, privilegedWithoutMfa: 0, dormantPrivileged: 0, riskyServiceAccounts: 0 },
    agents: { total: 0, protected: 0, unresponsive: 0, outdated: 0, isolated: 0, pending: 0, edrCoveredAssets: 0 },
    intel: { matches30d: 0, campaigns30d: 0 },
  };
}

const EFFECTIVE_AGENT_STATUS = `CASE WHEN status IN ('protected', 'outdated') AND last_checkin_at IS NOT NULL AND last_checkin_at < now() - interval '24 hours' THEN 'unresponsive' ELSE status END`;
const ENDPOINT_KINDS = "('endpoint', 'server', 'domain_controller', 'database', 'cloud_instance')";

type Num = Record<string, number | string | null>;
const n = (v: unknown): number => (v === null || v === undefined ? 0 : Number(v));

/** Load posture for the given organizations (null = every organization of the tenant). */
export async function loadPosture(tx: Queryable, orgIds: string[] | null): Promise<Map<string, OrgPosture>> {
  const orgRows = orgIds === null ? (await tx.query<{ id: string }>("SELECT id FROM organizations")).rows.map((r) => r.id) : orgIds;
  const out = new Map<string, OrgPosture>(orgRows.map((id) => [id, emptyPosture(id)]));
  if (out.size === 0) return out;
  const ids = [...out.keys()];
  const get = (id: unknown) => out.get(String(id));

  const [assets, vulns, identities, agents, intel] = await inOrder([
    () => tx.query<Num>(
      `SELECT a.organization_id,
              count(*) AS total,
              count(*) FILTER (WHERE a.internet_facing) AS internet_facing,
              count(*) FILTER (WHERE a.criticality = 'crown_jewel') AS crown_jewels,
              count(*) FILTER (WHERE a.kind IN ${ENDPOINT_KINDS}) AS endpoints,
              count(*) FILTER (WHERE a.internet_facing AND NOT EXISTS (SELECT 1 FROM agents ag WHERE ag.asset_id = a.id)) AS unmanaged_internet_facing
       FROM assets a WHERE a.organization_id = ANY($1::uuid[]) GROUP BY a.organization_id`,
      [ids],
    ),
    () => tx.query<Num>(
      `SELECT v.organization_id,
              count(*) AS open,
              count(*) FILTER (WHERE v.severity = 'critical') AS critical,
              count(*) FILTER (WHERE v.severity = 'high') AS high,
              count(*) FILTER (WHERE v.known_exploited) AS kev,
              count(*) FILTER (WHERE v.known_exploited AND a.internet_facing) AS kev_internet,
              count(*) FILTER (WHERE v.known_exploited AND a.criticality = 'crown_jewel') AS kev_crown,
              count(*) FILTER (WHERE v.epss >= 0.5) AS high_epss,
              count(*) FILTER (WHERE v.sla_due_at < now()) AS overdue_sla
       FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id
       WHERE v.organization_id = ANY($1::uuid[]) AND v.status IN ('open', 'in_remediation') GROUP BY v.organization_id`,
      [ids],
    ),
    () => tx.query<Num>(
      `SELECT organization_id,
              count(*) FILTER (WHERE enabled) AS total,
              count(*) FILTER (WHERE enabled AND kind = 'user') AS users,
              count(*) FILTER (WHERE enabled AND kind = 'user' AND mfa_enabled) AS users_mfa,
              count(*) FILTER (WHERE enabled AND privileged) AS privileged,
              count(*) FILTER (WHERE enabled AND privileged AND NOT mfa_enabled AND kind IN ('user', 'service_account')) AS privileged_no_mfa,
              count(*) FILTER (WHERE enabled AND privileged AND last_activity_at < now() - interval '90 days') AS dormant_privileged,
              count(*) FILTER (WHERE enabled AND kind IN ('service_account', 'service_principal') AND risk_score >= 70) AS risky_service_accounts
       FROM identities WHERE organization_id = ANY($1::uuid[]) GROUP BY organization_id`,
      [ids],
    ),
    () => tx.query<Num>(
      `SELECT organization_id,
              count(*) AS total,
              count(*) FILTER (WHERE eff = 'protected') AS protected,
              count(*) FILTER (WHERE eff = 'unresponsive') AS unresponsive,
              count(*) FILTER (WHERE eff = 'outdated') AS outdated,
              count(*) FILTER (WHERE eff = 'isolated') AS isolated,
              count(*) FILTER (WHERE eff = 'pending') AS pending,
              count(DISTINCT asset_id) FILTER (WHERE eff IN ('protected', 'isolated')) AS edr_assets
       FROM (SELECT organization_id, asset_id, ${EFFECTIVE_AGENT_STATUS} AS eff FROM agents WHERE organization_id = ANY($1::uuid[])) x
       GROUP BY organization_id`,
      [ids],
    ),
    () => tx.query<Num>(
      `SELECT m.organization_id, count(*) AS matches, count(DISTINCT i.campaign) FILTER (WHERE i.campaign IS NOT NULL) AS campaigns
       FROM indicator_matches m JOIN indicators i ON i.id = m.indicator_id
       WHERE m.organization_id = ANY($1::uuid[]) AND m.matched_at > now() - interval '30 days' GROUP BY m.organization_id`,
      [ids],
    ),
  ]);
  for (const r of assets.rows) {
    const p = get(r.organization_id);
    if (p) p.assets = { total: n(r.total), internetFacing: n(r.internet_facing), crownJewels: n(r.crown_jewels), endpoints: n(r.endpoints), unmanagedInternetFacing: n(r.unmanaged_internet_facing) };
  }
  for (const r of vulns.rows) {
    const p = get(r.organization_id);
    if (p)
      p.vulns = {
        open: n(r.open),
        critical: n(r.critical),
        high: n(r.high),
        knownExploited: n(r.kev),
        kevInternetFacing: n(r.kev_internet),
        kevCrownJewel: n(r.kev_crown),
        highEpss: n(r.high_epss),
        overdueSla: n(r.overdue_sla),
      };
  }
  for (const r of identities.rows) {
    const p = get(r.organization_id);
    if (p)
      p.identities = {
        total: n(r.total),
        users: n(r.users),
        usersWithMfa: n(r.users_mfa),
        privileged: n(r.privileged),
        privilegedWithoutMfa: n(r.privileged_no_mfa),
        dormantPrivileged: n(r.dormant_privileged),
        riskyServiceAccounts: n(r.risky_service_accounts),
      };
  }
  for (const r of agents.rows) {
    const p = get(r.organization_id);
    if (p)
      p.agents = {
        total: n(r.total),
        protected: n(r.protected),
        unresponsive: n(r.unresponsive),
        outdated: n(r.outdated),
        isolated: n(r.isolated),
        pending: n(r.pending),
        edrCoveredAssets: n(r.edr_assets),
      };
  }
  for (const r of intel.rows) {
    const p = get(r.organization_id);
    if (p) p.intel = { matches30d: n(r.matches), campaigns30d: n(r.campaigns) };
  }
  return out;
}

/** Element-wise sum of several organizations' posture (portfolio / "all organizations" view). */
export function sumPosture(list: Iterable<OrgPosture>, label = "aggregate"): OrgPosture {
  const acc = emptyPosture(label);
  for (const p of list) {
    for (const section of ["assets", "vulns", "identities", "agents", "intel"] as const) {
      const target = acc[section] as unknown as Record<string, number>;
      const src = p[section] as unknown as Record<string, number>;
      for (const k of Object.keys(target)) target[k] = (target[k] ?? 0) + (src[k] ?? 0);
    }
  }
  return acc;
}

export function exposureInputsFor(p: OrgPosture, attackPaths: { total: number; toCrownJewels: number } | null, organizationName?: string): ExposureInputs {
  return {
    ...(organizationName ? { organizationName } : {}),
    assets: { total: p.assets.total, internetFacing: p.assets.internetFacing, crownJewels: p.assets.crownJewels },
    external: { unmanagedExternalAssets: p.assets.unmanagedInternetFacing },
    vulnerabilities: {
      open: p.vulns.open,
      critical: p.vulns.critical,
      high: p.vulns.high,
      knownExploited: p.vulns.knownExploited,
      knownExploitedOnInternetFacing: p.vulns.kevInternetFacing,
      knownExploitedOnCrownJewels: p.vulns.kevCrownJewel,
      highEpss: p.vulns.highEpss,
      overdueSla: p.vulns.overdueSla,
    },
    identities: {
      total: p.identities.total,
      privileged: p.identities.privileged,
      privilegedWithoutMfa: p.identities.privilegedWithoutMfa,
      dormantPrivileged: p.identities.dormantPrivileged,
      riskyServiceAccounts: p.identities.riskyServiceAccounts,
    },
    ...(attackPaths ? { attackPaths: { total: attackPaths.total, toCrownJewels: attackPaths.toCrownJewels } } : {}),
    threatIntel: { matchesLast30d: p.intel.matches30d, activeCampaignsTargeting: p.intel.campaigns30d },
    controls: {
      ...(p.assets.endpoints > 0 ? { edrCoverage: Math.min(1, p.agents.edrCoveredAssets / p.assets.endpoints) } : {}),
      ...(p.identities.users > 0 ? { mfaCoverage: p.identities.usersWithMfa / p.identities.users } : {}),
    },
  };
}

/** Organizations where attack paths can exist at all (an internet-facing entry and a crown jewel). */
export function attackPathCandidates(posture: Map<string, OrgPosture>): string[] {
  return [...posture.values()].filter((p) => p.assets.internetFacing > 0 && p.assets.crownJewels > 0).map((p) => p.organizationId);
}
