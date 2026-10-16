import { gradePatching, osSupport, type HostPatchStatus, type MissingUpdate, type PatchEndpoint, type PatchGrade, type PatchState } from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";
import type { Row } from "../repo/mappers.js";

const iso = (v: unknown) => (v == null ? null : new Date(String(v)).toISOString());

/** Patch Compliance: update status per computer, how long security fixes wait, SLA grade. */
export class PatchingService {
  constructor(private readonly now: () => number = Date.now) {}

  /**
   * Record a computer's update status (already stored with the inventory). Keeps the time
   * security updates started waiting and returns the grade change, so a computer that just
   * breached the SLA alerts once.
   */
  async record(tx: Queryable, agentId: string, status: HostPatchStatus | null): Promise<{ before: PatchState | null; grade: PatchGrade; os: string | null } | null> {
    if (!status) return null;
    const now = new Date(this.now());
    const { rows } = await tx.query<Row>("SELECT host_info->>'os' AS os, security_pending_since, patch_state FROM agents WHERE id = $1", [agentId]);
    const row = rows[0];
    if (!row) return null;
    const security = status.pending.some((p) => p.security);
    // An OS that cannot list updates keeps the previous clock.
    const since = status.error ? iso(row.security_pending_since) : security ? (iso(row.security_pending_since) ?? now.toISOString()) : null;
    const os = (row.os as string | null) ?? null;
    const grade = gradePatching({ status, os: osSupport(os, now), securityPendingSince: since, now });
    await tx.query("UPDATE agents SET security_pending_since = $2, patch_state = $3 WHERE id = $1", [agentId, since, grade.state]);
    return { before: (row.patch_state as PatchState | null) ?? null, grade, os };
  }

  async overview(tx: Queryable, organizationId: string): Promise<{
    endpoints: PatchEndpoint[];
    missing: MissingUpdate[];
    summary: { endpoints: number; reporting: number; current: number; behind: number; breached: number; unknown: number; compliance: number | null; unsupportedOs: number; securityUpdates: number; rebootPending: number };
  }> {
    const now = new Date(this.now());
    const { rows } = await tx.query<Row>(
      `SELECT a.id, a.hostname, a.host_info->>'os' AS os, a.security_pending_since, i.patches, i.collected_at
         FROM agents a LEFT JOIN agent_inventory i ON i.agent_id = a.id
        WHERE a.organization_id = $1 AND a.engine = 'sciat' AND a.agent_token_hash IS NOT NULL
        ORDER BY a.hostname`,
      [organizationId],
    );
    const missing = new Map<string, MissingUpdate>();
    const endpoints: PatchEndpoint[] = rows.map((r) => {
      const status = (r.patches as HostPatchStatus | null) ?? null;
      const os = (r.os as string | null) ?? null;
      const support = osSupport(os, now);
      const since = iso(r.security_pending_since);
      const pending = status?.pending ?? [];
      for (const p of pending) {
        const key = `${p.id ?? ""}|${p.title}`.toLowerCase();
        const m = missing.get(key) ?? { title: p.title, id: p.id, security: p.security, severity: p.severity, endpoints: 0 };
        m.endpoints++;
        missing.set(key, m);
      }
      return {
        agentId: String(r.id),
        hostname: String(r.hostname),
        os,
        osSupport: support,
        source: status?.source ?? null,
        pendingCount: pending.length,
        securityCount: pending.filter((p) => p.security).length,
        criticalCount: pending.filter((p) => p.security && p.severity === "critical").length,
        rebootRequired: status?.rebootRequired ?? null,
        lastInstalledAt: status?.lastInstalledAt ?? null,
        lastCheckedAt: status?.lastCheckedAt ?? null,
        securityPendingSince: since,
        reportedAt: status ? iso(r.collected_at) : null,
        grade: gradePatching({ status, os: support, securityPendingSince: since, now }),
        pending: pending.slice(0, 200),
      };
    });
    const rank: Record<PatchState, number> = { breached: 0, behind: 1, unknown: 2, current: 3 };
    endpoints.sort((a, b) => rank[a.grade.state] - rank[b.grade.state] || b.securityCount - a.securityCount || a.hostname.localeCompare(b.hostname));
    const count = (s: PatchState) => endpoints.filter((e) => e.grade.state === s).length;
    const graded = endpoints.filter((e) => e.grade.state !== "unknown").length;
    const sev = { critical: 0, important: 1, moderate: 2, low: 3, unspecified: 4 } as const;
    return {
      endpoints,
      missing: [...missing.values()].sort((a, b) => Number(b.security) - Number(a.security) || sev[a.severity] - sev[b.severity] || b.endpoints - a.endpoints).slice(0, 500),
      summary: {
        endpoints: endpoints.length,
        reporting: endpoints.filter((e) => e.source).length,
        current: count("current"),
        behind: count("behind"),
        breached: count("breached"),
        unknown: count("unknown"),
        compliance: graded ? Math.round((count("current") / graded) * 100) : null,
        unsupportedOs: endpoints.filter((e) => e.osSupport.status === "ended").length,
        securityUpdates: endpoints.reduce((n, e) => n + e.securityCount, 0),
        rebootPending: endpoints.filter((e) => e.rebootRequired).length,
      },
    };
  }
}
