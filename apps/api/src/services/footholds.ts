import { assessFoothold, footholdFingerprint, type Foothold, type FootholdAssessment, type FootholdVerdict, type FootholdVerdictInput, type HostAutorun } from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";
import type { Row } from "../repo/mappers.js";

const MAX_ROWS = 50_000;
const MAX_GROUPS = 3000;
const MAX_ENDPOINTS = 50;
const iso = (v: unknown) => new Date(String(v)).toISOString();

export interface NewFoothold {
  fingerprint: string;
  entry: HostAutorun;
  assessment: FootholdAssessment;
  verdict: FootholdVerdict | null;
}

/** Persistent Footholds: autostart entries per computer, baseline and new entries, verdicts. */
export class FootholdsService {
  constructor(private readonly now: () => number = Date.now) {}

  /**
   * Store a computer's autostart entries. Entries in its first report form the baseline; any
   * entry that appears later (or comes back after being removed) is returned as new.
   * An empty list means the agent does not collect autoruns (older version): nothing changes.
   */
  async record(tx: Queryable, agent: { agentId: string; tenantId: string; organizationId: string }, autoruns: readonly HostAutorun[]): Promise<NewFoothold[]> {
    if (autoruns.length === 0) return [];
    const at = new Date(this.now()).toISOString();
    const byFp = new Map<string, HostAutorun>();
    for (const a of autoruns) {
      const fp = footholdFingerprint(a);
      if (!byFp.has(fp)) byFp.set(fp, a);
    }
    const baselined = (await tx.query<Row>("SELECT footholds_baselined_at FROM agents WHERE id = $1", [agent.agentId])).rows[0]?.footholds_baselined_at != null;
    const known = new Map((await tx.query<Row>("SELECT fingerprint, present FROM agent_footholds WHERE agent_id = $1", [agent.agentId])).rows.map((r) => [String(r.fingerprint), r.present === true]));
    const rows = [...byFp].map(([fp, a]) => {
      const assessment = assessFoothold(a);
      return { fp, a, assessment };
    });
    await tx.query(
      `INSERT INTO agent_footholds (agent_id, fingerprint, tenant_id, organization_id, kind, location, name, command, user_name, signed, signer, score, level, reasons, baseline, present, first_seen, last_seen)
       SELECT $1, r.fingerprint, $2, $3, r.kind, r.location, r.name, r.command, r.user_name, r.signed, r.signer, r.score, r.level, r.reasons, $4, true, $5, $5
         FROM jsonb_to_recordset($6::jsonb) AS r(fingerprint text, kind text, location text, name text, command text, user_name text, signed boolean, signer text, score int, level text, reasons jsonb)
       ON CONFLICT (agent_id, fingerprint) DO UPDATE SET
         organization_id = EXCLUDED.organization_id, location = EXCLUDED.location, name = EXCLUDED.name, command = EXCLUDED.command,
         user_name = EXCLUDED.user_name, signed = EXCLUDED.signed, signer = EXCLUDED.signer, score = EXCLUDED.score, level = EXCLUDED.level,
         reasons = EXCLUDED.reasons, present = true, last_seen = EXCLUDED.last_seen`,
      [
        agent.agentId,
        agent.tenantId,
        agent.organizationId,
        !baselined,
        at,
        JSON.stringify(
          rows.map(({ fp, a, assessment }) => ({
            fingerprint: fp,
            kind: a.kind,
            location: a.location,
            name: a.name,
            command: a.command,
            user_name: a.user,
            signed: a.signed,
            signer: a.signer,
            score: assessment.score,
            level: assessment.level,
            reasons: assessment.reasons,
          })),
        ),
      ],
    );
    await tx.query("UPDATE agent_footholds SET present = false WHERE agent_id = $1 AND present AND NOT (fingerprint = ANY($2::text[]))", [agent.agentId, [...byFp.keys()]]);
    if (!baselined) {
      await tx.query("UPDATE agents SET footholds_baselined_at = $2 WHERE id = $1", [agent.agentId, at]);
      return [];
    }
    const appeared = rows.filter((r) => known.get(r.fp) !== true);
    if (!appeared.length) return [];
    const verdicts = await this.verdictMap(tx, agent.organizationId, appeared.map((r) => r.fp));
    return appeared.map((r) => ({ fingerprint: r.fp, entry: r.a, assessment: r.assessment, verdict: verdicts.get(r.fp)?.verdict ?? null }));
  }

  /** New entries worth an alert: rated medium or high and not marked expected, or already marked malicious. */
  alertable(found: readonly NewFoothold[]): NewFoothold[] {
    return found.filter((f) => f.verdict === "malicious" || (f.verdict !== "expected" && f.assessment.level !== "low"));
  }

  private async verdictMap(tx: Queryable, organizationId: string, fingerprints?: string[]): Promise<Map<string, Foothold["verdict"] & object>> {
    const { rows } = await tx.query<Row>(
      `SELECT v.fingerprint, v.verdict, v.note, coalesce(u.display_name, u.email, v.decided_by) AS decided_by, v.decided_at
         FROM foothold_verdicts v LEFT JOIN users u ON 'user:' || u.id::text = v.decided_by
        WHERE v.organization_id = $1 ${fingerprints ? "AND v.fingerprint = ANY($2::text[])" : ""}`,
      fingerprints ? [organizationId, fingerprints] : [organizationId],
    );
    return new Map(rows.map((r) => [String(r.fingerprint), { verdict: r.verdict as FootholdVerdict, note: (r.note as string | null) ?? null, by: (r.decided_by as string | null) ?? null, at: iso(r.decided_at) }]));
  }

  /** Every entry present on the organization's computers, grouped across computers. */
  async overview(tx: Queryable, organizationId: string): Promise<{
    footholds: Foothold[];
    truncated: boolean;
    summary: { entries: number; suspicious: number; malicious: number; newLast7Days: number; endpointsReporting: number };
  }> {
    const { rows } = await tx.query<Row>(
      `SELECT f.agent_id, a.hostname, f.fingerprint, f.kind, f.location, f.name, f.command, f.user_name, f.signed, f.signer, f.reasons, f.score,
              f.baseline, f.first_seen, f.last_seen
         FROM agent_footholds f JOIN agents a ON a.id = f.agent_id
        WHERE f.organization_id = $1 AND f.present
        ORDER BY f.score DESC, f.first_seen DESC LIMIT ${MAX_ROWS}`,
      [organizationId],
    );
    const verdicts = await this.verdictMap(tx, organizationId);
    const groups = new Map<string, Foothold>();
    for (const r of rows) {
      const fp = String(r.fingerprint);
      let g = groups.get(fp);
      if (!g) {
        const score = Number(r.score);
        g = {
          fingerprint: fp,
          kind: r.kind as Foothold["kind"],
          location: String(r.location),
          name: String(r.name),
          command: (r.command as string | null) ?? null,
          signer: (r.signer as string | null) ?? null,
          signed: (r.signed as boolean | null) ?? null,
          assessment: { score, level: score >= 60 ? "high" : score >= 30 ? "medium" : "low", reasons: (r.reasons as FootholdAssessment["reasons"]) ?? [] },
          verdict: verdicts.get(fp) ?? null,
          isNew: false,
          firstSeen: iso(r.first_seen),
          endpointCount: 0,
          endpoints: [],
        };
        groups.set(fp, g);
      }
      g.endpointCount++;
      if (r.baseline !== true) g.isNew = true;
      if (iso(r.first_seen) < g.firstSeen) g.firstSeen = iso(r.first_seen);
      if (g.endpoints.length < MAX_ENDPOINTS) {
        g.endpoints.push({ agentId: String(r.agent_id), hostname: String(r.hostname), user: (r.user_name as string | null) ?? null, firstSeen: iso(r.first_seen), lastSeen: iso(r.last_seen), baseline: r.baseline === true });
      }
    }
    const rank = (f: Foothold) => (f.verdict?.verdict === "malicious" ? 0 : f.verdict?.verdict === "expected" ? 2 : 1);
    const all = [...groups.values()].sort((a, b) => rank(a) - rank(b) || b.assessment.score - a.assessment.score || Number(b.isNew) - Number(a.isNew) || b.firstSeen.localeCompare(a.firstSeen));
    const weekAgo = new Date(this.now() - 7 * 86_400_000).toISOString();
    const endpoints = (await tx.query<{ n: number }>("SELECT count(*)::int AS n FROM agents WHERE organization_id = $1 AND footholds_baselined_at IS NOT NULL", [organizationId])).rows[0]?.n ?? 0;
    return {
      footholds: all.slice(0, MAX_GROUPS),
      truncated: all.length > MAX_GROUPS || rows.length >= MAX_ROWS,
      summary: {
        entries: all.length,
        suspicious: all.filter((f) => !f.verdict && f.assessment.level !== "low").length,
        malicious: all.filter((f) => f.verdict?.verdict === "malicious").length,
        newLast7Days: all.filter((f) => f.isNew && f.endpoints.some((e) => !e.baseline && e.firstSeen >= weekAgo)).length,
        endpointsReporting: endpoints,
      },
    };
  }

  async setVerdict(tx: Queryable, tenantId: string, input: FootholdVerdictInput, actor: string): Promise<number> {
    if (input.verdict === null) {
      const { rowCount } = await tx.query("DELETE FROM foothold_verdicts WHERE organization_id = $1 AND fingerprint = ANY($2::text[])", [input.organizationId, input.fingerprints]);
      return rowCount ?? 0;
    }
    const { rowCount } = await tx.query(
      `INSERT INTO foothold_verdicts (organization_id, fingerprint, tenant_id, verdict, note, decided_by, decided_at)
       SELECT $1, fp, $2, $3, $4, $5, $6 FROM unnest($7::text[]) AS fp
       ON CONFLICT (organization_id, fingerprint) DO UPDATE SET verdict = EXCLUDED.verdict, note = EXCLUDED.note, decided_by = EXCLUDED.decided_by, decided_at = EXCLUDED.decided_at`,
      [input.organizationId, tenantId, input.verdict, input.note || null, actor, new Date(this.now()).toISOString(), input.fingerprints],
    );
    return rowCount ?? 0;
  }
}
