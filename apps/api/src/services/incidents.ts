import { SEVERITY_RANK, type AttackTechnique, type IncidentStatus, type Severity } from "@bloody/contracts";
import { normalizeHostname, type EntityRef, type RiskEngine } from "@bloody/engines";
import { writeAudit, type AuditActor } from "../audit/audit.js";
import type { Queryable } from "../db/pool.js";
import { badRequest } from "../http/errors.js";
import { toIncident, type IncidentView, type Row } from "../repo/mappers.js";
import { graphFor } from "./inventory.js";

/**
 * Incident lifecycle. Status changes follow an explicit state machine and stamp the SLA
 * timestamps the Command Center's MTTA / MTTC / MTTR are computed from:
 *
 *   acknowledged_at  first move out of `new` (or first assignment)
 *   contained_at     first move to `contained` / `remediated`
 *   remediated_at    first move to `remediated`
 *   closed_at        move to `closed` / `false_positive` (cleared on re-open)
 */
export const INCIDENT_TRANSITIONS: Record<IncidentStatus, readonly IncidentStatus[]> = {
  new: ["triage", "investigating", "contained", "remediated", "closed", "false_positive"],
  triage: ["investigating", "contained", "remediated", "closed", "false_positive"],
  investigating: ["triage", "contained", "remediated", "closed", "false_positive"],
  contained: ["investigating", "remediated", "closed"],
  remediated: ["investigating", "closed"],
  closed: ["triage", "investigating"],
  false_positive: ["triage"],
};

export const ACTIVE_STATUSES: readonly IncidentStatus[] = ["new", "triage", "investigating", "contained"];

export interface TransitionStamps {
  acknowledged: boolean;
  contained: boolean;
  remediated: boolean;
  closed: boolean;
  reopened: boolean;
}

export function canTransition(from: IncidentStatus, to: IncidentStatus): boolean {
  return from === to || INCIDENT_TRANSITIONS[from].includes(to);
}

/** Which timestamps a transition sets (only ever stamped when still null, except closed_at). */
export function transitionStamps(from: IncidentStatus, to: IncidentStatus): TransitionStamps {
  const closing = to === "closed" || to === "false_positive";
  return {
    acknowledged: from === "new" && to !== "new",
    contained: to === "contained" || to === "remediated",
    remediated: to === "remediated",
    closed: closing && from !== to,
    reopened: (from === "closed" || from === "false_positive") && !closing,
  };
}

export const CRITICAL_ESCALATION_MINUTES = 15;

/** Open an escalation for a critical incident (idempotent: one open escalation per incident). */
export async function escalateCritical(tx: Queryable, actor: AuditActor, incident: IncidentView, reason: string): Promise<string | null> {
  if (SEVERITY_RANK[incident.severity] < SEVERITY_RANK.critical) return null;
  const { rows } = await tx.query<{ id: string }>(
    `INSERT INTO escalations (tenant_id, organization_id, incident_id, title, reason, severity, status, due_at, created_by)
     VALUES ($1, $2, $3, $4, $5, 'critical', 'open', now() + make_interval(mins => $6), $7)
     ON CONFLICT (tenant_id, incident_id) WHERE incident_id IS NOT NULL AND status <> 'resolved' DO NOTHING
     RETURNING id`,
    [incident.tenantId, incident.organizationId, incident.id, `Critical incident #${incident.number}: ${incident.title}`.slice(0, 300), reason.slice(0, 2000), CRITICAL_ESCALATION_MINUTES, `${actor.actorKind}:${actor.actorId ?? "unknown"}`],
  );
  const id = rows[0]?.id ?? null;
  if (id) {
    await writeAudit(tx, actor, { action: "escalation.created", organizationId: incident.organizationId, targetKind: "escalation", targetId: id, details: { incidentId: incident.id, dueInMinutes: CRITICAL_ESCALATION_MINUTES } });
  }
  return id;
}

export interface CreateIncidentParams {
  tenantId: string;
  organizationId: string;
  title: string;
  summary?: string | undefined;
  severity: Severity;
  alertIds: string[];
  assetIds: string[];
  identityIds: string[];
  attack: AttackTechnique[];
  createdBy: string;
}

/**
 * Manual incident creation (analyst-declared). Referenced alerts/assets/identities must belong
 * to the incident's organization; risk is scored by the Risk Engine with its explanation.
 */
export async function createIncident(tx: Queryable, risk: RiskEngine, actor: AuditActor, p: CreateIncidentParams, onGraphError: (err: unknown) => void): Promise<IncidentView> {
  const alertRows = p.alertIds.length
    ? (await tx.query<Row>("SELECT * FROM alerts WHERE id = ANY($1::uuid[]) AND organization_id = $2", [p.alertIds, p.organizationId])).rows
    : [];
  if (alertRows.length !== new Set(p.alertIds).size) throw badRequest("alertIds must reference alerts of the incident's organization");
  const assetRows = p.assetIds.length
    ? (
        await tx.query<Row>(
          `SELECT a.*, EXISTS (SELECT 1 FROM agents ag WHERE ag.asset_id = a.id AND ag.status IN ('protected', 'isolated')) AS edr
           FROM assets a WHERE a.id = ANY($1::uuid[]) AND a.organization_id = $2`,
          [p.assetIds, p.organizationId],
        )
      ).rows
    : [];
  if (assetRows.length !== new Set(p.assetIds).size) throw badRequest("assetIds must reference assets of the incident's organization");
  const identityRows = p.identityIds.length
    ? (await tx.query<Row>("SELECT * FROM identities WHERE id = ANY($1::uuid[]) AND organization_id = $2", [p.identityIds, p.organizationId])).rows
    : [];
  if (identityRows.length !== new Set(p.identityIds).size) throw badRequest("identityIds must reference identities of the incident's organization");

  const attack = dedupeAttack([...p.attack, ...alertRows.flatMap((a) => (Array.isArray(a.attack) ? (a.attack as AttackTechnique[]) : []))]);
  const assessment = risk.scoreIncident({
    title: p.title,
    status: "new",
    attack,
    alerts: alertRows.map((a) => ({ ruleId: (a.rule_id as string | null) ?? null, title: String(a.title), severity: a.severity as Severity, confidence: Number(a.confidence), source: String(a.source), attack: (a.attack as AttackTechnique[]) ?? [] })),
    assets: assetRows.map((a) => ({ name: String(a.name), criticality: a.criticality as "low", edr: Boolean(a.edr) })),
    identities: identityRows.map((i) => ({ principal: String(i.principal), privileged: Boolean(i.privileged) })),
  });
  const severity = SEVERITY_RANK[assessment.severity] > SEVERITY_RANK[p.severity] ? assessment.severity : p.severity;
  const firstSeen = alertRows.map((a) => String(a.first_seen_at)).sort()[0] ?? null;
  const lastSeen = alertRows.map((a) => String(a.last_seen_at)).sort().at(-1) ?? null;
  const { rows } = await tx.query<Row>(
    `INSERT INTO incidents (tenant_id, organization_id, number, title, summary, severity, status, risk_score, risk, attack, asset_ids, identity_ids, source,
                            escalation_reasons, first_seen_at, last_seen_at, detected_at, created_by)
     VALUES ($1, $2, next_incident_number($1), $3, $4, $5, 'new', $6, $7::jsonb, $8::jsonb, $9, $10, 'manual', $11, $12, $13, now(), $14)
     RETURNING *`,
    [
      p.tenantId,
      p.organizationId,
      p.title,
      p.summary ?? null,
      severity,
      assessment.score,
      JSON.stringify(assessment),
      JSON.stringify(attack),
      [...new Set(p.assetIds)],
      [...new Set(p.identityIds)],
      severity !== p.severity ? [`Severity raised from ${p.severity} to ${severity} by the risk engine (${assessment.score}/100).`] : [],
      firstSeen,
      lastSeen,
      p.createdBy,
    ],
  );
  let incident = rows[0]!;
  if (alertRows.length > 0) {
    await tx.query(
      `INSERT INTO incident_alerts (incident_id, alert_id, tenant_id, organization_id)
       SELECT $1, a.id, a.tenant_id, a.organization_id FROM alerts a WHERE a.id = ANY($2::uuid[]) ON CONFLICT DO NOTHING`,
      [incident.id, p.alertIds],
    );
    await tx.query("UPDATE alerts SET incident_id = $1, status = CASE WHEN status IN ('new', 'triaged') THEN 'promoted' ELSE status END WHERE id = ANY($2::uuid[])", [incident.id, p.alertIds]);
    const counted = await tx.query<Row>("UPDATE incidents SET alert_count = (SELECT count(*) FROM incident_alerts WHERE incident_id = $1) WHERE id = $1 RETURNING *", [incident.id]);
    incident = counted.rows[0]!;
  }
  const view = toIncident(incident);

  const entities: EntityRef[] = [
    ...assetRows.map((a): EntityRef => {
      const host = typeof a.hostname === "string" ? normalizeHostname(a.hostname) : null;
      return { kind: "endpoint", key: host ?? `asset:${String(a.id)}`, label: String(a.name) };
    }),
    ...identityRows.map((i): EntityRef => ({ kind: "identity", key: `${String(i.provider).toLowerCase()}:${String(i.principal).toLowerCase()}`, label: String(i.principal) })),
  ];
  try {
    await tx.query("SAVEPOINT link_incident");
    await graphFor(tx, p.tenantId).linkIncident({ incidentId: view.id, organizationId: view.organizationId, title: view.title, severity: view.severity, status: view.status, detectedAt: view.detectedAt, entities, techniques: attack });
    await tx.query("RELEASE SAVEPOINT link_incident");
  } catch (err) {
    await tx.query("ROLLBACK TO SAVEPOINT link_incident");
    onGraphError(err);
  }
  await writeAudit(tx, actor, { action: "incident.created", organizationId: view.organizationId, targetKind: "incident", targetId: view.id, details: { number: view.number, severity: view.severity, riskScore: view.riskScore, alerts: view.alertCount, source: "manual" } });
  await escalateCritical(tx, actor, view, `Critical incident declared manually. ${assessment.summary}`);
  return view;
}

export function dedupeAttack(list: AttackTechnique[]): AttackTechnique[] {
  const out = new Map<string, AttackTechnique>();
  for (const t of list) if (!out.has(t.id)) out.set(t.id, t);
  return [...out.values()];
}
