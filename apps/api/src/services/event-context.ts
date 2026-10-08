import type { Database } from "../db/pool.js";
import { toAlert, toEscalation, toIncident, type Row } from "../repo/mappers.js";
import type { DomainEvent } from "./domain-events.js";

/**
 * Loads the entity behind a domain event (incident, escalation, alert, agent, response action…)
 * so notification templates (`{{incident.title}}`) and playbook conditions (`incident.severity`)
 * see current, tenant-scoped data rather than whatever the publisher happened to include.
 */

export interface EventContext {
  organizationName: string | null;
  /** Command Center path of the subject (joined with PUBLIC_URL for links). */
  path: string | null;
  /** Template / condition data (merged over the event's own data). */
  data: Record<string, unknown>;
}

function durationLabel(ms: number): string {
  const m = Math.round(ms / 60_000);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${m % 60} min`;
  return `${Math.floor(h / 24)} days`;
}

export async function loadEventContext(db: Database, e: DomainEvent, now: number): Promise<EventContext> {
  return db.withTenant(e.tenantId, async (tx) => {
    const orgName = e.organizationId ? ((await tx.query<{ name: string }>("SELECT name FROM organizations WHERE id = $1", [e.organizationId])).rows[0]?.name ?? null) : null;
    const data: Record<string, unknown> = { ...e.data };
    let path: string | null = null;
    const kind = e.subject.kind;
    const id = e.subject.id;
    const uuid = /^[0-9a-f-]{36}$/i.test(id);
    if (kind === "incident" && uuid) {
      const { rows } = await tx.query<Row>("SELECT * FROM incidents WHERE id = $1", [id]);
      if (rows[0]) {
        const i = toIncident(rows[0]);
        data.incident = {
          id: i.id,
          number: i.number,
          title: i.title,
          summary: i.summary,
          severity: i.severity,
          status: i.status,
          riskScore: i.riskScore,
          assetCount: i.assetIds.length,
          identityCount: i.identityIds.length,
          alertCount: i.alertCount,
          techniques: i.attack.map((t) => t.id),
          detectedAt: i.detectedAt,
          assigneeId: i.assigneeId,
          source: i.source,
        };
        data.severity ??= i.severity;
        path = `/incidents/${i.id}`;
      }
    } else if (kind === "escalation" && uuid) {
      const { rows } = await tx.query<Row>("SELECT e.*, i.number AS incident_number FROM escalations e LEFT JOIN incidents i ON i.id = e.incident_id WHERE e.id = $1", [id]);
      if (rows[0]) {
        const x = toEscalation(rows[0], now);
        data.escalation = {
          id: x.id,
          title: x.title,
          details: x.reason,
          severity: x.severity,
          status: x.status,
          dueAt: x.dueAt,
          overdue: x.overdue,
          overdueBy: x.overdue ? durationLabel(now - Date.parse(x.dueAt)) : null,
          incidentId: x.incidentId,
          incidentNumber: rows[0].incident_number ?? null,
        };
        data.severity ??= x.severity;
        path = `/escalations?id=${x.id}`;
      }
    } else if (kind === "alert" && uuid) {
      const { rows } = await tx.query<Row>("SELECT * FROM alerts WHERE id = $1", [id]);
      if (rows[0]) {
        const a = toAlert(rows[0]);
        data.alert = { id: a.id, title: a.title, severity: a.severity, status: a.status, ruleId: a.ruleId, riskScore: a.riskScore, confidence: a.confidence, techniques: a.attack.map((t) => t.id), assetId: a.assetId, identityId: a.identityId, incidentId: a.incidentId, firstSeenAt: a.firstSeenAt };
        data.severity ??= a.severity;
        path = `/alerts/${a.id}`;
      }
    } else if (kind === "response_action" && uuid) {
      const { rows } = await tx.query<Row>("SELECT * FROM response_actions WHERE id = $1", [id]);
      if (rows[0]) {
        const r = rows[0];
        data.action = { id: r.id, action: r.action, risk: r.risk, status: r.status, target: r.target, reason: r.reason, requestedBy: r.requested_by, requestedVia: r.requested_via, incidentId: r.incident_id };
        path = `/soar/approvals?action=${String(r.id)}`;
      }
    } else if (kind === "agent" && uuid) {
      const { rows } = await tx.query<Row>("SELECT * FROM agents WHERE id = $1", [id]);
      if (rows[0]) {
        data.agent = { id: rows[0].id, hostname: rows[0].hostname, platform: rows[0].platform, version: rows[0].version, lastCheckinAt: rows[0].last_checkin_at, status: rows[0].status };
        path = `/agents?id=${String(rows[0].id)}`;
      }
    } else if (kind === "report_run" && uuid) {
      path = `/reports?run=${id}`;
    }
    if (e.event === "indicator.matched" && !path) path = "/cti/matches";
    if (e.event === "vulnerability.kev_detected" && !path) path = "/vm/kev";
    if ((e.event === "trial.ending" || e.event === "usage.quota_exceeded") && !path) path = e.event === "trial.ending" ? "/trials" : "/billing";
    return { organizationName: orgName, path, data };
  });
}
