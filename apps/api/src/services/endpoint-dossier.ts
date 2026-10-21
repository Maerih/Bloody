import { HARDENING_CHECKS, RESPONSE_ACTIONS, type EndpointActivity, type EndpointDossier, type EndpointDossierAgent } from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";
import type { Row } from "../repo/mappers.js";
import { AppControlService } from "./app-control.js";
import { AttackReductionService } from "./attack-reduction.js";
import { FootholdsService } from "./footholds.js";
import { PatchingService } from "./patching.js";
import { RmmGuardService } from "./rmm-guard.js";

const MAX_ACTIVITY = 300;
const PER_SOURCE = 150;
const iso = (v: unknown) => new Date(v instanceof Date ? v : String(v)).toISOString();
const isoOrNull = (v: unknown) => (v == null ? null : iso(v));
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTION_LABEL = new Map<string, string>(RESPONSE_ACTIONS.map((a) => [a.key, a.label]));
const actionLabel = (k: string) => ACTION_LABEL.get(k) ?? k.replace(/_/g, " ");
const humanize = (s: string) => s.replace(/[._]/g, " ").replace(/^\w/, (c) => c.toUpperCase());

/**
 * One computer's dossier (EndpointDossier): its agents and isolation, patching, hardening,
 * persistence, remote-access tools and a timeline of what happened to it. Runs inside the
 * caller's tenant transaction; the caller checks access to the asset.
 */
export class EndpointDossierService {
  constructor(private readonly now: () => number) {}

  async build(tx: Queryable, assetId: string, opts: { since?: string; until?: string } = {}): Promise<EndpointDossier | null> {
    const at = this.now();
    const asset = (await tx.query<Row>("SELECT id, organization_id, name, hostname FROM assets WHERE id = $1", [assetId])).rows[0];
    if (!asset) return null;
    const organizationId = String(asset.organization_id);
    const since = opts.since ?? new Date(at - 90 * 86_400_000).toISOString();
    const until = opts.until ?? new Date(at + 60_000).toISOString();

    const agentRows = (await tx.query<Row>("SELECT * FROM agents WHERE asset_id = $1 ORDER BY (engine = 'sciat') DESC, updated_at DESC", [assetId])).rows;
    const agents: EndpointDossierAgent[] = agentRows.map((r) => {
      const iso_ = r.isolation as { mode?: string; since?: string; source?: string } | null;
      return {
        id: String(r.id),
        engine: String(r.engine),
        version: (r.version as string | null) ?? null,
        platform: (r.platform as string | null) ?? null,
        status: String(r.status),
        isolation: iso_ ? { mode: iso_.mode === "lan" ? "lan" : "full", since: iso_.since ? iso(iso_.since) : iso(r.updated_at), source: iso_.source === "endpoint" ? "endpoint" : "platform" } : null,
        enrolledAt: isoOrNull(r.enrolled_at ?? r.created_at),
        lastCheckinAt: isoOrNull(r.last_checkin_at),
      };
    });
    const sciat = agents.find((a) => a.engine === "sciat") ?? null;
    const agentIds = agents.map((a) => a.id);

    // Posture from the SCIAT Agent's reports (same rules as the organization views).
    let patching: EndpointDossier["patching"] = null;
    let hardening: EndpointDossier["hardening"] = null;
    let footholds: EndpointDossier["footholds"] = [];
    let remoteAccess: EndpointDossier["remoteAccess"] = [];
    if (sciat) {
      patching = (await new PatchingService(() => at).overview(tx, organizationId)).endpoints.find((e) => e.agentId === sciat.id) ?? null;
      const ar = new AttackReductionService();
      const exceptions = await ar.exceptions(tx, organizationId);
      const accepted = new Set(exceptions.keys());
      const mine = (await ar.endpoints(tx, organizationId, accepted)).find((e) => e.agentId === sciat.id);
      if (mine) {
        const meta = new Map(HARDENING_CHECKS.map((c) => [c.key, c]));
        hardening = {
          score: mine.score,
          collectedAt: mine.collectedAt,
          checks: mine.results
            .filter((r) => r.status !== "na" && meta.has(r.key))
            .map((r) => {
              const c = meta.get(r.key)!;
              return { key: r.key, title: c.title, severity: c.severity, status: r.status, detail: r.detail, accepted: accepted.has(r.key), fix: c.fix };
            }),
        };
      }
      footholds = (await new FootholdsService(() => at).overview(tx, organizationId, sciat.id)).footholds.map((f) => ({
        name: f.name,
        kind: f.kind,
        location: f.location,
        command: f.command,
        level: f.assessment.level,
        score: f.assessment.score,
        reasons: f.assessment.reasons.map((r) => r.text),
        verdict: f.verdict?.verdict ?? null,
        isNew: f.isNew,
        firstSeen: f.firstSeen,
      }));
      remoteAccess = (await new RmmGuardService(new AppControlService(() => at)).findings(tx, organizationId)).flatMap((f) => {
        const e = f.endpoints.find((x) => x.agentId === sciat.id);
        return e ? [{ name: f.tool.name, vendor: f.tool.vendor, approved: f.approved, evidence: e.evidence.map((v) => `${v.kind === "process" ? "Running" : "Installed"}: ${v.value}`) }] : [];
      });
    }

    const activity = await this.activity(tx, assetId, agentIds, agents, since, until);
    return {
      assetId,
      organizationId,
      hostname: String(asset.hostname ?? asset.name),
      generatedAt: new Date(at).toISOString(),
      agents,
      patching,
      hardening,
      footholds,
      remoteAccess,
      activity: activity.slice(0, MAX_ACTIVITY),
      activityTruncated: activity.length > MAX_ACTIVITY,
      activitySince: since,
    };
  }

  /** What happened to the computer, newest first. */
  private async activity(tx: Queryable, assetId: string, agentIds: string[], agents: EndpointDossierAgent[], since: string, until: string): Promise<EndpointActivity[]> {
    const out: EndpointActivity[] = [];
    const ev = (e: Omit<EndpointActivity, "detail" | "actor" | "outcome" | "severity"> & Partial<EndpointActivity>) =>
      out.push({ detail: null, actor: null, outcome: null, severity: null, ...e });
    const inWindow = (t: string | null) => t !== null && t >= since && t < until;

    for (const a of agents) {
      if (inWindow(a.enrolledAt)) ev({ at: a.enrolledAt!, kind: "agent", title: a.engine === "sciat" ? `SCIAT Agent installed${a.version ? ` (version ${a.version})` : ""}` : `${humanize(a.engine)} agent linked`, actor: a.engine === "sciat" ? "SCIAT Agent" : null, outcome: "success" });
    }

    // Response actions (isolate, release, scans…): requested → decided → finished.
    const actions = await tx.query<Row>(
      `SELECT * FROM response_actions WHERE target->>'kind' = 'asset' AND target->>'id' = $1
          AND (created_at >= $2 OR decided_at >= $2 OR finished_at >= $2) AND created_at < $3
        ORDER BY created_at DESC LIMIT ${PER_SOURCE}`,
      [assetId, since, until],
    );
    const names = await this.names(tx, [
      ...actions.rows.flatMap((r) => [r.requested_by, r.approved_by]),
    ]);
    const who = (id: unknown) => (id == null ? null : names.get(String(id)) ?? String(id));
    for (const r of actions.rows) {
      const action = String(r.action);
      const kind = action === "isolate_endpoint" || action === "release_endpoint" ? "isolation" : "response";
      const params = (r.parameters ?? {}) as Record<string, unknown>;
      const label = action === "isolate_endpoint" ? `Isolation${params.mode === "lan" ? " (LAN only)" : params.mode === "full" ? " (full)" : ""}` : actionLabel(action);
      const created = iso(r.created_at);
      if (inWindow(created)) ev({ at: created, kind, title: `${label} requested${r.emergency ? " (emergency)" : ""}`, detail: (r.reason as string | null) ?? null, actor: who(r.requested_by), outcome: "pending" });
      const decided = isoOrNull(r.decided_at);
      if (decided && inWindow(decided) && r.approved_by) {
        const rejected = r.status === "rejected";
        ev({ at: decided, kind, title: `${label} ${rejected ? "rejected" : "approved"}`, detail: (r.decision_comment as string | null) ?? null, actor: who(r.approved_by), outcome: rejected ? "failure" : "success" });
      }
      const finished = isoOrNull(r.finished_at);
      if (finished && inWindow(finished)) {
        const ok = r.status === "succeeded";
        const done =
          action === "isolate_endpoint" ? (ok ? "Isolated from the network" : "Isolation failed") : action === "release_endpoint" ? (ok ? "Released from isolation" : "Release failed") : `${actionLabel(action)} ${ok ? "completed" : "failed"}`;
        const err = (r.error as { message?: string } | null)?.message ?? null;
        ev({ at: finished, kind, title: done, detail: ok ? ((r.result as { summary?: string } | null)?.summary ?? null) : err, actor: String(r.executor ?? "") === "sciat:agent" ? "SCIAT Agent" : (r.executor as string | null) ?? null, outcome: ok ? "success" : "failure" });
      }
    }

    // Audit trail entries about the computer or its agents (response decisions are above).
    if (agentIds.length || assetId) {
      const audit = await tx.query<Row>(
        `SELECT action, outcome, actor_kind, actor_id, actor_label, details, at FROM audit_log
          WHERE (target_id = $1 OR target_id = ANY($2::text[]) OR details->>'agentId' = ANY($2::text[]))
            AND action NOT LIKE 'response.%' AND action NOT LIKE 'approval.%' AND action NOT LIKE 'get %'
            AND at >= $3 AND at < $4
          ORDER BY at DESC LIMIT ${PER_SOURCE}`,
        [assetId, agentIds, since, until],
      );
      const auditNames = await this.names(tx, audit.rows.map((r) => r.actor_id));
      for (const r of audit.rows) {
        const action = String(r.action);
        const d = (r.details ?? {}) as Record<string, unknown>;
        const actor = r.actor_kind === "user" ? auditNames.get(String(r.actor_id)) ?? (r.actor_label as string | null) : ((r.actor_label as string | null) ?? humanize(String(r.actor_kind)));
        const title =
          action === "agent.isolation_reported"
            ? `The computer reported it is isolated${d.mode === "lan" ? " (LAN only)" : ""}`
            : action === "agent.release_reported"
              ? "Released from isolation on the computer itself"
              : humanize(action.replace(/^(post|put|patch|delete) \/api\/v1\//, ""));
        ev({
          at: iso(r.at),
          kind: action.startsWith("agent.isolation") || action.startsWith("agent.release") ? "isolation" : action.startsWith("agent") ? "agent" : "change",
          title,
          actor,
          outcome: r.outcome === "failure" || r.outcome === "denied" ? "failure" : "success",
        });
      }
    }

    // Detections on the computer.
    const alerts = await tx.query<Row>(
      `SELECT title, severity, source, status, first_seen_at FROM alerts WHERE asset_id = $1 AND first_seen_at >= $2 AND first_seen_at < $3 ORDER BY first_seen_at DESC LIMIT ${PER_SOURCE}`,
      [assetId, since, until],
    );
    for (const r of alerts.rows) {
      ev({ at: iso(r.first_seen_at), kind: "alert", title: String(r.title), detail: [r.source ? `Source: ${String(r.source)}` : null, `Status: ${String(r.status).replace(/_/g, " ")}`].filter(Boolean).join(" · "), severity: r.severity as EndpointActivity["severity"] });
    }
    const incidents = await tx.query<Row>(
      `SELECT number, title, severity, status, detected_at, contained_at, closed_at FROM incidents
        WHERE $1 = ANY(asset_ids) AND (detected_at >= $2 OR closed_at >= $2) AND detected_at < $3 ORDER BY detected_at DESC LIMIT ${PER_SOURCE}`,
      [assetId, since, until],
    );
    for (const r of incidents.rows) {
      const sev = r.severity as EndpointActivity["severity"];
      if (inWindow(iso(r.detected_at))) ev({ at: iso(r.detected_at), kind: "incident", title: `Incident #${String(r.number)} opened: ${String(r.title)}`, severity: sev });
      const contained = isoOrNull(r.contained_at);
      if (contained && inWindow(contained)) ev({ at: contained, kind: "incident", title: `Incident #${String(r.number)} contained`, severity: sev, outcome: "success" });
      const closed = isoOrNull(r.closed_at);
      if (closed && inWindow(closed)) ev({ at: closed, kind: "incident", title: `Incident #${String(r.number)} closed`, severity: sev, outcome: "success" });
    }

    if (agentIds.length) {
      // Autostart entries that appeared after the computer's first report.
      const fh = await tx.query<Row>(
        `SELECT name, command, kind, level, first_seen FROM agent_footholds WHERE agent_id = ANY($1::uuid[]) AND NOT baseline AND first_seen >= $2 AND first_seen < $3
          ORDER BY first_seen DESC LIMIT ${PER_SOURCE}`,
        [agentIds, since, until],
      );
      for (const r of fh.rows) {
        const level = String(r.level);
        ev({ at: iso(r.first_seen), kind: "persistence", title: `New autostart entry: ${String(r.name)}`, detail: (r.command as string | null) ?? null, severity: level === "high" ? "high" : level === "medium" ? "medium" : "low", actor: "SCIAT Agent" });
      }
      const ac = await tx.query<Row>(
        `SELECT name, path, verdict, occurred_at FROM app_control_events WHERE agent_id = ANY($1::uuid[]) AND occurred_at >= $2 AND occurred_at < $3
          ORDER BY occurred_at DESC LIMIT ${PER_SOURCE}`,
        [agentIds, since, until],
      );
      for (const r of ac.rows) {
        const blocked = r.verdict === "blocked";
        ev({ at: iso(r.occurred_at), kind: "app_control", title: blocked ? `App Control blocked ${String(r.name)}` : `App Control would have blocked ${String(r.name)} (audit mode)`, detail: (r.path as string | null) ?? null, actor: "SCIAT Agent", outcome: blocked ? "success" : null, severity: blocked ? "medium" : "low" });
      }
      // Commands sent outside response actions (e.g. hardening fixes run by a playbook).
      const cmds = await tx.query<Row>(
        `SELECT kind, args, status, created_at, finished_at FROM agent_commands WHERE agent_id = ANY($1::uuid[]) AND response_action_id IS NULL AND created_at >= $2 AND created_at < $3
          ORDER BY created_at DESC LIMIT ${PER_SOURCE}`,
        [agentIds, since, until],
      );
      for (const r of cmds.rows) {
        const args = Array.isArray(r.args) ? (r.args as unknown[]).map(String) : [];
        ev({ at: iso(r.finished_at ?? r.created_at), kind: "response", title: `Command ${humanize(String(r.kind))}${args[0] ? ` (${args[0]})` : ""} ${r.status === "succeeded" ? "completed" : r.status === "failed" ? "failed" : "sent"}`, actor: "SCIAT Agent", outcome: r.status === "succeeded" ? "success" : r.status === "failed" ? "failure" : "pending" });
      }
    }

    return out.sort((a, b) => b.at.localeCompare(a.at));
  }

  /** Display names for user ids ("user:<id>" or bare ids); unknown ids are left out. */
  private async names(tx: Queryable, ids: unknown[]): Promise<Map<string, string>> {
    const raw = [...new Set(ids.filter((v): v is string => typeof v === "string"))];
    const bare = raw.map((v) => v.replace(/^user:/, "")).filter((v) => UUID_RE.test(v));
    if (!bare.length) return new Map();
    const { rows } = await tx.query<{ id: string; n: string }>("SELECT id::text AS id, coalesce(nullif(display_name, ''), email) AS n FROM users WHERE id = ANY($1::uuid[])", [bare]);
    const byId = new Map(rows.map((r) => [r.id, r.n]));
    const out = new Map<string, string>();
    for (const v of raw) {
      const n = byId.get(v.replace(/^user:/, ""));
      if (n) out.set(v, n);
    }
    return out;
  }
}

/**
 * Leave out what the reader may not see: alerts (alert:read), incidents (incident:read),
 * response actions other than isolation (incident:read, as on the approvals queue) and audit
 * changes (audit:read). Isolation, agent, persistence and App Control events come with asset:read.
 */
export function dossierFor(d: EndpointDossier, can: (permission: "alert:read" | "incident:read" | "audit:read") => boolean): EndpointDossier {
  const allowed: Record<EndpointActivity["kind"], boolean> = {
    agent: true,
    isolation: true,
    persistence: true,
    app_control: true,
    alert: can("alert:read"),
    incident: can("incident:read"),
    response: can("incident:read"),
    change: can("audit:read"),
  };
  return { ...d, activity: d.activity.filter((e) => allowed[e.kind]) };
}
