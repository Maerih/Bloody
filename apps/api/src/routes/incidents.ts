import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { CreateIncidentInput, IncidentStatus, RoleKey, Severity, UpdateIncidentInput, Uuid, principalCan, type Principal } from "@bloody/contracts";
import { actorFromRequest, markAudited, recordAudit } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { inOrder, type Queryable } from "../db/pool.js";
import { HttpError, badRequest, conflict } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor, likePattern } from "../http/params.js";
import { toAlert, toAsset, toEscalation, toIdentity, toIncident, toInvestigation, type Row } from "../repo/mappers.js";
import { ACTIVE_STATUSES, INCIDENT_TRANSITIONS, canTransition, createIncident, escalateCritical, transitionStamps } from "../services/incidents.js";
import { keysetClause, loadOne, orderBy, pageRows, parse, type KeysetSort } from "./util.js";

const SEVERITY_RANK_SQL = (col: string) => `(CASE ${col} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)`;

const SORTS: Record<string, KeysetSort> = {
  recent: { expr: "i.detected_at", dir: "desc", cast: "timestamptz" },
  risk: { expr: "i.risk_score", dir: "desc", cast: "numeric" },
  // Severity first, newest first within a severity — packed into one sortable numeric key.
  severity: { expr: `(${SEVERITY_RANK_SQL("i.severity")}::numeric * 10000000000000 + floor(extract(epoch FROM i.detected_at) * 1000))`, dir: "desc", cast: "numeric" },
  number: { expr: "i.number", dir: "desc", cast: "numeric" },
};

const StatusFilter = z
  .union([z.string(), z.array(z.string())])
  .transform((v, ctx): IncidentStatus[] | null => {
    const parts = (Array.isArray(v) ? v : [v]).flatMap((x) => x.split(",")).map((x) => x.trim()).filter(Boolean);
    if (parts.length === 0 || parts.includes("all")) return null;
    const out = new Set<IncidentStatus>();
    for (const p of parts) {
      if (p === "active") ACTIVE_STATUSES.forEach((x) => out.add(x));
      else {
        const parsed = IncidentStatus.safeParse(p);
        if (!parsed.success) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: `Unknown status ${p}` });
          return z.NEVER;
        }
        out.add(parsed.data);
      }
    }
    return [...out];
  });

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  severity: csvOf(Severity).optional(),
  status: StatusFilter.optional(),
  q: z.string().trim().max(200).optional(),
  assigneeId: z.union([Uuid, z.literal("me"), z.literal("unassigned")]).optional(),
  assetId: Uuid.optional(),
  identityId: Uuid.optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  includeMerged: z.enum(["true", "false"]).default("false"),
  sort: z.enum(["recent", "risk", "severity", "number"]).default("recent"),
  limit: Limit(500, 50),
  cursor: z.string().optional(),
});

const CreateBody = CreateIncidentInput.extend({ organizationId: Uuid }).strict();
const PatchBody = UpdateIncidentInput.strict();
const NoteBody = z.object({ body: z.string().trim().min(1).max(20_000), visibility: z.enum(["internal", "customer"]).default("internal") }).strict();

/** Principal-like view of a user's effective bindings (direct + team), for assignment checks. */
async function userPrincipal(tx: Queryable, tenantId: string, userId: string): Promise<Principal | null> {
  const u = await tx.query<{ id: string; email: string; status: string }>("SELECT id, email, status FROM users WHERE id = $1", [userId]);
  if (!u.rows[0] || u.rows[0].status !== "active") return null;
  const b = await tx.query<{ role: string; organization_id: string | null }>(
    `SELECT DISTINCT role, organization_id FROM role_bindings
     WHERE (principal_kind = 'user' AND principal_id = $1) OR (principal_kind = 'team' AND principal_id IN (SELECT team_id FROM team_members WHERE user_id = $1))`,
    [userId],
  );
  const bindings = b.rows.flatMap((r) => {
    const role = RoleKey.safeParse(r.role);
    return role.success ? [{ role: role.data, organizationId: r.organization_id }] : [];
  });
  return { kind: "user", id: userId, tenantId, email: u.rows[0].email, bindings };
}

async function incidentDetail(tx: Queryable, principal: Principal, row: Row) {
  const incident = toIncident(row);
  const org = incident.organizationId;
  const [orgRow, assignee, alerts, assets, identities, investigations, escalations] = await inOrder([
    () => tx.query<{ name: string }>("SELECT name FROM organizations WHERE id = $1", [org]),
    () => incident.assigneeId ? tx.query<{ display_name: string | null; email: string }>("SELECT display_name, email FROM users WHERE id = $1", [incident.assigneeId]) : Promise.resolve({ rows: [] as Array<{ display_name: string | null; email: string }> }),
    () => principalCan(principal, "alert:read", org)
      ? tx.query<Row>("SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = $1 ORDER BY a.first_seen_at, a.id LIMIT 200", [incident.id])
      : Promise.resolve({ rows: [] as Row[] }),
    () => principalCan(principal, "asset:read", org) && incident.assetIds.length
      ? tx.query<Row>("SELECT * FROM assets WHERE id = ANY($1::uuid[]) ORDER BY risk_score DESC NULLS LAST", [incident.assetIds])
      : Promise.resolve({ rows: [] as Row[] }),
    () => principalCan(principal, "identity:read", org) && incident.identityIds.length
      ? tx.query<Row>("SELECT * FROM identities WHERE id = ANY($1::uuid[]) ORDER BY risk_score DESC NULLS LAST", [incident.identityIds])
      : Promise.resolve({ rows: [] as Row[] }),
    () => principalCan(principal, "investigation:read", org) ? tx.query<Row>("SELECT * FROM investigations WHERE incident_id = $1 ORDER BY created_at", [incident.id]) : Promise.resolve({ rows: [] as Row[] }),
    () => principalCan(principal, "escalation:read", org) ? tx.query<Row>("SELECT * FROM escalations WHERE incident_id = $1 ORDER BY created_at DESC", [incident.id]) : Promise.resolve({ rows: [] as Row[] }),
  ]);
  const a = assignee.rows[0];
  return {
    ...incident,
    risk: row.risk ?? null,
    organizationName: orgRow.rows[0]?.name ?? null,
    assigneeName: a ? (a.display_name ?? a.email) : null,
    alerts: alerts.rows.map(toAlert),
    assets: assets.rows.map(toAsset),
    identities: identities.rows.map(toIdentity),
    investigations: investigations.rows.map(toInvestigation),
    escalations: escalations.rows.map((r) => toEscalation(r)),
    allowedTransitions: INCIDENT_TRANSITIONS[incident.status],
  };
}

/** Incidents: list/filter, manual declaration, detail with context, lifecycle and assignment. */
export async function incidentRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/incidents", async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "incident:read", q.organizationId);
    const sort = SORTS[q.sort]!;
    const params: unknown[] = [];
    const where: string[] = [];
    if (orgs) {
      params.push(orgs);
      where.push(`i.organization_id = ANY($${params.length}::uuid[])`);
    }
    if (q.includeMerged === "false") where.push("i.merged_into IS NULL");
    if (q.severity?.length) {
      params.push(q.severity);
      where.push(`i.severity = ANY($${params.length}::text[])`);
    }
    if (q.status) {
      params.push(q.status);
      where.push(`i.status = ANY($${params.length}::text[])`);
    }
    if (q.q) {
      const num = /^(?:#|inc-)?(\d{1,12})$/i.exec(q.q);
      params.push(likePattern(q.q));
      const like = `$${params.length}`;
      if (num) {
        params.push(Number(num[1]));
        where.push(`(i.title ILIKE ${like} OR i.number = $${params.length})`);
      } else where.push(`(i.title ILIKE ${like} OR i.summary ILIKE ${like})`);
    }
    if (q.assigneeId === "unassigned") where.push("i.assignee_id IS NULL");
    else if (q.assigneeId) {
      params.push(q.assigneeId === "me" ? auth.principal.id : q.assigneeId);
      where.push(`i.assignee_id = $${params.length}::uuid`);
    }
    if (q.assetId) {
      params.push(q.assetId);
      where.push(`$${params.length}::uuid = ANY(i.asset_ids)`);
    }
    if (q.identityId) {
      params.push(q.identityId);
      where.push(`$${params.length}::uuid = ANY(i.identity_ids)`);
    }
    if (q.from) {
      params.push(q.from);
      where.push(`i.detected_at >= $${params.length}`);
    }
    if (q.to) {
      params.push(q.to);
      where.push(`i.detected_at < $${params.length}`);
    }
    where.push(keysetClause(sort, "i.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT i.*, o.name AS organization_name, coalesce(u.display_name, u.email) AS assignee_name, ${sort.expr} AS sort_key
         FROM incidents i JOIN organizations o ON o.id = i.organization_id LEFT JOIN users u ON u.id = i.assignee_id
         WHERE ${where.join(" AND ")} ORDER BY ${orderBy(sort, "i.id")} LIMIT $${params.length}`,
        params,
      ),
    );
    return pageRows(rows, q.limit, (r) => ({ ...toIncident(r), organizationName: (r.organization_name as string | null) ?? null, assigneeName: (r.assignee_name as string | null) ?? null }));
  });

  app.post("/incidents", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateBody, request.body);
    requirePermission(request, "incident:write", body.organizationId);
    const detail = await s.db.withTenant(auth.tenantId, async (tx) => {
      await loadOne(tx, "organizations", body.organizationId, "Organization");
      const view = await createIncident(
        tx,
        s.risk,
        actorFromRequest(request),
        {
          tenantId: auth.tenantId,
          organizationId: body.organizationId,
          title: body.title,
          summary: body.summary,
          severity: body.severity,
          alertIds: body.alertIds,
          assetIds: body.assetIds,
          identityIds: body.identityIds,
          attack: body.attack,
          createdBy: `${auth.principal.kind}:${auth.principal.id}`,
        },
        (err) => request.log.warn({ err: err instanceof Error ? err.message : String(err) }, "linking manual incident into the graph failed"),
      );
      markAudited(tx, request);
      const row = await loadOne(tx, "incidents", view.id, "Incident");
      return incidentDetail(tx, auth.principal, row);
    });
    return reply.status(201).send(detail);
  });

  app.get("/incidents/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "incidents", id, "Incident");
      assertRecordAccess(request, "incident:read", String(row.organization_id), "Incident");
      return incidentDetail(tx, auth.principal, row);
    });
  });

  app.patch("/incidents/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const patch = parse(PatchBody, request.body);
    if (Object.keys(patch).length === 0) throw badRequest("Nothing to update");
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const current = await tx.query<Row>("SELECT * FROM incidents WHERE id = $1 FOR UPDATE", [id]);
      if (!current.rows[0]) throw new HttpError(404, "not_found", "Incident not found");
      const before = toIncident(current.rows[0]);
      assertRecordAccess(request, "incident:read", before.organizationId, "Incident");
      requirePermission(request, "incident:write", before.organizationId);
      if (current.rows[0].merged_into) throw conflict("This incident was merged into another incident and is read-only", { mergedInto: current.rows[0].merged_into });

      const sets: string[] = [];
      const params: unknown[] = [id];
      const set = (sql: string, v?: unknown) => {
        if (v === undefined) sets.push(sql);
        else {
          params.push(v);
          sets.push(sql.replace("?", `$${params.length}`));
        }
      };
      const changes: Record<string, { from: unknown; to: unknown }> = {};
      if (patch.title !== undefined && patch.title !== before.title) {
        set("title = ?", patch.title);
        changes.title = { from: before.title, to: patch.title };
      }
      if (patch.summary !== undefined && patch.summary !== before.summary) {
        set("summary = ?", patch.summary);
        changes.summary = { from: before.summary ? "[previous]" : null, to: patch.summary ? "[updated]" : null };
      }
      if (patch.severity !== undefined && patch.severity !== before.severity) {
        set("severity = ?", patch.severity);
        changes.severity = { from: before.severity, to: patch.severity };
      }
      if (patch.status !== undefined && patch.status !== before.status) {
        if (!canTransition(before.status, patch.status)) {
          throw new HttpError(409, "invalid_transition", `An incident cannot move from ${before.status} to ${patch.status}`, { from: before.status, allowed: INCIDENT_TRANSITIONS[before.status] });
        }
        const stamps = transitionStamps(before.status, patch.status);
        set("status = ?", patch.status);
        if (stamps.acknowledged) set("acknowledged_at = coalesce(acknowledged_at, now())");
        if (stamps.contained) set("contained_at = coalesce(contained_at, now())");
        if (stamps.remediated) set("remediated_at = coalesce(remediated_at, now())");
        if (stamps.closed) set("closed_at = now()");
        if (stamps.reopened) set("closed_at = NULL");
        changes.status = { from: before.status, to: patch.status };
      }
      if (patch.assigneeId !== undefined && patch.assigneeId !== before.assigneeId) {
        if (patch.assigneeId !== null) {
          const assignee = await userPrincipal(tx, auth.tenantId, patch.assigneeId);
          if (!assignee || !principalCan(assignee, "incident:read", before.organizationId)) {
            throw badRequest("The assignee must be an active user with access to this organization's incidents");
          }
          set("acknowledged_at = coalesce(acknowledged_at, now())");
        }
        set("assignee_id = ?", patch.assigneeId);
        changes.assigneeId = { from: before.assigneeId, to: patch.assigneeId };
      }
      if (sets.length === 0) return incidentDetail(tx, auth.principal, current.rows[0]);
      const { rows } = await tx.query<Row>(`UPDATE incidents SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, params);
      const after = rows[0]!;

      const actorLabel = auth.principal.email ?? auth.principal.displayName ?? auth.principal.id;
      if (changes.status) {
        // Mirror the lifecycle into every investigation of the incident.
        await tx.query(
          `INSERT INTO timeline_entries (tenant_id, organization_id, investigation_id, kind, actor_id, title, body, ref_id)
           SELECT tenant_id, organization_id, id, 'status_change', $2, $3, $4, $5::text FROM investigations WHERE incident_id = $1::uuid`,
          [id, `${auth.principal.kind}:${auth.principal.id}`, `Incident #${before.number} ${before.status} → ${patch.status}`, `Changed by ${actorLabel}`, id],
        );
        if (patch.status === "closed" || patch.status === "false_positive") {
          await tx.query(
            `UPDATE escalations SET status = 'resolved', resolved_at = now(), resolved_by = $2, resolution_note = coalesce(resolution_note, $3)
             WHERE incident_id = $1 AND status <> 'resolved'`,
            [id, `${auth.principal.kind}:${auth.principal.id}`, `Incident closed as ${patch.status}`],
          );
        }
      }
      if (changes.severity && patch.severity === "critical") {
        await escalateCritical(tx, actorFromRequest(request), toIncident(after), `Severity raised to critical by ${actorLabel}`);
      }
      await recordAudit(tx, request, {
        action: changes.status ? "incident.status_changed" : changes.assigneeId && Object.keys(changes).length === 1 ? "incident.assigned" : "incident.updated",
        organizationId: before.organizationId,
        targetKind: "incident",
        targetId: id,
        details: { number: before.number, changes },
      });
      return incidentDetail(tx, auth.principal, after);
    });
  });

  app.get("/incidents/:id/notes", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "incidents", id, "Incident");
      assertRecordAccess(request, "incident:read", String(row.organization_id), "Incident");
      // Customer-role principals only see notes shared with the customer.
      const internal = principalCan(auth.principal, "investigation:read", String(row.organization_id));
      const { rows } = await tx.query<Row>(
        `SELECT * FROM notes WHERE incident_id = $1 ${internal ? "" : "AND visibility = 'customer'"} ORDER BY created_at DESC LIMIT 500`,
        [id],
      );
      return { items: rows.map(noteView), nextCursor: null };
    });
  });

  app.post("/incidents/:id/notes", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(NoteBody, request.body);
    const note = await s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "incidents", id, "Incident");
      assertRecordAccess(request, "incident:read", String(row.organization_id), "Incident");
      requirePermission(request, "incident:write", String(row.organization_id));
      const { rows } = await tx.query<Row>(
        "INSERT INTO notes (tenant_id, organization_id, incident_id, author_id, author_label, body, visibility) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        [auth.tenantId, row.organization_id, id, `${auth.principal.kind}:${auth.principal.id}`, auth.principal.email ?? auth.principal.displayName ?? null, body.body, body.visibility],
      );
      await recordAudit(tx, request, { action: "incident.note_added", organizationId: String(row.organization_id), targetKind: "incident", targetId: id, details: { noteId: rows[0]!.id, visibility: body.visibility } });
      return noteView(rows[0]!);
    });
    return reply.status(201).send(note);
  });
}

export function noteView(r: Row) {
  return {
    id: String(r.id),
    organizationId: String(r.organization_id),
    incidentId: (r.incident_id as string | null) ?? null,
    investigationId: (r.investigation_id as string | null) ?? null,
    authorId: String(r.author_id),
    authorLabel: (r.author_label as string | null) ?? null,
    body: String(r.body),
    visibility: String(r.visibility),
    createdAt: String(r.created_at),
  };
}
