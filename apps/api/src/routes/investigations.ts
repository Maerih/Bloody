import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { InvestigationStatus, TimelineEntryKind, Uuid, type Evidence } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AuthContext } from "../auth/types.js";
import type { AppServices } from "../context.js";
import { inOrder, type Queryable } from "../db/pool.js";
import { HttpError, badRequest, notFound } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor, likePattern } from "../http/params.js";
import { toEvidence, toIncident, toInvestigation, toTimelineEntry, type Row } from "../repo/mappers.js";
import { sha256Hex } from "../security/crypto.js";
import { noteView } from "./incidents.js";
import { keysetClause, loadOne, orderBy, pageRows, parse, type KeysetSort } from "./util.js";

const MAX_INLINE_EVIDENCE_BYTES = 10 * 1024 * 1024;
const EVIDENCE_KINDS = ["file", "memory", "disk_artifact", "log_export", "pcap", "screenshot", "note"] as const;
const SHA256 = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[0-9a-f]{64}$/, "must be a hex sha256");

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  incidentId: Uuid.optional(),
  status: csvOf(InvestigationStatus).optional(),
  leadId: Uuid.optional(),
  q: z.string().trim().max(200).optional(),
  limit: Limit(500, 50),
  cursor: z.string().optional(),
});
const CreateBody = z
  .object({
    organizationId: Uuid.optional(),
    incidentId: Uuid.optional(),
    title: z.string().trim().min(3).max(300),
    hypothesis: z.string().trim().max(10_000).optional(),
    leadId: Uuid.optional(),
  })
  .strict()
  .refine((b) => b.organizationId || b.incidentId, { message: "organizationId or incidentId is required" });
const PatchBody = z
  .object({ title: z.string().trim().min(3).max(300), status: InvestigationStatus, leadId: Uuid.nullable(), hypothesis: z.string().trim().max(10_000).nullable() })
  .partial()
  .strict();
const TimelineBody = z
  .object({
    kind: TimelineEntryKind.exclude(["status_change", "note", "evidence"]),
    title: z.string().trim().min(1).max(500),
    body: z.string().max(20_000).optional(),
    refId: z.string().trim().max(200).optional(),
    at: z.string().datetime({ offset: true }).optional(),
  })
  .strict();
const NoteBody = z.object({ body: z.string().trim().min(1).max(20_000), visibility: z.enum(["internal", "customer"]).default("internal") }).strict();
const TaskBody = z
  .object({
    title: z.string().trim().min(1).max(500),
    description: z.string().max(10_000).optional(),
    assigneeId: Uuid.optional(),
    dueAt: z.string().datetime({ offset: true }).optional(),
  })
  .strict();
const TaskPatchBody = z
  .object({
    title: z.string().trim().min(1).max(500),
    description: z.string().max(10_000).nullable(),
    status: z.enum(["open", "in_progress", "done", "cancelled"]),
    assigneeId: Uuid.nullable(),
    dueAt: z.string().datetime({ offset: true }).nullable(),
  })
  .partial()
  .strict();
const TaskParams = z.object({ id: Uuid, taskId: Uuid });
const EvidenceParams = z.object({ id: Uuid, evidenceId: Uuid });
const EvidenceBody = z
  .object({
    name: z.string().trim().min(1).max(500),
    kind: z.enum(EVIDENCE_KINDS),
    tags: z.array(z.string().trim().min(1).max(64)).max(32).default([]),
    /** Inline upload (≤ 10 MiB): the platform computes the sha256 and stores the bytes. */
    contentBase64: z.string().max(Math.ceil((MAX_INLINE_EVIDENCE_BYTES * 4) / 3) + 4).optional(),
    /** Externally stored artifact (object storage / collector): declared digest + size + reference. */
    sha256: SHA256.optional(),
    sizeBytes: z.number().int().min(0).max(1024 ** 4).optional(),
    storageRef: z
      .string()
      .trim()
      .max(1000)
      .regex(/^(s3|gs|az|velociraptor|arkime|file):\/\/\S+$/, "must be an object-storage / collector reference (s3://, gs://, az://, velociraptor://, arkime://, file://)")
      .optional(),
    note: z.string().trim().max(2000).optional(),
  })
  .strict()
  .refine((b) => (b.contentBase64 !== undefined) !== (b.sha256 !== undefined && b.storageRef !== undefined && b.sizeBytes !== undefined), {
    message: "Provide either contentBase64, or sha256 + sizeBytes + storageRef",
  });
const CustodyBody = z
  .object({
    action: z.enum(["accessed", "analyzed", "transferred", "exported", "verified", "sealed", "returned"]),
    note: z.string().trim().max(2000).optional(),
  })
  .strict();

export type CustodyEntry = Evidence["custody"][number] & { note?: string };

/** sha256 over (previous hash | evidence digest | at | actor | action | note): a tamper-evident chain. */
export function custodyHash(prev: string | null, evidenceSha256: string, e: { at: string; actor: string; action: string; note?: string | undefined }): string {
  return sha256Hex([prev ?? "genesis", evidenceSha256, e.at, e.actor, e.action, e.note ?? ""].join("|"));
}

export function verifyCustody(evidenceSha256: string, custody: CustodyEntry[]): { valid: boolean; brokenAt: number | null } {
  let prev: string | null = null;
  for (let i = 0; i < custody.length; i++) {
    const e = custody[i]!;
    if (e.hash !== custodyHash(prev, evidenceSha256, e)) return { valid: false, brokenAt: i };
    prev = e.hash;
  }
  return { valid: true, brokenAt: null };
}

function custodyEntry(prev: CustodyEntry[], evidenceSha256: string, actor: string, action: string, at: string, note?: string): CustodyEntry {
  const last = prev.length > 0 ? prev[prev.length - 1]!.hash : null;
  const base = { at, actor, action, ...(note ? { note } : {}) };
  return { ...base, hash: custodyHash(last, evidenceSha256, base) };
}

function evidenceView(r: Row) {
  const e = toEvidence(r);
  return { ...e, custodyVerification: verifyCustody(e.sha256, e.custody as CustodyEntry[]), inline: String(r.storage_ref).startsWith("db://") };
}

function actorOf(auth: AuthContext): string {
  return `${auth.principal.kind}:${auth.principal.id}`;
}

async function loadInvestigation(tx: Queryable, request: FastifyRequest, id: string, write = false): Promise<Row> {
  const row = await loadOne(tx, "investigations", id, "Investigation");
  assertRecordAccess(request, "investigation:read", String(row.organization_id), "Investigation");
  if (write) requirePermission(request, "investigation:write", String(row.organization_id));
  return row;
}

async function addTimeline(tx: Queryable, inv: Row, entry: { kind: string; title: string; body?: string | null; refId?: string | null; actor: string | null; at?: string }): Promise<Row> {
  const { rows } = await tx.query<Row>(
    `INSERT INTO timeline_entries (tenant_id, organization_id, investigation_id, kind, at, actor_id, title, body, ref_id)
     VALUES ($1, $2, $3, $4, coalesce($5::timestamptz, now()), $6, $7, $8, $9) RETURNING *`,
    [inv.tenant_id, inv.organization_id, inv.id, entry.kind, entry.at ?? null, entry.actor, entry.title.slice(0, 500), entry.body ?? null, entry.refId ?? null],
  );
  return rows[0]!;
}

async function assertAssignable(tx: Queryable, userId: string): Promise<void> {
  const { rows } = await tx.query<{ status: string }>("SELECT status FROM users WHERE id = $1", [userId]);
  if (!rows[0] || rows[0].status !== "active") throw badRequest("The user must be an active user of this tenant");
}

const SORT: KeysetSort = { expr: "v.created_at", dir: "desc", cast: "timestamptz" };

/** Investigation workspace: case, timeline, notes, tasks, evidence with chain of custody. */
export async function investigationRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/investigations", async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "investigation:read", q.organizationId);
    const params: unknown[] = [];
    const where: string[] = [];
    const add = (sql: string, v: unknown) => {
      params.push(v);
      where.push(sql.replaceAll("?", `$${params.length}`));
    };
    if (orgs) add("v.organization_id = ANY(?::uuid[])", orgs);
    if (q.incidentId) add("v.incident_id = ?", q.incidentId);
    if (q.status?.length) add("v.status = ANY(?::text[])", q.status);
    if (q.leadId) add("v.lead_id = ?", q.leadId);
    if (q.q) add("(v.title ILIKE ? OR v.hypothesis ILIKE ?)", likePattern(q.q));
    where.push(keysetClause(SORT, "v.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT v.*, o.name AS organization_name, i.number AS incident_number, i.severity AS incident_severity,
                (SELECT count(*)::int FROM tasks t WHERE t.investigation_id = v.id AND t.status IN ('open', 'in_progress')) AS open_tasks,
                (SELECT count(*)::int FROM evidence e WHERE e.investigation_id = v.id) AS evidence_count,
                ${SORT.expr} AS sort_key
         FROM investigations v JOIN organizations o ON o.id = v.organization_id LEFT JOIN incidents i ON i.id = v.incident_id
         WHERE ${where.join(" AND ")} ORDER BY ${orderBy(SORT, "v.id")} LIMIT $${params.length}`,
        params,
      ),
    );
    return pageRows(rows, q.limit, (r) => ({
      ...toInvestigation(r),
      organizationName: (r.organization_name as string | null) ?? null,
      incidentNumber: (r.incident_number as number | null) ?? null,
      incidentSeverity: (r.incident_severity as string | null) ?? null,
      openTasks: Number(r.open_tasks ?? 0),
      evidenceCount: Number(r.evidence_count ?? 0),
    }));
  });

  app.post("/investigations", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateBody, request.body);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      let organizationId = body.organizationId ?? null;
      let incident: Row | null = null;
      if (body.incidentId) {
        incident = await loadOne(tx, "incidents", body.incidentId, "Incident");
        assertRecordAccess(request, "incident:read", String(incident.organization_id), "Incident");
        if (organizationId && organizationId !== incident.organization_id) throw badRequest("organizationId does not match the incident's organization");
        organizationId = String(incident.organization_id);
      }
      requirePermission(request, "investigation:write", organizationId);
      await loadOne(tx, "organizations", organizationId!, "Organization");
      if (body.leadId) await assertAssignable(tx, body.leadId);
      const { rows } = await tx.query<Row>(
        "INSERT INTO investigations (tenant_id, organization_id, incident_id, title, hypothesis, lead_id, status, created_by) VALUES ($1, $2, $3, $4, $5, $6, 'open', $7) RETURNING *",
        [auth.tenantId, organizationId, body.incidentId ?? null, body.title, body.hypothesis ?? null, body.leadId ?? null, actorOf(auth)],
      );
      const inv = rows[0]!;
      await addTimeline(tx, inv, { kind: "status_change", title: "Investigation opened", body: body.hypothesis ?? null, actor: actorOf(auth) });
      if (incident) {
        // Seed the timeline with the incident's detections, in event time.
        await tx.query(
          `INSERT INTO timeline_entries (tenant_id, organization_id, investigation_id, kind, at, actor_id, title, body, ref_id)
           SELECT a.tenant_id, a.organization_id, $1, 'alert', a.first_seen_at, 'system:pipeline', left(a.title, 500), a.severity || ' · ' || coalesce(a.rule_id, a.source), a.id::text
           FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = $2 ORDER BY a.first_seen_at LIMIT 500`,
          [inv.id, incident.id],
        );
        if (incident.status === "new") {
          await tx.query("UPDATE incidents SET status = 'investigating', acknowledged_at = coalesce(acknowledged_at, now()) WHERE id = $1", [incident.id]);
        }
      }
      await recordAudit(tx, request, { action: "investigation.created", organizationId, targetKind: "investigation", targetId: String(inv.id), details: { incidentId: body.incidentId ?? null, title: body.title } });
      return toInvestigation(inv);
    });
    return reply.status(201).send(created);
  });

  app.get("/investigations/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id);
      const [timeline, notes, tasks, evidence, incident, org] = await inOrder([
        () => tx.query<Row>("SELECT * FROM timeline_entries WHERE investigation_id = $1 ORDER BY at, created_at LIMIT 2000", [id]),
        () => tx.query<Row>("SELECT * FROM notes WHERE investigation_id = $1 ORDER BY created_at DESC LIMIT 500", [id]),
        () => tx.query<Row>("SELECT * FROM tasks WHERE investigation_id = $1 ORDER BY (status IN ('done', 'cancelled')), due_at NULLS LAST, created_at", [id]),
        () => tx.query<Row>("SELECT * FROM evidence WHERE investigation_id = $1 ORDER BY created_at", [id]),
        () => inv.incident_id ? tx.query<Row>("SELECT * FROM incidents WHERE id = $1", [inv.incident_id]) : Promise.resolve({ rows: [] as Row[] }),
        () => tx.query<{ name: string }>("SELECT name FROM organizations WHERE id = $1", [inv.organization_id]),
      ]);
      return {
        ...toInvestigation(inv),
        organizationName: org.rows[0]?.name ?? null,
        incident: incident.rows[0] ? toIncident(incident.rows[0]) : null,
        timeline: timeline.rows.map(toTimelineEntry),
        notes: notes.rows.map(noteView),
        tasks: tasks.rows.map(taskView),
        evidence: evidence.rows.map(evidenceView),
      };
    });
  });

  app.patch("/investigations/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const patch = parse(PatchBody, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id, true);
      if (patch.leadId) await assertAssignable(tx, patch.leadId);
      const sets: string[] = [];
      const params: unknown[] = [id];
      const set = (col: string, v: unknown) => {
        params.push(v);
        sets.push(`${col} = $${params.length}`);
      };
      if (patch.title !== undefined) set("title", patch.title);
      if (patch.hypothesis !== undefined) set("hypothesis", patch.hypothesis);
      if (patch.leadId !== undefined) set("lead_id", patch.leadId);
      if (patch.status !== undefined && patch.status !== inv.status) {
        set("status", patch.status);
        sets.push(patch.status === "closed" ? "closed_at = now()" : "closed_at = NULL");
      }
      if (sets.length === 0) return toInvestigation(inv);
      const { rows } = await tx.query<Row>(`UPDATE investigations SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, params);
      if (patch.status !== undefined && patch.status !== inv.status) {
        await addTimeline(tx, inv, { kind: "status_change", title: `Investigation ${inv.status} → ${patch.status}`, actor: actorOf(auth) });
      }
      if (patch.leadId !== undefined && patch.leadId !== inv.lead_id) {
        await addTimeline(tx, inv, { kind: "action", title: patch.leadId ? "Lead investigator assigned" : "Lead investigator removed", refId: patch.leadId, actor: actorOf(auth) });
      }
      await recordAudit(tx, request, { action: "investigation.updated", organizationId: String(inv.organization_id), targetKind: "investigation", targetId: id, details: { changed: Object.keys(patch), status: patch.status ?? null } });
      return toInvestigation(rows[0]!);
    });
  });

  // ─── Timeline ────────────────────────────────────────────────────────────

  app.get("/investigations/:id/timeline", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await loadInvestigation(tx, request, id);
      const { rows } = await tx.query<Row>("SELECT * FROM timeline_entries WHERE investigation_id = $1 ORDER BY at, created_at LIMIT 5000", [id]);
      return { items: rows.map(toTimelineEntry), nextCursor: null };
    });
  });

  app.post("/investigations/:id/timeline", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(TimelineBody, request.body);
    const entry = await s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id, true);
      const row = await addTimeline(tx, inv, { kind: body.kind, title: body.title, body: body.body ?? null, refId: body.refId ?? null, actor: actorOf(auth), ...(body.at ? { at: body.at } : {}) });
      await recordAudit(tx, request, { action: "investigation.timeline_added", organizationId: String(inv.organization_id), targetKind: "investigation", targetId: id, details: { kind: body.kind, refId: body.refId ?? null } });
      return toTimelineEntry(row);
    });
    return reply.status(201).send(entry);
  });

  // ─── Notes ───────────────────────────────────────────────────────────────

  app.post("/investigations/:id/notes", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(NoteBody, request.body);
    const note = await s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id, true);
      const { rows } = await tx.query<Row>(
        "INSERT INTO notes (tenant_id, organization_id, investigation_id, incident_id, author_id, author_label, body, visibility) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
        [auth.tenantId, inv.organization_id, id, inv.incident_id ?? null, actorOf(auth), auth.principal.email ?? auth.principal.displayName ?? null, body.body, body.visibility],
      );
      const n = rows[0]!;
      await addTimeline(tx, inv, { kind: "note", title: body.body.split("\n")[0]!.slice(0, 200), body: body.body, refId: String(n.id), actor: actorOf(auth) });
      await recordAudit(tx, request, { action: "investigation.note_added", organizationId: String(inv.organization_id), targetKind: "investigation", targetId: id, details: { noteId: n.id, visibility: body.visibility } });
      return noteView(n);
    });
    return reply.status(201).send(note);
  });

  // ─── Tasks ───────────────────────────────────────────────────────────────

  app.post("/investigations/:id/tasks", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(TaskBody, request.body);
    const task = await s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id, true);
      if (body.assigneeId) await assertAssignable(tx, body.assigneeId);
      const { rows } = await tx.query<Row>(
        "INSERT INTO tasks (tenant_id, organization_id, investigation_id, title, description, assignee_id, due_at, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
        [auth.tenantId, inv.organization_id, id, body.title, body.description ?? null, body.assigneeId ?? null, body.dueAt ?? null, actorOf(auth)],
      );
      await addTimeline(tx, inv, { kind: "action", title: `Task created: ${body.title}`, refId: String(rows[0]!.id), actor: actorOf(auth) });
      await recordAudit(tx, request, { action: "investigation.task_created", organizationId: String(inv.organization_id), targetKind: "task", targetId: String(rows[0]!.id), details: { investigationId: id } });
      return taskView(rows[0]!);
    });
    return reply.status(201).send(task);
  });

  app.patch("/investigations/:id/tasks/:taskId", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id, taskId } = parse(TaskParams, request.params);
    const patch = parse(TaskPatchBody, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id, true);
      const cur = await tx.query<Row>("SELECT * FROM tasks WHERE id = $1 AND investigation_id = $2", [taskId, id]);
      if (!cur.rows[0]) throw notFound("Task");
      if (patch.assigneeId) await assertAssignable(tx, patch.assigneeId);
      const sets: string[] = [];
      const params: unknown[] = [taskId];
      const set = (col: string, v: unknown) => {
        params.push(v);
        sets.push(`${col} = $${params.length}`);
      };
      if (patch.title !== undefined) set("title", patch.title);
      if (patch.description !== undefined) set("description", patch.description);
      if (patch.assigneeId !== undefined) set("assignee_id", patch.assigneeId);
      if (patch.dueAt !== undefined) set("due_at", patch.dueAt);
      if (patch.status !== undefined) {
        set("status", patch.status);
        sets.push(patch.status === "done" ? "completed_at = coalesce(completed_at, now())" : "completed_at = NULL");
      }
      if (sets.length === 0) return taskView(cur.rows[0]);
      const { rows } = await tx.query<Row>(`UPDATE tasks SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, params);
      if (patch.status !== undefined && patch.status !== cur.rows[0].status) {
        await addTimeline(tx, inv, { kind: "action", title: `Task ${patch.status.replace("_", " ")}: ${String(rows[0]!.title)}`, refId: taskId, actor: actorOf(auth) });
      }
      await recordAudit(tx, request, { action: "investigation.task_updated", organizationId: String(inv.organization_id), targetKind: "task", targetId: taskId, details: { changed: Object.keys(patch), status: patch.status ?? null } });
      return taskView(rows[0]!);
    });
  });

  // ─── Evidence & chain of custody ─────────────────────────────────────────

  app.post("/investigations/:id/evidence", { bodyLimit: 16 * 1024 * 1024, config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(EvidenceBody, request.body);
    let content: Buffer | null = null;
    let sha256: string;
    let sizeBytes: number;
    if (body.contentBase64 !== undefined) {
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body.contentBase64)) throw badRequest("contentBase64 is not valid base64");
      content = Buffer.from(body.contentBase64, "base64");
      if (content.length > MAX_INLINE_EVIDENCE_BYTES) throw new HttpError(413, "payload_too_large", "Inline evidence is limited to 10 MiB; upload to object storage and register a storageRef");
      sha256 = sha256Hex(content);
      sizeBytes = content.length;
    } else {
      sha256 = body.sha256!;
      sizeBytes = body.sizeBytes!;
    }
    const evidence = await s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id, true);
      if (inv.status === "closed") throw new HttpError(409, "investigation_closed", "Evidence cannot be added to a closed investigation");
      const evidenceId = randomUUID();
      const storageRef = content ? `db://evidence_blobs/${evidenceId}` : body.storageRef!;
      const at = new Date(s.now()).toISOString();
      const custody = [custodyEntry([], sha256, actorOf(auth), content ? "collected:uploaded" : "collected:registered", at, body.note)];
      const { rows } = await tx.query<Row>(
        `INSERT INTO evidence (id, tenant_id, organization_id, investigation_id, name, kind, sha256, size_bytes, storage_ref, tags, collected_by, custody)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb) RETURNING *`,
        [evidenceId, auth.tenantId, inv.organization_id, id, body.name, body.kind, sha256, sizeBytes, storageRef, body.tags, actorOf(auth), JSON.stringify(custody)],
      );
      if (content) await tx.query("INSERT INTO evidence_blobs (evidence_id, tenant_id, organization_id, content) VALUES ($1, $2, $3, $4)", [evidenceId, auth.tenantId, inv.organization_id, content]);
      await addTimeline(tx, inv, { kind: "evidence", title: `Evidence collected: ${body.name}`, body: `sha256 ${sha256} · ${sizeBytes} bytes`, refId: evidenceId, actor: actorOf(auth) });
      await recordAudit(tx, request, { action: "evidence.collected", organizationId: String(inv.organization_id), targetKind: "evidence", targetId: evidenceId, details: { investigationId: id, sha256, sizeBytes, kind: body.kind, storage: content ? "inline" : "external" } });
      return evidenceView(rows[0]!);
    });
    return reply.status(201).send(evidence);
  });

  app.get("/investigations/:id/evidence/:evidenceId", async (request) => {
    const auth = requireAuth(request);
    const { id, evidenceId } = parse(EvidenceParams, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await loadInvestigation(tx, request, id);
      const { rows } = await tx.query<Row>("SELECT * FROM evidence WHERE id = $1 AND investigation_id = $2", [evidenceId, id]);
      if (!rows[0]) throw notFound("Evidence");
      return evidenceView(rows[0]);
    });
  });

  app.post("/investigations/:id/evidence/:evidenceId/custody", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id, evidenceId } = parse(EvidenceParams, request.params);
    const body = parse(CustodyBody, request.body);
    const ev = await s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id, true);
      const { rows } = await tx.query<Row>("SELECT * FROM evidence WHERE id = $1 AND investigation_id = $2 FOR UPDATE", [evidenceId, id]);
      const row = rows[0];
      if (!row) throw notFound("Evidence");
      const current = toEvidence(row).custody as CustodyEntry[];
      const entry = custodyEntry(current, String(row.sha256), actorOf(auth), body.action, new Date(s.now()).toISOString(), body.note);
      const upd = await tx.query<Row>("UPDATE evidence SET custody = custody || $2::jsonb WHERE id = $1 RETURNING *", [evidenceId, JSON.stringify([entry])]);
      await addTimeline(tx, inv, { kind: "evidence", title: `Custody: ${body.action} — ${String(row.name)}`, body: body.note ?? null, refId: evidenceId, actor: actorOf(auth) });
      await recordAudit(tx, request, { action: "evidence.custody_appended", organizationId: String(inv.organization_id), targetKind: "evidence", targetId: evidenceId, details: { action: body.action, hash: entry.hash } });
      return evidenceView(upd.rows[0]!);
    });
    return reply.status(201).send(ev);
  });

  // Download inline evidence content. Every access is appended to the chain of custody.
  app.get("/investigations/:id/evidence/:evidenceId/content", async (request, reply) => {
    const auth = requireAuth(request);
    const { id, evidenceId } = parse(EvidenceParams, request.params);
    const out = await s.db.withTenant(auth.tenantId, async (tx) => {
      const inv = await loadInvestigation(tx, request, id);
      const { rows } = await tx.query<Row>("SELECT * FROM evidence WHERE id = $1 AND investigation_id = $2 FOR UPDATE", [evidenceId, id]);
      const row = rows[0];
      if (!row) throw notFound("Evidence");
      const blob = await tx.query<{ content: Buffer }>("SELECT content FROM evidence_blobs WHERE evidence_id = $1", [evidenceId]);
      if (!blob.rows[0]) throw new HttpError(409, "evidence_external", "This evidence is stored externally; retrieve it from its storageRef", { storageRef: row.storage_ref });
      const content = blob.rows[0].content;
      if (sha256Hex(content) !== row.sha256) throw new HttpError(500, "evidence_integrity_failure", "Stored evidence no longer matches its recorded sha256");
      const current = toEvidence(row).custody as CustodyEntry[];
      const entry = custodyEntry(current, String(row.sha256), actorOf(auth), "accessed:downloaded", new Date(s.now()).toISOString());
      await tx.query("UPDATE evidence SET custody = custody || $2::jsonb WHERE id = $1", [evidenceId, JSON.stringify([entry])]);
      await recordAudit(tx, request, { action: "evidence.downloaded", organizationId: String(inv.organization_id), targetKind: "evidence", targetId: evidenceId, details: { sha256: row.sha256 } });
      return { content, name: String(row.name), sha256: String(row.sha256) };
    });
    const safeName = out.name.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 150) || "evidence.bin";
    void reply.header("content-type", "application/octet-stream");
    void reply.header("content-disposition", `attachment; filename="${safeName}"`);
    void reply.header("x-evidence-sha256", out.sha256);
    return reply.send(out.content);
  });
}

function taskView(r: Row) {
  return {
    id: String(r.id),
    investigationId: String(r.investigation_id),
    organizationId: String(r.organization_id),
    title: String(r.title),
    description: (r.description as string | null) ?? null,
    status: String(r.status),
    assigneeId: (r.assignee_id as string | null) ?? null,
    dueAt: (r.due_at as string | null) ?? null,
    completedAt: (r.completed_at as string | null) ?? null,
    createdBy: (r.created_by as string | null) ?? null,
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
    overdue: r.due_at !== null && r.due_at !== undefined && !["done", "cancelled"].includes(String(r.status)) && Date.parse(String(r.due_at)) < Date.now(),
  };
}
