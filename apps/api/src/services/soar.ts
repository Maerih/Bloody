import type { Playbook } from "@bloody/contracts";
import {
  PlaybookValidationError,
  diffPlaybooks,
  playbookNameKey,
  validatePlaybook,
  type ExecutionStatus,
  type ExecutionStore,
  type PlaybookChange,
  type PlaybookDraft,
  type PlaybookExecution,
  type PlaybookRepository,
} from "@bloody/automation";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";

/**
 * SOAR persistence: playbooks with immutable version history (`playbooks` + `playbook_versions`)
 * and playbook executions (`playbook_runs`, optimistic concurrency on `state_version`). These
 * implement the `@bloody/automation` ports the PlaybookEngine runs on.
 */

export function toPlaybook(r: Row): Playbook {
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: (r.organization_id as string | null) ?? null,
    name: String(r.name),
    description: (r.description as string | null) ?? null,
    version: Number(r.version),
    enabled: Boolean(r.enabled),
    trigger: r.trigger as Playbook["trigger"],
    conditions: (r.conditions as Playbook["conditions"]) ?? [],
    steps: (r.steps as Playbook["steps"]) ?? [],
  };
}

export interface PlaybookView extends Playbook {
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export function playbookView(r: Row): PlaybookView {
  return { ...toPlaybook(r), createdBy: (r.created_by as string | null) ?? null, createdAt: String(r.created_at), updatedAt: String(r.updated_at) };
}

export interface PlaybookVersionView {
  version: number;
  definition: Playbook;
  comment: string | null;
  changes: PlaybookChange[];
  createdBy: string | null;
  createdAt: string;
}

/** Engine read port. Each call runs in its own tenant transaction. */
export class PgPlaybookRepository implements PlaybookRepository {
  constructor(private readonly db: Database) {}

  async listForOrganization(tenantId: string, organizationId: string): Promise<Playbook[]> {
    return this.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM playbooks WHERE organization_id IS NULL OR organization_id = $1 ORDER BY name", [organizationId])).rows.map(toPlaybook));
  }

  async get(tenantId: string, id: string): Promise<Playbook | null> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM playbooks WHERE id = $1", [id]);
      return rows[0] ? toPlaybook(rows[0]) : null;
    });
  }
}

function invalid(issues: Array<{ path: string; message: string }>): HttpError {
  return new HttpError(400, "invalid_playbook", "Invalid playbook", issues);
}

/** Write side (inside the caller's tenant transaction, so audit rows commit atomically). */
export class PlaybookStore {
  async assertUniqueName(tx: Queryable, organizationId: string | null, name: string, exceptId: string | null): Promise<void> {
    const { rows } = await tx.query<{ id: string; name: string }>(
      "SELECT id, name FROM playbooks WHERE organization_id IS NOT DISTINCT FROM $1 AND ($2::uuid IS NULL OR id <> $2)",
      [organizationId, exceptId],
    );
    const key = playbookNameKey(name);
    if (rows.some((r) => playbookNameKey(r.name) === key)) throw new HttpError(409, "conflict", `A playbook named "${name}" already exists in this scope`);
  }

  async create(tx: Queryable, tenantId: string, draft: PlaybookDraft, actor: string, comment?: string): Promise<{ playbook: PlaybookView; warnings: string[] }> {
    const v = validatePlaybook(draft);
    if (!v.ok || !v.draft) throw invalid(v.issues);
    await this.assertUniqueName(tx, v.draft.organizationId, v.draft.name, null);
    const d = v.draft;
    const { rows } = await tx.query<Row>(
      `INSERT INTO playbooks (tenant_id, organization_id, name, description, version, enabled, trigger, conditions, steps, created_by)
       VALUES ($1, $2, $3, $4, 1, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9) RETURNING *`,
      [tenantId, d.organizationId, d.name, d.description, d.enabled, JSON.stringify(d.trigger), JSON.stringify(d.conditions), JSON.stringify(d.steps), actor],
    );
    const playbook = toPlaybook(rows[0]!);
    await this.insertVersion(tx, playbook, actor, comment ?? null, [{ path: "", kind: "added", summary: "playbook created" }]);
    return { playbook: playbookView(rows[0]!), warnings: v.warnings };
  }

  async update(
    tx: Queryable,
    id: string,
    draft: PlaybookDraft,
    actor: string,
    opts: { expectedVersion?: number | undefined; comment?: string | undefined } = {},
  ): Promise<{ playbook: PlaybookView; changed: boolean; changes: PlaybookChange[]; warnings: string[] }> {
    const { rows } = await tx.query<Row>("SELECT * FROM playbooks WHERE id = $1 FOR UPDATE", [id]);
    if (!rows[0]) throw notFound("Playbook");
    const cur = toPlaybook(rows[0]);
    if (opts.expectedVersion !== undefined && opts.expectedVersion !== cur.version) {
      throw new HttpError(409, "version_conflict", `The playbook was modified (current version ${cur.version}, expected ${opts.expectedVersion})`, { currentVersion: cur.version });
    }
    const v = validatePlaybook(draft);
    if (!v.ok || !v.draft) throw invalid(v.issues);
    if (v.draft.organizationId !== cur.organizationId) throw new HttpError(400, "invalid_playbook", "A playbook cannot move between organizations; create an organization override instead");
    if (playbookNameKey(v.draft.name) !== playbookNameKey(cur.name)) await this.assertUniqueName(tx, cur.organizationId, v.draft.name, id);
    const candidate: Playbook = { ...cur, ...v.draft };
    const changes = diffPlaybooks(cur, candidate);
    if (changes.length === 0) return { playbook: playbookView(rows[0]), changed: false, changes, warnings: v.warnings };
    const d = v.draft;
    const res = await tx.query<Row>(
      `UPDATE playbooks SET name = $2, description = $3, version = version + 1, enabled = $4, trigger = $5::jsonb, conditions = $6::jsonb, steps = $7::jsonb
       WHERE id = $1 RETURNING *`,
      [id, d.name, d.description, d.enabled, JSON.stringify(d.trigger), JSON.stringify(d.conditions), JSON.stringify(d.steps)],
    );
    const next = toPlaybook(res.rows[0]!);
    await this.insertVersion(tx, next, actor, opts.comment ?? null, changes);
    return { playbook: playbookView(res.rows[0]!), changed: true, changes, warnings: v.warnings };
  }

  async setEnabled(tx: Queryable, id: string, enabled: boolean, actor: string): Promise<{ playbook: PlaybookView; changed: boolean }> {
    const { rows } = await tx.query<Row>("SELECT * FROM playbooks WHERE id = $1", [id]);
    if (!rows[0]) throw notFound("Playbook");
    const cur = toPlaybook(rows[0]);
    const { id: _i, tenantId: _t, version: _v, ...content } = cur;
    const res = await this.update(tx, id, { ...content, enabled }, actor, { comment: enabled ? "enabled" : "disabled" });
    return { playbook: res.playbook, changed: res.changed };
  }

  async versions(tx: Queryable, id: string): Promise<PlaybookVersionView[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM playbook_versions WHERE playbook_id = $1 ORDER BY version DESC", [id]);
    return rows.map((r) => ({
      version: Number(r.version),
      definition: r.definition as Playbook,
      comment: (r.comment as string | null) ?? null,
      changes: (r.changes as PlaybookChange[]) ?? [],
      createdBy: (r.created_by as string | null) ?? null,
      createdAt: String(r.created_at),
    }));
  }

  /** Restore an earlier version's content as a NEW version. */
  async rollback(tx: Queryable, id: string, version: number, actor: string): Promise<{ playbook: PlaybookView; changed: boolean; changes: PlaybookChange[] }> {
    const { rows } = await tx.query<Row>("SELECT definition FROM playbook_versions WHERE playbook_id = $1 AND version = $2", [id, version]);
    if (!rows[0]) throw new HttpError(404, "not_found", `Version ${version} not found`);
    const { id: _i, tenantId: _t, version: _v, ...content } = rows[0].definition as Playbook;
    const res = await this.update(tx, id, content, actor, { comment: `rollback to version ${version}` });
    return { playbook: res.playbook, changed: res.changed, changes: res.changes };
  }

  private async insertVersion(tx: Queryable, p: Playbook, actor: string, comment: string | null, changes: PlaybookChange[]): Promise<void> {
    await tx.query(
      `INSERT INTO playbook_versions (tenant_id, organization_id, playbook_id, version, definition, comment, created_by, changes)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8::jsonb)`,
      [p.tenantId, p.organizationId, p.id, p.version, JSON.stringify(p), comment, actor, JSON.stringify(changes)],
    );
  }
}

export { PlaybookValidationError };

// ─── Executions ──────────────────────────────────────────────────────────────

const TERMINAL: ReadonlySet<ExecutionStatus> = new Set(["succeeded", "partially_succeeded", "failed", "rejected", "cancelled"]);

function execFromRow(r: Row): PlaybookExecution {
  return r.execution as PlaybookExecution;
}

/** `playbook_runs` as the engine's ExecutionStore (full execution JSON + mirrored columns). */
export class PgExecutionStore implements ExecutionStore {
  constructor(private readonly db: Database) {}

  private columns(e: PlaybookExecution): unknown[] {
    return [
      e.status,
      JSON.stringify(e.trigger.subjectRef ?? {}),
      JSON.stringify(e.playbook),
      JSON.stringify(e.log),
      e.version,
      e.finishedAt,
      e.playbookName,
      JSON.stringify(e.initiatedBy),
      JSON.stringify(e),
    ];
  }

  async insert(e: PlaybookExecution): Promise<boolean> {
    return this.db.withTenant(e.tenantId, async (tx) => {
      const { rows } = await tx.query(
        `INSERT INTO playbook_runs (id, tenant_id, organization_id, playbook_id, playbook_version, trigger_event, idempotency_key, started_at,
                                    status, subject, snapshot, log, state_version, finished_at, playbook_name, initiated_by, execution)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13, $14, $15, $16::jsonb, $17::jsonb)
         ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING RETURNING id`,
        [e.id, e.tenantId, e.organizationId, e.playbookId, e.playbookVersion, e.trigger.type, e.idempotencyKey, e.startedAt, ...this.columns(e)],
      );
      return rows.length > 0;
    });
  }

  async get(tenantId: string, id: string): Promise<PlaybookExecution | null> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT execution FROM playbook_runs WHERE id = $1", [id]);
      return rows[0]?.execution ? execFromRow(rows[0]) : null;
    });
  }

  async findByIdempotencyKey(tenantId: string, key: string): Promise<PlaybookExecution | null> {
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT execution FROM playbook_runs WHERE idempotency_key = $1", [key]);
      return rows[0]?.execution ? execFromRow(rows[0]) : null;
    });
  }

  async findByApproval(tenantId: string, approvalId: string): Promise<PlaybookExecution | null> {
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT execution FROM playbook_runs WHERE execution -> 'steps' @> $1::jsonb LIMIT 1", [JSON.stringify([{ approvalId }])]);
      return rows[0]?.execution ? execFromRow(rows[0]) : null;
    });
  }

  async compareAndSet(next: PlaybookExecution, expectedVersion: number): Promise<boolean> {
    return this.db.withTenant(next.tenantId, async (tx) => {
      const res = await tx.query(
        `UPDATE playbook_runs SET status = $3, subject = $4::jsonb, snapshot = $5::jsonb, log = $6::jsonb, state_version = $7, finished_at = $8, playbook_name = $9,
                initiated_by = $10::jsonb, execution = $11::jsonb
         WHERE id = $1 AND state_version = $2`,
        [next.id, expectedVersion, ...this.columns(next)],
      );
      return (res.rowCount ?? 0) === 1;
    });
  }

  async list(tenantId: string, filter: { organizationId?: string; playbookId?: string; status?: ExecutionStatus; limit?: number } = {}): Promise<PlaybookExecution[]> {
    return this.db.withTenant(tenantId, async (tx) => {
      const params: unknown[] = [];
      const where = ["execution IS NOT NULL"];
      if (filter.organizationId) where.push(`organization_id = $${params.push(filter.organizationId)}`);
      if (filter.playbookId) where.push(`playbook_id = $${params.push(filter.playbookId)}`);
      if (filter.status) where.push(`status = $${params.push(filter.status)}`);
      params.push(Math.min(filter.limit ?? 100, 500));
      const { rows } = await tx.query<Row>(`SELECT execution FROM playbook_runs WHERE ${where.join(" AND ")} ORDER BY started_at DESC LIMIT $${params.length}`, params);
      return rows.map(execFromRow);
    });
  }
}

export function isTerminal(status: ExecutionStatus): boolean {
  return TERMINAL.has(status);
}

/** Compact run view for lists (the full log is returned by GET /playbooks/runs/:id). */
export function runSummary(e: PlaybookExecution) {
  return {
    id: e.id,
    organizationId: e.organizationId,
    playbookId: e.playbookId,
    playbookName: e.playbookName,
    playbookVersion: e.playbookVersion,
    status: e.status,
    trigger: e.trigger,
    initiatedBy: e.initiatedBy,
    steps: e.steps,
    conditionResults: e.conditionResults,
    startedAt: e.startedAt,
    updatedAt: e.updatedAt,
    finishedAt: e.finishedAt,
  };
}
