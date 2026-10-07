import { Playbook, PlaybookCondition, PlaybookStep as PlaybookStepSchema, PlaybookTrigger, actionRisk } from "@bloody/contracts";
import { z } from "zod";
import { validateConditions } from "../conditions.js";
import { parseCron } from "../scheduling/cron.js";
import { validateTemplate } from "../template.js";
import { AutomationError, ConcurrencyError } from "../util/errors.js";
import { canonicalJson, systemClock, uuidIds, type Clock, type IdGenerator } from "../util/runtime.js";

/** Input of the playbook editor (id/tenant/version are assigned by the system). */
export const PlaybookDraft = z.object({
  organizationId: z.string().uuid().nullable(),
  name: z.string().trim().min(1).max(120),
  description: z.string().max(4000).nullable().default(null),
  enabled: z.boolean().default(true),
  trigger: PlaybookTrigger,
  conditions: z.array(PlaybookCondition).max(50).default([]),
  steps: z.array(PlaybookStepSchema).min(1).max(50),
});
export type PlaybookDraft = z.input<typeof PlaybookDraft>;
type ParsedDraft = z.output<typeof PlaybookDraft>;

export interface ValidationIssue {
  path: string;
  message: string;
}

export interface PlaybookValidation {
  ok: boolean;
  issues: ValidationIssue[];
  /** Non-blocking notes shown in the editor (explainability). */
  warnings: string[];
  draft: ParsedDraft | null;
}

const STEP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** Validate a playbook draft: schema, unique step ids, cron for schedule triggers, conditions, templates. */
export function validatePlaybook(input: unknown): PlaybookValidation {
  const parsed = PlaybookDraft.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
      warnings: [],
      draft: null,
    };
  }
  const d = parsed.data;
  const issues: ValidationIssue[] = [];
  const warnings: string[] = [];
  const seen = new Set<string>();
  d.steps.forEach((s, i) => {
    if (!STEP_ID_RE.test(s.id)) issues.push({ path: `steps.${i}.id`, message: "step id must be 1-64 chars of letters, digits, '_' or '-'" });
    if (seen.has(s.id)) issues.push({ path: `steps.${i}.id`, message: `duplicate step id "${s.id}"` });
    seen.add(s.id);
    for (const [k, v] of Object.entries(s.parameters)) {
      if (typeof v === "string" && v.includes("{{")) {
        for (const t of validateTemplate(v)) issues.push({ path: `steps.${i}.parameters.${k}`, message: t.message });
      }
    }
    if (actionRisk(s.action) === "high") warnings.push(`step "${s.id}" (${s.action}) is high-risk and will always wait for human approval`);
    else if (s.requireApproval) warnings.push(`step "${s.id}" (${s.action}) waits for approval (requireApproval)`);
  });
  issues.push(...validateConditions(d.conditions));
  if (d.trigger.on === "schedule") {
    if (!d.trigger.cron) issues.push({ path: "trigger.cron", message: "schedule triggers require a cron expression" });
    else {
      try {
        parseCron(d.trigger.cron);
      } catch (err) {
        issues.push({ path: "trigger.cron", message: err instanceof Error ? err.message : String(err) });
      }
    }
  } else if (d.trigger.cron) {
    warnings.push(`trigger "${d.trigger.on}" ignores the cron expression`);
  }
  if (d.organizationId === null) warnings.push("global playbook: applies to every organization unless an organization defines a playbook with the same name");
  return { ok: issues.length === 0, issues, warnings, draft: issues.length === 0 ? d : null };
}

export class PlaybookValidationError extends AutomationError {
  readonly issues: ValidationIssue[];

  constructor(issues: ValidationIssue[]) {
    super("invalid_playbook", `invalid playbook: ${issues.map((i) => `${i.path}: ${i.message}`).join("; ")}`, { issues });
    this.name = "PlaybookValidationError";
    this.issues = issues;
  }
}

// ─── global / override resolution ───────────────────────────────────────────

export function playbookNameKey(name: string): string {
  return name.trim().toLowerCase().replace(/\s+/g, " ");
}

export interface EffectivePlaybook {
  playbook: Playbook;
  source: "global" | "organization" | "override";
  /** Global playbook this organization playbook overrides. */
  overrides: { id: string; version: number } | null;
}

/**
 * Effective playbooks for one organization: global MSSP playbooks (organizationId = null) plus
 * the organization's own; an organization playbook with the same name (case-insensitive)
 * REPLACES the global one — including a disabled override, which switches the global off for
 * that customer. Playbooks of other tenants/organizations are never returned.
 */
export function resolveEffectivePlaybooks(playbooks: readonly Playbook[], tenantId: string, organizationId: string): EffectivePlaybook[] {
  const byName = new Map<string, EffectivePlaybook>();
  for (const p of playbooks) {
    if (p.tenantId !== tenantId || p.organizationId !== null) continue;
    byName.set(playbookNameKey(p.name), { playbook: p, source: "global", overrides: null });
  }
  for (const p of playbooks) {
    if (p.tenantId !== tenantId || p.organizationId !== organizationId) continue;
    const key = playbookNameKey(p.name);
    const global = byName.get(key);
    byName.set(key, {
      playbook: p,
      source: global && global.source === "global" ? "override" : "organization",
      overrides: global && global.source === "global" ? { id: global.playbook.id, version: global.playbook.version } : null,
    });
  }
  return [...byName.values()].sort((a, b) => a.playbook.name.localeCompare(b.playbook.name));
}

// ─── versioning ─────────────────────────────────────────────────────────────

export interface PlaybookChange {
  path: string;
  kind: "added" | "removed" | "changed";
  before?: unknown;
  after?: unknown;
  summary: string;
}

/** Human-readable diff between two playbook versions (for history & review). */
export function diffPlaybooks(before: Playbook, after: Playbook): PlaybookChange[] {
  const changes: PlaybookChange[] = [];
  const simple: (keyof Playbook)[] = ["name", "description", "enabled"];
  for (const k of simple) {
    if (before[k] !== after[k]) changes.push({ path: k, kind: "changed", before: before[k], after: after[k], summary: `${k} changed from ${JSON.stringify(before[k])} to ${JSON.stringify(after[k])}` });
  }
  if (canonicalJson(before.trigger) !== canonicalJson(after.trigger)) {
    changes.push({ path: "trigger", kind: "changed", before: before.trigger, after: after.trigger, summary: `trigger changed from ${describeTrigger(before.trigger)} to ${describeTrigger(after.trigger)}` });
  }
  if (canonicalJson(before.conditions) !== canonicalJson(after.conditions)) {
    changes.push({ path: "conditions", kind: "changed", before: before.conditions, after: after.conditions, summary: `conditions changed (${before.conditions.length} → ${after.conditions.length})` });
  }
  const beforeSteps = new Map(before.steps.map((s) => [s.id, s]));
  const afterSteps = new Map(after.steps.map((s) => [s.id, s]));
  for (const [id, s] of afterSteps) {
    const prev = beforeSteps.get(id);
    if (!prev) changes.push({ path: `steps.${id}`, kind: "added", after: s, summary: `step "${id}" (${s.action}) added` });
    else if (canonicalJson(prev) !== canonicalJson(s)) changes.push({ path: `steps.${id}`, kind: "changed", before: prev, after: s, summary: `step "${id}" changed` });
  }
  for (const [id, s] of beforeSteps) {
    if (!afterSteps.has(id)) changes.push({ path: `steps.${id}`, kind: "removed", before: s, summary: `step "${id}" (${s.action}) removed` });
  }
  const orderBefore = before.steps.map((s) => s.id).filter((id) => afterSteps.has(id));
  const orderAfter = after.steps.map((s) => s.id).filter((id) => beforeSteps.has(id));
  if (orderBefore.join("\u0000") !== orderAfter.join("\u0000")) changes.push({ path: "steps", kind: "changed", before: orderBefore, after: orderAfter, summary: "step order changed" });
  return changes;
}

function describeTrigger(t: Playbook["trigger"]): string {
  return t.on === "schedule" ? `schedule (${t.cron ?? "?"})` : t.on;
}

export interface PlaybookVersionRecord {
  playbookId: string;
  tenantId: string;
  version: number;
  snapshot: Playbook;
  changedBy: string;
  changedAt: string;
  comment: string | null;
  changes: PlaybookChange[];
}

/** Persistence port the engine reads from. The API implements it with SQL (playbooks + playbook_versions). */
export interface PlaybookRepository {
  /** Global playbooks of the tenant plus the organization's own playbooks. */
  listForOrganization(tenantId: string, organizationId: string): Promise<Playbook[]>;
  get(tenantId: string, id: string): Promise<Playbook | null>;
}

/**
 * Reference repository with full versioning semantics (also used by tests and the single
 * process deployment): every save increments `version` and appends an immutable history row;
 * rollback creates a NEW version carrying an old version's content.
 */
export class InMemoryPlaybookRepository implements PlaybookRepository {
  private readonly current = new Map<string, Playbook>();
  private readonly history = new Map<string, PlaybookVersionRecord[]>();
  private readonly clock: Clock;
  private readonly ids: IdGenerator;

  constructor(opts: { clock?: Clock; ids?: IdGenerator } = {}) {
    this.clock = opts.clock ?? systemClock;
    this.ids = opts.ids ?? uuidIds;
  }

  async listForOrganization(tenantId: string, organizationId: string): Promise<Playbook[]> {
    return [...this.current.values()].filter((p) => p.tenantId === tenantId && (p.organizationId === null || p.organizationId === organizationId)).map((p) => structuredClone(p));
  }

  async listAll(tenantId: string): Promise<Playbook[]> {
    return [...this.current.values()].filter((p) => p.tenantId === tenantId).map((p) => structuredClone(p));
  }

  async get(tenantId: string, id: string): Promise<Playbook | null> {
    const p = this.current.get(id);
    return p && p.tenantId === tenantId ? structuredClone(p) : null;
  }

  async create(tenantId: string, draft: PlaybookDraft, actor: string, comment?: string): Promise<{ playbook: Playbook; warnings: string[] }> {
    const v = validatePlaybook(draft);
    if (!v.ok || !v.draft) throw new PlaybookValidationError(v.issues);
    this.assertUniqueName(tenantId, v.draft.organizationId, v.draft.name, null);
    const playbook: Playbook = { id: this.ids(), tenantId, version: 1, ...v.draft };
    this.current.set(playbook.id, structuredClone(playbook));
    this.history.set(playbook.id, [
      { playbookId: playbook.id, tenantId, version: 1, snapshot: structuredClone(playbook), changedBy: actor, changedAt: this.clock.now().toISOString(), comment: comment ?? null, changes: [{ path: "", kind: "added", summary: "playbook created" }] },
    ]);
    return { playbook, warnings: v.warnings };
  }

  /**
   * Save a new version. `expectedVersion` guards against lost updates from two editors.
   * Saving identical content is a no-op (no new version).
   */
  async update(tenantId: string, id: string, draft: PlaybookDraft, actor: string, opts: { expectedVersion?: number; comment?: string } = {}): Promise<{ playbook: Playbook; changed: boolean; changes: PlaybookChange[]; warnings: string[] }> {
    const cur = this.current.get(id);
    if (!cur || cur.tenantId !== tenantId) throw new AutomationError("not_found", "playbook not found");
    if (opts.expectedVersion !== undefined && opts.expectedVersion !== cur.version) {
      throw new ConcurrencyError(`playbook was modified (current version ${cur.version}, expected ${opts.expectedVersion})`, { currentVersion: cur.version });
    }
    const v = validatePlaybook(draft);
    if (!v.ok || !v.draft) throw new PlaybookValidationError(v.issues);
    if (v.draft.organizationId !== cur.organizationId) throw new AutomationError("invalid_playbook", "a playbook cannot move between organizations; create an override instead");
    this.assertUniqueName(tenantId, v.draft.organizationId, v.draft.name, id);
    const candidate: Playbook = { ...cur, ...v.draft };
    const changes = diffPlaybooks(cur, candidate);
    if (changes.length === 0) return { playbook: structuredClone(cur), changed: false, changes, warnings: v.warnings };
    const next: Playbook = { ...candidate, version: cur.version + 1 };
    this.current.set(id, structuredClone(next));
    this.history.get(id)!.push({ playbookId: id, tenantId, version: next.version, snapshot: structuredClone(next), changedBy: actor, changedAt: this.clock.now().toISOString(), comment: opts.comment ?? null, changes });
    return { playbook: next, changed: true, changes, warnings: v.warnings };
  }

  async versions(tenantId: string, id: string): Promise<PlaybookVersionRecord[]> {
    const h = this.history.get(id);
    if (!h || h[0]?.tenantId !== tenantId) return [];
    return h.map((r) => structuredClone(r)).reverse();
  }

  /** Restore the content of `version` as a new version. */
  async rollback(tenantId: string, id: string, version: number, actor: string): Promise<Playbook> {
    const cur = this.current.get(id);
    const h = this.history.get(id);
    if (!cur || !h || cur.tenantId !== tenantId) throw new AutomationError("not_found", "playbook not found");
    const target = h.find((r) => r.version === version);
    if (!target) throw new AutomationError("not_found", `version ${version} not found`);
    const { id: _id, tenantId: _t, version: _v, ...content } = target.snapshot;
    const res = await this.update(tenantId, id, content, actor, { comment: `rollback to version ${version}` });
    return res.playbook;
  }

  async delete(tenantId: string, id: string): Promise<boolean> {
    const cur = this.current.get(id);
    if (!cur || cur.tenantId !== tenantId) return false;
    this.current.delete(id);
    return true;
  }

  private assertUniqueName(tenantId: string, organizationId: string | null, name: string, exceptId: string | null): void {
    const key = playbookNameKey(name);
    for (const p of this.current.values()) {
      if (p.id !== exceptId && p.tenantId === tenantId && p.organizationId === organizationId && playbookNameKey(p.name) === key) {
        throw new AutomationError("conflict", `a playbook named "${name}" already exists in this scope`);
      }
    }
  }
}
