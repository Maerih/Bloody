import { randomBytes } from "node:crypto";
import { NodeKind, type CanonicalEvent, type IndicatorType, type Severity } from "@bloody/contracts";
import {
  BUILTIN_RULES,
  DetectionEngine,
  IndicatorSet,
  ManualClock,
  buildTestEvent,
  runRuleTests,
  sigmaToRule,
  validateRule,
  type DetectionMatch,
  type DetectionRule,
  type RuleTestReport,
} from "@bloody/engines";
import { z } from "zod";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, badRequest, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";

/**
 * Detection-as-code for a tenant: the built-in rule pack plus tenant rules (Sigma, threshold,
 * sequence, IOC), every save validated by the Detection Engine (`validateRule`) and versioned in
 * `detection_rule_versions`; tuning through suppressions and analyst verdicts. The analytics
 * pipeline picks rule and suppression changes up on its next batch (version fingerprints).
 */

export const RULE_KINDS = ["sigma", "threshold", "sequence", "ioc"] as const;
export const RESERVED_RULE_IDS = new Set(["suppressions", "validate", "test", "coverage", "stats", "feedback", "versions"]);
const RULE_ID_RE = /^[a-z0-9][a-z0-9._:-]{2,127}$/i;
const BUILTIN = new Map(BUILTIN_RULES.map((r) => [r.id, r]));
/** Non-malicious verdicts for the same rule + entity before it is auto-suppressed. */
export const AUTO_SUPPRESS_AFTER = 3;
export const AUTO_SUPPRESS_DAYS = 30;

export const DetectionInput = z
  .object({
    id: z.string().trim().regex(RULE_ID_RE, "rule id may contain letters, digits, '.', '_', ':' and '-' (3-128 chars)").optional(),
    organizationId: z.string().uuid().nullable().optional(),
    /** Complete engine rule definition (any kind). */
    definition: z.record(z.unknown()).optional(),
    kind: z.enum(RULE_KINDS).optional(),
    /** Sigma YAML (kind sigma) or the JSON definition (other kinds) as text. */
    source: z.string().min(1).max(100_000).optional(),
    name: z.string().trim().min(3).max(200).optional(),
    description: z.string().max(4000).nullable().optional(),
    severity: z.enum(["info", "low", "medium", "high", "critical"]).optional(),
    enabled: z.boolean().optional(),
    tags: z.array(z.string().max(100)).max(50).optional(),
    attack: z.array(z.object({ id: z.string().regex(/^T\d{4}(\.\d{3})?$/), name: z.string().optional(), tactic: z.string().optional() })).max(50).optional(),
    tests: z.array(z.record(z.unknown())).max(100).optional(),
    cooldownSeconds: z.number().int().min(0).max(30 * 86400).optional(),
    comment: z.string().trim().max(1000).optional(),
  })
  .strict();
export type DetectionInput = z.infer<typeof DetectionInput>;

export interface DetectionRuleView {
  id: string;
  organizationId: string | null;
  name: string;
  description: string | null;
  kind: DetectionRule["kind"];
  severity: Severity;
  enabled: boolean;
  version: number;
  /** Sigma YAML for sigma rules, otherwise the JSON definition. */
  source: string;
  definition: DetectionRule;
  attack: DetectionRule["attack"];
  tags: string[];
  builtin: boolean;
  overridesBuiltin: boolean;
  createdBy: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  lastMatchedAt: string | null;
  matches24h: number | null;
  matches7d: number | null;
}

export interface RuleWarnings {
  warnings: string[];
}

function sourceOf(rule: DetectionRule): string {
  if (rule.kind === "sigma") return rule.sigma;
  const { tests: _t, scope: _s, ...rest } = rule as DetectionRule & { scope?: unknown };
  return JSON.stringify(rest, null, 2);
}

function stripScope(def: Record<string, unknown>): Record<string, unknown> {
  const { scope: _scope, ...rest } = def;
  return rest;
}

function slug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60) || "rule";
}

export function generateRuleId(name: string): string {
  return `custom.${slug(name)}-${randomBytes(3).toString("hex")}`;
}

function invalidRule(errors: string[], warnings: string[] = []): HttpError {
  return new HttpError(422, "invalid_rule", `The detection rule is invalid: ${errors.slice(0, 3).join("; ")}`, { errors, warnings });
}

/**
 * Build a complete rule definition from API input (+ the stored rule when updating), then
 * validate it end to end. Returns the engine-parsed rule (defaults applied, scope removed).
 */
export function buildRule(input: DetectionInput, base: { id: string; version: number; definition?: Record<string, unknown> }): { rule: DetectionRule; warnings: string[] } {
  let def: Record<string, unknown>;
  const kind = input.kind ?? ((input.definition?.kind as string | undefined) ?? (base.definition?.kind as string | undefined) ?? "sigma");
  if (input.definition) {
    def = { ...input.definition };
  } else if (input.source !== undefined) {
    if (kind === "sigma") {
      const res = sigmaToRule(input.source, {
        id: base.id,
        version: base.version,
        ...(input.name ? { name: input.name } : {}),
        ...(input.description !== undefined && input.description !== null ? { description: input.description } : {}),
        ...(input.severity ? { severity: input.severity } : {}),
      });
      if (!res.value) throw invalidRule(res.errors, res.warnings);
      def = { ...(base.definition ?? {}), ...(res.value as unknown as Record<string, unknown>) };
      if (base.definition?.tests && input.tests === undefined) def.tests = base.definition.tests;
    } else {
      try {
        const parsed: unknown = JSON.parse(input.source);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
        def = parsed as Record<string, unknown>;
      } catch {
        throw invalidRule([`source: a ${kind} rule source must be its JSON definition`]);
      }
      def.kind = kind;
    }
  } else if (base.definition) {
    def = { ...base.definition };
  } else {
    throw badRequest("Provide the rule `definition`, or `kind` + `source` (Sigma YAML for sigma rules)");
  }
  if (input.name !== undefined) def.name = input.name;
  if (input.description !== undefined) def.description = input.description ?? "";
  if (input.severity !== undefined) def.severity = input.severity;
  if (input.tags !== undefined) def.tags = input.tags;
  if (input.attack !== undefined) def.attack = input.attack;
  if (input.tests !== undefined) def.tests = input.tests;
  if (input.cooldownSeconds !== undefined) def.cooldownSeconds = input.cooldownSeconds;
  if (input.enabled !== undefined) def.enabled = input.enabled;
  def = stripScope(def);
  def.id = base.id;
  def.version = base.version;
  const result = validateRule(def);
  if (!result.valid || !result.rule) throw invalidRule(result.errors, result.warnings);
  return { rule: stripScope(result.rule as unknown as Record<string, unknown>) as unknown as DetectionRule, warnings: result.warnings };
}

function toView(rule: DetectionRule, row: Row | null, stats: Map<string, { last: string | null; d1: number; d7: number }>): DetectionRuleView {
  const s = stats.get(rule.id);
  const builtin = BUILTIN.has(rule.id);
  return {
    id: rule.id,
    organizationId: (row?.organization_id as string | null | undefined) ?? null,
    name: rule.name,
    description: rule.description || null,
    kind: rule.kind,
    severity: rule.severity,
    enabled: row ? Boolean(row.enabled) : rule.enabled,
    version: rule.version,
    source: sourceOf(rule),
    definition: rule,
    attack: rule.attack,
    tags: rule.tags,
    builtin,
    overridesBuiltin: Boolean(row?.overrides_builtin),
    createdBy: (row?.created_by as string | null | undefined) ?? null,
    createdAt: (row?.created_at as string | null | undefined) ?? null,
    updatedAt: (row?.updated_at as string | null | undefined) ?? null,
    lastMatchedAt: s?.last ?? null,
    matches24h: s?.d1 ?? 0,
    matches7d: s?.d7 ?? 0,
  };
}

export interface RuleTestOutcome {
  ruleId: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  tests: RuleTestReport;
  /** Replay of stored telemetry (tenant + organization scoped). */
  replay: { from: string; to: string; scanned: number; matched: number; truncated: boolean; matches: Array<Pick<DetectionMatch, "id" | "organizationId" | "title" | "severity" | "confidence" | "explanation" | "firstSeenAt" | "lastSeenAt"> & { eventIds: string[] }> };
  /** Supplied sample events. */
  samples: { scanned: number; matched: number; explanation: string[] } | null;
  matched: number;
  scanned: number;
  /** Matching stored events (bounded). */
  events: CanonicalEvent[];
}

export class DetectionService {
  constructor(
    private readonly db: Database,
    private readonly now: () => number,
  ) {}

  private async stats(tx: Queryable, orgs: string[] | null): Promise<Map<string, { last: string | null; d1: number; d7: number }>> {
    const { rows } = await tx.query<{ rule_id: string; last: string | null; d1: number; d7: number }>(
      `SELECT rule_id, max(last_seen_at) AS last,
              count(*) FILTER (WHERE created_at > now() - interval '1 day')::int AS d1,
              count(*) FILTER (WHERE created_at > now() - interval '7 days')::int AS d7
       FROM alerts WHERE rule_id IS NOT NULL AND created_at > now() - interval '90 days' ${orgs ? "AND organization_id = ANY($1::uuid[])" : ""}
       GROUP BY rule_id`,
      orgs ? [orgs] : [],
    );
    return new Map(rows.map((r) => [r.rule_id, { last: r.last, d1: r.d1, d7: r.d7 }]));
  }

  private parseStored(row: Row): DetectionRule | null {
    const parsed = validateRule({ ...(row.definition as Record<string, unknown>), enabled: Boolean(row.enabled) });
    return parsed.rule ? (stripScope(parsed.rule as unknown as Record<string, unknown>) as unknown as DetectionRule) : null;
  }

  /** Built-in pack + tenant rules visible in `orgs` (null = whole tenant). */
  async list(tx: Queryable, orgs: string[] | null): Promise<DetectionRuleView[]> {
    const { rows } = await tx.query<Row>(
      `SELECT * FROM detection_rules WHERE ${orgs ? "(organization_id IS NULL OR organization_id = ANY($1::uuid[]))" : "TRUE"} ORDER BY name`,
      orgs ? [orgs] : [],
    );
    const stats = await this.stats(tx, orgs);
    const byId = new Map(rows.map((r) => [String(r.id), r]));
    const out: DetectionRuleView[] = [];
    for (const b of BUILTIN_RULES) {
      const row = byId.get(b.id);
      const rule = row ? (this.parseStored(row) ?? b) : b;
      out.push(toView(rule, row ?? null, stats));
    }
    for (const r of rows) {
      if (BUILTIN.has(String(r.id))) continue;
      const rule = this.parseStored(r);
      if (rule) out.push(toView(rule, r, stats));
    }
    return out;
  }

  async get(tx: Queryable, id: string, orgs: string[] | null): Promise<{ view: DetectionRuleView; row: Row | null } | null> {
    const { rows } = await tx.query<Row>("SELECT * FROM detection_rules WHERE id = $1", [id]);
    const row = rows[0] ?? null;
    if (row && row.organization_id && orgs && !orgs.includes(String(row.organization_id))) return null;
    const builtin = BUILTIN.get(id);
    if (!row && !builtin) return null;
    const rule = row ? this.parseStored(row) : builtin!;
    if (!rule) return null;
    return { view: toView(rule, row, await this.stats(tx, orgs)), row };
  }

  async create(tx: Queryable, tenantId: string, input: DetectionInput, actor: string): Promise<{ view: DetectionRuleView; warnings: string[] }> {
    const definedId = typeof input.definition?.id === "string" && RULE_ID_RE.test(input.definition.id) ? input.definition.id : undefined;
    const id = input.id ?? definedId ?? generateRuleId(input.name ?? (typeof input.definition?.name === "string" ? input.definition.name : "rule"));
    if (RESERVED_RULE_IDS.has(id)) throw badRequest(`"${id}" is a reserved rule id`);
    if (BUILTIN.has(id)) throw new HttpError(409, "conflict", `"${id}" is a built-in rule; enable/disable it or create a rule with another id`);
    const { rule, warnings } = buildRule(input, { id, version: 1 });
    const { rows } = await tx.query<Row>(
      `INSERT INTO detection_rules (id, tenant_id, organization_id, name, kind, version, enabled, severity, definition, overrides_builtin, created_by)
       VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8::jsonb, false, $9) RETURNING *`,
      [id, tenantId, input.organizationId ?? null, rule.name, rule.kind, rule.enabled, rule.severity, JSON.stringify(rule), actor],
    );
    await this.recordVersion(tx, tenantId, rows[0]!, rule, input.comment ?? "created", actor);
    return { view: toView(rule, rows[0]!, new Map()), warnings };
  }

  /** Save a new version (content change) or toggle `enabled` (not versioned). */
  async update(tx: Queryable, tenantId: string, id: string, input: DetectionInput, actor: string, orgs: string[] | null): Promise<{ view: DetectionRuleView; changed: boolean; warnings: string[] }> {
    const cur = await this.get(tx, id, orgs);
    if (!cur) throw notFound("Detection rule");
    if (input.organizationId !== undefined && input.organizationId !== cur.view.organizationId) throw badRequest("A rule cannot move between organizations; create a new rule instead");
    if (cur.view.builtin && (input.definition || input.source !== undefined || input.kind)) throw badRequest("Built-in rules cannot be edited; disable the built-in rule and create a custom copy instead");
    const contentKeys: Array<keyof DetectionInput> = ["definition", "source", "kind", "name", "description", "severity", "tags", "attack", "tests", "cooldownSeconds"];
    const contentChange = contentKeys.some((k) => input[k] !== undefined);
    if (!contentChange) {
      if (input.enabled === undefined) return { view: cur.view, changed: false, warnings: [] };
      return { view: (await this.setEnabled(tx, tenantId, id, input.enabled, actor, orgs)).view, changed: true, warnings: [] };
    }
    const { rule, warnings } = buildRule({ ...input, enabled: input.enabled ?? cur.view.enabled }, { id, version: cur.view.version, definition: cur.view.definition as unknown as Record<string, unknown> });
    const before = JSON.stringify({ ...cur.view.definition, version: 0, enabled: null });
    const after = JSON.stringify({ ...rule, version: 0, enabled: null });
    if (before === after) {
      if (input.enabled !== undefined && input.enabled !== cur.view.enabled) return { view: (await this.setEnabled(tx, tenantId, id, input.enabled, actor, orgs)).view, changed: true, warnings };
      return { view: cur.view, changed: false, warnings };
    }
    const next = { ...rule, version: cur.view.version + 1 } as DetectionRule;
    const { rows } = await tx.query<Row>(
      `UPDATE detection_rules SET name = $2, kind = $3, version = $4, enabled = $5, severity = $6, definition = $7::jsonb WHERE id = $1 RETURNING *`,
      [id, next.name, next.kind, next.version, next.enabled, next.severity, JSON.stringify(next)],
    );
    await this.recordVersion(tx, tenantId, rows[0]!, next, input.comment ?? null, actor);
    return { view: toView(next, rows[0]!, await this.stats(tx, orgs)), changed: true, warnings };
  }

  /** Enable/disable; for a built-in rule this stores (or updates) a tenant override row. */
  async setEnabled(tx: Queryable, tenantId: string, id: string, enabled: boolean, actor: string, orgs: string[] | null): Promise<{ view: DetectionRuleView; changed: boolean }> {
    const cur = await this.get(tx, id, orgs);
    if (!cur) throw notFound("Detection rule");
    if (cur.view.enabled === enabled && cur.row) return { view: cur.view, changed: false };
    let row: Row;
    if (cur.row) {
      row = (await tx.query<Row>("UPDATE detection_rules SET enabled = $2 WHERE id = $1 RETURNING *", [id, enabled])).rows[0]!;
    } else {
      const b = BUILTIN.get(id)!;
      row = (
        await tx.query<Row>(
          `INSERT INTO detection_rules (id, tenant_id, organization_id, name, kind, version, enabled, severity, definition, overrides_builtin, created_by)
           VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8::jsonb, true, $9) RETURNING *`,
          [id, tenantId, b.name, b.kind, b.version, enabled, b.severity, JSON.stringify(b), actor],
        )
      ).rows[0]!;
    }
    const rule = this.parseStored(row)!;
    return { view: toView(rule, row, await this.stats(tx, orgs)), changed: true };
  }

  async versions(tx: Queryable, id: string): Promise<Array<{ version: number; comment: string | null; createdBy: string | null; createdAt: string; definition: unknown }>> {
    const { rows } = await tx.query<Row>("SELECT version, comment, created_by, created_at, definition FROM detection_rule_versions WHERE rule_id = $1 ORDER BY version DESC", [id]);
    return rows.map((r) => ({ version: Number(r.version), comment: (r.comment as string | null) ?? null, createdBy: (r.created_by as string | null) ?? null, createdAt: String(r.created_at), definition: r.definition }));
  }

  async rollback(tx: Queryable, tenantId: string, id: string, version: number, actor: string, orgs: string[] | null): Promise<DetectionRuleView> {
    const { rows } = await tx.query<Row>("SELECT definition FROM detection_rule_versions WHERE rule_id = $1 AND version = $2", [id, version]);
    if (!rows[0]) throw notFound(`Version ${version} of the rule`);
    const res = await this.update(tx, tenantId, id, { definition: rows[0].definition as Record<string, unknown>, comment: `rollback to version ${version}` }, actor, orgs);
    return res.view;
  }

  async remove(tx: Queryable, id: string, orgs: string[] | null): Promise<{ builtinReverted: boolean }> {
    const cur = await this.get(tx, id, orgs);
    if (!cur || !cur.row) throw notFound("Detection rule");
    await tx.query("DELETE FROM detection_rules WHERE id = $1", [id]);
    return { builtinReverted: cur.view.builtin };
  }

  private async recordVersion(tx: Queryable, tenantId: string, row: Row, rule: DetectionRule, comment: string | null, actor: string): Promise<void> {
    await tx.query(
      `INSERT INTO detection_rule_versions (tenant_id, organization_id, rule_id, version, definition, comment, created_by)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7) ON CONFLICT (tenant_id, rule_id, version) DO NOTHING`,
      [tenantId, row.organization_id ?? null, rule.id, rule.version, JSON.stringify(rule), comment, actor],
    );
  }

  /**
   * Test a rule: its embedded tests, supplied sample events, and a replay of the tenant's stored
   * telemetry for the look-back window (bounded). Nothing is persisted.
   */
  async test(tenantId: string, orgs: string[] | null, rule: DetectionRule, opts: { lookbackHours: number; maxEvents: number; samples?: Array<Record<string, unknown>> }): Promise<RuleTestOutcome> {
    const validation = validateRule(rule);
    const tests = runRuleTests(rule);
    const to = this.now();
    const from = to - opts.lookbackHours * 3_600_000;
    const { events, indicators } = await this.db.withTenant(tenantId, async (tx) => {
      const params: unknown[] = [new Date(from).toISOString(), new Date(to).toISOString(), opts.maxEvents + 1];
      const orgClause = orgs ? `AND organization_id = ANY($4::uuid[])` : "";
      if (orgs) params.push(orgs);
      const ev = await tx.query<{ doc: CanonicalEvent }>(
        `SELECT doc FROM (SELECT doc, occurred_at, id FROM events WHERE occurred_at >= $1 AND occurred_at <= $2 ${orgClause} ORDER BY occurred_at DESC, id DESC LIMIT $3) x ORDER BY occurred_at, id`,
        params,
      );
      const ind =
        rule.kind === "ioc"
          ? (
              await tx.query<Row>(
                `SELECT id, tenant_id, organization_id, type, value, confidence, severity, source, threat_actor, malware, campaign, expires_at FROM indicators
                 WHERE NOT revoked AND (expires_at IS NULL OR expires_at > now()) ${orgs ? "AND (organization_id IS NULL OR organization_id = ANY($1::uuid[]))" : ""} LIMIT 200000`,
                orgs ? [orgs] : [],
              )
            ).rows
          : [];
      return { events: ev.rows.map((r) => r.doc), indicators: ind };
    });
    const truncated = events.length > opts.maxEvents;
    const replayEvents = truncated ? events.slice(events.length - opts.maxEvents) : events;
    const clock = new ManualClock(from);
    const set = new IndicatorSet({ clock });
    set.addMany(
      indicators.map((r) => ({
        id: String(r.id),
        tenantId: String(r.tenant_id),
        organizationId: (r.organization_id as string | null) ?? null,
        type: r.type as IndicatorType,
        value: String(r.value),
        confidence: Number(r.confidence),
        severity: r.severity as Severity,
        source: String(r.source),
        threatActor: (r.threat_actor as string | null) ?? null,
        malware: (r.malware as string | null) ?? null,
        campaign: (r.campaign as string | null) ?? null,
        expiresAt: (r.expires_at as string | null) ?? null,
      })),
    );
    const engine = new DetectionEngine({ rules: [{ ...rule, enabled: true } as DetectionRule], clock, indicators: set });
    const matches: DetectionMatch[] = [];
    for (const e of replayEvents) {
      clock.set(e.timestamp);
      matches.push(...engine.process(e));
    }
    const matchedIds = new Set(matches.flatMap((m) => m.events.map((e) => e.id)));
    let samples: RuleTestOutcome["samples"] = null;
    if (opts.samples && opts.samples.length > 0) {
      const sampleClock = new ManualClock(0);
      const sampleEngine = new DetectionEngine({ rules: [{ ...rule, enabled: true } as DetectionRule], clock: sampleClock, indicators: set });
      const built = opts.samples.map((ev, i) => {
        try {
          return buildTestEvent(ev, i, { ruleId: rule.id, testName: "api-samples", tenantId, organizationId: orgs?.[0] ?? "00000000-0000-4000-8000-00000000b001" });
        } catch (err) {
          throw new HttpError(400, "invalid_sample", `Sample event ${i} is not a valid canonical event: ${(err as Error).message.slice(0, 300)}`);
        }
      });
      const sampleMatches: DetectionMatch[] = [];
      for (const e of built.sort((a, b) => a.timestamp.localeCompare(b.timestamp))) {
        sampleClock.set(e.timestamp);
        sampleMatches.push(...sampleEngine.process(e));
      }
      samples = { scanned: built.length, matched: sampleMatches.length, explanation: sampleMatches.flatMap((m) => m.explanation).slice(0, 20) };
    }
    return {
      ruleId: rule.id,
      valid: validation.valid,
      errors: validation.errors,
      warnings: validation.warnings,
      tests,
      replay: {
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
        scanned: replayEvents.length,
        matched: matches.length,
        truncated,
        matches: matches.slice(0, 50).map((m) => ({
          id: m.id,
          organizationId: m.organizationId,
          title: m.title,
          severity: m.severity,
          confidence: m.confidence,
          explanation: m.explanation,
          firstSeenAt: m.firstSeenAt,
          lastSeenAt: m.lastSeenAt,
          eventIds: m.events.map((e) => e.id),
        })),
      },
      samples,
      matched: matches.length,
      scanned: replayEvents.length,
      events: replayEvents.filter((e) => matchedIds.has(e.id)).slice(0, 50),
    };
  }
}

// ─── Suppressions & feedback ────────────────────────────────────────────────

export const SuppressionInput = z
  .object({
    organizationId: z.string().uuid().nullable().default(null),
    ruleId: z.string().trim().refine((v) => v === "*" || RULE_ID_RE.test(v), "ruleId must be a rule id or '*'"),
    entity: z.object({ kind: NodeKind, key: z.string().trim().min(1).max(2048) }).nullable().optional(),
    reason: z.string().trim().min(3).max(2000),
    expiresAt: z.string().datetime({ offset: true }).nullable().optional(),
    expiresInDays: z.number().int().min(1).max(3650).optional(),
  })
  .strict();
export type SuppressionInput = z.infer<typeof SuppressionInput>;

export interface SuppressionView {
  id: string;
  organizationId: string | null;
  ruleId: string;
  entity: { kind: string; key: string } | null;
  reason: string;
  source: "analyst" | "feedback";
  alertId: string | null;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
  revokedBy: string | null;
  active: boolean;
}

export function toSuppression(r: Row, now: number): SuppressionView {
  const expiresAt = (r.expires_at as string | null) ?? null;
  const revokedAt = (r.revoked_at as string | null) ?? null;
  return {
    id: String(r.id),
    organizationId: (r.organization_id as string | null) ?? null,
    ruleId: String(r.rule_id),
    entity: r.entity_kind ? { kind: String(r.entity_kind), key: String(r.entity_key) } : null,
    reason: String(r.reason),
    source: r.source as "analyst" | "feedback",
    alertId: (r.alert_id as string | null) ?? null,
    createdBy: String(r.created_by),
    createdAt: String(r.created_at),
    expiresAt,
    revokedAt,
    revokedBy: (r.revoked_by as string | null) ?? null,
    active: revokedAt === null && (expiresAt === null || Date.parse(expiresAt) > now),
  };
}

export async function insertSuppression(
  tx: Queryable,
  tenantId: string,
  input: { organizationId: string | null; ruleId: string; entity: { kind: string; key: string } | null; reason: string; expiresAt: string | null; source: "analyst" | "feedback"; alertId: string | null; createdBy: string },
): Promise<Row> {
  const { rows } = await tx.query<Row>(
    `INSERT INTO detection_suppressions (tenant_id, organization_id, rule_id, entity_kind, entity_key, reason, source, alert_id, created_by, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
    [tenantId, input.organizationId, input.ruleId, input.entity?.kind ?? null, input.entity?.key ?? null, input.reason, input.source, input.alertId, input.createdBy, input.expiresAt],
  );
  return rows[0]!;
}
