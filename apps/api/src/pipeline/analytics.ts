import {
  SEVERITY_RANK,
  maxSeverity,
  type AttackTechnique,
  type AutomationEvent,
  type CanonicalEvent,
  type Criticality,
  type IndicatorType,
  type NodeKind,
  type Severity,
} from "@bloody/contracts";
import {
  ASSET_NODE_KINDS,
  BUILTIN_RULES,
  Correlator,
  DetectionEngine,
  DetectionRuleSchema,
  IndicatorSet,
  InMemorySuppressionList,
  extractObservables,
  lookupCandidates,
  type DetectionMatch,
  type DetectionRule,
  type EntityRef,
  type IncidentDraft,
  type IndicatorRecord,
  type RiskEngine,
} from "@bloody/engines";
import { SYSTEM_ACTOR, writeAudit } from "../audit/audit.js";
import type { Database, Queryable } from "../db/pool.js";
import type { Metrics } from "../metrics.js";
import { toIncident, type Row } from "../repo/mappers.js";
import { graphFor, type InventoryService } from "../services/inventory.js";
import { TOPICS, type EventBus } from "./event-bus.js";
import type { IngestBatchMessage } from "./ingest.js";

/**
 * Analytics pipeline worker (consumer of `bloody.events.ingested.v1`).
 *
 *   events → asset/identity discovery → Security Graph upsert → Detection Engine (built-in pack
 *   + tenant rules; Sigma / threshold / sequence / IOC) → alerts → Correlator → incidents
 *   (+ escalations for critical) → IOC matches → Risk Engine re-scoring of touched assets and
 *   identities → audit + automation events.
 *
 * Stateful detection windows and correlation clusters live per tenant in this process; the bus
 * delivers one tenant's batches serially (partition key = tenant), so state is never shared
 * across customers. Persistence is idempotent (deterministic alert ids, ON CONFLICT), so a
 * redelivered batch cannot duplicate alerts or incidents.
 */

export interface AutomationEnvelope {
  tenantId: string;
  organizationId: string;
  event: AutomationEvent;
  occurredAt: string;
  severity?: Severity;
  subject: { kind: string; id: string; label?: string };
  data: Record<string, unknown>;
}

/** Hand-off to @bloody/automation (rules engine / playbooks). Wired by the composition root. */
export interface AutomationSink {
  emit(envelope: AutomationEnvelope): Promise<void> | void;
}

export interface PipelineLogger {
  info(obj: unknown, msg?: string): void;
  warn(obj: unknown, msg?: string): void;
  error(obj: unknown, msg?: string): void;
  debug(obj: unknown, msg?: string): void;
}

export interface BatchResult {
  tenantId: string;
  organizationId: string;
  events: number;
  matches: number;
  alertsCreated: string[];
  incidentsCreated: string[];
  incidentsUpdated: string[];
  escalationsCreated: string[];
  indicatorMatches: number;
  graphErrors: number;
}

interface TenantState {
  engine: DetectionEngine;
  correlator: Correlator;
  indicatorsVersion: string;
  rulesVersion: string;
  suppressionsVersion: string;
  suppressions: InMemorySuppressionList;
  assetCtx: Map<string, { criticality: Criticality; edr: boolean }>;
  identityCtx: Map<string, boolean>;
  draftIncident: Map<string, string>;
  indicators: IndicatorSet | null;
  lastUsed: number;
}

const ACTIVE = ["new", "triage", "investigating", "contained"];
const CRITICAL_ESCALATION_MINUTES = 15;
const MAX_TENANT_STATES = 2000;
const GRAPH_CHUNK = 200;

function dedupeAttack(list: AttackTechnique[]): AttackTechnique[] {
  const out = new Map<string, AttackTechnique>();
  for (const t of list) if (!out.has(t.id)) out.set(t.id, t);
  return [...out.values()];
}

export class AnalyticsPipeline {
  private readonly tenants = new Map<string, TenantState>();
  private unsubscribe: (() => void) | null = null;

  constructor(
    private readonly deps: {
      db: Database;
      bus: EventBus;
      metrics: Metrics;
      inventory: InventoryService;
      risk: RiskEngine;
      log: PipelineLogger;
      automation?: AutomationSink | undefined;
      /** Called after each committed batch (attack-path cache invalidation, alert.created triggers). */
      onBatchProcessed?: ((result: BatchResult) => void) | undefined;
      now?: () => number;
    },
  ) {}

  private now(): number {
    return this.deps.now ? this.deps.now() : Date.now();
  }

  start(): void {
    if (this.unsubscribe) return;
    this.unsubscribe = this.deps.bus.subscribe<IngestBatchMessage>(TOPICS.eventsIngested, async (msg) => {
      const stats = this.deps.bus.stats();
      this.deps.metrics.queueDepth.set(stats.depth);
      this.deps.metrics.queueLag.set(Math.max(0, (this.now() - Date.parse(msg.publishedAt)) / 1000));
      await this.process(msg.payload);
    });
  }

  stop(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
  }

  /** Forget a tenant's in-memory state (rule/indicator changes are also picked up automatically). */
  reset(tenantId?: string): void {
    if (tenantId) this.tenants.delete(tenantId);
    else this.tenants.clear();
  }

  // ─── Tenant state ────────────────────────────────────────────────────────

  private async stateFor(tenantId: string): Promise<TenantState> {
    const versions = await this.deps.db.withTenant(tenantId, async (tx) => {
      const ind = await tx.query<{ v: string }>("SELECT count(*)::text || '|' || coalesce(max(updated_at)::text, '') AS v FROM indicators");
      const rules = await tx.query<{ v: string }>("SELECT count(*)::text || '|' || coalesce(max(updated_at)::text, '') AS v FROM detection_rules");
      const sup = await tx.query<{ v: string }>("SELECT count(*)::text || '|' || coalesce(max(updated_at)::text, '') AS v FROM detection_suppressions");
      return { indicators: ind.rows[0]!.v, rules: rules.rows[0]!.v, suppressions: sup.rows[0]!.v };
    });
    let state = this.tenants.get(tenantId);
    if (!state) {
      if (this.tenants.size >= MAX_TENANT_STATES) {
        const oldest = [...this.tenants.entries()].sort((a, b) => a[1].lastUsed - b[1].lastUsed)[0];
        if (oldest) this.tenants.delete(oldest[0]);
      }
      const assetCtx = new Map<string, { criticality: Criticality; edr: boolean }>();
      const identityCtx = new Map<string, boolean>();
      const suppressions = new InMemorySuppressionList();
      state = {
        engine: new DetectionEngine({ suppressions, clock: { now: () => this.now() } }),
        correlator: new Correlator({
          riskEngine: this.deps.risk,
          clock: { now: () => this.now() },
          context: {
            assetCriticality: (org, key) => assetCtx.get(`${org}|${key}`)?.criticality,
            assetHasEdr: (org, key) => assetCtx.get(`${org}|${key}`)?.edr,
            identityPrivileged: (org, key) => identityCtx.get(`${org}|${key}`),
          },
        }),
        indicatorsVersion: "",
        rulesVersion: "",
        suppressionsVersion: "",
        suppressions,
        assetCtx,
        identityCtx,
        draftIncident: new Map(),
        indicators: null,
        lastUsed: this.now(),
      };
      this.tenants.set(tenantId, state);
    }
    state.lastUsed = this.now();
    if (state.rulesVersion !== versions.rules) {
      await this.loadRules(tenantId, state);
      state.rulesVersion = versions.rules;
    }
    if (state.indicatorsVersion !== versions.indicators) {
      await this.loadIndicators(tenantId, state);
      state.indicatorsVersion = versions.indicators;
    }
    if (state.suppressionsVersion !== versions.suppressions) {
      await this.loadSuppressions(tenantId, state);
      state.suppressionsVersion = versions.suppressions;
    }
    return state;
  }

  /** Active analyst / feedback suppressions (detection_suppressions) → the engine's hot-path list. */
  private async loadSuppressions(tenantId: string, state: TenantState): Promise<void> {
    const rows = await this.deps.db.withTenant(tenantId, async (tx) =>
      (
        await tx.query<Row>(
          "SELECT id, organization_id, rule_id, entity_kind, entity_key, reason, created_by, created_at, expires_at FROM detection_suppressions WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
        )
      ).rows,
    );
    for (const s of state.suppressions.list(tenantId)) state.suppressions.remove(s.id);
    for (const r of rows) {
      state.suppressions.add({
        id: String(r.id),
        tenantId,
        organizationId: (r.organization_id as string | null) ?? null,
        ruleId: String(r.rule_id),
        ...(r.entity_kind ? { entity: { kind: r.entity_kind as NodeKind, key: String(r.entity_key) } } : {}),
        reason: String(r.reason),
        createdBy: String(r.created_by),
        createdAt: String(r.created_at),
        expiresAt: (r.expires_at as string | null) ?? null,
      });
    }
  }

  private async loadRules(tenantId: string, state: TenantState): Promise<void> {
    const rows = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT id, organization_id, enabled, definition FROM detection_rules")).rows);
    const rules = new Map<string, DetectionRule>(BUILTIN_RULES.map((r) => [r.id, r]));
    for (const r of rows) {
      const parsed = DetectionRuleSchema.safeParse({
        ...(r.definition as Record<string, unknown>),
        enabled: Boolean(r.enabled),
        scope: { tenantId, ...(r.organization_id ? { organizationIds: [String(r.organization_id)] } : {}) },
      });
      if (!parsed.success) {
        this.deps.log.warn({ tenantId, ruleId: r.id, issues: parsed.error.issues.slice(0, 5) }, "stored detection rule failed validation; skipped");
        continue;
      }
      rules.set(parsed.data.id, parsed.data);
    }
    const res = state.engine.loadRules([...rules.values()]);
    for (const rej of res.rejected) this.deps.log.warn({ tenantId, ruleId: rej.ruleId, errors: rej.errors }, "detection rule rejected by the engine");
  }

  private async loadIndicators(tenantId: string, state: TenantState): Promise<void> {
    const rows = await this.deps.db.withTenant(tenantId, async (tx) =>
      (
        await tx.query<Row>(
          "SELECT id, tenant_id, organization_id, type, value, confidence, severity, source, threat_actor, malware, campaign, expires_at FROM indicators WHERE NOT revoked AND (expires_at IS NULL OR expires_at > now())",
        )
      ).rows,
    );
    const set = new IndicatorSet({ clock: { now: () => this.now() } });
    set.addMany(
      rows.map(
        (r): IndicatorRecord => ({
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
        }),
      ),
    );
    state.engine.setIndicatorProvider(set);
    state.indicators = set;
  }

  // ─── Batch processing ────────────────────────────────────────────────────

  async process(batch: IngestBatchMessage): Promise<BatchResult> {
    const started = this.now();
    const { tenantId, organizationId } = batch;
    const events = [...batch.events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    const result: BatchResult = { tenantId, organizationId, events: events.length, matches: 0, alertsCreated: [], incidentsCreated: [], incidentsUpdated: [], escalationsCreated: [], indicatorMatches: 0, graphErrors: 0 };
    if (events.length === 0) return result;
    const state = await this.stateFor(tenantId);

    // 1. Discovery (assets / identities) — keeps inventory, graph aliases and last-seen current.
    await this.deps.db.withTenant(tenantId, (tx) => this.discover(tx, tenantId, organizationId, events));

    // 2. Security Graph (savepoint per event: one bad event never aborts the batch).
    for (let i = 0; i < events.length; i += GRAPH_CHUNK) {
      const chunk = events.slice(i, i + GRAPH_CHUNK);
      result.graphErrors += await this.deps.db.withTenant(tenantId, async (tx) => {
        const graph = graphFor(tx, tenantId);
        let errors = 0;
        for (const e of chunk) {
          await tx.query("SAVEPOINT graph_event");
          try {
            await graph.ingestEvent(e);
            await tx.query("RELEASE SAVEPOINT graph_event");
          } catch (err) {
            errors++;
            await tx.query("ROLLBACK TO SAVEPOINT graph_event");
            this.deps.metrics.pipelineErrors.inc({ stage: "graph" });
            this.deps.log.warn({ tenantId, eventId: e.id, err: err instanceof Error ? err.message : String(err) }, "graph ingestion failed for event");
          }
        }
        return errors;
      });
    }

    // 3. Detection (synchronous engine, event-time ordered).
    let matches: DetectionMatch[] = [];
    try {
      matches = state.engine.processBatch(events);
    } catch (err) {
      this.deps.metrics.pipelineErrors.inc({ stage: "detection" });
      this.deps.log.error({ tenantId, err }, "detection engine failed for batch");
    }
    result.matches = matches.length;

    // 4. IOC observations for the intel-match ledger.
    const indicatorSet = state.indicators;
    const iocHits: Array<{ indicatorId: string; eventId: string; field: string; observed: string; eventTime: string; host: string | null }> = [];
    if (indicatorSet && indicatorSet.size > 0) {
      for (const e of events) {
        for (const o of extractObservables(e)) {
          for (const cand of lookupCandidates(o, true)) {
            for (const rec of indicatorSet.lookup(tenantId, e.organizationId, o.type, cand)) {
              if (rec.id) iocHits.push({ indicatorId: rec.id, eventId: e.id, field: o.field, observed: o.value, eventTime: e.timestamp, host: e.asset?.hostname ?? null });
            }
          }
        }
      }
    }

    // 5. Alerts → correlation → incidents/escalations → risk, in one transaction.
    const notifications: AutomationEnvelope[] = [];
    await this.deps.db.withTenant(tenantId, async (tx) => {
      const ctx = await this.loadEntityContext(tx, matches, state);
      const fresh = await this.persistAlerts(tx, tenantId, matches, ctx);
      result.alertsCreated = fresh.map((m) => m.id);
      for (const m of fresh) this.deps.metrics.pipelineDetections.inc({ severity: m.severity });

      result.indicatorMatches = await this.persistIocHits(tx, tenantId, organizationId, iocHits, matches, ctx.assetByKey);
      if (result.indicatorMatches > 0) {
        notifications.push({ tenantId, organizationId, event: "indicator.matched", occurredAt: new Date(this.now()).toISOString(), severity: "high", subject: { kind: "organization", id: organizationId }, data: { matches: result.indicatorMatches } });
      }

      const drafts = new Map<string, IncidentDraft>();
      const merged = new Map<string, string>();
      for (const m of [...fresh].sort((a, b) => a.firstSeenAt.localeCompare(b.firstSeenAt) || a.id.localeCompare(b.id))) {
        const r = state.correlator.add(m, { alertId: m.id });
        for (const mid of r.mergedIncidentIds) {
          merged.set(mid, r.incident.id);
          drafts.delete(mid);
        }
        drafts.set(r.incident.id, r.incident);
      }
      const matchById = new Map(matches.map((m) => [m.id, m]));
      for (const draft of drafts.values()) {
        const mergedFrom = [...merged.entries()].filter(([, into]) => into === draft.id).map(([from]) => from);
        const outcome = await this.persistDraft(tx, tenantId, state, draft, mergedFrom, matchById, ctx, notifications);
        if (outcome?.created) result.incidentsCreated.push(outcome.id);
        else if (outcome) result.incidentsUpdated.push(outcome.id);
        if (outcome?.escalationId) result.escalationsCreated.push(outcome.escalationId);
      }

      // Risk re-scoring of every asset / identity touched by a new detection.
      const touchedAssets = new Set<string>();
      const touchedIdentities = new Set<string>();
      for (const m of fresh) {
        const ids = this.resolveEntityIds(m.entities, m.organizationId, ctx);
        if (ids.assetId) touchedAssets.add(ids.assetId);
        if (ids.identityId) touchedIdentities.add(ids.identityId);
      }
      for (const h of iocHits) if (h.host) {
        const id = ctx.assetByKey.get(`${organizationId}|${h.host.toLowerCase().split(".")[0]}`);
        if (id) touchedAssets.add(id);
      }
      for (const id of touchedAssets) await this.deps.inventory.scoreAsset(tx, tenantId, id);
      for (const id of touchedIdentities) await this.deps.inventory.scoreIdentity(tx, tenantId, id);
    });

    this.deps.metrics.pipelineEvents.inc(events.length);
    this.deps.metrics.pipelineIncidents.inc({ kind: "created" }, result.incidentsCreated.length);
    this.deps.metrics.pipelineIncidents.inc({ kind: "updated" }, result.incidentsUpdated.length);
    this.deps.metrics.pipelineBatchDuration.observe((this.now() - started) / 1000);
    state.engine.gc();
    state.correlator.expire();

    try {
      this.deps.onBatchProcessed?.(result);
    } catch (err) {
      this.deps.log.warn({ tenantId, err: err instanceof Error ? err.message : String(err) }, "batch hook failed");
    }

    if (this.deps.automation) {
      for (const n of notifications) {
        try {
          await this.deps.automation.emit(n);
        } catch (err) {
          this.deps.metrics.pipelineErrors.inc({ stage: "automation" });
          this.deps.log.warn({ tenantId, event: n.event, err: err instanceof Error ? err.message : String(err) }, "automation hand-off failed");
        }
      }
    }
    return result;
  }

  private async discover(tx: Queryable, tenantId: string, organizationId: string, events: CanonicalEvent[]): Promise<void> {
    const hosts = events
      .filter((e) => e.asset?.hostname)
      .map((e) => ({ hostname: e.asset!.hostname!, os: e.asset?.os, ips: e.asset?.ip, lastSeenAt: e.timestamp }));
    await this.deps.inventory.resolveOrDiscoverHosts(tx, tenantId, organizationId, hosts);

    const idents = new Map<string, { provider: string; principal: string; privileged: boolean | undefined; mfa: boolean | undefined; at: string }>();
    for (const e of events) {
      const principal = e.identity?.principal?.trim();
      if (!principal) continue;
      const provider = (e.identity?.provider ?? e.source.product).trim().toLowerCase();
      const k = `${provider}:${principal.toLowerCase()}`;
      const prev = idents.get(k);
      if (!prev || prev.at < e.timestamp) idents.set(k, { provider, principal, privileged: e.identity?.privileged ?? prev?.privileged, mfa: e.identity?.mfa ?? prev?.mfa, at: e.timestamp });
    }
    for (const i of idents.values()) {
      const { rows } = await tx.query<{ id: string; inserted: boolean }>(
        `INSERT INTO identities (tenant_id, organization_id, kind, provider, principal, privileged, mfa_enabled, last_activity_at, external_source)
         VALUES ($1, $2, 'user', $3, $4, $5, $6, $7, 'discovered')
         ON CONFLICT (tenant_id, organization_id, lower(provider), lower(principal)) DO UPDATE SET last_activity_at = GREATEST(identities.last_activity_at, EXCLUDED.last_activity_at)
         RETURNING id, (xmax = 0) AS inserted`,
        [tenantId, organizationId, i.provider, i.principal, i.privileged ?? false, i.mfa ?? false, i.at],
      );
      if (rows[0]?.inserted) {
        await graphFor(tx, tenantId).ingestIdentity({ id: rows[0].id, organizationId, provider: i.provider, principal: i.principal, privileged: i.privileged ?? false, mfaEnabled: i.mfa ?? false });
      }
    }
  }

  private async loadEntityContext(tx: Queryable, matches: DetectionMatch[], state: TenantState) {
    const hostKeys = new Set<string>();
    const identityKeys = new Set<string>();
    const userKeys = new Set<string>();
    for (const m of matches) {
      for (const e of m.entities) {
        if (ASSET_NODE_KINDS.includes(e.kind)) hostKeys.add(e.key);
        else if (e.kind === "identity") identityKeys.add(e.key);
        else if (e.kind === "user") userKeys.add(e.key);
      }
    }
    const assetByKey = new Map<string, string>();
    const assetInfo = new Map<string, { id: string; name: string; criticality: Criticality; edr: boolean; internetFacing: boolean }>();
    if (hostKeys.size > 0) {
      const { rows } = await tx.query<{ id: string; key: string; name: string; criticality: Criticality; edr: boolean | null; internet_facing: boolean; organization_id: string }>(
        `SELECT a.id, a.organization_id, split_part(lower(a.hostname), '.', 1) AS key, a.name, a.criticality, a.internet_facing,
                (ag.status IN ('protected', 'isolated')) AS edr
         FROM assets a
         LEFT JOIN LATERAL (SELECT status FROM agents WHERE asset_id = a.id ORDER BY updated_at DESC LIMIT 1) ag ON true
         WHERE a.hostname IS NOT NULL AND split_part(lower(a.hostname), '.', 1) = ANY($1::text[])`,
        [[...hostKeys]],
      );
      for (const r of rows) {
        assetByKey.set(`${r.organization_id}|${r.key}`, r.id);
        assetInfo.set(r.id, { id: r.id, name: r.name, criticality: r.criticality, edr: r.edr === true, internetFacing: r.internet_facing });
        state.assetCtx.set(`${r.organization_id}|${r.key}`, { criticality: r.criticality, edr: r.edr === true });
      }
    }
    const identityByKey = new Map<string, string>();
    const identityInfo = new Map<string, { id: string; principal: string; privileged: boolean }>();
    if (identityKeys.size > 0 || userKeys.size > 0) {
      const { rows } = await tx.query<{ id: string; organization_id: string; ikey: string; p: string; privileged: boolean; principal: string }>(
        `SELECT id, organization_id, lower(provider) || ':' || lower(principal) AS ikey, lower(principal) AS p, privileged, principal
         FROM identities WHERE lower(provider) || ':' || lower(principal) = ANY($1::text[]) OR lower(principal) = ANY($2::text[])`,
        [[...identityKeys], [...userKeys]],
      );
      for (const r of rows) {
        identityByKey.set(`${r.organization_id}|identity|${r.ikey}`, r.id);
        identityByKey.set(`${r.organization_id}|user|${r.p}`, r.id);
        identityInfo.set(r.id, { id: r.id, principal: r.principal, privileged: r.privileged });
        state.identityCtx.set(`${r.organization_id}|${r.ikey}`, r.privileged);
        state.identityCtx.set(`${r.organization_id}|${r.p}`, r.privileged);
      }
    }
    return { assetByKey, assetInfo, identityByKey, identityInfo };
  }

  private resolveEntityIds(entities: EntityRef[], organizationId: string, ctx: Awaited<ReturnType<AnalyticsPipeline["loadEntityContext"]>>): { assetId: string | null; identityId: string | null; assetIds: string[]; identityIds: string[] } {
    const assetIds: string[] = [];
    const identityIds: string[] = [];
    for (const e of entities) {
      if (ASSET_NODE_KINDS.includes(e.kind)) {
        const id = ctx.assetByKey.get(`${organizationId}|${e.key}`);
        if (id && !assetIds.includes(id)) assetIds.push(id);
      } else if (e.kind === "identity" || e.kind === "user") {
        const id = ctx.identityByKey.get(`${organizationId}|${e.kind}|${e.key}`);
        if (id && !identityIds.includes(id)) identityIds.push(id);
      }
    }
    return { assetId: assetIds[0] ?? null, identityId: identityIds[0] ?? null, assetIds, identityIds };
  }

  private async persistAlerts(tx: Queryable, tenantId: string, matches: DetectionMatch[], ctx: Awaited<ReturnType<AnalyticsPipeline["loadEntityContext"]>>): Promise<DetectionMatch[]> {
    const fresh: DetectionMatch[] = [];
    for (const m of matches) {
      const ids = this.resolveEntityIds(m.entities, m.organizationId, ctx);
      const assets = ids.assetIds.map((id) => ctx.assetInfo.get(id)!).filter(Boolean);
      const identities = ids.identityIds.map((id) => ctx.identityInfo.get(id)!).filter(Boolean);
      const risk = this.deps.risk.scoreIncident({
        title: m.title,
        attack: m.attack,
        alerts: [{ ruleId: m.rule.id, title: m.rule.name, severity: m.severity, confidence: m.confidence, source: m.events[0]?.source.product ?? m.rule.kind, attack: m.attack }],
        assets: assets.length > 0 ? assets.map((a) => ({ name: a.name, criticality: a.criticality, edr: a.edr })) : [],
        identities: identities.map((i) => ({ principal: i.principal, privileged: i.privileged })),
        intelMatches: (m.indicators ?? []).map((h) => ({ value: h.value, confidence: h.confidence, severity: h.severity, threatActor: h.threatActor ?? null, campaign: h.campaign ?? null })),
      });
      const explanation = [...m.explanation, `Risk ${risk.score}/100: ${risk.summary}`];
      const { rows } = await tx.query<{ id: string }>(
        `INSERT INTO alerts (id, tenant_id, organization_id, title, severity, status, rule_id, rule_version, rule_kind, source, event_ids, asset_id, identity_id,
                             attack, confidence, risk_score, explanation, entities, indicators, first_seen_at, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, 'new', $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15, $16::jsonb, $17::jsonb, $18::jsonb, $19, $20)
         ON CONFLICT (id) DO NOTHING RETURNING id`,
        [
          m.id,
          tenantId,
          m.organizationId,
          m.title.slice(0, 500),
          m.severity,
          m.rule.id,
          m.rule.version,
          m.rule.kind,
          m.events[0]?.source.product ?? "bloody",
          [...new Set(m.events.map((e) => e.id))],
          ids.assetId,
          ids.identityId,
          JSON.stringify(m.attack),
          Math.min(1, Math.max(0, m.confidence)),
          risk.score,
          JSON.stringify(explanation),
          JSON.stringify(m.entities),
          JSON.stringify(m.indicators ?? []),
          m.firstSeenAt,
          m.lastSeenAt,
        ],
      );
      if (rows[0]) fresh.push(m);
    }
    return fresh;
  }

  private async persistIocHits(
    tx: Queryable,
    tenantId: string,
    organizationId: string,
    hits: Array<{ indicatorId: string; eventId: string; field: string; observed: string; eventTime: string; host: string | null }>,
    matches: DetectionMatch[],
    assetByKey: Map<string, string>,
  ): Promise<number> {
    if (hits.length === 0) return 0;
    const alertByEvent = new Map<string, string>();
    for (const m of matches) if (m.rule.kind === "ioc") for (const e of m.events) alertByEvent.set(e.id, m.id);
    let n = 0;
    for (const h of hits) {
      const assetId = h.host ? (assetByKey.get(`${organizationId}|${h.host.toLowerCase().split(".")[0]}`) ?? null) : null;
      const res = await tx.query(
        `INSERT INTO indicator_matches (tenant_id, organization_id, indicator_id, event_id, alert_id, asset_id, observed_value, field, event_time)
         SELECT $1, $2, $3, $4, (SELECT id FROM alerts WHERE id = $5), $6, $7, $8, $9
         ON CONFLICT (tenant_id, indicator_id, event_id, field) DO NOTHING`,
        [tenantId, organizationId, h.indicatorId, h.eventId, alertByEvent.get(h.eventId) ?? null, assetId, h.observed, h.field, h.eventTime],
      );
      n += res.rowCount ?? 0;
    }
    if (n > 0) await tx.query("UPDATE indicators SET last_seen_at = now() WHERE id = ANY($1::uuid[]) AND last_seen_at < now() - interval '1 minute'", [[...new Set(hits.map((h) => h.indicatorId))]]);
    return n;
  }

  private async findIncidentForDraft(tx: Queryable, state: TenantState, draft: IncidentDraft, mergedFrom: string[]): Promise<Row | null> {
    const candidates = [state.draftIncident.get(draft.id), ...mergedFrom.map((m) => state.draftIncident.get(m))].filter((x): x is string => typeof x === "string");
    if (candidates.length > 0) {
      const { rows } = await tx.query<Row>("SELECT * FROM incidents WHERE id = ANY($1::uuid[]) AND merged_into IS NULL AND status = ANY($2::text[]) ORDER BY number LIMIT 1 FOR UPDATE", [candidates, ACTIVE]);
      if (rows[0]) return rows[0];
    }
    const byCorrelation = await tx.query<Row>("SELECT * FROM incidents WHERE correlation_id = $1 AND merged_into IS NULL AND status = ANY($2::text[]) FOR UPDATE", [draft.id, ACTIVE]);
    if (byCorrelation.rows[0]) return byCorrelation.rows[0];
    // Restart resilience: an active correlated incident of the same organization that shares a
    // join entity and was active within the correlation window.
    if (draft.correlationKeys.length > 0) {
      const { rows } = await tx.query<Row>(
        `SELECT * FROM incidents
         WHERE organization_id = $1 AND source = 'correlation' AND merged_into IS NULL AND status = ANY($2::text[])
           AND correlation_keys && $3::text[] AND last_seen_at > $4::timestamptz - interval '6 hours'
         ORDER BY number LIMIT 1 FOR UPDATE`,
        [draft.organizationId, ACTIVE, draft.correlationKeys, draft.firstSeenAt],
      );
      if (rows[0]) return rows[0];
    }
    return null;
  }

  private async persistDraft(
    tx: Queryable,
    tenantId: string,
    state: TenantState,
    draft: IncidentDraft,
    mergedFrom: string[],
    matchById: Map<string, DetectionMatch>,
    ctx: Awaited<ReturnType<AnalyticsPipeline["loadEntityContext"]>>,
    notifications: AutomationEnvelope[],
  ): Promise<{ id: string; created: boolean; escalationId: string | null } | null> {
    const existing = await this.findIncidentForDraft(tx, state, draft, mergedFrom);
    if (!existing && !draft.promote) return null;

    const draftMatches = draft.matchIds.map((id) => matchById.get(id)).filter((m): m is DetectionMatch => m !== undefined);
    const entities = draftMatches.flatMap((m) => m.entities);
    const resolved = this.resolveEntityIds(entities, draft.organizationId, ctx);
    const actor = SYSTEM_ACTOR(tenantId, "pipeline");
    let incident: Row;
    let created = false;
    let severityChanged: { from: Severity; to: Severity } | null = null;

    if (!existing) {
      const { rows } = await tx.query<Row>(
        `INSERT INTO incidents (tenant_id, organization_id, number, title, summary, severity, status, risk_score, risk, attack, asset_ids, identity_ids,
                                source, correlation_id, correlation_keys, correlation_revision, escalation_reasons, first_seen_at, last_seen_at, detected_at, created_by)
         VALUES ($1, $2, next_incident_number($1), $3, $4, $5, 'new', $6, $7::jsonb, $8::jsonb, $9, $10, 'correlation', $11, $12, $13, $14, $15, $16, now(), 'system:pipeline')
         RETURNING *`,
        [
          tenantId,
          draft.organizationId,
          draft.title.length >= 3 ? draft.title : `Correlated detection ${draft.title}`.slice(0, 300),
          draft.summary,
          draft.severity,
          draft.riskScore,
          JSON.stringify(draft.risk),
          JSON.stringify(draft.attack),
          resolved.assetIds,
          resolved.identityIds,
          draft.id,
          draft.correlationKeys,
          draft.revision,
          draft.escalationReasons,
          draft.firstSeenAt,
          draft.lastSeenAt,
        ],
      );
      incident = rows[0]!;
      created = true;
    } else {
      const prevSeverity = existing.severity as Severity;
      const severity = maxSeverity(prevSeverity, draft.severity);
      if (severity !== prevSeverity) severityChanged = { from: prevSeverity, to: severity };
      const attack = dedupeAttack([...((existing.attack as AttackTechnique[]) ?? []), ...draft.attack]);
      const { rows } = await tx.query<Row>(
        `UPDATE incidents SET
           severity = $2,
           risk_score = GREATEST(risk_score, $3),
           risk = CASE WHEN $3 >= risk_score THEN $4::jsonb ELSE risk END,
           attack = $5::jsonb,
           asset_ids = ARRAY(SELECT DISTINCT x FROM unnest(asset_ids || $6::uuid[]) x),
           identity_ids = ARRAY(SELECT DISTINCT x FROM unnest(identity_ids || $7::uuid[]) x),
           correlation_keys = ARRAY(SELECT DISTINCT x FROM unnest(correlation_keys || $8::text[]) x),
           correlation_revision = correlation_revision + 1,
           escalation_reasons = ARRAY(SELECT DISTINCT x FROM unnest(escalation_reasons || $9::text[]) x),
           first_seen_at = LEAST(coalesce(first_seen_at, $10), $10),
           last_seen_at = GREATEST(coalesce(last_seen_at, $11), $11),
           summary = CASE WHEN status = 'new' AND source = 'correlation' THEN $12 ELSE summary END,
           title = CASE WHEN status = 'new' AND source = 'correlation' AND length($13) >= 3 THEN $13 ELSE title END
         WHERE id = $1 RETURNING *`,
        [
          existing.id,
          severity,
          draft.riskScore,
          JSON.stringify(draft.risk),
          JSON.stringify(attack),
          resolved.assetIds,
          resolved.identityIds,
          draft.correlationKeys,
          draft.escalationReasons,
          draft.firstSeenAt,
          draft.lastSeenAt,
          draft.summary,
          draft.title,
        ],
      );
      incident = rows[0]!;
    }
    const incidentId = String(incident.id);
    state.draftIncident.set(draft.id, incidentId);
    for (const m of mergedFrom) state.draftIncident.set(m, incidentId);

    // Absorb incidents of merged drafts (a new detection bridged two clusters).
    for (const m of mergedFrom) {
      const other = await tx.query<Row>("SELECT id, number FROM incidents WHERE correlation_id = $1 AND id <> $2 AND merged_into IS NULL", [m, incidentId]);
      const o = other.rows[0];
      if (!o) continue;
      await tx.query(
        `INSERT INTO incident_alerts (incident_id, alert_id, tenant_id, organization_id)
         SELECT $1, alert_id, tenant_id, organization_id FROM incident_alerts WHERE incident_id = $2 ON CONFLICT DO NOTHING`,
        [incidentId, o.id],
      );
      await tx.query("UPDATE alerts SET incident_id = $1 WHERE incident_id = $2", [incidentId, o.id]);
      await tx.query(
        "UPDATE incidents SET merged_into = $1, status = 'closed', closed_at = now(), summary = 'Merged into incident #' || $3 || ' by correlation. ' || coalesce(summary, '') WHERE id = $2",
        [incidentId, o.id, String(incident.number)],
      );
      await writeAudit(tx, actor, { action: "incident.merged", organizationId: draft.organizationId, targetKind: "incident", targetId: String(o.id), details: { into: incidentId } });
    }

    // Link alerts.
    await tx.query(
      `INSERT INTO incident_alerts (incident_id, alert_id, tenant_id, organization_id)
       SELECT $1, a.id, a.tenant_id, a.organization_id FROM alerts a WHERE a.id = ANY($2::uuid[]) AND a.organization_id = $3
       ON CONFLICT DO NOTHING`,
      [incidentId, draft.alertIds, draft.organizationId],
    );
    await tx.query(
      "UPDATE alerts SET incident_id = $1, status = CASE WHEN status IN ('new', 'triaged') THEN 'promoted' ELSE status END WHERE id = ANY($2::uuid[]) AND incident_id IS DISTINCT FROM $1",
      [incidentId, draft.alertIds],
    );
    const counted = await tx.query<Row>("UPDATE incidents SET alert_count = (SELECT count(*) FROM incident_alerts WHERE incident_id = $1) WHERE id = $1 RETURNING *", [incidentId]);
    incident = counted.rows[0]!;

    // Security Graph: incident node + involves edges.
    const indicators = draft.indicatorKeys
      .map((k) => {
        const idx = k.indexOf(":");
        return idx > 0 ? { type: k.slice(0, idx) as IndicatorType, value: k.slice(idx + 1) } : null;
      })
      .filter((x): x is { type: IndicatorType; value: string } => x !== null);
    try {
      await tx.query("SAVEPOINT link_incident");
      await graphFor(tx, tenantId).linkIncident({
        incidentId,
        organizationId: draft.organizationId,
        title: String(incident.title),
        severity: incident.severity as Severity,
        status: String(incident.status),
        detectedAt: String(incident.detected_at),
        entities: entities.filter((e, i, all) => all.findIndex((x) => x.kind === e.kind && x.key === e.key) === i),
        techniques: draft.attack,
        indicators,
        malware: [...new Set(draftMatches.flatMap((m) => (m.indicators ?? []).map((h) => h.malware).filter((x): x is string => !!x)))],
        threatActors: [...new Set(draftMatches.flatMap((m) => (m.indicators ?? []).map((h) => h.threatActor).filter((x): x is string => !!x)))],
      });
      await tx.query("RELEASE SAVEPOINT link_incident");
    } catch (err) {
      await tx.query("ROLLBACK TO SAVEPOINT link_incident");
      this.deps.metrics.pipelineErrors.inc({ stage: "graph_link" });
      this.deps.log.warn({ tenantId, incidentId, err: err instanceof Error ? err.message : String(err) }, "linking incident into the graph failed");
    }

    const view = toIncident(incident);
    const at = new Date(this.now()).toISOString();
    if (created) {
      await writeAudit(tx, actor, {
        action: "incident.created",
        organizationId: view.organizationId,
        targetKind: "incident",
        targetId: incidentId,
        details: { number: view.number, severity: view.severity, riskScore: view.riskScore, reason: draft.promoteReason, alerts: view.alertCount },
      });
      notifications.push({ tenantId, organizationId: view.organizationId, event: "incident.created", occurredAt: at, severity: view.severity, subject: { kind: "incident", id: incidentId, label: view.title }, data: { number: view.number, riskScore: view.riskScore, summary: view.summary } });
    } else if (severityChanged) {
      await writeAudit(tx, actor, { action: "incident.severity_changed", organizationId: view.organizationId, targetKind: "incident", targetId: incidentId, details: { ...severityChanged, reasons: draft.escalationReasons } });
      notifications.push({ tenantId, organizationId: view.organizationId, event: "incident.severity_changed", occurredAt: at, severity: view.severity, subject: { kind: "incident", id: incidentId, label: view.title }, data: severityChanged });
    }

    let escalationId: string | null = null;
    if (SEVERITY_RANK[view.severity] >= SEVERITY_RANK.critical) {
      const reason = [draft.promoteReason, ...draft.escalationReasons].join(" ").slice(0, 2000);
      const { rows } = await tx.query<{ id: string }>(
        `INSERT INTO escalations (tenant_id, organization_id, incident_id, title, reason, severity, status, due_at, created_by)
         VALUES ($1, $2, $3, $4, $5, 'critical', 'open', now() + make_interval(mins => $6), 'system:pipeline')
         ON CONFLICT (tenant_id, incident_id) WHERE incident_id IS NOT NULL AND status <> 'resolved' DO NOTHING
         RETURNING id`,
        [tenantId, view.organizationId, incidentId, `Critical incident #${view.number}: ${view.title}`.slice(0, 300), reason, CRITICAL_ESCALATION_MINUTES],
      );
      if (rows[0]) {
        escalationId = rows[0].id;
        await writeAudit(tx, actor, { action: "escalation.created", organizationId: view.organizationId, targetKind: "escalation", targetId: escalationId, details: { incidentId, dueInMinutes: CRITICAL_ESCALATION_MINUTES } });
        notifications.push({ tenantId, organizationId: view.organizationId, event: "escalation.created", occurredAt: at, severity: "critical", subject: { kind: "escalation", id: escalationId, label: view.title }, data: { incidentId, number: view.number } });
      }
    }
    return { id: incidentId, created, escalationId };
  }
}
