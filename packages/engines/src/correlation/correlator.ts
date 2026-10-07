import { maxSeverity, SEVERITY_RANK, severityFromScore, type AttackTechnique, type Criticality, type NodeKind, type Severity } from "@bloody/contracts";
import type { DetectionMatch } from "../detection/types.js";
import { ASSET_NODE_KINDS, isCorrelatableEntity, type EntityRef } from "../entities/keys.js";
import { nullSink, safeSink, type EngineEventSink } from "../notifications.js";
import type { ExplainedRiskAssessment } from "../risk/model.js";
import { RiskEngine } from "../risk/risk-engine.js";
import { killChainOrder, tacticOf, tacticsOf } from "../risk/tactics.js";
import { systemClock, toEpochMs, toIso, type Clock } from "../util/clock.js";
import { stableId } from "../util/uuid.js";

/** Incident proposal produced by correlation; the control plane persists it as an Incident. */
export interface IncidentDraft {
  id: string;
  tenantId: string;
  organizationId: string;
  title: string;
  severity: Severity;
  /** Alert ids (= detection match ids unless the caller supplied its own alert ids). */
  alertIds: string[];
  matchIds: string[];
  ruleIds: string[];
  assetKeys: string[];
  identityKeys: string[];
  indicatorKeys: string[];
  attack: AttackTechnique[];
  summary: string;
  riskScore: number;
  risk: ExplainedRiskAssessment;
  /** Why severity is above the strongest single detection, if it is. */
  escalationReasons: string[];
  /** Entity keys ("kind:key") that joined the detections together. */
  correlationKeys: string[];
  firstSeenAt: string;
  lastSeenAt: string;
  /** Increments on every update — lets the control plane apply updates idempotently. */
  revision: number;
  /** Whether the cluster warrants an incident (vs. remaining stand-alone alerts). */
  promote: boolean;
  promoteReason: string;
}

export interface CorrelationContext {
  assetCriticality?(organizationId: string, assetKey: string): Criticality | undefined;
  assetHasEdr?(organizationId: string, assetKey: string): boolean | undefined;
  identityPrivileged?(organizationId: string, key: string): boolean | undefined;
}

export interface CorrelatorOptions {
  /** Max gap between a detection and a cluster's last activity to join it (default 6 h). */
  windowSeconds?: number;
  /** Entity kinds used to join detections (default assets, identities, indicators, public observables). */
  joinKinds?: readonly NodeKind[];
  /** Ignore these entity ids ("kind:key") for joining (e.g. a shared jump host). */
  ignoreEntities?: readonly string[];
  /** An entity seen in more than this many open clusters stops joining (super-node guard). */
  maxEntityFanout?: number;
  /** Minimum severity for a single detection to be promoted on its own (default "high"). */
  promoteSeverity?: Severity;
  /** Minimum risk score for promotion of a multi-detection cluster (default 40). */
  promoteRiskScore?: number;
  maxMatchesPerIncident?: number;
  riskEngine?: RiskEngine;
  context?: CorrelationContext;
  clock?: Clock;
  sink?: EngineEventSink;
}

export interface CorrelationResult {
  incident: IncidentDraft;
  created: boolean;
  /** Draft ids absorbed into `incident` because this detection bridged them. */
  mergedIncidentIds: string[];
}

interface Cluster {
  id: string;
  tenantId: string;
  organizationId: string;
  matches: DetectionMatch[];
  alertIds: string[];
  entities: Map<string, EntityRef>;
  joinKeys: Set<string>;
  firstSeen: number;
  lastSeen: number;
  revision: number;
  draft: IncidentDraft | null;
  announced: boolean;
}

const DEFAULT_JOIN_KINDS: readonly NodeKind[] = [...ASSET_NODE_KINDS, "user", "identity", "service_account", "indicator", "hash", "domain", "url", "ip"];
const IDENTITY_KINDS = new Set<NodeKind>(["user", "identity", "service_account"]);

/**
 * Groups detection matches into incident drafts. Two detections land in the same incident when
 * they share a correlatable entity (asset, identity, indicator, public IP / domain / URL /
 * hash) and occur within `windowSeconds` of the cluster's activity — transitively (a detection
 * that bridges two clusters merges them). Clusters never cross tenant or organization.
 *
 * Severity = max(strongest detection, Risk-Engine severity of the cluster) — escalation is
 * explainable (`escalationReasons`) and never de-escalates below the strongest detection.
 */
export class Correlator {
  private readonly clusters = new Map<string, Cluster>();
  private readonly index = new Map<string, Set<string>>();
  private readonly windowMs: number;
  private readonly joinKinds: Set<NodeKind>;
  private readonly ignore: Set<string>;
  private readonly maxFanout: number;
  private readonly promoteSeverity: Severity;
  private readonly promoteRiskScore: number;
  private readonly maxMatches: number;
  private readonly risk: RiskEngine;
  private readonly context: CorrelationContext;
  private readonly clock: Clock;
  private readonly sink: EngineEventSink;

  constructor(options: CorrelatorOptions = {}) {
    this.windowMs = (options.windowSeconds ?? 6 * 3600) * 1000;
    this.joinKinds = new Set(options.joinKinds ?? DEFAULT_JOIN_KINDS);
    this.ignore = new Set(options.ignoreEntities ?? []);
    this.maxFanout = options.maxEntityFanout ?? 20;
    this.promoteSeverity = options.promoteSeverity ?? "high";
    this.promoteRiskScore = options.promoteRiskScore ?? 40;
    this.maxMatches = options.maxMatchesPerIncident ?? 500;
    this.risk = options.riskEngine ?? new RiskEngine();
    this.context = options.context ?? {};
    this.clock = options.clock ?? systemClock;
    this.sink = safeSink(options.sink ?? nullSink);
  }

  add(match: DetectionMatch, options: { alertId?: string } = {}): CorrelationResult {
    const scope = `${match.tenantId}|${match.organizationId}`;
    const t0 = toEpochMs(match.firstSeenAt);
    const t1 = toEpochMs(match.lastSeenAt);
    const keys = this.joinKeysOf(match);

    // candidate clusters: same tenant+org, sharing a key, active within the window
    const candidates = new Set<string>();
    for (const k of keys) {
      const ids = this.index.get(`${scope}|${k}`);
      if (!ids) continue;
      const live = [...ids].filter((id) => {
        const c = this.clusters.get(id);
        return c !== undefined && t0 <= c.lastSeen + this.windowMs && t1 >= c.firstSeen - this.windowMs;
      });
      if (live.length > this.maxFanout) continue; // super-node: too common to mean anything
      live.forEach((id) => candidates.add(id));
    }
    const existing = [...candidates].map((id) => this.clusters.get(id)!).sort((a, b) => a.firstSeen - b.firstSeen || a.id.localeCompare(b.id));

    let cluster: Cluster;
    let created = false;
    const merged: string[] = [];
    if (existing.length === 0) {
      cluster = { id: stableId("incident-draft", match.tenantId, match.organizationId, match.id), tenantId: match.tenantId, organizationId: match.organizationId, matches: [], alertIds: [], entities: new Map(), joinKeys: new Set(), firstSeen: t0, lastSeen: t1, revision: 0, draft: null, announced: false };
      this.clusters.set(cluster.id, cluster);
      created = true;
    } else {
      cluster = existing[0]!;
      for (const other of existing.slice(1)) {
        this.absorb(cluster, other);
        merged.push(other.id);
      }
    }
    if (!cluster.matches.some((m) => m.id === match.id)) {
      cluster.matches.push(match);
      cluster.alertIds.push(options.alertId ?? match.id);
      if (cluster.matches.length > this.maxMatches) {
        cluster.matches.shift();
        cluster.alertIds.shift();
      }
    }
    for (const e of match.entities) cluster.entities.set(`${e.kind}:${e.key}`, e);
    for (const k of keys) {
      cluster.joinKeys.add(k);
      const ik = `${scope}|${k}`;
      (this.index.get(ik) ?? this.index.set(ik, new Set()).get(ik)!).add(cluster.id);
    }
    cluster.firstSeen = Math.min(cluster.firstSeen, t0);
    cluster.lastSeen = Math.max(cluster.lastSeen, t1);
    cluster.revision++;
    const previous = cluster.draft;
    const draft = this.buildDraft(cluster);
    cluster.draft = draft;
    this.announce(cluster, draft, previous);
    return { incident: draft, created, mergedIncidentIds: merged };
  }

  addMany(matches: readonly DetectionMatch[]): CorrelationResult[] {
    return [...matches].sort((a, b) => a.firstSeenAt.localeCompare(b.firstSeenAt) || a.id.localeCompare(b.id)).map((m) => this.add(m));
  }

  get(id: string): IncidentDraft | null {
    return this.clusters.get(id)?.draft ?? null;
  }

  list(filter: { tenantId?: string; organizationId?: string; promotedOnly?: boolean } = {}): IncidentDraft[] {
    return [...this.clusters.values()]
      .map((c) => c.draft!)
      .filter((d) => (!filter.tenantId || d.tenantId === filter.tenantId) && (!filter.organizationId || d.organizationId === filter.organizationId) && (!filter.promotedOnly || d.promote))
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.riskScore - a.riskScore || b.lastSeenAt.localeCompare(a.lastSeenAt));
  }

  /** Close clusters idle for longer than the window; returns their final drafts. */
  expire(): IncidentDraft[] {
    const now = this.clock.now();
    const out: IncidentDraft[] = [];
    for (const c of [...this.clusters.values()]) {
      if (c.lastSeen + this.windowMs < now) {
        out.push(c.draft!);
        this.drop(c);
      }
    }
    return out;
  }

  private joinKeysOf(match: DetectionMatch): string[] {
    const keys: string[] = [];
    for (const e of match.entities) {
      if (!this.joinKinds.has(e.kind)) continue;
      const id = `${e.kind}:${e.key}`;
      if (this.ignore.has(id) || !isCorrelatableEntity(e)) continue;
      keys.push(id);
    }
    return [...new Set(keys)];
  }

  private absorb(into: Cluster, other: Cluster): void {
    for (let i = 0; i < other.matches.length; i++) {
      const m = other.matches[i]!;
      if (into.matches.some((x) => x.id === m.id)) continue;
      into.matches.push(m);
      into.alertIds.push(other.alertIds[i] ?? m.id);
    }
    for (const [k, e] of other.entities) into.entities.set(k, e);
    for (const k of other.joinKeys) into.joinKeys.add(k);
    into.firstSeen = Math.min(into.firstSeen, other.firstSeen);
    into.lastSeen = Math.max(into.lastSeen, other.lastSeen);
    into.announced = into.announced || other.announced;
    this.drop(other);
    const scope = `${into.tenantId}|${into.organizationId}`;
    for (const k of into.joinKeys) (this.index.get(`${scope}|${k}`) ?? this.index.set(`${scope}|${k}`, new Set()).get(`${scope}|${k}`)!).add(into.id);
  }

  private drop(c: Cluster): void {
    this.clusters.delete(c.id);
    const scope = `${c.tenantId}|${c.organizationId}`;
    for (const k of c.joinKeys) {
      const s = this.index.get(`${scope}|${k}`);
      s?.delete(c.id);
      if (s && s.size === 0) this.index.delete(`${scope}|${k}`);
    }
  }

  private buildDraft(c: Cluster): IncidentDraft {
    const org = c.organizationId;
    const entities = [...c.entities.values()];
    const assets = entities.filter((e) => ASSET_NODE_KINDS.includes(e.kind));
    const identities = entities.filter((e) => IDENTITY_KINDS.has(e.kind) && isCorrelatableEntity(e));
    const indicators = entities.filter((e) => e.kind === "indicator");
    const attack = dedupeAttack(c.matches.flatMap((m) => m.attack));
    const maxMatch = c.matches.reduce<Severity>((s, m) => maxSeverity(s, m.severity), "info");

    const assetCtx = assets.map((a) => ({ name: a.label, criticality: this.context.assetCriticality?.(org, a.key) ?? ("medium" as Criticality), edr: this.context.assetHasEdr?.(org, a.key) ?? false }));
    const identityCtx = identities.map((i) => ({ principal: i.label, privileged: this.context.identityPrivileged?.(org, i.key) ?? false }));
    const intel = c.matches.flatMap((m) => m.indicators ?? []).map((h) => ({ value: h.value, confidence: h.confidence, severity: h.severity, threatActor: h.threatActor ?? null, campaign: h.campaign ?? null }));
    const title = this.title(c, assets, identities, attack);
    const risk = this.risk.scoreIncident({
      title,
      attack,
      alerts: c.matches.map((m) => ({ ruleId: m.rule.id, title: m.rule.name, severity: m.severity, confidence: m.confidence, source: m.events[0]?.source.product ?? m.rule.kind, attack: m.attack })),
      assets: assetCtx,
      identities: identityCtx,
      intelMatches: intel,
    });
    const riskSeverity = severityFromScore(risk.score);
    const severity = maxSeverity(maxMatch, riskSeverity);
    const escalationReasons: string[] = [];
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[maxMatch]) {
      escalationReasons.push(`Escalated from ${maxMatch} to ${severity}: correlated risk score ${risk.score}/100.`);
      for (const f of risk.factors.filter((x) => x.contribution > 0).slice(0, 3)) escalationReasons.push(`${f.label}: ${f.explanation}`);
    }
    const ruleIds = [...new Set(c.matches.map((m) => m.rule.id))];
    let promote = false;
    let promoteReason = "Single low-severity detection — kept as an alert.";
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK[this.promoteSeverity]) {
      promote = true;
      promoteReason = `Severity ${severity} ≥ ${this.promoteSeverity}.`;
    } else if (ruleIds.length >= 2 && risk.score >= this.promoteRiskScore) {
      promote = true;
      promoteReason = `${ruleIds.length} distinct detections correlated with risk ${risk.score} ≥ ${this.promoteRiskScore}.`;
    } else if (indicators.length > 0 && SEVERITY_RANK[severity] >= SEVERITY_RANK.medium) {
      promote = true;
      promoteReason = "Threat-intelligence match with medium or higher severity.";
    }
    return {
      id: c.id,
      tenantId: c.tenantId,
      organizationId: org,
      title,
      severity,
      alertIds: [...c.alertIds],
      matchIds: c.matches.map((m) => m.id),
      ruleIds,
      assetKeys: assets.map((a) => a.key),
      identityKeys: identities.map((i) => i.key),
      indicatorKeys: indicators.map((i) => i.key),
      attack,
      summary: this.summary(c, assets, identities, indicators, attack, severity, risk),
      riskScore: risk.score,
      risk,
      escalationReasons,
      correlationKeys: [...c.joinKeys].sort(),
      firstSeenAt: toIso(c.firstSeen),
      lastSeenAt: toIso(c.lastSeen),
      revision: c.revision,
      promote,
      promoteReason,
    };
  }

  private title(c: Cluster, assets: EntityRef[], identities: EntityRef[], attack: AttackTechnique[]): string {
    const strongest = [...c.matches].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.confidence - a.confidence)[0]!;
    const tactics = killChainOrder(tacticsOf(attack));
    const lead = tactics.length >= 2 ? tactics.slice(-2).map(humanTactic).join(" and ") : strongest.rule.name;
    const subject = assets[0]?.label ?? identities[0]?.label;
    const extra = assets.length > 1 ? ` (+${assets.length - 1} asset${assets.length > 2 ? "s" : ""})` : "";
    const related = c.matches.length > 1 && tactics.length < 2 ? ` and ${c.matches.length - 1} related detection${c.matches.length > 2 ? "s" : ""}` : "";
    return `${lead}${related}${subject ? ` on ${subject}${extra}` : ""}`.slice(0, 300);
  }

  private summary(c: Cluster, assets: EntityRef[], identities: EntityRef[], indicators: EntityRef[], attack: AttackTechnique[], severity: Severity, risk: ExplainedRiskAssessment): string {
    const span = Math.round((c.lastSeen - c.firstSeen) / 60000);
    const rules = new Map<string, { name: string; severity: Severity; n: number }>();
    for (const m of c.matches) {
      const r = rules.get(m.rule.id) ?? { name: m.rule.name, severity: m.severity, n: 0 };
      r.n++;
      r.severity = maxSeverity(r.severity, m.severity);
      rules.set(m.rule.id, r);
    }
    const lines = [
      `${c.matches.length} detection(s) from ${rules.size} rule(s) between ${toIso(c.firstSeen)} and ${toIso(c.lastSeen)} (${span} min) affecting ${assets.length} asset(s) and ${identities.length} identit${identities.length === 1 ? "y" : "ies"}.`,
      `Detections: ${[...rules.values()].map((r) => `${r.name} (${r.severity}${r.n > 1 ? ` ×${r.n}` : ""})`).join("; ")}.`,
    ];
    if (assets.length) lines.push(`Assets: ${assets.slice(0, 10).map((a) => a.label).join(", ")}.`);
    if (identities.length) lines.push(`Identities: ${identities.slice(0, 10).map((i) => i.label).join(", ")}.`);
    if (indicators.length) lines.push(`Indicators: ${indicators.slice(0, 10).map((i) => i.label).join(", ")}.`);
    if (attack.length) lines.push(`ATT&CK: ${attack.map((t) => `${t.id}${tacticOf(t) ? ` (${tacticOf(t)})` : ""}`).join(", ")}.`);
    lines.push(`Severity ${severity}; ${risk.summary}`);
    return lines.join("\n");
  }

  private announce(c: Cluster, draft: IncidentDraft, previous: IncidentDraft | null): void {
    const at = toIso(this.clock.now());
    if (draft.promote && !c.announced) {
      c.announced = true;
      this.sink.emit({ type: "incident.created", tenantId: draft.tenantId, organizationId: draft.organizationId, at, incidentDraftId: draft.id, title: draft.title, severity: draft.severity, riskScore: draft.riskScore });
      return;
    }
    if (!c.announced || !previous) return;
    if (SEVERITY_RANK[draft.severity] > SEVERITY_RANK[previous.severity]) {
      this.sink.emit({ type: "incident.severity_changed", tenantId: draft.tenantId, organizationId: draft.organizationId, at, incidentDraftId: draft.id, title: draft.title, severity: draft.severity, previousSeverity: previous.severity, riskScore: draft.riskScore, reasons: draft.escalationReasons });
    } else {
      this.sink.emit({ type: "incident.updated", tenantId: draft.tenantId, organizationId: draft.organizationId, at, incidentDraftId: draft.id, title: draft.title, severity: draft.severity, previousSeverity: previous.severity, riskScore: draft.riskScore, reasons: [`${draft.alertIds.length} alert(s) now correlated`] });
    }
  }
}

function dedupeAttack(ts: AttackTechnique[]): AttackTechnique[] {
  const m = new Map<string, AttackTechnique>();
  for (const t of ts) {
    const cur = m.get(t.id);
    if (!cur || (!cur.tactic && t.tactic)) m.set(t.id, t);
  }
  return [...m.values()].sort((a, b) => a.id.localeCompare(b.id));
}

function humanTactic(t: string): string {
  return t
    .split("-")
    .map((w) => (w === "and" ? w : w[0]!.toUpperCase() + w.slice(1)))
    .join(" ");
}
