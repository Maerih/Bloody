import type { NodeKind } from "@bloody/contracts";
import { systemClock, toIso, type Clock } from "../util/clock.js";
import { round } from "../util/math.js";
import { stableId } from "../util/uuid.js";
import type { DetectionMatch } from "./types.js";

/**
 * False-positive handling: suppressions (tuning) and analyst feedback (precision tracking).
 *
 * A suppression silences matches of one rule (or every rule: "*") in a tenant, optionally only
 * for one organization and/or one entity (kind + key), optionally until it expires. Suppressed
 * matches are still counted in metrics and reported through the sink, so tuning stays
 * auditable and reversible.
 */
export interface Suppression {
  id: string;
  tenantId: string;
  organizationId: string | null;
  ruleId: string | "*";
  entity?: { kind: NodeKind; key: string };
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
}

export interface SuppressionStore {
  /** The first active suppression covering this match, or null. Synchronous (hot path). */
  find(match: DetectionMatch, atMs: number): Suppression | null;
}

export class InMemorySuppressionList implements SuppressionStore {
  private readonly items = new Map<string, Suppression>();

  add(s: Omit<Suppression, "id"> & { id?: string }): Suppression {
    const id = s.id ?? stableId("suppression", s.tenantId, s.organizationId, s.ruleId, s.entity?.kind, s.entity?.key, s.createdAt);
    const full: Suppression = { ...s, id };
    this.items.set(id, full);
    return full;
  }

  remove(id: string): boolean {
    return this.items.delete(id);
  }

  list(tenantId: string): Suppression[] {
    return [...this.items.values()].filter((s) => s.tenantId === tenantId).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  find(match: DetectionMatch, atMs: number): Suppression | null {
    for (const s of this.items.values()) {
      if (s.tenantId !== match.tenantId) continue;
      if (s.organizationId !== null && s.organizationId !== match.organizationId) continue;
      if (s.ruleId !== "*" && s.ruleId !== match.rule.id) continue;
      if (s.expiresAt && Date.parse(s.expiresAt) <= atMs) continue;
      if (s.entity && !match.entities.some((e) => e.kind === s.entity!.kind && e.key === s.entity!.key)) continue;
      return s;
    }
    return null;
  }
}

export type FeedbackVerdict = "true_positive" | "false_positive" | "benign_positive";

export interface FeedbackInput {
  tenantId: string;
  organizationId: string;
  ruleId: string;
  verdict: FeedbackVerdict;
  analyst: string;
  matchId?: string;
  /** Entity the verdict is about (e.g. the host running a legitimate admin tool). */
  entity?: { kind: NodeKind; key: string };
  comment?: string;
}

export interface RuleFeedbackStats {
  tenantId: string;
  ruleId: string;
  truePositives: number;
  falsePositives: number;
  benignPositives: number;
  /** TP / (TP + FP), null without verdicts. */
  precision: number | null;
}

/**
 * Records analyst verdicts per rule; after `autoSuppressAfter` false positives for the same
 * (tenant, organization, rule, entity) it creates an expiring entity-scoped suppression.
 */
export class FeedbackTracker {
  private readonly verdicts = new Map<string, { tp: number; fp: number; bp: number }>();
  private readonly fpByEntity = new Map<string, number>();
  private readonly clock: Clock;
  private readonly suppressions: InMemorySuppressionList | undefined;
  private readonly autoSuppressAfter: number;
  private readonly autoSuppressDays: number;

  constructor(options: { suppressions?: InMemorySuppressionList; autoSuppressAfter?: number; autoSuppressDays?: number; clock?: Clock } = {}) {
    this.clock = options.clock ?? systemClock;
    this.suppressions = options.suppressions;
    this.autoSuppressAfter = options.autoSuppressAfter ?? 3;
    this.autoSuppressDays = options.autoSuppressDays ?? 30;
  }

  record(input: FeedbackInput): { stats: RuleFeedbackStats; autoSuppression: Suppression | null } {
    const key = `${input.tenantId}|${input.ruleId}`;
    const v = this.verdicts.get(key) ?? { tp: 0, fp: 0, bp: 0 };
    if (input.verdict === "true_positive") v.tp++;
    else if (input.verdict === "false_positive") v.fp++;
    else v.bp++;
    this.verdicts.set(key, v);

    let autoSuppression: Suppression | null = null;
    if (input.verdict !== "true_positive" && input.entity && this.suppressions && this.autoSuppressAfter > 0) {
      const ek = `${input.tenantId}|${input.organizationId}|${input.ruleId}|${input.entity.kind}|${input.entity.key}`;
      const n = (this.fpByEntity.get(ek) ?? 0) + 1;
      this.fpByEntity.set(ek, n);
      if (n === this.autoSuppressAfter) {
        const now = this.clock.now();
        autoSuppression = this.suppressions.add({
          tenantId: input.tenantId,
          organizationId: input.organizationId,
          ruleId: input.ruleId,
          entity: input.entity,
          reason: `Auto-suppressed after ${n} non-malicious verdicts (last by ${input.analyst})`,
          createdBy: "feedback-tracker",
          createdAt: toIso(now),
          expiresAt: toIso(now + this.autoSuppressDays * 86_400_000),
        });
      }
    }
    return { stats: this.toStats(input.tenantId, input.ruleId, v), autoSuppression };
  }

  stats(tenantId: string): RuleFeedbackStats[] {
    const out: RuleFeedbackStats[] = [];
    for (const [k, v] of this.verdicts) {
      const [t, ruleId] = k.split("|");
      if (t === tenantId && ruleId) out.push(this.toStats(tenantId, ruleId, v));
    }
    return out.sort((a, b) => (a.precision ?? 1) - (b.precision ?? 1) || a.ruleId.localeCompare(b.ruleId));
  }

  private toStats(tenantId: string, ruleId: string, v: { tp: number; fp: number; bp: number }): RuleFeedbackStats {
    return { tenantId, ruleId, truePositives: v.tp, falsePositives: v.fp, benignPositives: v.bp, precision: v.tp + v.fp > 0 ? round(v.tp / (v.tp + v.fp), 4) : null };
  }
}
