import { systemClock, toIso, type Clock } from "../util/clock.js";
import { contentHash } from "../util/uuid.js";
import { runRuleTests, type RuleTestReport } from "./test-runner.js";
import type { DetectionRule } from "./types.js";
import { validateRule } from "./validate.js";

export interface RuleRevision {
  rule: DetectionRule;
  /** SHA-256 of the canonical rule JSON (integrity / change detection). */
  contentHash: string;
  deployedAt: string;
  deployedBy: string;
  comment?: string;
}

export interface RuleHistoryEntry {
  action: "deploy" | "rollback" | "enable" | "disable";
  version: number;
  at: string;
  by: string;
  comment?: string;
}

export type DeployResult =
  | { ok: true; revision: RuleRevision; unchanged: boolean; testReport: RuleTestReport; warnings: string[] }
  | { ok: false; errors: string[]; warnings: string[]; testReport?: RuleTestReport };

export interface RegistrySnapshot {
  rules: Array<{ ruleId: string; activeVersion: number; enabled: boolean; revisions: RuleRevision[]; history: RuleHistoryEntry[] }>;
}

interface Entry {
  revisions: Map<number, RuleRevision>;
  activeVersion: number;
  enabled: boolean;
  history: RuleHistoryEntry[];
}

/**
 * Versioned rule registry implementing the detection-as-code lifecycle:
 * validate → test → deploy (monotonic versions, idempotent re-deploy of identical content)
 * → enable/disable → rollback to any earlier revision, with a full change history.
 * The registry is serializable (`snapshot` / `restore`) so the control plane persists it.
 */
export class RuleRegistry {
  private readonly entries = new Map<string, Entry>();
  private readonly clock: Clock;
  private readonly requireTests: boolean;

  constructor(options: { clock?: Clock; requireTests?: boolean } = {}) {
    this.clock = options.clock ?? systemClock;
    this.requireTests = options.requireTests ?? false;
  }

  deploy(input: unknown, meta: { by: string; comment?: string }): DeployResult {
    const v = validateRule(input);
    if (!v.valid || !v.rule) return { ok: false, errors: v.errors, warnings: v.warnings };
    const rule = v.rule;
    const report = runRuleTests(rule);
    if (!report.passed) {
      const failed = report.results.filter((r) => !r.passed).map((r) => `test "${r.name}" failed (expected ${r.expect}${r.expectedMatches !== undefined ? ` ×${r.expectedMatches}` : ""}, got ${r.matches} match(es))${r.error ? `: ${r.error}` : ""}`);
      return { ok: false, errors: failed, warnings: v.warnings, testReport: report };
    }
    if (this.requireTests && rule.tests.length === 0) return { ok: false, errors: ["tests: this registry requires every rule to ship tests"], warnings: v.warnings, testReport: report };

    const hash = contentHash(rule);
    const entry = this.entries.get(rule.id);
    if (entry) {
      const existing = entry.revisions.get(rule.version);
      if (existing) {
        if (existing.contentHash === hash) return { ok: true, revision: existing, unchanged: true, testReport: report, warnings: v.warnings };
        return { ok: false, errors: [`version: ${rule.id} v${rule.version} already exists with different content — bump the version`], warnings: v.warnings, testReport: report };
      }
      const latest = Math.max(...entry.revisions.keys());
      if (rule.version < latest) return { ok: false, errors: [`version: ${rule.version} is lower than the latest deployed version ${latest}; use rollback to reactivate an old version`], warnings: v.warnings, testReport: report };
    }
    const revision: RuleRevision = { rule, contentHash: hash, deployedAt: toIso(this.clock.now()), deployedBy: meta.by, ...(meta.comment ? { comment: meta.comment } : {}) };
    const e = entry ?? { revisions: new Map<number, RuleRevision>(), activeVersion: rule.version, enabled: rule.enabled, history: [] };
    e.revisions.set(rule.version, revision);
    e.activeVersion = rule.version;
    e.enabled = rule.enabled;
    e.history.push({ action: "deploy", version: rule.version, at: revision.deployedAt, by: meta.by, ...(meta.comment ? { comment: meta.comment } : {}) });
    this.entries.set(rule.id, e);
    return { ok: true, revision, unchanged: false, testReport: report, warnings: v.warnings };
  }

  /** Reactivate an earlier revision (default: the one before the active version). */
  rollback(ruleId: string, meta: { by: string; toVersion?: number; comment?: string }): { ok: true; revision: RuleRevision } | { ok: false; error: string } {
    const e = this.entries.get(ruleId);
    if (!e) return { ok: false, error: `unknown rule ${ruleId}` };
    const versions = [...e.revisions.keys()].sort((a, b) => a - b);
    const target = meta.toVersion ?? versions.filter((x) => x < e.activeVersion).at(-1);
    if (target === undefined) return { ok: false, error: `${ruleId} has no earlier version to roll back to` };
    const revision = e.revisions.get(target);
    if (!revision) return { ok: false, error: `${ruleId} has no version ${target}` };
    e.activeVersion = target;
    e.history.push({ action: "rollback", version: target, at: toIso(this.clock.now()), by: meta.by, ...(meta.comment ? { comment: meta.comment } : {}) });
    return { ok: true, revision };
  }

  setEnabled(ruleId: string, enabled: boolean, meta: { by: string; comment?: string }): boolean {
    const e = this.entries.get(ruleId);
    if (!e) return false;
    e.enabled = enabled;
    e.history.push({ action: enabled ? "enable" : "disable", version: e.activeVersion, at: toIso(this.clock.now()), by: meta.by, ...(meta.comment ? { comment: meta.comment } : {}) });
    return true;
  }

  get(ruleId: string): DetectionRule | null {
    const e = this.entries.get(ruleId);
    if (!e) return null;
    const r = e.revisions.get(e.activeVersion)!.rule;
    return { ...r, enabled: e.enabled };
  }

  /** Active revision of every rule (enabled flag applied) — feed to `DetectionEngine.loadRules`. */
  active(): DetectionRule[] {
    return [...this.entries.keys()].sort().map((id) => this.get(id)!);
  }

  revisions(ruleId: string): RuleRevision[] {
    const e = this.entries.get(ruleId);
    return e ? [...e.revisions.values()].sort((a, b) => a.rule.version - b.rule.version) : [];
  }

  history(ruleId: string): RuleHistoryEntry[] {
    return [...(this.entries.get(ruleId)?.history ?? [])];
  }

  snapshot(): RegistrySnapshot {
    return {
      rules: [...this.entries.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([ruleId, e]) => ({ ruleId, activeVersion: e.activeVersion, enabled: e.enabled, revisions: [...e.revisions.values()], history: [...e.history] })),
    };
  }

  static restore(snapshot: RegistrySnapshot, options: { clock?: Clock; requireTests?: boolean } = {}): RuleRegistry {
    const reg = new RuleRegistry(options);
    for (const r of snapshot.rules) {
      for (const rev of r.revisions) {
        if (contentHash(rev.rule) !== rev.contentHash) throw new Error(`Rule ${r.ruleId} v${rev.rule.version} failed integrity check`);
      }
      reg.entries.set(r.ruleId, { revisions: new Map(r.revisions.map((rev) => [rev.rule.version, rev])), activeVersion: r.activeVersion, enabled: r.enabled, history: [...r.history] });
    }
    return reg;
  }
}
