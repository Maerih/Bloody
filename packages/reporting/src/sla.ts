import type { Severity } from "@bloody/contracts";
import type { EscalationFact, IncidentFact } from "./datasource.js";

/** Per-severity SLA objectives in minutes. */
export interface SlaTargets {
  acknowledgeMinutes: Record<Severity, number>;
  resolveMinutes: Record<Severity, number>;
}

/** Industry-typical MDR objectives; tenants override per organization (contract SLAs). */
export const DEFAULT_SLA_TARGETS: SlaTargets = {
  acknowledgeMinutes: { critical: 15, high: 60, medium: 240, low: 1440, info: 2880 },
  resolveMinutes: { critical: 240, high: 1440, medium: 4320, low: 10080, info: 20160 },
};

export function mergeSlaTargets(base: SlaTargets, override: Partial<SlaTargets> | null | undefined): SlaTargets {
  if (!override) return base;
  return {
    acknowledgeMinutes: { ...base.acknowledgeMinutes, ...override.acknowledgeMinutes },
    resolveMinutes: { ...base.resolveMinutes, ...override.resolveMinutes },
  };
}

export type SlaOutcome = "met" | "breached" | "pending";

export interface IncidentSlaResult {
  incident: IncidentFact;
  acknowledge: { outcome: SlaOutcome; minutes: number | null; targetMinutes: number };
  resolve: { outcome: SlaOutcome; minutes: number | null; targetMinutes: number };
  /** Human-readable reasons for breaches (explainability). */
  reasons: string[];
}

export interface SlaBucket {
  met: number;
  breached: number;
  pending: number;
  /** met / (met + breached) × 100, null when nothing was due. */
  attainmentPct: number | null;
}

export interface SlaSummary {
  incidents: IncidentSlaResult[];
  acknowledge: SlaBucket;
  resolve: SlaBucket;
  overall: SlaBucket;
  bySeverity: Record<Severity, { acknowledge: SlaBucket; resolve: SlaBucket }>;
}

const RESOLVED: ReadonlySet<string> = new Set(["closed", "false_positive", "remediated"]);

function bucket(met: number, breached: number, pending: number): SlaBucket {
  const due = met + breached;
  return { met, breached, pending, attainmentPct: due === 0 ? null : (met / due) * 100 };
}

function minutesBetween(a: string, b: string | Date): number {
  return ((b instanceof Date ? b.getTime() : Date.parse(b)) - Date.parse(a)) / 60_000;
}

function fmtMinutes(m: number): string {
  if (m < 60) return `${Math.round(m)}m`;
  if (m < 1440) return `${Math.floor(m / 60)}h ${Math.round(m % 60)}m`;
  return `${Math.floor(m / 1440)}d ${Math.round((m % 1440) / 60)}h`;
}

/**
 * Evaluate acknowledge/resolve SLAs for incidents DETECTED in the period, as of `asOf`.
 * Unacknowledged / unresolved incidents count as breached once their target elapsed, and as
 * pending (not yet due) before that — they never inflate attainment.
 */
export function evaluateIncidentSla(incidents: readonly IncidentFact[], targetsFor: (organizationId: string) => SlaTargets, asOf: Date): SlaSummary {
  const results: IncidentSlaResult[] = [];
  const sev: Record<Severity, { a: number[]; r: number[] }> = { critical: { a: [0, 0, 0], r: [0, 0, 0] }, high: { a: [0, 0, 0], r: [0, 0, 0] }, medium: { a: [0, 0, 0], r: [0, 0, 0] }, low: { a: [0, 0, 0], r: [0, 0, 0] }, info: { a: [0, 0, 0], r: [0, 0, 0] } };
  const idx: Record<SlaOutcome, number> = { met: 0, breached: 1, pending: 2 };
  for (const inc of incidents) {
    const t = targetsFor(inc.organizationId);
    const ackTarget = t.acknowledgeMinutes[inc.severity];
    const resTarget = t.resolveMinutes[inc.severity];
    const reasons: string[] = [];
    const ackAt = inc.acknowledgedAt ?? inc.containedAt ?? inc.closedAt;
    let ack: IncidentSlaResult["acknowledge"];
    if (ackAt) {
      const m = Math.max(0, minutesBetween(inc.detectedAt, ackAt));
      ack = { outcome: m <= ackTarget ? "met" : "breached", minutes: m, targetMinutes: ackTarget };
      if (ack.outcome === "breached") reasons.push(`acknowledged after ${fmtMinutes(m)} (target ${fmtMinutes(ackTarget)})`);
    } else {
      const elapsed = minutesBetween(inc.detectedAt, asOf);
      ack = { outcome: elapsed > ackTarget ? "breached" : "pending", minutes: null, targetMinutes: ackTarget };
      if (ack.outcome === "breached") reasons.push(`not acknowledged after ${fmtMinutes(elapsed)} (target ${fmtMinutes(ackTarget)})`);
    }
    let res: IncidentSlaResult["resolve"];
    if (inc.closedAt && RESOLVED.has(inc.status)) {
      const m = Math.max(0, minutesBetween(inc.detectedAt, inc.closedAt));
      res = { outcome: m <= resTarget ? "met" : "breached", minutes: m, targetMinutes: resTarget };
      if (res.outcome === "breached") reasons.push(`resolved after ${fmtMinutes(m)} (target ${fmtMinutes(resTarget)})`);
    } else {
      const elapsed = minutesBetween(inc.detectedAt, asOf);
      res = { outcome: elapsed > resTarget ? "breached" : "pending", minutes: null, targetMinutes: resTarget };
      if (res.outcome === "breached") reasons.push(`still open after ${fmtMinutes(elapsed)} (target ${fmtMinutes(resTarget)})`);
    }
    sev[inc.severity].a[idx[ack.outcome]]! += 1;
    sev[inc.severity].r[idx[res.outcome]]! += 1;
    results.push({ incident: inc, acknowledge: ack, resolve: res, reasons });
  }
  const sum = (k: "a" | "r", i: number): number => Object.values(sev).reduce((n, s) => n + s[k][i]!, 0);
  const acknowledge = bucket(sum("a", 0), sum("a", 1), sum("a", 2));
  const resolve = bucket(sum("r", 0), sum("r", 1), sum("r", 2));
  const bySeverity = Object.fromEntries(
    (Object.keys(sev) as Severity[]).map((s) => [s, { acknowledge: bucket(sev[s].a[0]!, sev[s].a[1]!, sev[s].a[2]!), resolve: bucket(sev[s].r[0]!, sev[s].r[1]!, sev[s].r[2]!) }]),
  ) as SlaSummary["bySeverity"];
  return {
    incidents: results,
    acknowledge,
    resolve,
    overall: bucket(acknowledge.met + resolve.met, acknowledge.breached + resolve.breached, acknowledge.pending + resolve.pending),
    bySeverity,
  };
}

export interface EscalationSlaSummary {
  onTime: number;
  late: number;
  overdueOpen: number;
  openWithinDue: number;
  onTimePct: number | null;
  overdue: EscalationFact[];
}

/** Escalations: resolved by their due date (on time), resolved after it (late), or still open past it (overdue). */
export function evaluateEscalations(escalations: readonly EscalationFact[], asOf: Date): EscalationSlaSummary {
  let onTime = 0;
  let late = 0;
  let overdueOpen = 0;
  let openWithinDue = 0;
  const overdue: EscalationFact[] = [];
  for (const e of escalations) {
    const due = Date.parse(e.dueAt);
    if (e.resolvedAt) {
      if (Date.parse(e.resolvedAt) <= due) onTime += 1;
      else late += 1;
    } else if (asOf.getTime() > due) {
      overdueOpen += 1;
      overdue.push(e);
    } else {
      openWithinDue += 1;
    }
  }
  const decided = onTime + late + overdueOpen;
  return { onTime, late, overdueOpen, openWithinDue, onTimePct: decided === 0 ? null : (onTime / decided) * 100, overdue: overdue.sort((a, b) => a.dueAt.localeCompare(b.dueAt)) };
}
