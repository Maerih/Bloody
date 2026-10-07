import { SEVERITY_RANK, maxSeverity, type Severity } from "@bloody/contracts";
import type { NormalizationResult } from "./adapter.js";
import { signal, type AdapterSignal } from "./signals.js";

/**
 * Ingest reporting — turns a normalization run into report-ready aggregates for:
 *  - SOC operations reports (events analysed, severity mix, ATT&CK coverage, top assets);
 *  - the integration / data-source health page and MSSP portfolio view (acceptance rate,
 *    rejection reasons, silent sources);
 *  - customer monthly reviews ("what we watched for you").
 * `@bloody/reporting` renders these; nothing here formats HTML/PDF.
 */

export type IngestHealth = "healthy" | "degraded" | "failing";

export interface IngestReport {
  adapter: string;
  adapterVersion: string;
  receivedAt: string;
  generatedAt: string;
  totals: { records: number; events: number; skipped: number; rejected: number; acceptanceRate: number; truncated: boolean };
  window: { from: string; to: string } | null;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  topEventTypes: Array<{ eventType: string; count: number }>;
  topAssets: Array<{ asset: string; events: number; maxSeverity: Severity }>;
  attack: Array<{ id: string; name?: string; tactic?: string; count: number }>;
  tactics: Array<{ tactic: string; count: number }>;
  indicators: { total: number; byType: Record<string, number> };
  rejections: Array<{ reason: string; count: number; sampleIndexes: number[] }>;
  skips: Array<{ reason: string; count: number }>;
  health: { status: IngestHealth; reasons: string[] };
  /** One-line narrative for dashboards, digests and notification emails. */
  headline: string;
}

function bump<K>(m: Map<K, number>, k: K, by = 1): void {
  m.set(k, (m.get(k) ?? 0) + by);
}

function top<K>(m: Map<K, number>, n: number): Array<[K, number]> {
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

/** Normalize volatile parts of rejection reasons (line numbers, values) so they group. */
function reasonKey(reason: string): string {
  return reason.replace(/^line \d+: /, "").replace(/\(.*\)$/, "").replace(/\d+/g, "#").trim().slice(0, 200);
}

export interface IngestReportOptions {
  now?: Date;
  top?: number;
  /** Rejection ratio above which the source is degraded (default 0.05). */
  degradedRejectRatio?: number;
  /** Rejection ratio above which the source is failing (default 0.5). */
  failingRejectRatio?: number;
}

export function buildIngestReport(result: NormalizationResult, opts: IngestReportOptions = {}): IngestReport {
  const n = opts.top ?? 10;
  const bySeverity: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const byCategory = new Map<string, number>();
  const byType = new Map<string, number>();
  const assets = new Map<string, { events: number; max: Severity }>();
  const attack = new Map<string, { name?: string; tactic?: string; count: number }>();
  const tactics = new Map<string, number>();
  const indicatorTypes = new Map<string, number>();
  let indicatorTotal = 0;
  let from: string | null = null;
  let to: string | null = null;

  for (const e of result.events) {
    bySeverity[e.severity]++;
    bump(byCategory, e.category);
    bump(byType, e.eventType);
    if (!from || e.timestamp < from) from = e.timestamp;
    if (!to || e.timestamp > to) to = e.timestamp;
    const asset = e.asset?.hostname ?? e.asset?.ip?.[0] ?? e.cloudResource?.resourceId;
    if (asset) {
      const a = assets.get(asset) ?? { events: 0, max: "info" as Severity };
      a.events++;
      a.max = maxSeverity(a.max, e.severity);
      assets.set(asset, a);
    }
    for (const t of e.attack) {
      const cur = attack.get(t.id) ?? { ...(t.name ? { name: t.name } : {}), ...(t.tactic ? { tactic: t.tactic } : {}), count: 0 };
      cur.count++;
      attack.set(t.id, cur);
      if (t.tactic) bump(tactics, t.tactic);
    }
    for (const i of e.indicators) {
      indicatorTotal++;
      bump(indicatorTypes, i.type);
    }
  }

  const rejections = new Map<string, { count: number; sampleIndexes: number[] }>();
  for (const r of result.rejected) {
    const k = reasonKey(r.reason);
    const cur = rejections.get(k) ?? { count: 0, sampleIndexes: [] };
    cur.count++;
    if (cur.sampleIndexes.length < 5) cur.sampleIndexes.push(r.index);
    rejections.set(k, cur);
  }
  const skips = new Map<string, number>();
  for (const s of result.skipped) bump(skips, reasonKey(s.reason));

  const considered = result.records - result.skipped.length;
  const rejectRatio = considered > 0 ? result.rejected.length / considered : 0;
  const acceptanceRate = considered > 0 ? Math.round((1 - rejectRatio) * 1000) / 1000 : 1;
  const reasons: string[] = [];
  let status: IngestHealth = "healthy";
  if (result.records > 0 && result.events.length === 0 && result.skipped.length < result.records) {
    status = "failing";
    reasons.push("no record could be normalized");
  } else if (rejectRatio > (opts.failingRejectRatio ?? 0.5)) {
    status = "failing";
    reasons.push(`${Math.round(rejectRatio * 100)}% of records rejected`);
  } else if (rejectRatio > (opts.degradedRejectRatio ?? 0.05)) {
    status = "degraded";
    reasons.push(`${Math.round(rejectRatio * 100)}% of records rejected`);
  }
  if (result.truncated) {
    if (status === "healthy") status = "degraded";
    reasons.push("payload truncated at the per-batch record limit");
  }

  const highPlus = bySeverity.high + bySeverity.critical;
  const headline =
    `${result.adapter}: ${result.events.length} event${result.events.length === 1 ? "" : "s"} from ${result.records} record${result.records === 1 ? "" : "s"}` +
    (highPlus > 0 ? `, ${highPlus} high/critical` : "") +
    (attack.size > 0 ? `, ${attack.size} ATT&CK technique${attack.size === 1 ? "" : "s"}` : "") +
    (result.rejected.length > 0 ? `, ${result.rejected.length} rejected` : "") +
    (status !== "healthy" ? ` — source ${status}` : "");

  return {
    adapter: result.adapter,
    adapterVersion: result.adapterVersion,
    receivedAt: result.receivedAt,
    generatedAt: (opts.now ?? new Date()).toISOString(),
    totals: { records: result.records, events: result.events.length, skipped: result.skipped.length, rejected: result.rejected.length, acceptanceRate, truncated: result.truncated },
    window: from && to ? { from, to } : null,
    bySeverity,
    byCategory: Object.fromEntries(byCategory),
    topEventTypes: top(byType, n).map(([eventType, count]) => ({ eventType, count })),
    topAssets: [...assets.entries()]
      .sort((a, b) => SEVERITY_RANK[b[1].max] - SEVERITY_RANK[a[1].max] || b[1].events - a[1].events)
      .slice(0, n)
      .map(([asset, v]) => ({ asset, events: v.events, maxSeverity: v.max })),
    attack: [...attack.entries()].sort((a, b) => b[1].count - a[1].count).map(([id, v]) => ({ id, ...v })),
    tactics: top(tactics, 20).map(([tactic, count]) => ({ tactic, count })),
    indicators: { total: indicatorTotal, byType: Object.fromEntries(indicatorTypes) },
    rejections: [...rejections.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, n).map(([reason, v]) => ({ reason, ...v })),
    skips: top(skips, n).map(([reason, count]) => ({ reason, count })),
    health: { status, reasons },
    headline,
  };
}

/** Combine several reports of the same adapter (e.g. a day of batches) into one. */
export function mergeIngestReports(reports: readonly IngestReport[], opts: { now?: Date; top?: number } = {}): IngestReport | null {
  const first = reports[0];
  if (!first) return null;
  const n = opts.top ?? 10;
  const sum = <K extends string>(get: (r: IngestReport) => Record<K, number>): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const r of reports) for (const [k, v] of Object.entries(get(r)) as Array<[string, number]>) out[k] = (out[k] ?? 0) + v;
    return out;
  };
  const records = reports.reduce((a, r) => a + r.totals.records, 0);
  const events = reports.reduce((a, r) => a + r.totals.events, 0);
  const skipped = reports.reduce((a, r) => a + r.totals.skipped, 0);
  const rejected = reports.reduce((a, r) => a + r.totals.rejected, 0);
  const considered = records - skipped;
  const worst = reports.some((r) => r.health.status === "failing") ? "failing" : reports.some((r) => r.health.status === "degraded") ? "degraded" : "healthy";
  const windows = reports.map((r) => r.window).filter((w): w is { from: string; to: string } => w !== null);
  const attack = new Map<string, { name?: string; tactic?: string; count: number }>();
  for (const r of reports) for (const t of r.attack) {
    const cur = attack.get(t.id) ?? { ...(t.name ? { name: t.name } : {}), ...(t.tactic ? { tactic: t.tactic } : {}), count: 0 };
    cur.count += t.count;
    attack.set(t.id, cur);
  }
  const assets = new Map<string, { events: number; max: Severity }>();
  for (const r of reports) for (const a of r.topAssets) {
    const cur = assets.get(a.asset) ?? { events: 0, max: "info" as Severity };
    cur.events += a.events;
    cur.max = maxSeverity(cur.max, a.maxSeverity);
    assets.set(a.asset, cur);
  }
  const bySeverity = sum((r) => r.bySeverity) as Record<Severity, number>;
  const highPlus = (bySeverity.high ?? 0) + (bySeverity.critical ?? 0);
  return {
    adapter: first.adapter,
    adapterVersion: first.adapterVersion,
    receivedAt: reports.map((r) => r.receivedAt).sort()[0] ?? first.receivedAt,
    generatedAt: (opts.now ?? new Date()).toISOString(),
    totals: {
      records,
      events,
      skipped,
      rejected,
      acceptanceRate: considered > 0 ? Math.round((1 - rejected / considered) * 1000) / 1000 : 1,
      truncated: reports.some((r) => r.totals.truncated),
    },
    window: windows.length ? { from: windows.map((w) => w.from).sort()[0]!, to: windows.map((w) => w.to).sort().at(-1)! } : null,
    bySeverity: { info: bySeverity.info ?? 0, low: bySeverity.low ?? 0, medium: bySeverity.medium ?? 0, high: bySeverity.high ?? 0, critical: bySeverity.critical ?? 0 },
    byCategory: sum((r) => r.byCategory),
    topEventTypes: Object.entries(sum((r) => Object.fromEntries(r.topEventTypes.map((t) => [t.eventType, t.count]))))
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([eventType, count]) => ({ eventType, count })),
    topAssets: [...assets.entries()]
      .sort((a, b) => SEVERITY_RANK[b[1].max] - SEVERITY_RANK[a[1].max] || b[1].events - a[1].events)
      .slice(0, n)
      .map(([asset, v]) => ({ asset, events: v.events, maxSeverity: v.max })),
    attack: [...attack.entries()].sort((a, b) => b[1].count - a[1].count).map(([id, v]) => ({ id, ...v })),
    tactics: Object.entries(sum((r) => Object.fromEntries(r.tactics.map((t) => [t.tactic, t.count]))))
      .sort((a, b) => b[1] - a[1])
      .map(([tactic, count]) => ({ tactic, count })),
    indicators: { total: reports.reduce((a, r) => a + r.indicators.total, 0), byType: sum((r) => r.indicators.byType) },
    rejections: Object.entries(sum((r) => Object.fromEntries(r.rejections.map((x) => [x.reason, x.count]))))
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([reason, count]) => ({ reason, count, sampleIndexes: [] })),
    skips: Object.entries(sum((r) => Object.fromEntries(r.skips.map((x) => [x.reason, x.count]))))
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([reason, count]) => ({ reason, count })),
    health: { status: worst, reasons: [...new Set(reports.flatMap((r) => r.health.reasons))] },
    headline: `${first.adapter}: ${events} events from ${records} records across ${reports.length} batches${highPlus > 0 ? `, ${highPlus} high/critical` : ""}${worst !== "healthy" ? ` — source ${worst}` : ""}`,
  };
}

/**
 * Automation signal for a degraded/failing data source, so the SOC (and the MSSP operator
 * owning the integration) is told by email/chat when telemetry quality drops.
 */
export function ingestHealthSignal(report: IngestReport, ctx: { organizationRef: string | null; integrationRef: string; now?: string }): AdapterSignal | undefined {
  if (report.health.status === "healthy") return undefined;
  return signal({
    // The shared AUTOMATION_EVENTS vocabulary has no integration-health event yet: a batch cut
    // at the record limit maps to usage.quota_exceeded, unusable telemetry to agent.unresponsive
    // (the collector is effectively silent). `subject.kind = "integration"` disambiguates.
    event: report.totals.truncated && report.health.reasons.length === 1 ? "usage.quota_exceeded" : "agent.unresponsive",
    severity: report.health.status === "failing" ? "high" : "medium",
    at: ctx.now ?? report.generatedAt,
    dedupKey: `ingest-health:${ctx.integrationRef}:${report.health.status}`,
    emit: "on_change",
    organizationRef: ctx.organizationRef,
    subject: { kind: "integration", ref: ctx.integrationRef, label: `${report.adapter} integration` },
    title: `${report.adapter} data source ${report.health.status}`,
    summary: [report.headline, ...report.health.reasons, ...report.rejections.slice(0, 3).map((r) => `${r.count}× ${r.reason}`)].join("\n"),
    facts: {
      adapter: report.adapter,
      status: report.health.status,
      records: report.totals.records,
      events: report.totals.events,
      rejected: report.totals.rejected,
      acceptanceRate: report.totals.acceptanceRate,
    },
    audience: ["soc", "mssp"],
  });
}
