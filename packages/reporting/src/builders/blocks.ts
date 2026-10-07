import type { Severity } from "@bloody/contracts";
import { SEVERITY_COLOR } from "../branding.js";
import type { NamedCount } from "../datasource.js";
import type { ChartSpec, ReportBlock, TableColumn, TableSpec, ValueUnit } from "../model.js";
import { SEVERITIES_DESC, type TimeBuckets } from "../metrics.js";
import { SEVERITY_LABEL } from "./context.js";

/** Small factories that keep builders declarative. */

export function severityDonut(id: string, title: string, counts: Record<Severity, number>, opts: { includeInfo?: boolean; subtitle?: string } = {}): ChartSpec {
  const sev = SEVERITIES_DESC.filter((s) => opts.includeInfo || s !== "info" || counts.info > 0);
  return {
    id,
    type: "donut",
    title,
    ...(opts.subtitle ? { subtitle: opts.subtitle } : {}),
    unit: "count",
    categories: sev.map((s) => SEVERITY_LABEL[s]),
    categoryColors: sev.map((s) => SEVERITY_COLOR[s]),
    series: [{ key: "count", name: title, values: sev.map((s) => counts[s]) }],
    emptyMessage: "Nothing recorded in this period.",
  };
}

export function severityStacked(id: string, title: string, buckets: TimeBuckets, bySeverity: Record<Severity, number[]>, opts: { subtitle?: string } = {}): ChartSpec {
  const sev = SEVERITIES_DESC.filter((s) => s !== "info" || bySeverity.info.some((v) => v > 0));
  return {
    id,
    type: "stacked_bar",
    title,
    ...(opts.subtitle ? { subtitle: opts.subtitle } : {}),
    unit: "count",
    categories: buckets.labels,
    // Stack bottom→top from least to most severe so critical caps the column.
    series: [...sev].reverse().map((s) => ({ key: s, name: SEVERITY_LABEL[s], values: bySeverity[s], color: SEVERITY_COLOR[s] })),
    emptyMessage: "Nothing recorded in this period.",
  };
}

export function hbar(id: string, title: string, items: readonly NamedCount[], opts: { unit?: ValueUnit; subtitle?: string; seriesName?: string; currency?: string } = {}): ChartSpec {
  return {
    id,
    type: "hbar",
    title,
    ...(opts.subtitle ? { subtitle: opts.subtitle } : {}),
    unit: opts.unit ?? "count",
    ...(opts.currency ? { currency: opts.currency } : {}),
    categories: items.map((i) => i.name),
    series: [{ key: "value", name: opts.seriesName ?? title, values: items.map((i) => i.count) }],
    emptyMessage: "No data for this period.",
  };
}

export function lineChart(id: string, title: string, categories: string[], series: { key: string; name: string; values: (number | null)[]; color?: string }[], unit: ValueUnit, opts: { subtitle?: string } = {}): ChartSpec {
  return { id, type: "line", title, ...(opts.subtitle ? { subtitle: opts.subtitle } : {}), unit, categories, series, emptyMessage: "No data for this period." };
}

export function barChart(id: string, title: string, categories: string[], series: { key: string; name: string; values: (number | null)[]; color?: string }[], unit: ValueUnit, opts: { subtitle?: string; categoryColors?: (string | null)[]; currency?: string } = {}): ChartSpec {
  return {
    id,
    type: "bar",
    title,
    ...(opts.subtitle ? { subtitle: opts.subtitle } : {}),
    unit,
    ...(opts.currency ? { currency: opts.currency } : {}),
    categories,
    series,
    ...(opts.categoryColors ? { categoryColors: opts.categoryColors } : {}),
    emptyMessage: "No data for this period.",
  };
}

export function table(id: string, title: string, columns: TableColumn[], rows: TableSpec["rows"], opts: { emptyMessage?: string; totalRows?: number; note?: string; currency?: string } = {}): ReportBlock {
  return {
    kind: "table",
    table: {
      id,
      title,
      columns,
      rows,
      emptyMessage: opts.emptyMessage ?? "Nothing to report for this period.",
      ...(opts.totalRows !== undefined && opts.totalRows > rows.length ? { totalRows: opts.totalRows } : {}),
      ...(opts.note ? { note: opts.note } : {}),
      ...(opts.currency ? { currency: opts.currency } : {}),
    },
  };
}

export function chart(spec: ChartSpec): ReportBlock {
  return { kind: "chart", chart: spec };
}

export function narrative(paragraphs: (string | null | undefined | false)[], opts: { tone?: "default" | "ai" | "note"; label?: string } = {}): ReportBlock {
  return { kind: "narrative", paragraphs: paragraphs.filter((p): p is string => typeof p === "string" && p.trim().length > 0), ...opts };
}

export function topNamed(items: readonly NamedCount[], n: number): NamedCount[] {
  return [...items].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)).slice(0, n);
}

/** "3 critical, 5 high and 12 medium" */
export function severityPhrase(counts: Record<Severity, number>): string {
  const parts = SEVERITIES_DESC.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
  if (parts.length === 0) return "none";
  if (parts.length === 1) return parts[0]!;
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** "rose 12%" / "fell 30%" / "was unchanged" for narratives. */
export function changePhrase(current: number | null, previous: number | null, opts: { up?: string; down?: string } = {}): string {
  if (current === null || previous === null) return "has no comparable previous period";
  if (previous === 0) return current === 0 ? "was unchanged" : `${opts.up ?? "rose"} from zero`;
  const pct = ((current - previous) / Math.abs(previous)) * 100;
  if (Math.abs(pct) < 0.5) return "was unchanged";
  return `${pct > 0 ? (opts.up ?? "rose") : (opts.down ?? "fell")} ${Math.abs(pct).toFixed(Math.abs(pct) < 10 ? 1 : 0)}%`;
}
