import type { CellValue, ReportData, TableSpec } from "../model.js";

/**
 * CSV export (RFC 4180): CRLF line endings, fields quoted when they contain a comma, quote,
 * CR or LF, embedded quotes doubled.
 *
 * Formula-injection protection (CWE-1236): any TEXT cell starting with = + - @ (or tab / CR,
 * or their full-width forms) is prefixed with a single quote so spreadsheet software treats it
 * as text — report data contains attacker-controlled strings (hostnames, command lines, file
 * names). Real numbers are written as numbers and are not altered.
 */
const DANGEROUS_PREFIX = /^[=+\-@\t\r＝＋－＠]/;

export function neutralizeFormula(value: string): string {
  return DANGEROUS_PREFIX.test(value) ? `'${value}` : value;
}

export function csvField(value: CellValue | undefined): string {
  if (value === null || value === undefined) return "";
  let s: string;
  if (typeof value === "number") s = Number.isFinite(value) ? String(value) : "";
  else if (typeof value === "boolean") s = value ? "true" : "false";
  else s = neutralizeFormula(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function csvRow(values: readonly (CellValue | undefined)[]): string {
  return values.map(csvField).join(",");
}

export interface CsvOptions {
  /** Export a single table (by table id) in wide format instead of the tidy all-in-one file. */
  tableId?: string;
  /** Prepend a UTF-8 BOM (helps Excel detect UTF-8). Default false. */
  bom?: boolean;
}

function tableToCsv(t: TableSpec): string {
  const lines = [csvRow(t.columns.map((c) => c.label)), ...t.rows.map((r) => csvRow(t.columns.map((c) => r[c.key] ?? null)))];
  return `${lines.join("\r\n")}\r\n`;
}

/** Every table in the report, plus KPIs and chart data, as separate wide CSV files. */
export function renderCsvTables(report: ReportData): { id: string; title: string; filename: string; csv: string }[] {
  const out: { id: string; title: string; filename: string; csv: string }[] = [];
  const kpiRows = [csvRow(["Section", "Metric", "Value", "Unit", "Previous", "Change %", "Target", "Status", "How it is computed"])];
  for (const s of report.sections) {
    for (const b of s.blocks) {
      if (b.kind === "kpis") for (const k of b.items) kpiRows.push(csvRow([s.title, k.label, k.value, k.unit === "currency" ? (k.currency ?? "currency") : k.unit, k.delta?.previous ?? null, k.delta?.percent === null || k.delta?.percent === undefined ? null : Math.round(k.delta.percent * 10) / 10, k.target, k.status, k.explanation]));
    }
  }
  out.push({ id: "kpis", title: "Key metrics", filename: "kpis.csv", csv: `${kpiRows.join("\r\n")}\r\n` });
  for (const s of report.sections) {
    for (const b of s.blocks) {
      if (b.kind === "table") out.push({ id: b.table.id, title: b.table.title, filename: `${b.table.id}.csv`, csv: tableToCsv(b.table) });
      if (b.kind === "chart") {
        const c = b.chart;
        const lines = [csvRow(["Category", ...c.series.map((x) => x.name)]), ...c.categories.map((cat, i) => csvRow([cat, ...c.series.map((x) => x.values[i] ?? null)]))];
        out.push({ id: `chart-${c.id}`, title: c.title, filename: `chart-${c.id}.csv`, csv: `${lines.join("\r\n")}\r\n` });
      }
      if (b.kind === "risks" && b.items.length > 0) {
        const lines = [csvRow(["Risk", "Subject", "Severity", "Score", "Factor", "Contribution", "Explanation", "Recommendation"])];
        for (const r of b.items) {
          if (r.factors.length === 0) lines.push(csvRow([r.title, r.subject, r.severity, r.score, null, null, null, r.recommendation]));
          for (const f of r.factors) lines.push(csvRow([r.title, r.subject, r.severity, r.score, f.label, f.contribution, f.explanation, r.recommendation]));
        }
        out.push({ id: `risks-${s.id}`, title: `${s.title} — risks`, filename: `risks-${s.id}.csv`, csv: `${lines.join("\r\n")}\r\n` });
      }
    }
  }
  return out;
}

/**
 * Default export: one tidy CSV with a fixed header — section, dataset, row, field, value —
 * containing every KPI, chart data point, table cell, risk factor and recommendation. Easy to
 * pivot in a spreadsheet or load into a BI tool.
 */
export function renderCsv(report: ReportData, opts: CsvOptions = {}): string {
  const bom = opts.bom ? "﻿" : "";
  if (opts.tableId) {
    for (const s of report.sections) for (const b of s.blocks) if (b.kind === "table" && b.table.id === opts.tableId) return bom + tableToCsv(b.table);
    throw new Error(`table "${opts.tableId}" not found in report`);
  }
  const lines: string[] = [csvRow(["section", "dataset", "row", "field", "value"])];
  const push = (section: string, dataset: string, row: string | number, field: string, value: CellValue | undefined): void => {
    lines.push(csvRow([section, dataset, typeof row === "number" ? row : row, field, value ?? null]));
  };
  push("Report", "metadata", 1, "title", report.title);
  push("Report", "metadata", 1, "type", report.type);
  push("Report", "metadata", 1, "organization", report.scope.organizationName ?? `${report.scope.organizationCount} organizations`);
  push("Report", "metadata", 1, "period_from", report.period.from);
  push("Report", "metadata", 1, "period_to", report.period.to);
  push("Report", "metadata", 1, "generated_at", report.generatedAt);
  push("Report", "metadata", 1, "classification", report.classification);
  push("Summary", "headline", 1, "text", report.summary.headline);
  report.summary.highlights.forEach((h, i) => push("Summary", "highlights", i + 1, "text", h));
  for (const s of report.sections) {
    for (const b of s.blocks) {
      switch (b.kind) {
        case "kpis":
          for (const k of b.items) {
            push(s.title, "kpis", k.label, "value", k.value);
            push(s.title, "kpis", k.label, "unit", k.unit === "currency" ? (k.currency ?? "currency") : k.unit);
            if (k.delta) {
              push(s.title, "kpis", k.label, "previous", k.delta.previous);
              push(s.title, "kpis", k.label, "change_percent", k.delta.percent === null ? null : Math.round(k.delta.percent * 10) / 10);
            }
            if (k.target !== null) push(s.title, "kpis", k.label, "target", k.target);
          }
          break;
        case "chart":
          b.chart.categories.forEach((cat, i) => {
            for (const se of b.chart.series) push(s.title, b.chart.title, cat, se.name, se.values[i] ?? null);
          });
          break;
        case "table":
          b.table.rows.forEach((r, i) => {
            for (const c of b.table.columns) push(s.title, b.table.title, i + 1, c.label, r[c.key] ?? null);
          });
          break;
        case "risks":
          b.items.forEach((r, i) => {
            push(s.title, b.title ?? "Risks", i + 1, "risk", r.title);
            push(s.title, b.title ?? "Risks", i + 1, "score", r.score);
            push(s.title, b.title ?? "Risks", i + 1, "severity", r.severity);
            for (const f of r.factors) push(s.title, b.title ?? "Risks", i + 1, `factor: ${f.label}`, f.contribution);
            if (r.recommendation) push(s.title, b.title ?? "Risks", i + 1, "recommendation", r.recommendation);
          });
          break;
        case "recommendations":
          b.items.forEach((r, i) => {
            push(s.title, b.title ?? "Recommendations", i + 1, "priority", r.priority);
            push(s.title, b.title ?? "Recommendations", i + 1, "title", r.title);
            push(s.title, b.title ?? "Recommendations", i + 1, "rationale", r.rationale);
          });
          break;
        case "narrative":
          b.paragraphs.forEach((p, i) => push(s.title, b.tone === "ai" ? "ai_commentary" : "narrative", i + 1, "text", p));
          break;
        case "callout":
          push(s.title, "callout", 1, b.title, b.text);
          break;
      }
    }
  }
  report.dataQuality.forEach((d, i) => push("Appendix", "data_quality", i + 1, "note", d));
  return `${bom}${lines.join("\r\n")}\r\n`;
}
