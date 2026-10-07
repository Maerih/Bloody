import { formatCurrency, formatDate, formatDateTime, formatDuration, formatNumber, formatPercent } from "../format.js";
import type { CellValue, TableColumn } from "../model.js";

export interface CellFormatOptions {
  timeZone?: string;
  currency?: string;
}

/** Humanise enum-like status values ("false_positive" → "False positive"). */
export function humanize(value: string): string {
  const s = value.replace(/_/g, " ").trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Display text for a table cell according to its column format (shared by HTML, PDF and CSV). */
export function formatCell(value: CellValue, column: TableColumn, opts: CellFormatOptions = {}): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  switch (column.format) {
    case "number":
      return typeof value === "number" ? formatNumber(value) : String(value);
    case "score":
      return typeof value === "number" ? formatNumber(Math.round(value)) : String(value);
    case "percent":
      return typeof value === "number" ? formatPercent(value) : String(value);
    case "minutes":
      return typeof value === "number" ? formatDuration(value) : String(value);
    case "days":
      return typeof value === "number" ? `${formatNumber(value, { digits: 1 })} d` : String(value);
    case "currency":
      return typeof value === "number" ? formatCurrency(value, opts.currency ?? "USD") : String(value);
    case "date":
      return typeof value === "string" ? formatDate(value, opts.timeZone ?? "UTC") : String(value);
    case "datetime":
      return typeof value === "string" ? formatDateTime(value, opts.timeZone ?? "UTC") : String(value);
    case "severity":
    case "status":
      return humanize(String(value));
    default:
      return typeof value === "number" ? formatNumber(value) : String(value);
  }
}

export function isNumericColumn(column: TableColumn): boolean {
  return column.align === "right" || ["number", "score", "percent", "minutes", "days", "currency"].includes(column.format ?? "");
}
