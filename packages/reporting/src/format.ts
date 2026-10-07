import type { ValueUnit } from "./model.js";

/** Formatting helpers shared by builders (narratives) and renderers (tiles, tables, axes). */
export interface FormatOptions {
  locale?: string;
  currency?: string;
  timeZone?: string;
}

const nf = new Map<string, Intl.NumberFormat>();

function numberFormat(locale: string, opts: Intl.NumberFormatOptions): Intl.NumberFormat {
  const key = `${locale}|${JSON.stringify(opts)}`;
  let f = nf.get(key);
  if (!f) {
    f = new Intl.NumberFormat(locale, opts);
    nf.set(key, f);
  }
  return f;
}

export function formatNumber(value: number | null | undefined, opts: FormatOptions & { compact?: boolean; digits?: number } = {}): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  const locale = opts.locale ?? "en-US";
  if (opts.compact && Math.abs(value) >= 10_000) {
    return numberFormat(locale, { notation: "compact", maximumFractionDigits: 1 }).format(value);
  }
  const digits = opts.digits ?? (Number.isInteger(value) ? 0 : Math.abs(value) < 10 ? 1 : 0);
  return numberFormat(locale, { maximumFractionDigits: digits, minimumFractionDigits: 0 }).format(value);
}

export function formatPercent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  const rounded = Number(value.toFixed(digits));
  return `${Number.isInteger(rounded) ? rounded.toFixed(0) : rounded.toFixed(digits)}%`;
}

/** 45 → "45m", 200 → "3h 20m", 3000 → "2d 2h". */
export function formatDuration(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined || !Number.isFinite(minutes)) return "—";
  const m = Math.max(0, minutes);
  if (m < 1) return "<1m";
  if (m < 60) return `${Math.round(m)}m`;
  if (m < 1440) {
    const h = Math.floor(m / 60);
    const rest = Math.round(m % 60);
    return rest === 0 ? `${h}h` : rest === 60 ? `${h + 1}h` : `${h}h ${rest}m`;
  }
  const d = Math.floor(m / 1440);
  const h = Math.round((m % 1440) / 60);
  return h === 0 ? `${d}d` : h === 24 ? `${d + 1}d` : `${d}d ${h}h`;
}

export function formatCurrency(value: number | null | undefined, currency = "USD", opts: { locale?: string; compact?: boolean } = {}): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  const locale = opts.locale ?? "en-US";
  try {
    return numberFormat(locale, {
      style: "currency",
      currency,
      ...(opts.compact && Math.abs(value) >= 100_000 ? { notation: "compact", maximumFractionDigits: 1 } : { maximumFractionDigits: 0 }),
    }).format(value);
  } catch {
    return `${formatNumber(value, { locale })} ${currency}`;
  }
}

function dateParts(iso: string | Date, timeZone: string): Record<string, string> | null {
  const d = iso instanceof Date ? iso : new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone, day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(d);
  const out: Record<string, string> = {};
  for (const p of parts) out[p.type] = p.value;
  return out;
}

export function formatDate(iso: string | Date | null | undefined, timeZone = "UTC"): string {
  if (!iso) return "—";
  const p = dateParts(iso, timeZone);
  return p ? `${p["day"]} ${p["month"]} ${p["year"]}` : "—";
}

export function formatDateTime(iso: string | Date | null | undefined, timeZone = "UTC"): string {
  if (!iso) return "—";
  const p = dateParts(iso, timeZone);
  return p ? `${p["day"]} ${p["month"]} ${p["year"]} ${p["hour"]}:${p["minute"]}${timeZone === "UTC" ? " UTC" : ""}` : "—";
}

/** "1 – 30 Sep 2026" style label for a [from, to) period. */
export function formatPeriod(from: Date, to: Date, timeZone = "UTC"): string {
  const end = new Date(to.getTime() - 1);
  const f = (d: Date, opts: Intl.DateTimeFormatOptions): string => new Intl.DateTimeFormat("en-GB", { timeZone, ...opts }).format(d);
  const sameYear = f(from, { year: "numeric" }) === f(end, { year: "numeric" });
  const sameMonth = sameYear && f(from, { month: "short" }) === f(end, { month: "short" });
  if (sameMonth) return `${f(from, { day: "numeric" })} – ${f(end, { day: "numeric", month: "short", year: "numeric" })}`;
  if (sameYear) return `${f(from, { day: "numeric", month: "short" })} – ${f(end, { day: "numeric", month: "short", year: "numeric" })}`;
  return `${f(from, { day: "numeric", month: "short", year: "numeric" })} – ${f(end, { day: "numeric", month: "short", year: "numeric" })}`;
}

/** Format a value for display according to its unit. */
export function formatValue(value: number | null | undefined, unit: ValueUnit, opts: FormatOptions & { compact?: boolean } = {}): string {
  switch (unit) {
    case "percent":
      return formatPercent(value);
    case "minutes":
      return formatDuration(value);
    case "hours":
      return value === null || value === undefined ? "—" : formatDuration(value * 60);
    case "days":
      return value === null || value === undefined || !Number.isFinite(value) ? "—" : `${formatNumber(value, { digits: value < 10 ? 1 : 0 })} d`;
    case "currency":
      return formatCurrency(value, opts.currency ?? "USD", { ...(opts.locale ? { locale: opts.locale } : {}), ...(opts.compact ? { compact: true } : {}) });
    case "ratio":
      return value === null || value === undefined ? "—" : formatPercent(value * 100);
    case "score":
      return value === null || value === undefined || !Number.isFinite(value) ? "—" : formatNumber(Math.round(value));
    case "count":
    default:
      return formatNumber(value, { ...(opts.locale ? { locale: opts.locale } : {}), compact: opts.compact ?? false });
  }
}

/** Short axis-tick formatting (compact numbers, % and durations). */
export function formatTick(value: number, unit: ValueUnit, currency?: string): string {
  if (unit === "percent") return `${formatNumber(value, { digits: value % 1 === 0 ? 0 : 1 })}%`;
  if (unit === "minutes") return formatDuration(value);
  if (unit === "currency") return formatCurrency(value, currency ?? "USD", { compact: true });
  if (Math.abs(value) >= 1000) return numberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value);
  return formatNumber(value, { digits: value % 1 === 0 ? 0 : 1 });
}

/** Make an indicator safe to print / share (no live links). */
export function defang(value: string): string {
  return value
    .replace(/^http(s?):\/\//i, (_m, s: string) => `hxxp${s}://`)
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

export function slugify(value: string): string {
  return (
    value
      .normalize("NFKD")
      .replace(/[̀-ͯ]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60) || "report"
  );
}

export function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
