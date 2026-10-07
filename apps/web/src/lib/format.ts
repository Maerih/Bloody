/**
 * Display formatting helpers. Pure functions — no locale state — so they are trivially testable
 * and render identically on every analyst's screen (SOC screenshots get shared in tickets).
 */

const EM_DASH = "—";

const UNITS: { value: number; suffix: string }[] = [
  { value: 1e12, suffix: "T" },
  { value: 1e9, suffix: "B" },
  { value: 1e6, suffix: "M" },
  { value: 1e3, suffix: "K" },
];

function trimZeros(text: string): string {
  return text.includes(".") ? text.replace(/\.?0+$/, "") : text;
}

/**
 * Compact number formatting used across dashboards: 58_700 → "58.7K", 1_250_000 → "1.3M".
 * Values below 1,000 are shown as-is (integers) or with up to `precision` decimals.
 * Null/undefined/NaN render as an em dash so missing data is never shown as a fake zero.
 */
export function formatNumber(value: number | null | undefined, precision = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EM_DASH;
  const sign = value < 0 ? "-" : "";
  const abs = Math.abs(value);
  if (abs < 1000) {
    return sign + trimZeros(Number.isInteger(abs) ? String(abs) : abs.toFixed(precision));
  }
  for (let i = 0; i < UNITS.length; i++) {
    const unit = UNITS[i]!;
    if (abs >= unit.value) {
      const scaled = abs / unit.value;
      const rounded = Number(scaled.toFixed(precision));
      // 999_950 → 999.95K rounds to "1000K": promote to the next larger unit instead.
      if (rounded >= 1000 && i > 0) {
        const bigger = UNITS[i - 1]!;
        return sign + trimZeros((abs / bigger.value).toFixed(precision)) + bigger.suffix;
      }
      return sign + trimZeros(scaled.toFixed(precision)) + unit.suffix;
    }
  }
  return sign + String(abs);
}

/** Full integer with thousands separators: 128421 → "128,421". */
export function formatInteger(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EM_DASH;
  return Math.round(value).toLocaleString("en-US");
}

/** Percentage of `part` in `total`; returns "—" when total is 0 (no denominator, no claim). */
export function formatPercent(part: number, total: number, precision = 0): string {
  if (!Number.isFinite(part) || !Number.isFinite(total) || total <= 0) return EM_DASH;
  return `${trimZeros(((part / total) * 100).toFixed(precision))}%`;
}

export function ratio(part: number, total: number): number | null {
  if (!Number.isFinite(part) || !Number.isFinite(total) || total <= 0) return null;
  return part / total;
}

/** Minutes → "45m", "1h 24m", "2d 3h". Null → "—". */
export function formatDuration(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined || !Number.isFinite(minutes) || minutes < 0) return EM_DASH;
  if (minutes < 1) return "<1m";
  const total = Math.round(minutes);
  const days = Math.floor(total / 1440);
  const hours = Math.floor((total % 1440) / 60);
  const mins = total % 60;
  if (days > 0) return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  if (hours > 0) return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  return `${mins}m`;
}

function toDate(value: string | number | Date): Date | null {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** "just now", "5m ago", "3h ago", "2d ago", "in 4h"; older than 30 days → date. */
export function formatRelativeTime(value: string | number | Date | null | undefined, now: number = Date.now()): string {
  if (value === null || value === undefined) return EM_DASH;
  const d = toDate(value);
  if (!d) return EM_DASH;
  const diffSec = Math.round((now - d.getTime()) / 1000);
  const future = diffSec < 0;
  const abs = Math.abs(diffSec);
  let text: string;
  if (abs < 45) return future ? "in a moment" : "just now";
  if (abs < 3600) text = `${Math.round(abs / 60)}m`;
  else if (abs < 86_400) text = `${Math.round(abs / 3600)}h`;
  else if (abs < 30 * 86_400) text = `${Math.round(abs / 86_400)}d`;
  else return formatDate(d);
  return future ? `in ${text}` : `${text} ago`;
}

const DATE_FMT = new Intl.DateTimeFormat("en-CA", { year: "numeric", month: "2-digit", day: "2-digit" });
const DATETIME_FMT = new Intl.DateTimeFormat("en-CA", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

/** ISO-like local date "2026-11-01". */
export function formatDate(value: string | number | Date | null | undefined): string {
  if (value === null || value === undefined) return EM_DASH;
  const d = toDate(value);
  return d ? DATE_FMT.format(d) : EM_DASH;
}

/** Local date-time "2026-11-01, 14:03". */
export function formatDateTime(value: string | number | Date | null | undefined): string {
  if (value === null || value === undefined) return EM_DASH;
  const d = toDate(value);
  return d ? DATETIME_FMT.format(d) : EM_DASH;
}

/** Whole days from now until `value` (negative when in the past). */
export function daysUntil(value: string | number | Date, now: number = Date.now()): number | null {
  const d = toDate(value);
  if (!d) return null;
  return Math.ceil((d.getTime() - now) / 86_400_000);
}

/** Currency, compact above 100K: 12400 → "$12,400", 1_240_000 → "$1.2M". */
export function formatCurrency(value: number | null | undefined, currency = "USD"): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EM_DASH;
  const abs = Math.abs(value);
  if (abs >= 100_000) {
    const symbol = currency === "USD" ? "$" : `${currency} `;
    return (value < 0 ? "-" : "") + symbol + formatNumber(abs);
  }
  return new Intl.NumberFormat("en-US", { style: "currency", currency, maximumFractionDigits: 0 }).format(value);
}

/** "Hello World & Co" → "hello-world-co" (matches Organization.slug regex). */
export function slugify(input: string): string {
  return input
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

/** Pluralize a count label: plural(1, "agent") → "1 agent", plural(3, "agent") → "3 agents". */
export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${formatInteger(count)} ${count === 1 ? singular : pluralForm}`;
}

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** Human description for the common report-schedule cron shapes; falls back to the raw expression. */
export function describeCron(cron: string): string {
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) return cron;
  const [min, hour, dom, mon, dow] = parts as [string, string, string, string, string];
  const isNum = (s: string) => /^\d+$/.test(s);
  if (!isNum(min) || !isNum(hour)) return cron;
  const time = `${hour.padStart(2, "0")}:${min.padStart(2, "0")} UTC`;
  if (dom === "*" && mon === "*" && dow === "*") return `Daily at ${time}`;
  if (dom === "*" && mon === "*" && dow === "1-5") return `Weekdays at ${time}`;
  if (dom === "*" && mon === "*" && isNum(dow)) return `Weekly on ${WEEKDAYS[Number(dow) % 7]} at ${time}`;
  if (isNum(dom) && mon === "*" && dow === "*") return `Monthly on day ${dom} at ${time}`;
  return cron;
}

/** Title-case snake/kebab identifiers for display: "false_positive" → "False positive". */
export function humanize(value: string): string {
  const text = value.replace(/[_-]+/g, " ").trim();
  return text.charAt(0).toUpperCase() + text.slice(1);
}
