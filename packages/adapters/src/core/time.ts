/**
 * Timestamp normalization. Engines emit at least seven timestamp dialects:
 *
 *   ISO-8601 with `Z`, `+00:00` or `+0000` offsets and 0–9 fractional digits (Wazuh,
 *   Suricata, Falco, Nuclei, Trivy) · epoch seconds as float (Zeek) · epoch ms (Keycloak) ·
 *   "YYYY-MM-DD HH:MM:SS.ffffff" without zone (OpenCanary) · RFC 3164 "Mar  5 10:11:12"
 *   without year (BSD syslog) · "Tue Mar  5 10:11:12 2024 UTC" (osquery calendarTime) ·
 *   "Mar 05 2024 10:11:12" (CEF `rt`).
 *
 * Everything is converted to a UTC `Date` (millisecond precision) and serialized with
 * `toISOString()`, which always satisfies the contracts' `IsoDateTime`.
 */

const MONTHS: Record<string, number> = {
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11,
};

export interface ParseTimestampOptions {
  /** Reference "now" for formats without a year (RFC 3164). Defaults to the current time. */
  reference?: Date;
  /** Unit for bare numbers. "auto" infers s / ms / µs / ns from magnitude. Default "auto". */
  epochUnit?: "s" | "ms" | "auto";
  /** Earliest plausible year; older values (e.g. the 1970 "never seen" sentinel) are rejected. */
  minYear?: number;
}

const ISO_RE =
  /^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?\s*(Z|z|UTC|GMT|[+-]\d{2}(?::?\d{2})?)?$/;
const RFC3164_RE = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/;
const CTIME_RE = /^(?:[A-Za-z]{3},?\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})(?:\s+(UTC|GMT|Z))?$/;
const CEF_RT_RE = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:\s+(UTC|GMT|Z))?$/;

function fractionToMs(frac: string | undefined): number {
  if (!frac) return 0;
  return Number.parseInt(`${frac}000`.slice(0, 3), 10);
}

function offsetMinutes(tz: string | undefined): number {
  if (!tz || /^(z|utc|gmt)$/i.test(tz)) return 0;
  const m = /^([+-])(\d{2}):?(\d{2})?$/.exec(tz);
  if (!m) return 0;
  const sign = m[1] === "-" ? -1 : 1;
  return sign * (Number(m[2]) * 60 + Number(m[3] ?? "0"));
}

function build(y: number, mo: number, d: number, h: number, mi: number, s: number, ms: number, offsetMin: number): Date | undefined {
  if (mo < 0 || mo > 11 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return undefined;
  const t = Date.UTC(y, mo, d, h, mi, Math.min(s, 59), ms) - offsetMin * 60_000;
  const date = new Date(t);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function fromEpoch(n: number, unit: "s" | "ms" | "auto"): Date | undefined {
  if (!Number.isFinite(n) || n < 0) return undefined;
  let ms: number;
  if (unit === "s") ms = n * 1000;
  else if (unit === "ms") ms = n;
  else if (n < 1e11) ms = n * 1000; // seconds (until year 5138)
  else if (n < 1e14) ms = n; // milliseconds
  else if (n < 1e17) ms = n / 1000; // microseconds
  else ms = n / 1e6; // nanoseconds
  const d = new Date(Math.round(ms));
  return Number.isNaN(d.getTime()) ? undefined : d;
}

export function parseTimestamp(value: unknown, opts: ParseTimestampOptions = {}): Date | undefined {
  const minYear = opts.minYear ?? 1990;
  const ok = (d: Date | undefined): Date | undefined => {
    if (!d) return undefined;
    const y = d.getUTCFullYear();
    return y >= minYear && y <= 2200 ? d : undefined;
  };
  if (value instanceof Date) return ok(Number.isNaN(value.getTime()) ? undefined : value);
  if (typeof value === "number") return ok(fromEpoch(value, opts.epochUnit ?? "auto"));
  if (typeof value !== "string") return undefined;
  const s = value.trim();
  if (s === "" || s === "-") return undefined;

  if (/^\d+(\.\d+)?$/.test(s)) return ok(fromEpoch(Number(s), opts.epochUnit ?? "auto"));

  let m = ISO_RE.exec(s);
  if (m) {
    return ok(
      build(
        Number(m[1]),
        Number(m[2]) - 1,
        Number(m[3]),
        Number(m[4] ?? "0"),
        Number(m[5] ?? "0"),
        Number(m[6] ?? "0"),
        fractionToMs(m[7]),
        offsetMinutes(m[8]),
      ),
    );
  }

  m = CTIME_RE.exec(s);
  if (m) {
    const mo = MONTHS[(m[1] ?? "").toLowerCase()];
    if (mo === undefined) return undefined;
    return ok(build(Number(m[6]), mo, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), 0, 0));
  }

  m = CEF_RT_RE.exec(s);
  if (m) {
    const mo = MONTHS[(m[1] ?? "").toLowerCase()];
    if (mo === undefined) return undefined;
    return ok(build(Number(m[3]), mo, Number(m[2]), Number(m[4]), Number(m[5]), Number(m[6]), fractionToMs(m[7]), 0));
  }

  m = RFC3164_RE.exec(s);
  if (m) {
    const mo = MONTHS[(m[1] ?? "").toLowerCase()];
    if (mo === undefined) return undefined;
    const ref = opts.reference ?? new Date();
    let year = ref.getUTCFullYear();
    let d = build(year, mo, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), fractionToMs(m[6]), 0);
    // A BSD syslog line from "Dec 31" received on Jan 1 belongs to the previous year.
    if (d && d.getTime() - ref.getTime() > 24 * 3600_000) {
      year -= 1;
      d = build(year, mo, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), fractionToMs(m[6]), 0);
    }
    return ok(d);
  }

  // RFC 2822 / HTTP-date ("Tue, 05 Mar 2024 10:11:12 GMT"): only with an explicit zone.
  if (/\b\d{4}\b/.test(s) && /(GMT|UTC|[+-]\d{4})$/.test(s)) {
    const t = Date.parse(s);
    if (!Number.isNaN(t)) return ok(new Date(t));
  }
  return undefined;
}

/** ISO-8601 UTC string or undefined. */
export function toIso(value: unknown, opts?: ParseTimestampOptions): string | undefined {
  return parseTimestamp(value, opts)?.toISOString();
}

/** Latest of several timestamps (ISO), ignoring unparsable values. */
export function latestIso(...values: unknown[]): string | undefined {
  let best: Date | undefined;
  for (const v of values) {
    const d = parseTimestamp(v);
    if (d && (!best || d.getTime() > best.getTime())) best = d;
  }
  return best?.toISOString();
}
