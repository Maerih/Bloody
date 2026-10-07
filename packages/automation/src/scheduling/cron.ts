/**
 * Five-field cron expressions (minute hour day-of-month month day-of-week) for report
 * schedules and scheduled playbooks. Written for Bloody; semantics follow the classic Vixie
 * cron conventions:
 *
 *  - `*`, lists `1,15`, ranges `1-5`, steps `*\/15`, `10-50/10`, `5/15` (= 5-max/15)
 *  - month names JAN–DEC, weekday names SUN–SAT, `7` is Sunday, `?` = `*` in day fields
 *  - macros @yearly @annually @monthly @weekly @daily @midnight @hourly
 *  - when BOTH day-of-month and day-of-week are restricted, a day matches if EITHER matches;
 *    a field starting with `*` counts as unrestricted
 *  - optional IANA time zone: schedules fire at wall-clock times of that zone. Times skipped
 *    by a DST jump do not fire that day; times repeated by a DST fall-back fire once.
 */
export interface CronSchedule {
  source: string;
  minutes: readonly number[];
  hours: readonly number[];
  daysOfMonth: readonly number[];
  months: readonly number[];
  /** 0 = Sunday … 6 = Saturday. */
  daysOfWeek: readonly number[];
  domRestricted: boolean;
  dowRestricted: boolean;
}

export class CronParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CronParseError";
  }
}

const MACROS: Record<string, string> = {
  "@yearly": "0 0 1 1 *",
  "@annually": "0 0 1 1 *",
  "@monthly": "0 0 1 * *",
  "@weekly": "0 0 * * 0",
  "@daily": "0 0 * * *",
  "@midnight": "0 0 * * *",
  "@hourly": "0 * * * *",
};

const MONTH_NAMES = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
const DAY_NAMES = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

interface FieldSpec {
  name: string;
  min: number;
  max: number;
  names?: string[];
  namesOffset?: number;
}

const FIELDS: FieldSpec[] = [
  { name: "minute", min: 0, max: 59 },
  { name: "hour", min: 0, max: 23 },
  { name: "day-of-month", min: 1, max: 31 },
  { name: "month", min: 1, max: 12, names: MONTH_NAMES, namesOffset: 1 },
  { name: "day-of-week", min: 0, max: 7, names: DAY_NAMES, namesOffset: 0 },
];

function parseValue(token: string, spec: FieldSpec): number {
  const upper = token.toUpperCase();
  if (spec.names) {
    const idx = spec.names.indexOf(upper);
    if (idx !== -1) return idx + (spec.namesOffset ?? 0);
  }
  if (!/^\d{1,2}$/.test(token)) throw new CronParseError(`invalid ${spec.name} value "${token}"`);
  const n = Number(token);
  if (n < spec.min || n > spec.max) throw new CronParseError(`${spec.name} value ${n} out of range ${spec.min}-${spec.max}`);
  return n;
}

function parseField(text: string, spec: FieldSpec): number[] {
  if (text.length === 0) throw new CronParseError(`empty ${spec.name} field`);
  const values = new Set<number>();
  for (const part of text.split(",")) {
    if (part.length === 0) throw new CronParseError(`empty list element in ${spec.name} field`);
    const [rangePart, stepPart, extra] = part.split("/");
    if (extra !== undefined) throw new CronParseError(`invalid step syntax "${part}" in ${spec.name} field`);
    let step = 1;
    if (stepPart !== undefined) {
      if (!/^\d{1,2}$/.test(stepPart) || Number(stepPart) === 0) throw new CronParseError(`invalid step "${stepPart}" in ${spec.name} field`);
      step = Number(stepPart);
    }
    let lo: number;
    let hi: number;
    if (rangePart === "*" || rangePart === "?") {
      if (rangePart === "?" && spec.name !== "day-of-month" && spec.name !== "day-of-week") {
        throw new CronParseError(`'?' is only allowed in day fields`);
      }
      lo = spec.min;
      hi = spec.name === "day-of-week" ? 6 : spec.max;
    } else if (rangePart !== undefined && rangePart.includes("-")) {
      const [a, b, more] = rangePart.split("-");
      if (more !== undefined || a === undefined || b === undefined) throw new CronParseError(`invalid range "${rangePart}" in ${spec.name} field`);
      lo = parseValue(a, spec);
      hi = parseValue(b, spec);
      if (lo > hi) throw new CronParseError(`range "${rangePart}" in ${spec.name} field must be ascending (wrap-around ranges are not supported)`);
    } else if (rangePart !== undefined) {
      lo = parseValue(rangePart, spec);
      hi = stepPart !== undefined ? (spec.name === "day-of-week" ? 6 : spec.max) : lo;
    } else {
      throw new CronParseError(`invalid ${spec.name} field "${text}"`);
    }
    for (let v = lo; v <= hi; v += step) values.add(spec.name === "day-of-week" && v === 7 ? 0 : v);
  }
  return [...values].sort((a, b) => a - b);
}

const cache = new Map<string, CronSchedule>();

export function parseCron(expression: string): CronSchedule {
  const source = expression.trim();
  const cached = cache.get(source);
  if (cached) return cached;
  if (source.length === 0 || source.length > 200) throw new CronParseError("cron expression must be 1-200 characters");
  const expanded = source.startsWith("@") ? MACROS[source.toLowerCase()] : source;
  if (expanded === undefined) throw new CronParseError(`unsupported macro "${source}"`);
  const parts = expanded.split(/\s+/);
  if (parts.length !== 5) throw new CronParseError(`expected 5 fields (minute hour day-of-month month day-of-week), got ${parts.length}`);
  const [mi, h, dom, mo, dow] = parts as [string, string, string, string, string];
  const schedule: CronSchedule = {
    source,
    minutes: parseField(mi, FIELDS[0]!),
    hours: parseField(h, FIELDS[1]!),
    daysOfMonth: parseField(dom, FIELDS[2]!),
    months: parseField(mo, FIELDS[3]!),
    daysOfWeek: parseField(dow, FIELDS[4]!),
    domRestricted: !(dom.startsWith("*") || dom.startsWith("?")),
    dowRestricted: !(dow.startsWith("*") || dow.startsWith("?")),
  };
  if (cache.size > 1000) cache.clear();
  cache.set(source, schedule);
  return schedule;
}

export function isValidCron(expression: string): boolean {
  try {
    parseCron(expression);
    return true;
  } catch {
    return false;
  }
}

/** Editor-friendly validation result. */
export function validateCron(expression: string): { ok: true; description: string } | { ok: false; error: string } {
  try {
    parseCron(expression);
    return { ok: true, description: describeCron(expression) };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

// ─── wall-clock arithmetic ──────────────────────────────────────────────────

interface Wall {
  y: number;
  mo: number; // 1-12
  d: number;
  h: number;
  mi: number;
}

function daysInMonth(y: number, mo: number): number {
  return new Date(Date.UTC(y, mo, 0)).getUTCDate();
}

function weekday(w: Wall): number {
  return new Date(Date.UTC(w.y, w.mo - 1, w.d)).getUTCDay();
}

function dayMatches(s: CronSchedule, w: Wall): boolean {
  const domOk = s.daysOfMonth.includes(w.d);
  const dowOk = s.daysOfWeek.includes(weekday(w));
  if (s.domRestricted && s.dowRestricted) return domOk || dowOk;
  if (s.domRestricted) return domOk;
  if (s.dowRestricted) return dowOk;
  return true;
}

function nextDay(w: Wall): Wall {
  if (w.d < daysInMonth(w.y, w.mo)) return { y: w.y, mo: w.mo, d: w.d + 1, h: 0, mi: 0 };
  if (w.mo < 12) return { y: w.y, mo: w.mo + 1, d: 1, h: 0, mi: 0 };
  return { y: w.y + 1, mo: 1, d: 1, h: 0, mi: 0 };
}

function addMinute(w: Wall): Wall {
  if (w.mi < 59) return { ...w, mi: w.mi + 1 };
  if (w.h < 23) return { ...w, h: w.h + 1, mi: 0 };
  return nextDay(w);
}

const formatterCache = new Map<string, Intl.DateTimeFormat>();

function formatterFor(timeZone: string): Intl.DateTimeFormat {
  let f = formatterCache.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", {
      timeZone,
      hourCycle: "h23",
      year: "numeric",
      month: "numeric",
      day: "numeric",
      hour: "numeric",
      minute: "numeric",
      second: "numeric",
    });
    formatterCache.set(timeZone, f);
  }
  return f;
}

function isUtc(tz: string | undefined): boolean {
  return tz === undefined || tz === "UTC" || tz === "Etc/UTC" || tz === "GMT";
}

function wallOf(instant: number, timeZone: string | undefined): Wall & { s: number } {
  if (isUtc(timeZone)) {
    const d = new Date(instant);
    return { y: d.getUTCFullYear(), mo: d.getUTCMonth() + 1, d: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), s: d.getUTCSeconds() };
  }
  const parts = formatterFor(timeZone!).formatToParts(new Date(instant));
  const get = (t: Intl.DateTimeFormatPartTypes): number => Number(parts.find((p) => p.type === t)?.value ?? "0");
  return { y: get("year"), mo: get("month"), d: get("day"), h: get("hour") % 24, mi: get("minute"), s: get("second") };
}

function offsetMs(instant: number, timeZone: string): number {
  const flooredInstant = Math.floor(instant / 1000) * 1000;
  const w = wallOf(flooredInstant, timeZone);
  return Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi, w.s) - flooredInstant;
}

/** Convert a wall-clock time in `timeZone` to an instant, or null if it does not exist (DST gap). */
function toInstant(w: Wall, timeZone: string | undefined): number | null {
  const naive = Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi);
  if (isUtc(timeZone)) return naive;
  const tz = timeZone!;
  let inst = naive - offsetMs(naive, tz);
  const off2 = offsetMs(inst, tz);
  if (naive - off2 !== inst) inst = naive - off2;
  const check = wallOf(inst, tz);
  if (check.y !== w.y || check.mo !== w.mo || check.d !== w.d || check.h !== w.h || check.mi !== w.mi) return null;
  return inst;
}

function assertTimeZone(timeZone: string | undefined): void {
  if (isUtc(timeZone)) return;
  try {
    formatterFor(timeZone!);
  } catch {
    throw new CronParseError(`unknown time zone "${timeZone}"`);
  }
}

export interface CronOptions {
  /** IANA time zone for wall-clock evaluation (default UTC). */
  timeZone?: string;
  /** Search horizon in years (default 5). */
  maxYears?: number;
}

/** First fire time strictly after `after`, or null if none within the horizon (e.g. "0 0 30 2 *"). */
export function nextRun(expression: string | CronSchedule, after: Date, opts: CronOptions = {}): Date | null {
  const s = typeof expression === "string" ? parseCron(expression) : expression;
  assertTimeZone(opts.timeZone);
  const afterMs = after.getTime();
  if (!Number.isFinite(afterMs)) throw new CronParseError("invalid reference date");
  const start = wallOf(afterMs, opts.timeZone);
  const limitYear = start.y + (opts.maxYears ?? 5);
  let w: Wall = addMinute({ y: start.y, mo: start.mo, d: start.d, h: start.h, mi: start.mi });
  for (let guard = 0; guard < 500_000; guard++) {
    if (w.y > limitYear) return null;
    if (!s.months.includes(w.mo)) {
      const nm = s.months.find((m) => m > w.mo);
      w = nm !== undefined ? { y: w.y, mo: nm, d: 1, h: 0, mi: 0 } : { y: w.y + 1, mo: s.months[0]!, d: 1, h: 0, mi: 0 };
      continue;
    }
    if (!dayMatches(s, w)) {
      w = nextDay(w);
      continue;
    }
    if (!s.hours.includes(w.h)) {
      const nh = s.hours.find((h) => h > w.h);
      w = nh !== undefined ? { ...w, h: nh, mi: 0 } : nextDay(w);
      continue;
    }
    if (!s.minutes.includes(w.mi)) {
      const nmi = s.minutes.find((m) => m > w.mi);
      if (nmi !== undefined) w = { ...w, mi: nmi };
      else w = w.h < 23 ? { ...w, h: w.h + 1, mi: 0 } : nextDay(w);
      continue;
    }
    const inst = toInstant(w, opts.timeZone);
    if (inst !== null && inst > afterMs) return new Date(inst);
    w = addMinute(w);
  }
  return null;
}

/** The next `count` fire times after `after`. */
export function nextRuns(expression: string | CronSchedule, after: Date, count: number, opts: CronOptions = {}): Date[] {
  const out: Date[] = [];
  let cur = after;
  for (let i = 0; i < Math.min(count, 1000); i++) {
    const n = nextRun(expression, cur, opts);
    if (!n) break;
    out.push(n);
    cur = n;
  }
  return out;
}

/** Fire times in the half-open window (from, to], capped at `limit` (default 1000). */
export function firesBetween(expression: string | CronSchedule, from: Date, to: Date, opts: CronOptions & { limit?: number } = {}): Date[] {
  const out: Date[] = [];
  let cur = from;
  const limit = opts.limit ?? 1000;
  while (out.length < limit) {
    const n = nextRun(expression, cur, opts);
    if (!n || n.getTime() > to.getTime()) break;
    out.push(n);
    cur = n;
  }
  return out;
}

/** True if the schedule fires at the minute containing `at`. */
export function cronMatches(expression: string | CronSchedule, at: Date, opts: CronOptions = {}): boolean {
  const minuteStart = new Date(Math.floor(at.getTime() / 60_000) * 60_000 - 1);
  const n = nextRun(expression, minuteStart, opts);
  return n !== null && Math.floor(n.getTime() / 60_000) === Math.floor(at.getTime() / 60_000);
}

export interface DueCheck {
  due: boolean;
  /** The fire time this run stands for (latest missed fire, missed runs are coalesced). */
  scheduledFor: Date | null;
  /** Number of fire times between the anchor and now (1 = on time, >1 = runs were missed). */
  missedRuns: number;
  /** Next fire time strictly after `now`. */
  nextRunAt: Date | null;
}

/**
 * Is a schedule due? The anchor is the last run, else the schedule's creation time, else one
 * minute ago (so a brand-new schedule does not fire for an old slot). Missed runs (scheduler
 * downtime) are coalesced into a single run for the latest slot.
 */
export function isDue(input: { cron: string; now: Date; lastRunAt?: Date | string | null; createdAt?: Date | string | null; timeZone?: string }): DueCheck {
  const toDate = (v: Date | string | null | undefined): Date | null => (v ? (v instanceof Date ? v : new Date(v)) : null);
  const opts: CronOptions = input.timeZone ? { timeZone: input.timeZone } : {};
  const anchor = toDate(input.lastRunAt) ?? toDate(input.createdAt) ?? new Date(input.now.getTime() - 60_000);
  const fires = firesBetween(input.cron, anchor, input.now, { ...opts, limit: 10_000 });
  const nextRunAt = nextRun(input.cron, input.now, opts);
  const latest = fires.length > 0 ? fires[fires.length - 1]! : null;
  return { due: latest !== null, scheduledFor: latest, missedRuns: fires.length, nextRunAt };
}

// ─── human-readable description ─────────────────────────────────────────────

const DAY_LABELS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTH_LABELS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

function pad2(n: number): string {
  return n.toString().padStart(2, "0");
}

function isFull(values: readonly number[], min: number, max: number): boolean {
  return values.length === max - min + 1;
}

function stepOf(values: readonly number[], min: number, max: number): number | null {
  if (values.length < 2 || values[0] !== min) return null;
  const step = values[1]! - values[0]!;
  for (let i = 1; i < values.length; i++) if (values[i]! - values[i - 1]! !== step) return null;
  return values[values.length - 1]! + step > max ? step : null;
}

function listText(values: readonly number[], label: (n: number) => string): string {
  const labels = values.map(label);
  if (labels.length <= 1) return labels.join("");
  return `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
}

function ordinal(n: number): string {
  const s = ["th", "st", "nd", "rd"];
  const v = n % 100;
  return `${n}${s[(v - 20) % 10] ?? s[v] ?? s[0]}`;
}

/** "Every day at 08:00", "Every 15 minutes", "Mondays at 06:30", "On the 1st at 07:00 in March"… */
export function describeCron(expression: string): string {
  const s = parseCron(expression);
  let time: string;
  const allMinutes = isFull(s.minutes, 0, 59);
  const allHours = isFull(s.hours, 0, 23);
  const minuteStep = stepOf(s.minutes, 0, 59);
  if (allMinutes && allHours) time = "every minute";
  else if (minuteStep !== null && allHours) time = `every ${minuteStep} minutes`;
  else if (allHours && s.minutes.length === 1) time = s.minutes[0] === 0 ? "every hour" : `every hour at ${pad2(s.minutes[0]!)} minutes past`;
  else if (s.hours.length * s.minutes.length <= 6 && !allMinutes) {
    const times: string[] = [];
    for (const h of s.hours) for (const m of s.minutes) times.push(`${pad2(h)}:${pad2(m)}`);
    time = `at ${listText(times.map((_, i) => i), (i) => times[i]!)}`;
  } else {
    const hourStep = stepOf(s.hours, 0, 23);
    const mins = allMinutes ? "every minute" : `at minute ${listText(s.minutes, String)}`;
    time = hourStep !== null ? `${mins} of every ${hourStep} hours` : `${mins} during hour ${listText(s.hours, pad2)}`;
  }
  let days = "";
  if (s.domRestricted && s.dowRestricted) {
    days = ` on the ${listText(s.daysOfMonth, ordinal)} or on ${listText(s.daysOfWeek, (d) => `${DAY_LABELS[d]}s`)}`;
  } else if (s.domRestricted) {
    days = ` on the ${listText(s.daysOfMonth, ordinal)} of the month`;
  } else if (s.dowRestricted) {
    const dows = s.daysOfWeek;
    days = dows.length === 5 && dows.join(",") === "1,2,3,4,5" ? " on weekdays" : ` on ${listText(dows, (d) => `${DAY_LABELS[d]}s`)}`;
  } else {
    days = time.startsWith("at ") ? " every day" : "";
  }
  const months = isFull(s.months, 1, 12) ? "" : ` in ${listText(s.months, (m) => MONTH_LABELS[m - 1]!)}`;
  const text = time.startsWith("at ") ? `${days.trim() ? days.trim().replace(/^on /, "On ").replace(/^every day/, "Every day") : "Every day"} ${time}${months}` : `${time.charAt(0).toUpperCase()}${time.slice(1)}${days}${months}`;
  return text.replace(/\s{2,}/g, " ").trim();
}
