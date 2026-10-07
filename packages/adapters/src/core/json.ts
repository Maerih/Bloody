/**
 * Defensive accessors for untrusted, vendor-shaped JSON.
 *
 * Engine output is never trusted to match its documentation: fields go missing, change
 * type between versions ("1709633472" vs 1709633472), use sentinel strings ("-", "(null)")
 * or switch between flat dotted keys (`"id.orig_h"`) and nested objects. Every normalizer
 * reads through these helpers so a malformed record degrades to "field absent" instead of
 * throwing or leaking a wrongly-typed value into the canonical event.
 */

export type JsonRecord = Record<string, unknown>;

export function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Values engines use to mean "no value". Treated as absent by {@link str}. */
const NULLISH_STRINGS = new Set(["", "-", "(null)", "null", "NULL", "n/a", "N/A", "(empty)", "none", "None", "unknown", "Unknown"]);

/**
 * Read a field by dotted path. Supports nested objects (`a.b.c`), flat dotted keys
 * (`{"id.orig_h": …}`) and any mix of the two (`{"id": {"orig_h": …}}`).
 */
export function field(obj: unknown, path: string): unknown {
  if (!isRecord(obj)) return undefined;
  if (Object.prototype.hasOwnProperty.call(obj, path)) return obj[path];
  const parts = path.split(".");
  if (parts.length === 1) return undefined;
  for (let i = 1; i < parts.length; i++) {
    const head = parts.slice(0, i).join(".");
    if (Object.prototype.hasOwnProperty.call(obj, head)) {
      const found = field(obj[head], parts.slice(i).join("."));
      if (found !== undefined) return found;
    }
  }
  return undefined;
}

/** Non-empty trimmed string, or undefined. Numbers/booleans are stringified. */
export function str(value: unknown): string | undefined {
  if (typeof value === "string") {
    const t = value.trim();
    return NULLISH_STRINGS.has(t) ? undefined : t;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  return undefined;
}

/** Like {@link str} but keeps every non-empty string verbatim (no sentinel filtering). */
export function rawStr(value: unknown): string | undefined {
  if (typeof value === "string") return value.length > 0 ? value : undefined;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

/** Finite number from a number or numeric string (decimal or 0x-hex). */
export function num(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "string") {
    const t = value.trim();
    if (t === "") return undefined;
    if (/^0x[0-9a-f]+$/i.test(t)) {
      const n = Number.parseInt(t.slice(2), 16);
      return Number.isFinite(n) ? n : undefined;
    }
    if (!/^[+-]?(\d+(\.\d*)?|\.\d+)(e[+-]?\d+)?$/i.test(t)) return undefined;
    const n = Number(t);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

/** Safe integer (truncated) from a number or numeric string. */
export function int(value: unknown): number | undefined {
  const n = num(value);
  if (n === undefined) return undefined;
  const t = Math.trunc(n);
  return Number.isSafeInteger(t) ? t : undefined;
}

/** Non-negative safe integer (sizes, byte counts, ports, pids). */
export function uint(value: unknown): number | undefined {
  const n = int(value);
  return n !== undefined && n >= 0 ? n : undefined;
}

/** TCP/UDP port (0..65535). */
export function port(value: unknown): number | undefined {
  const n = uint(value);
  return n !== undefined && n <= 65535 ? n : undefined;
}

export function bool(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value === 1 ? true : value === 0 ? false : undefined;
  if (typeof value === "string") {
    const t = value.trim().toLowerCase();
    if (["true", "yes", "y", "1", "on", "t"].includes(t)) return true;
    if (["false", "no", "n", "0", "off", "f"].includes(t)) return false;
  }
  return undefined;
}

/** Array view: arrays pass through, null/undefined become [], scalars become [value]. */
export function arr(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

/** Array of non-empty strings (see {@link str}). */
export function strArr(value: unknown): string[] {
  const out: string[] = [];
  for (const v of arr(value)) {
    const s = str(v);
    if (s !== undefined) out.push(s);
  }
  return out;
}

export function rec(value: unknown): JsonRecord | undefined {
  return isRecord(value) ? value : undefined;
}

/** First argument that is not undefined. */
export function first<T>(...values: Array<T | undefined>): T | undefined {
  for (const v of values) if (v !== undefined) return v;
  return undefined;
}

type Compacted<T> = { [K in keyof T]?: Exclude<T[K], undefined> };

/**
 * Drop `undefined` (and empty-array) properties; return undefined when nothing is left so
 * canonical events never carry empty `{}` sub-objects.
 */
export function compact<T extends object>(obj: T): Compacted<T> | undefined {
  const out: Record<string, unknown> = {};
  let n = 0;
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    out[k] = v;
    n++;
  }
  return n === 0 ? undefined : (out as Compacted<T>);
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

/** File name from a Windows or POSIX path. */
export function basename(path: string | undefined): string | undefined {
  if (!path) return undefined;
  const parts = path.split(/[\\/]/);
  const last = parts[parts.length - 1];
  return last && last.length > 0 ? last : undefined;
}

/** Unique values preserving first-seen order. */
export function unique<T>(values: Iterable<T>, keyOf: (v: T) => string = (v) => String(v)): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const v of values) {
    const k = keyOf(v);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  return out;
}

/** Deep-clone a JSON value while replacing the listed keys (case-insensitive, any depth). */
export function redactKeys(value: unknown, keys: ReadonlySet<string>, replacement = "[REDACTED]"): unknown {
  if (Array.isArray(value)) return value.map((v) => redactKeys(v, keys, replacement));
  if (!isRecord(value)) return value;
  const out: JsonRecord = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = keys.has(k.toLowerCase()) ? replacement : redactKeys(v, keys, replacement);
  }
  return out;
}

/** Remove the listed top-level/nested keys entirely (case-insensitive, any depth). */
export function omitKeys(value: unknown, keys: ReadonlySet<string>): unknown {
  if (Array.isArray(value)) return value.map((v) => omitKeys(v, keys));
  if (!isRecord(value)) return value;
  const out: JsonRecord = {};
  for (const [k, v] of Object.entries(value)) {
    if (keys.has(k.toLowerCase())) continue;
    out[k] = omitKeys(v, keys);
  }
  return out;
}
