export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export type JsonParseResult = { ok: true; value: unknown } | { ok: false; error: string };

export function safeJsonParse(text: string): JsonParseResult {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Deterministic JSON (sorted object keys) — used for de-duplication keys and hashing. */
export function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value, new WeakSet()));
}

function sortKeys(value: unknown, seen: WeakSet<object>): unknown {
  if (Array.isArray(value)) return value.map((v) => sortKeys(v, seen));
  if (isRecord(value)) {
    if (seen.has(value)) return "[circular]";
    seen.add(value);
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) out[key] = sortKeys(value[key], seen);
    return out;
  }
  return value;
}

/** JSON.stringify that never throws (cycles / BigInt are rendered as strings). */
export function safeStringify(value: unknown): string {
  const seen = new WeakSet<object>();
  try {
    return (
      JSON.stringify(value, (_key, v: unknown) => {
        if (typeof v === "bigint") return v.toString();
        if (typeof v === "object" && v !== null) {
          if (seen.has(v)) return "[circular]";
          seen.add(v);
        }
        return v;
      }) ?? "null"
    );
  } catch {
    return '"[unserializable]"';
  }
}

export function truncate(text: string, max: number, suffix = "…[truncated]"): string {
  if (text.length <= max) return text;
  if (max <= suffix.length) return text.slice(0, max);
  return text.slice(0, max - suffix.length) + suffix;
}
