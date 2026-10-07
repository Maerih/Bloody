import type { UpsertOptions } from "./types.js";

/**
 * Shallow prop merge used by every store implementation so semantics are identical:
 * incoming keys win, undefined values are ignored, observation bookkeeping is applied.
 */
export function mergeProps(existing: Record<string, unknown> | undefined, incoming: Record<string, unknown> | undefined, options?: UpsertOptions): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(existing ?? {}) };
  for (const [k, v] of Object.entries(incoming ?? {})) {
    if (v === undefined) continue;
    if (k === "firstSeenAt" || k === "lastSeenAt" || k === "seenCount") continue; // reserved
    out[k] = v;
  }
  if (options?.observedAt) {
    const at = options.observedAt;
    const first = typeof out.firstSeenAt === "string" ? out.firstSeenAt : null;
    const last = typeof out.lastSeenAt === "string" ? out.lastSeenAt : null;
    out.firstSeenAt = first === null || Date.parse(at) < Date.parse(first) ? at : first;
    out.lastSeenAt = last === null || Date.parse(at) > Date.parse(last) ? at : last;
    out.seenCount = (typeof out.seenCount === "number" ? out.seenCount : 0) + 1;
  }
  return out;
}

export function propString(props: Record<string, unknown> | undefined, key: string): string | undefined {
  const v = props?.[key];
  return typeof v === "string" ? v : undefined;
}

export function propNumber(props: Record<string, unknown> | undefined, key: string): number | undefined {
  const v = props?.[key];
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

export function propBool(props: Record<string, unknown> | undefined, key: string): boolean | undefined {
  const v = props?.[key];
  return typeof v === "boolean" ? v : undefined;
}
