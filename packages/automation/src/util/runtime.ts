import { createHash, randomUUID } from "node:crypto";

/** Injected wall clock (tests pin time; production uses {@link systemClock}). */
export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

/** Produces unique ids (UUID v4 in production — contracts require UUIDs for persisted ids). */
export type IdGenerator = () => string;

export const uuidIds: IdGenerator = () => randomUUID();

/** Delay used between retries; injected so tests never wait. */
export type SleepFn = (ms: number) => Promise<void>;

export const defaultSleep: SleepFn = (ms) => new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, ms)));

/** Uniform random in [0,1); injected for deterministic jitter in tests. */
export type RandomFn = () => number;

/** Canonical JSON: object keys sorted recursively, so equal values hash identically. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value instanceof Date) return value.toISOString();
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}

/** Short, stable SHA-256 based digest of any JSON-able value (hex, `length` chars). */
export function stableHash(value: unknown, length = 32): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex").slice(0, length);
}

/** Exponential backoff with "equal jitter": half fixed, half random — avoids thundering herds. */
export interface RetryPolicy {
  /** Total attempts including the first one (>= 1). */
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  factor: number;
}

export const DEFAULT_RETRY: RetryPolicy = { maxAttempts: 3, baseDelayMs: 1_000, maxDelayMs: 30_000, factor: 2 };

export function backoffDelay(policy: RetryPolicy, attempt: number, random: RandomFn = Math.random): number {
  const exp = Math.min(policy.maxDelayMs, policy.baseDelayMs * Math.pow(policy.factor, Math.max(0, attempt - 1)));
  const half = exp / 2;
  return Math.round(half + random() * half);
}

/** Error message extraction that never throws on odd values. */
export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

/** Truncate a string to `max` characters, appending an ellipsis when cut. */
export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}
