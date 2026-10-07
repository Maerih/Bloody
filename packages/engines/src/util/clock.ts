/**
 * Injected time source. Engines never call `Date.now()` directly so that windows,
 * cooldowns, dormancy and state expiry are deterministic under test and replay.
 */
export interface Clock {
  /** Current time in epoch milliseconds. */
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };

/** Manually driven clock for tests, replays and backfills. */
export class ManualClock implements Clock {
  private current: number;

  constructor(start: number | string | Date = 0) {
    this.current = toEpochMs(start);
  }

  now(): number {
    return this.current;
  }

  set(at: number | string | Date): void {
    this.current = toEpochMs(at);
  }

  advance(ms: number): void {
    this.current += ms;
  }
}

/** Parse an ISO timestamp / Date / epoch ms into epoch ms. Throws on invalid input. */
export function toEpochMs(at: number | string | Date): number {
  const ms = typeof at === "number" ? at : typeof at === "string" ? Date.parse(at) : at.getTime();
  if (!Number.isFinite(ms)) throw new RangeError(`Invalid timestamp: ${String(at)}`);
  return ms;
}

export function toIso(ms: number): string {
  return new Date(ms).toISOString();
}
