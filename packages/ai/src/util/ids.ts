import { randomUUID } from "node:crypto";

export type IdGenerator = () => string;

/** RFC 4122 v4 UUIDs (conversation, action and audit ids are UUIDs in the contracts). */
export const uuidGenerator: IdGenerator = () => randomUUID();

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export type SleepFn = (ms: number, signal?: AbortSignal) => Promise<void>;

/** Abortable sleep. Rejects with the signal's reason when aborted. */
export const defaultSleep: SleepFn = (ms, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error("aborted"));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, Math.max(0, ms));
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason ?? new Error("aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
