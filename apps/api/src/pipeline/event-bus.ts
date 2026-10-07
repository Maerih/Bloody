import { randomUUID } from "node:crypto";

/**
 * Data-fabric abstraction. The single-process deployment uses {@link InMemoryEventBus}; a Kafka
 * transport implements the same interface (topic = Kafka topic, key = partition key, payload =
 * JSON value), so nothing upstream or downstream changes when the backbone is swapped.
 *
 * Delivery semantics: at-least-once, ordered per (topic, key). Consumers must be idempotent —
 * the analytics pipeline is (deterministic alert ids, upserts, ON CONFLICT DO NOTHING).
 */
export interface BusMessage<T> {
  id: string;
  topic: string;
  key: string;
  payload: T;
  publishedAt: string;
  attempt: number;
}

export type BusHandler<T> = (message: BusMessage<T>) => Promise<void>;

export interface EventBus {
  publish<T>(topic: string, key: string, payload: T): Promise<void>;
  subscribe<T>(topic: string, handler: BusHandler<T>): () => void;
  /** Resolve once every message published so far has been handled (or dead-lettered). */
  drain(): Promise<void>;
  stats(): { depth: number; oldestAgeMs: number; deadLetters: number };
  close(): Promise<void>;
}

export const TOPICS = {
  eventsIngested: "bloody.events.ingested.v1",
} as const;

interface Pending {
  message: BusMessage<unknown>;
  enqueuedAt: number;
}

export interface InMemoryBusOptions {
  maxAttempts?: number;
  retryDelayMs?: number;
  onError?: (err: unknown, message: BusMessage<unknown>, final: boolean) => void;
}

/** In-process bus: one serial queue per (topic, key), queues run concurrently. */
export class InMemoryEventBus implements EventBus {
  private readonly handlers = new Map<string, Set<BusHandler<unknown>>>();
  private readonly queues = new Map<string, Pending[]>();
  private readonly running = new Set<string>();
  private readonly idleWaiters: Array<() => void> = [];
  private readonly deadLetters: Array<BusMessage<unknown>> = [];
  private closed = false;

  constructor(private readonly options: InMemoryBusOptions = {}) {}

  async publish<T>(topic: string, key: string, payload: T): Promise<void> {
    if (this.closed) throw new Error("Event bus is closed");
    // Serialize like a real broker would: consumers never share mutable state with producers.
    const message: BusMessage<unknown> = { id: randomUUID(), topic, key, payload: JSON.parse(JSON.stringify(payload)) as unknown, publishedAt: new Date().toISOString(), attempt: 1 };
    const qk = `${topic}\u0000${key}`;
    const q = this.queues.get(qk) ?? [];
    q.push({ message, enqueuedAt: Date.now() });
    this.queues.set(qk, q);
    if (!this.running.has(qk)) void this.run(qk);
  }

  subscribe<T>(topic: string, handler: BusHandler<T>): () => void {
    const set = this.handlers.get(topic) ?? new Set();
    set.add(handler as BusHandler<unknown>);
    this.handlers.set(topic, set);
    return () => set.delete(handler as BusHandler<unknown>);
  }

  private async run(qk: string): Promise<void> {
    this.running.add(qk);
    try {
      const q = this.queues.get(qk)!;
      while (q.length > 0) {
        const item = q[0]!;
        await this.deliver(item.message);
        q.shift();
      }
      this.queues.delete(qk);
    } finally {
      this.running.delete(qk);
      if (this.running.size === 0 && [...this.queues.values()].every((x) => x.length === 0)) {
        for (const w of this.idleWaiters.splice(0)) w();
      }
    }
  }

  private async deliver(message: BusMessage<unknown>): Promise<void> {
    const handlers = [...(this.handlers.get(message.topic) ?? [])];
    const maxAttempts = this.options.maxAttempts ?? 3;
    for (const handler of handlers) {
      for (let attempt = 1; ; attempt++) {
        try {
          await handler({ ...message, attempt });
          break;
        } catch (err) {
          const final = attempt >= maxAttempts;
          this.options.onError?.(err, message, final);
          if (final) {
            this.deadLetters.push(message);
            break;
          }
          await new Promise((r) => setTimeout(r, (this.options.retryDelayMs ?? 200) * attempt));
        }
      }
    }
  }

  drain(): Promise<void> {
    if (this.running.size === 0 && [...this.queues.values()].every((q) => q.length === 0)) return Promise.resolve();
    return new Promise((resolve) => this.idleWaiters.push(resolve));
  }

  stats(): { depth: number; oldestAgeMs: number; deadLetters: number } {
    let depth = 0;
    let oldest = Infinity;
    for (const q of this.queues.values()) {
      depth += q.length;
      if (q[0]) oldest = Math.min(oldest, q[0].enqueuedAt);
    }
    return { depth, oldestAgeMs: oldest === Infinity ? 0 : Date.now() - oldest, deadLetters: this.deadLetters.length };
  }

  deadLettered(): ReadonlyArray<BusMessage<unknown>> {
    return this.deadLetters;
  }

  async close(): Promise<void> {
    await this.drain();
    this.closed = true;
  }
}
