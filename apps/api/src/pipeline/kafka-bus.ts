import { randomUUID } from "node:crypto";
import { Kafka, logLevel, type Consumer, type Producer } from "kafkajs";
import type { BusHandler, BusMessage, EventBus } from "./event-bus.js";

export interface KafkaBusOptions {
  brokers: string[];
  clientId?: string;
  /** Consumer group: every API replica with the pipeline enabled shares it (partitions are split). */
  groupId?: string;
  maxAttempts?: number;
  retryDelayMs?: number;
  /** Partitions for topics this bus creates (default 6). */
  partitions?: number;
  /** Suffix of the dead-letter topic (`<topic><suffix>`). */
  deadLetterSuffix?: string;
  onError?: (err: unknown, message: BusMessage<unknown>, final: boolean) => void;
  log?: { warn: (obj: object, msg: string) => void };
}

/**
 * Kafka transport for the data fabric (same contract as InMemoryEventBus): topic = Kafka topic,
 * key = partition key (ordering per key), value = JSON BusMessage. At-least-once: offsets are
 * committed after handlers succeed; a message that still fails after `maxAttempts` goes to
 * `<topic>.dlq` and is committed, so one poison record never blocks a partition.
 *
 * `drain()` waits for the messages THIS process published to be handled (by any replica in the
 * group). It is meant for tests and graceful shutdown, not for cross-replica coordination.
 */
export class KafkaEventBus implements EventBus {
  private readonly kafka: Kafka;
  private readonly handlers = new Map<string, Set<BusHandler<unknown>>>();
  private producer: Producer | null = null;
  private producerReady: Promise<Producer> | null = null;
  private consumer: Consumer | null = null;
  private consumerTopics = new Set<string>();
  private restart: Promise<void> = Promise.resolve();
  private readonly pending = new Map<string, number>();
  private readonly idleWaiters: Array<() => void> = [];
  private deadLetters = 0;
  private closed = false;

  constructor(private readonly opts: KafkaBusOptions) {
    this.kafka = new Kafka({ clientId: opts.clientId ?? "bloody-api", brokers: opts.brokers, logLevel: logLevel.WARN, retry: { retries: 8 } });
  }

  private getProducer(): Promise<Producer> {
    this.producerReady ??= (async () => {
      const p = this.kafka.producer({ allowAutoTopicCreation: true, idempotent: true, maxInFlightRequests: 1 });
      await p.connect();
      this.producer = p;
      return p;
    })();
    return this.producerReady;
  }

  async publish<T>(topic: string, key: string, payload: T): Promise<void> {
    if (this.closed) throw new Error("Event bus is closed");
    const message: BusMessage<unknown> = { id: randomUUID(), topic, key, payload: JSON.parse(JSON.stringify(payload)) as unknown, publishedAt: new Date().toISOString(), attempt: 1 };
    this.pending.set(message.id, Date.now());
    try {
      const producer = await this.getProducer();
      await producer.send({ topic, acks: -1, messages: [{ key, value: JSON.stringify(message) }] });
    } catch (err) {
      this.settle(message.id);
      throw err;
    }
  }

  subscribe<T>(topic: string, handler: BusHandler<T>): () => void {
    const set = this.handlers.get(topic) ?? new Set();
    set.add(handler as BusHandler<unknown>);
    this.handlers.set(topic, set);
    if (!this.consumerTopics.has(topic)) {
      this.consumerTopics.add(topic);
      this.restart = this.restart.then(() => this.startConsumer()).catch((err) => this.opts.log?.warn({ err: String(err) }, "kafka consumer start failed"));
    }
    return () => set.delete(handler as BusHandler<unknown>);
  }

  /** Resolves once the consumer has joined the group (useful before the first publish). */
  ready(): Promise<void> {
    return this.restart;
  }

  private async startConsumer(): Promise<void> {
    if (this.closed) return;
    if (this.consumer) await this.consumer.disconnect();
    // Create the topics first: a consumer that joins before its topic exists starts at "latest"
    // once the topic appears and would skip the first messages.
    const admin = this.kafka.admin();
    await admin.connect();
    try {
      const existing = new Set(await admin.listTopics());
      const missing = [...this.consumerTopics].filter((t) => !existing.has(t));
      if (missing.length) await admin.createTopics({ waitForLeaders: true, topics: missing.map((topic) => ({ topic, numPartitions: this.opts.partitions ?? 6 })) });
    } finally {
      await admin.disconnect();
    }
    const consumer = this.kafka.consumer({ groupId: this.opts.groupId ?? "bloody-pipeline", allowAutoTopicCreation: true });
    await consumer.connect();
    for (const topic of this.consumerTopics) await consumer.subscribe({ topic, fromBeginning: false });
    let joined!: () => void;
    const hasJoined = new Promise<void>((r) => (joined = r));
    const off = consumer.on(consumer.events.GROUP_JOIN, () => joined());
    await consumer.run({ autoCommit: true, eachMessage: async ({ topic, message }) => this.handle(topic, message.value) });
    await Promise.race([hasJoined, new Promise((r) => setTimeout(r, 30_000))]);
    off();
    this.consumer = consumer;
  }

  private async handle(topic: string, value: Buffer | null): Promise<void> {
    if (!value) return;
    let message: BusMessage<unknown>;
    try {
      message = JSON.parse(value.toString("utf8")) as BusMessage<unknown>;
    } catch {
      this.opts.log?.warn({ topic }, "dropping unparseable bus message");
      return;
    }
    const maxAttempts = this.opts.maxAttempts ?? 3;
    try {
      for (const handler of [...(this.handlers.get(topic) ?? [])]) {
        for (let attempt = 1; ; attempt++) {
          try {
            await handler({ ...message, attempt });
            break;
          } catch (err) {
            const final = attempt >= maxAttempts;
            this.opts.onError?.(err, message, final);
            if (final) {
              await this.deadLetter(topic, message, err);
              break;
            }
            await new Promise((r) => setTimeout(r, (this.opts.retryDelayMs ?? 200) * attempt));
          }
        }
      }
    } finally {
      this.settle(message.id);
    }
  }

  private async deadLetter(topic: string, message: BusMessage<unknown>, err: unknown): Promise<void> {
    this.deadLetters++;
    const producer = await this.getProducer();
    await producer.send({
      topic: `${topic}${this.opts.deadLetterSuffix ?? ".dlq"}`,
      messages: [{ key: message.key, value: JSON.stringify(message), headers: { error: String(err instanceof Error ? err.message : err).slice(0, 500) } }],
    });
  }

  private settle(id: string): void {
    this.pending.delete(id);
    if (this.pending.size === 0) for (const w of this.idleWaiters.splice(0)) w();
  }

  drain(): Promise<void> {
    if (this.pending.size === 0) return Promise.resolve();
    return new Promise((resolve) => this.idleWaiters.push(resolve));
  }

  stats(): { depth: number; oldestAgeMs: number; deadLetters: number } {
    let oldest = Infinity;
    for (const at of this.pending.values()) oldest = Math.min(oldest, at);
    return { depth: this.pending.size, oldestAgeMs: oldest === Infinity ? 0 : Date.now() - oldest, deadLetters: this.deadLetters };
  }

  async close(): Promise<void> {
    await Promise.race([this.drain(), new Promise((r) => setTimeout(r, 10_000))]);
    this.closed = true;
    await this.restart.catch(() => undefined);
    await this.consumer?.disconnect().catch(() => undefined);
    await this.producer?.disconnect().catch(() => undefined);
  }
}
