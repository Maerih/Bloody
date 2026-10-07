import type { AutomationEvent, AutomationRule, NotificationChannel } from "@bloody/contracts";
import type { NotificationMessage } from "../channels/types.js";

/** Rules port — the API implements it with SQL (`automation_rules`), filtered by tenant. */
export interface AutomationRuleRepository {
  /** Enabled rules of the tenant for an event (any organization scope; the engine filters). */
  listForEvent(tenantId: string, event: AutomationEvent): Promise<AutomationRule[]>;
  get(tenantId: string, id: string): Promise<AutomationRule | null>;
}

/** Channels port — returns only channels of `tenantId`. */
export interface ChannelRepository {
  getMany(tenantId: string, ids: readonly string[]): Promise<NotificationChannel[]>;
}

export interface ThrottleDecision {
  allowed: boolean;
  /** Notifications suppressed in the current window (including this one when not allowed). */
  suppressed: number;
  windowStartedAt: Date;
  windowEndsAt: Date;
}

/**
 * Throttle / de-dup window per key. Production: Valkey `SET key NX PX window` + `INCR`;
 * the in-memory implementation is for tests and single-process deployments.
 */
export interface ThrottleStore {
  hit(key: string, now: Date, windowMs: number): Promise<ThrottleDecision>;
}

export class InMemoryThrottleStore implements ThrottleStore {
  private readonly windows = new Map<string, { startedAt: number; endsAt: number; suppressed: number }>();

  async hit(key: string, now: Date, windowMs: number): Promise<ThrottleDecision> {
    const t = now.getTime();
    if (this.windows.size > 10_000) {
      for (const [k, w] of this.windows) if (w.endsAt <= t) this.windows.delete(k);
    }
    const w = this.windows.get(key);
    if (w && w.endsAt > t) {
      w.suppressed += 1;
      return { allowed: false, suppressed: w.suppressed, windowStartedAt: new Date(w.startedAt), windowEndsAt: new Date(w.endsAt) };
    }
    const fresh = { startedAt: t, endsAt: t + windowMs, suppressed: 0 };
    this.windows.set(key, fresh);
    return { allowed: true, suppressed: 0, windowStartedAt: new Date(fresh.startedAt), windowEndsAt: new Date(fresh.endsAt) };
  }
}

export type DeadLetterStatus = "pending" | "redriven" | "discarded";

/** A notification that could not be delivered after retries. Attachments are dropped (only metadata kept). */
export interface DeadLetter {
  id: string;
  tenantId: string;
  organizationId: string | null;
  ruleId: string | null;
  channelId: string;
  channelKind: string;
  event: string;
  message: Omit<NotificationMessage, "attachments"> & { attachments?: { filename: string; contentType: string; sizeBytes: number }[] };
  error: { code: string; message: string; retryable: boolean };
  attempts: number;
  createdAt: string;
  updatedAt: string;
  status: DeadLetterStatus;
}

export interface DeadLetterStore {
  put(entry: DeadLetter): Promise<void>;
  get(tenantId: string, id: string): Promise<DeadLetter | null>;
  list(tenantId: string, filter?: { status?: DeadLetterStatus; channelId?: string; limit?: number }): Promise<DeadLetter[]>;
  update(entry: DeadLetter): Promise<void>;
}

export class InMemoryDeadLetterStore implements DeadLetterStore {
  readonly rows = new Map<string, DeadLetter>();

  async put(entry: DeadLetter): Promise<void> {
    this.rows.set(entry.id, structuredClone(entry));
  }

  async get(tenantId: string, id: string): Promise<DeadLetter | null> {
    const r = this.rows.get(id);
    return r && r.tenantId === tenantId ? structuredClone(r) : null;
  }

  async list(tenantId: string, filter: { status?: DeadLetterStatus; channelId?: string; limit?: number } = {}): Promise<DeadLetter[]> {
    return [...this.rows.values()]
      .filter((r) => r.tenantId === tenantId)
      .filter((r) => (filter.status ? r.status === filter.status : true))
      .filter((r) => (filter.channelId ? r.channelId === filter.channelId : true))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, filter.limit ?? 100)
      .map((r) => structuredClone(r));
  }

  async update(entry: DeadLetter): Promise<void> {
    if (!this.rows.has(entry.id)) throw new Error(`dead letter ${entry.id} not found`);
    this.rows.set(entry.id, structuredClone(entry));
  }
}

export class InMemoryRuleRepository implements AutomationRuleRepository {
  constructor(private readonly rules: AutomationRule[] = []) {}

  add(rule: AutomationRule): void {
    this.rules.push(rule);
  }

  async listForEvent(tenantId: string, event: AutomationEvent): Promise<AutomationRule[]> {
    return this.rules.filter((r) => r.tenantId === tenantId && r.event === event && r.enabled).map((r) => structuredClone(r));
  }

  async get(tenantId: string, id: string): Promise<AutomationRule | null> {
    const r = this.rules.find((x) => x.id === id && x.tenantId === tenantId);
    return r ? structuredClone(r) : null;
  }
}

export class InMemoryChannelRepository implements ChannelRepository {
  constructor(private readonly channels: NotificationChannel[] = []) {}

  add(channel: NotificationChannel): void {
    this.channels.push(channel);
  }

  async getMany(tenantId: string, ids: readonly string[]): Promise<NotificationChannel[]> {
    return this.channels.filter((c) => c.tenantId === tenantId && ids.includes(c.id)).map((c) => structuredClone(c));
  }
}
