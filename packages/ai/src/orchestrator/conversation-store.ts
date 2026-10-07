import type { AiActionRecord, AiChatRequest, AiMessage, Page } from "@bloody/contracts";

/**
 * Conversation persistence. The API implements it on Postgres (`ai_conversations`,
 * `ai_messages`, `ai_actions` with RLS); {@link InMemoryConversationStore} serves tests and
 * single-process development. Every method is tenant-scoped.
 *
 * Retention: messages expire with the provider's `retentionDays` (0 = message content is not
 * retained at all). Action records are audit artefacts and are kept independently.
 */

export interface AiConversation {
  id: string;
  tenantId: string;
  organizationId: string;
  principalId: string;
  providerId: string | null;
  title: string;
  context: { kind: NonNullable<AiChatRequest["context"]>["kind"]; id?: string };
  createdAt: string;
  updatedAt: string;
  /** When retained message content expires (null = not retained). */
  expiresAt: string | null;
  retainMessages: boolean;
  messageCount: number;
  usage: { inputTokens: number; outputTokens: number; requests: number };
}

export interface StoredAiMessage {
  seq: number;
  at: string;
  /** Content expiry (retentionDays after the message was written); null = no expiry configured. */
  expiresAt: string | null;
  message: AiMessage;
}

export interface ConversationListFilter {
  organizationId?: string;
  principalId?: string;
  limit: number;
  cursor?: string;
}

export interface ConversationStore {
  create(conversation: AiConversation): Promise<void>;
  get(tenantId: string, id: string): Promise<AiConversation | null>;
  update(tenantId: string, id: string, patch: Partial<Pick<AiConversation, "title" | "updatedAt" | "expiresAt" | "retainMessages" | "messageCount" | "usage" | "providerId">>): Promise<void>;
  appendMessages(tenantId: string, conversationId: string, messages: StoredAiMessage[]): Promise<void>;
  /** The most recent `limit` messages, oldest first. */
  listMessages(tenantId: string, conversationId: string, opts?: { limit?: number }): Promise<StoredAiMessage[]>;
  /** Insert or replace action records by id. */
  saveActions(tenantId: string, conversationId: string, actions: AiActionRecord[]): Promise<void>;
  listActions(tenantId: string, conversationId: string): Promise<AiActionRecord[]>;
  getAction(tenantId: string, actionId: string): Promise<{ action: AiActionRecord; organizationId: string } | null>;
  list(tenantId: string, filter: ConversationListFilter): Promise<Page<AiConversation>>;
  /** Delete every message whose `expiresAt` has passed. Returns the number of messages purged. */
  purgeExpired(now: Date): Promise<number>;
}

interface TenantBucket {
  conversations: Map<string, AiConversation>;
  messages: Map<string, StoredAiMessage[]>;
  actions: Map<string, Map<string, AiActionRecord>>;
}

export class InMemoryConversationStore implements ConversationStore {
  private readonly tenants = new Map<string, TenantBucket>();

  private bucket(tenantId: string): TenantBucket {
    let b = this.tenants.get(tenantId);
    if (!b) {
      b = { conversations: new Map(), messages: new Map(), actions: new Map() };
      this.tenants.set(tenantId, b);
    }
    return b;
  }

  async create(conversation: AiConversation): Promise<void> {
    const b = this.bucket(conversation.tenantId);
    if (b.conversations.has(conversation.id)) throw new Error("conversation already exists");
    b.conversations.set(conversation.id, structuredClone(conversation));
  }

  async get(tenantId: string, id: string): Promise<AiConversation | null> {
    const c = this.tenants.get(tenantId)?.conversations.get(id);
    return c ? structuredClone(c) : null;
  }

  async update(tenantId: string, id: string, patch: Parameters<ConversationStore["update"]>[2]): Promise<void> {
    const c = this.tenants.get(tenantId)?.conversations.get(id);
    if (!c) throw new Error("conversation not found");
    Object.assign(c, structuredClone(patch));
  }

  async appendMessages(tenantId: string, conversationId: string, messages: StoredAiMessage[]): Promise<void> {
    const b = this.bucket(tenantId);
    if (!b.conversations.has(conversationId)) throw new Error("conversation not found");
    const list = b.messages.get(conversationId) ?? [];
    list.push(...structuredClone(messages));
    b.messages.set(conversationId, list);
  }

  async listMessages(tenantId: string, conversationId: string, opts: { limit?: number } = {}): Promise<StoredAiMessage[]> {
    const list = this.tenants.get(tenantId)?.messages.get(conversationId) ?? [];
    const limit = opts.limit ?? list.length;
    return structuredClone(list.slice(Math.max(0, list.length - limit)));
  }

  async saveActions(tenantId: string, conversationId: string, actions: AiActionRecord[]): Promise<void> {
    const b = this.bucket(tenantId);
    if (!b.conversations.has(conversationId)) throw new Error("conversation not found");
    const map = b.actions.get(conversationId) ?? new Map<string, AiActionRecord>();
    for (const a of actions) map.set(a.id, structuredClone(a));
    b.actions.set(conversationId, map);
  }

  async listActions(tenantId: string, conversationId: string): Promise<AiActionRecord[]> {
    return structuredClone([...(this.tenants.get(tenantId)?.actions.get(conversationId)?.values() ?? [])]);
  }

  async getAction(tenantId: string, actionId: string): Promise<{ action: AiActionRecord; organizationId: string } | null> {
    const b = this.tenants.get(tenantId);
    if (!b) return null;
    for (const [conversationId, map] of b.actions) {
      const action = map.get(actionId);
      if (action) {
        const conv = b.conversations.get(conversationId);
        if (!conv) return null;
        return { action: structuredClone(action), organizationId: conv.organizationId };
      }
    }
    return null;
  }

  async list(tenantId: string, filter: ConversationListFilter): Promise<Page<AiConversation>> {
    const all = [...(this.tenants.get(tenantId)?.conversations.values() ?? [])]
      .filter((c) => (!filter.organizationId || c.organizationId === filter.organizationId) && (!filter.principalId || c.principalId === filter.principalId))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || b.id.localeCompare(a.id));
    const start = filter.cursor ? all.findIndex((c) => c.id === filter.cursor) + 1 : 0;
    const items = all.slice(start, start + filter.limit);
    const hasMore = start + filter.limit < all.length;
    return { items: structuredClone(items), nextCursor: hasMore ? (items[items.length - 1]?.id ?? null) : null, total: all.length };
  }

  async purgeExpired(now: Date): Promise<number> {
    let purged = 0;
    const iso = now.toISOString();
    for (const b of this.tenants.values()) {
      for (const [conversationId, list] of b.messages) {
        const kept = list.filter((m) => m.expiresAt === null || m.expiresAt > iso);
        purged += list.length - kept.length;
        if (kept.length !== list.length) {
          b.messages.set(conversationId, kept);
          const conv = b.conversations.get(conversationId);
          if (conv) conv.messageCount = kept.length;
        }
      }
    }
    return purged;
  }
}
