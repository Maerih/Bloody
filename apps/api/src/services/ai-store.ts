import type { AiActionRecord, AiMessage, AiToolTier, Page } from "@bloody/contracts";
import type { AiConversation, ConversationListFilter, ConversationStore, StoredAiMessage } from "@bloody/ai";
import type { Database } from "../db/pool.js";
import { decodeCursor, encodeCursor } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { activeTenants } from "./approvals.js";

/**
 * AI SOC conversation persistence on Postgres (`ai_conversations`, `ai_messages`, `ai_actions`,
 * all RLS-protected). Message content carries a per-message expiry (provider retention); action
 * records are audit artefacts and are kept independently of message retention.
 */

interface ConversationState {
  expiresAt: string | null;
  retainMessages: boolean;
  messageCount: number;
  usage: AiConversation["usage"];
}

function toConversation(r: Row): AiConversation {
  const st = (r.state as Partial<ConversationState>) ?? {};
  const ctx = (r.context as AiConversation["context"]) ?? { kind: "none" };
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: String(r.organization_id),
    principalId: String(r.principal_id),
    providerId: (r.provider_id as string | null) ?? null,
    title: String(r.title ?? ""),
    context: ctx,
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
    expiresAt: st.expiresAt ?? null,
    retainMessages: st.retainMessages ?? false,
    messageCount: Number(st.messageCount ?? 0),
    usage: st.usage ?? { inputTokens: 0, outputTokens: 0, requests: 0 },
  };
}

export function toAiAction(r: Row): AiActionRecord {
  return {
    id: String(r.id),
    conversationId: String(r.conversation_id),
    tool: String(r.tool),
    tier: r.tier as AiToolTier,
    arguments: (r.arguments as Record<string, unknown>) ?? {},
    status: r.status as AiActionRecord["status"],
    result: r.result ?? null,
    requestedBy: String(r.requested_by),
    approvedBy: (r.approved_by as string | null) ?? null,
    at: String(r.at),
  };
}

function toStoredMessage(r: Row): StoredAiMessage {
  const message: AiMessage = { role: r.role as AiMessage["role"], content: String(r.content ?? "") };
  if (r.tool_calls) message.toolCalls = r.tool_calls as NonNullable<AiMessage["toolCalls"]>;
  if (r.tool_call_id) message.toolCallId = String(r.tool_call_id);
  return { seq: Number(r.seq), at: String(r.created_at), expiresAt: (r.expires_at as string | null) ?? null, message };
}

export class PgConversationStore implements ConversationStore {
  constructor(
    private readonly db: Database,
    private readonly now: () => number,
  ) {}

  async create(c: AiConversation): Promise<void> {
    const state: ConversationState = { expiresAt: c.expiresAt, retainMessages: c.retainMessages, messageCount: c.messageCount, usage: c.usage };
    await this.db.withTenant(c.tenantId, (tx) =>
      tx.query(
        `INSERT INTO ai_conversations (id, tenant_id, organization_id, principal_id, provider_id, title, context, state, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10)`,
        [c.id, c.tenantId, c.organizationId, c.principalId, c.providerId, c.title.slice(0, 200), JSON.stringify(c.context), JSON.stringify(state), c.createdAt, c.updatedAt],
      ),
    );
  }

  async get(tenantId: string, id: string): Promise<AiConversation | null> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM ai_conversations WHERE id = $1", [id]);
      return rows[0] ? toConversation(rows[0]) : null;
    });
  }

  async update(tenantId: string, id: string, patch: Parameters<ConversationStore["update"]>[2]): Promise<void> {
    await this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM ai_conversations WHERE id = $1 FOR UPDATE", [id]);
      if (!rows[0]) throw new Error("conversation not found");
      const cur = toConversation(rows[0]);
      const next = { ...cur, ...patch };
      const state: ConversationState = { expiresAt: next.expiresAt, retainMessages: next.retainMessages, messageCount: next.messageCount, usage: next.usage };
      await tx.query("UPDATE ai_conversations SET title = $2, provider_id = $3, state = $4::jsonb, updated_at = $5 WHERE id = $1", [id, next.title.slice(0, 200), next.providerId, JSON.stringify(state), next.updatedAt]);
    });
  }

  async appendMessages(tenantId: string, conversationId: string, messages: StoredAiMessage[]): Promise<void> {
    if (messages.length === 0) return;
    await this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<{ organization_id: string }>("SELECT organization_id FROM ai_conversations WHERE id = $1", [conversationId]);
      if (!rows[0]) throw new Error("conversation not found");
      for (const m of messages) {
        await tx.query(
          `INSERT INTO ai_messages (tenant_id, organization_id, conversation_id, seq, role, content, tool_calls, tool_call_id, expires_at, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10) ON CONFLICT (tenant_id, conversation_id, seq) DO NOTHING`,
          [tenantId, rows[0].organization_id, conversationId, m.seq, m.message.role, m.message.content, m.message.toolCalls ? JSON.stringify(m.message.toolCalls) : null, m.message.toolCallId ?? null, m.expiresAt, m.at],
        );
      }
    });
  }

  async listMessages(tenantId: string, conversationId: string, opts: { limit?: number } = {}): Promise<StoredAiMessage[]> {
    return this.db.withTenant(tenantId, async (tx) => {
      const limit = Math.min(Math.max(opts.limit ?? 10_000, 1), 10_000);
      const { rows } = await tx.query<Row>(
        `SELECT * FROM (SELECT * FROM ai_messages WHERE conversation_id = $1 AND (expires_at IS NULL OR expires_at > $3) ORDER BY seq DESC LIMIT $2) x ORDER BY seq`,
        [conversationId, limit, new Date(this.now()).toISOString()],
      );
      return rows.map(toStoredMessage);
    });
  }

  async saveActions(tenantId: string, conversationId: string, actions: AiActionRecord[]): Promise<void> {
    if (actions.length === 0) return;
    await this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<{ organization_id: string }>("SELECT organization_id FROM ai_conversations WHERE id = $1", [conversationId]);
      if (!rows[0]) throw new Error("conversation not found");
      for (const a of actions) {
        await tx.query(
          `INSERT INTO ai_actions (id, tenant_id, organization_id, conversation_id, tool, tier, arguments, status, result, requested_by, approved_by, at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::jsonb, $10, $11, $12)
           ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, result = EXCLUDED.result, approved_by = EXCLUDED.approved_by, at = EXCLUDED.at`,
          [a.id, tenantId, rows[0].organization_id, conversationId, a.tool, a.tier, JSON.stringify(a.arguments), a.status, a.result === undefined ? null : JSON.stringify(a.result), a.requestedBy, a.approvedBy, a.at],
        );
      }
    });
  }

  async listActions(tenantId: string, conversationId: string): Promise<AiActionRecord[]> {
    return this.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM ai_actions WHERE conversation_id = $1 ORDER BY at, id", [conversationId])).rows.map(toAiAction));
  }

  async getAction(tenantId: string, actionId: string): Promise<{ action: AiActionRecord; organizationId: string } | null> {
    if (!/^[0-9a-f-]{36}$/i.test(actionId)) return null;
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM ai_actions WHERE id = $1", [actionId]);
      return rows[0] ? { action: toAiAction(rows[0]), organizationId: String(rows[0].organization_id) } : null;
    });
  }

  async list(tenantId: string, filter: ConversationListFilter): Promise<Page<AiConversation>> {
    return this.db.withTenant(tenantId, async (tx) => {
      const params: unknown[] = [];
      const where: string[] = ["TRUE"];
      if (filter.organizationId) where.push(`organization_id = $${params.push(filter.organizationId)}`);
      if (filter.principalId) where.push(`principal_id = $${params.push(filter.principalId)}`);
      const cursor = decodeCursor(filter.cursor);
      if (cursor) where.push(`(updated_at, id) < ($${params.push(cursor[0])}::timestamptz, $${params.push(cursor[1])}::uuid)`);
      const limit = Math.min(Math.max(filter.limit, 1), 200);
      params.push(limit + 1);
      const { rows } = await tx.query<Row>(`SELECT * FROM ai_conversations WHERE ${where.join(" AND ")} ORDER BY updated_at DESC, id DESC LIMIT $${params.length}`, params);
      const items = rows.slice(0, limit).map(toConversation);
      const last = items[items.length - 1];
      return { items, nextCursor: rows.length > limit && last ? encodeCursor([last.updatedAt, last.id]) : null };
    });
  }

  /** Delete expired message content in every active tenant (retention). */
  async purgeExpired(now: Date): Promise<number> {
    let purged = 0;
    for (const t of await activeTenants(this.db)) purged += await this.purgeTenant(t.id, now);
    return purged;
  }

  async purgeTenant(tenantId: string, now: Date): Promise<number> {
    return this.db.withTenant(tenantId, async (tx) => {
      // messageCount is the monotonic sequence of the transcript (it is never lowered, so the next
      // appended message can never collide with a retained one).
      const res = await tx.query("DELETE FROM ai_messages WHERE expires_at IS NOT NULL AND expires_at <= $1", [now.toISOString()]);
      return res.rowCount ?? 0;
    });
  }
}
