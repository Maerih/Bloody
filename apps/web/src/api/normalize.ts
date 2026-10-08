import type { AiActionRecord, AiMessage, AttackPath, CanonicalEvent, GraphEdge, GraphNode, Subgraph } from "@bloody/contracts";
import type {
  AiChatResult,
  AiConversationDetail,
  AiConversationSummary,
  AiProviderTestResult,
  AiThreadMessage,
  AttackPathResult,
  AttackPathSummaryView,
  EventSearchResult,
  RemediationPriorityView,
} from "./types";

/**
 * Pure normalizers for endpoints whose envelope differs between deployments or API versions
 * (bare arrays vs `Page<T>`, `{ nodes, edges }` vs `{ graph }`, stored vs plain AI messages).
 * They never invent values: missing data stays missing.
 */

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
const str = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** First array found under any of `keys` (or the value itself when it is an array). */
export function pickArray<T = unknown>(raw: unknown, keys: string[] = ["items", "results", "data"]): T[] {
  if (Array.isArray(raw)) return raw as T[];
  if (!isRecord(raw)) return [];
  for (const k of keys) {
    const v = raw[k];
    if (Array.isArray(v)) return v as T[];
  }
  return [];
}

function isGraphNode(v: unknown): v is GraphNode {
  return isRecord(v) && typeof v.id === "string" && typeof v.kind === "string";
}
function isGraphEdge(v: unknown): v is GraphEdge {
  return isRecord(v) && typeof v.id === "string" && typeof v.from === "string" && typeof v.to === "string";
}

function cleanNode(n: GraphNode): GraphNode {
  return { ...n, key: n.key ?? n.id, label: n.label || n.key || n.id, organizationId: n.organizationId ?? null, props: isRecord(n.props) ? n.props : {} };
}

/** `{nodes, edges}` | `{graph: {nodes, edges}}` | `{subgraph}` → deduplicated Subgraph without dangling edges. */
export function toSubgraph(raw: unknown): Subgraph {
  const src = isRecord(raw) && isRecord(raw.graph) ? raw.graph : isRecord(raw) && isRecord(raw.subgraph) ? raw.subgraph : raw;
  const nodes = new Map<string, GraphNode>();
  for (const n of pickArray(src, ["nodes"])) if (isGraphNode(n)) nodes.set(n.id, cleanNode(n));
  // A neighbors response may carry the centre node separately.
  if (isRecord(src) && isGraphNode(src.node) && !nodes.has(src.node.id)) nodes.set(src.node.id, cleanNode(src.node));
  const edges = new Map<string, GraphEdge>();
  for (const e of pickArray(src, ["edges"])) {
    if (isGraphEdge(e) && nodes.has(e.from) && nodes.has(e.to)) edges.set(e.id, { ...e, props: isRecord(e.props) ? e.props : {} });
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

/** Merge subgraphs (expanding neighbors in the explorer). Later nodes refresh earlier copies. */
export function mergeSubgraphs(...graphs: Subgraph[]): Subgraph {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  for (const g of graphs) {
    for (const n of g.nodes) nodes.set(n.id, n);
    for (const e of g.edges) edges.set(e.id, e);
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()].filter((e) => nodes.has(e.from) && nodes.has(e.to)) };
}

export function toGraphNodes(raw: unknown): GraphNode[] {
  return pickArray(raw, ["items", "nodes", "results", "hits"]).filter(isGraphNode).map(cleanNode);
}

function toRemediation(raw: unknown): RemediationPriorityView | null {
  if (!isRecord(raw) || typeof raw.action !== "string") return null;
  const out: RemediationPriorityView = { action: raw.action, pathsBroken: num(raw.pathsBroken) ?? 0 };
  if (str(raw.nodeId)) out.nodeId = raw.nodeId as string;
  if (str(raw.edgeId)) out.edgeId = raw.edgeId as string;
  if (num(raw.marginalPathsBroken) !== null) out.marginalPathsBroken = raw.marginalPathsBroken as number;
  if (num(raw.riskReduced) !== null) out.riskReduced = raw.riskReduced as number;
  if (raw.rank === null || num(raw.rank) !== null) out.rank = raw.rank as number | null;
  if (raw.effort === "low" || raw.effort === "medium" || raw.effort === "high") out.effort = raw.effort;
  if (str(raw.category)) out.category = raw.category as string;
  return out;
}

function isAttackPath(v: unknown): v is AttackPath {
  return isRecord(v) && typeof v.id === "string" && Array.isArray(v.nodes) && isRecord(v.risk) && isRecord(v.target) && isRecord(v.entry);
}

/** `AttackPathAnalysis` (`{paths, remediations, summary}`), `Page<AttackPath>` or `AttackPath[]`. */
export function toAttackPathResult(raw: unknown): AttackPathResult {
  const paths = pickArray(raw, ["paths", "items"]).filter(isAttackPath).map((p) => ({ ...p, edges: Array.isArray(p.edges) ? p.edges : [], remediations: Array.isArray(p.remediations) ? p.remediations : [] }));
  const remediations = isRecord(raw) ? pickArray(raw, ["remediations"]).map(toRemediation).filter((r): r is RemediationPriorityView => r !== null) : [];
  let summary: AttackPathSummaryView | null = null;
  if (isRecord(raw) && isRecord(raw.summary) && num(raw.summary.totalPaths) !== null) summary = raw.summary as unknown as AttackPathSummaryView;
  return { paths, remediations, summary };
}

export function toEventSearchResult(raw: unknown): EventSearchResult {
  const items = pickArray<CanonicalEvent>(raw, ["items", "events", "results", "hits"]).filter((e) => isRecord(e) && typeof e.id === "string");
  const rec = isRecord(raw) ? raw : {};
  const out: EventSearchResult = { items, nextCursor: str(rec.nextCursor) };
  if (num(rec.total) !== null) out.total = rec.total as number;
  if (typeof rec.truncated === "boolean") out.truncated = rec.truncated;
  return out;
}

function toAiMessage(raw: unknown): AiMessage | null {
  if (!isRecord(raw)) return null;
  const role = raw.role;
  if (role !== "system" && role !== "user" && role !== "assistant" && role !== "tool") return null;
  const msg: AiMessage = { role, content: typeof raw.content === "string" ? raw.content : "" };
  if (typeof raw.toolCallId === "string") msg.toolCallId = raw.toolCallId;
  if (Array.isArray(raw.toolCalls)) {
    msg.toolCalls = raw.toolCalls
      .filter((c): c is Record<string, unknown> => isRecord(c) && typeof c.name === "string")
      .map((c, i) => ({ id: str(c.id) ?? `call-${i}`, name: c.name as string, arguments: isRecord(c.arguments) ? c.arguments : {} }));
  }
  return msg;
}

/** Stored messages (`{seq, at, message}`) or plain `AiMessage`s, system prompts removed. */
export function toThreadMessages(raw: unknown): AiThreadMessage[] {
  const list = pickArray(raw, ["messages", "items"]);
  const out: AiThreadMessage[] = [];
  list.forEach((entry, index) => {
    const stored = isRecord(entry) && isRecord(entry.message);
    const message = toAiMessage(stored ? (entry as Record<string, unknown>).message : entry);
    if (!message || message.role === "system") return;
    const rec = entry as Record<string, unknown>;
    out.push({ seq: num(rec.seq) ?? index, at: str(rec.at) ?? str(rec.createdAt), message });
  });
  return out.sort((a, b) => a.seq - b.seq);
}

function toConversationSummary(raw: unknown, fallbackId?: string): AiConversationSummary | null {
  if (!isRecord(raw)) return null;
  const id = str(raw.id) ?? fallbackId;
  if (!id) return null;
  const now = new Date(0).toISOString();
  const ctx = isRecord(raw.context) && typeof raw.context.kind === "string" ? (raw.context as AiConversationSummary["context"]) : null;
  return {
    id,
    title: str(raw.title),
    organizationId: str(raw.organizationId),
    context: ctx,
    providerId: str(raw.providerId),
    model: str(raw.model),
    createdAt: str(raw.createdAt) ?? str(raw.updatedAt) ?? now,
    updatedAt: str(raw.updatedAt) ?? str(raw.createdAt) ?? now,
    messageCount: num(raw.messageCount),
  };
}

export function toConversationList(raw: unknown): AiConversationSummary[] {
  return pickArray(raw, ["items", "conversations"])
    .map((c) => toConversationSummary(c))
    .filter((c): c is AiConversationSummary => c !== null)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function isActionRecord(v: unknown): v is AiActionRecord {
  return isRecord(v) && typeof v.id === "string" && typeof v.tool === "string" && typeof v.tier === "string" && typeof v.status === "string";
}

/** GET /ai/conversations/:id — `{conversation, messages, actions}` or a flat conversation with messages. */
export function toConversationDetail(raw: unknown, id: string): AiConversationDetail {
  const rec = isRecord(raw) ? raw : {};
  const conversation = toConversationSummary(isRecord(rec.conversation) ? rec.conversation : rec, id) ?? toConversationSummary({ id })!;
  return {
    conversation,
    messages: toThreadMessages(rec.messages ?? []),
    actions: pickArray(rec, ["actions"]).filter(isActionRecord),
  };
}

/** POST /ai/chat → AiRunResult subset the UI needs. */
export function toChatResult(raw: unknown): AiChatResult {
  const rec = isRecord(raw) ? raw : {};
  const servedBy = isRecord(rec.servedBy) ? rec.servedBy : {};
  const tier = rec.maxToolTier;
  return {
    conversationId: str(rec.conversationId) ?? "",
    providerId: str(rec.providerId) ?? str(servedBy.providerId),
    model: str(rec.model) ?? str(servedBy.model),
    answer: typeof rec.answer === "string" ? rec.answer : "",
    finishReason: str(rec.finishReason),
    actions: pickArray(rec, ["actions"]).filter(isActionRecord),
    maxToolTier: tier === "read" || tier === "investigate" || tier === "recommend" || tier === "require_approval" || tier === "execute" ? tier : null,
    fallbackUsed: rec.fallbackUsed === true,
  };
}

/** Provider health (`{ok}` / `{healthy}` / `{status: "ok"}`) → uniform result. */
export function toProviderTestResult(raw: unknown): AiProviderTestResult {
  const rec = isRecord(raw) ? raw : {};
  const ok = rec.ok === true || rec.healthy === true || rec.status === "ok" || rec.status === "healthy";
  const models = pickArray(rec, ["models"])
    .map((m) => (typeof m === "string" ? m : isRecord(m) ? str(m.id) ?? str(m.name) : null))
    .filter((m): m is string => m !== null);
  return {
    ok,
    latencyMs: num(rec.latencyMs),
    message: str(rec.message) ?? str(rec.detail) ?? str(rec.error),
    models,
  };
}
