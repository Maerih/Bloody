import type { AiActionRecord, AiMessage } from "@bloody/contracts";
import { clsx } from "clsx";
import { Bot, Check, ChevronDown, ChevronRight, LoaderCircle, Send, ShieldAlert, User, Wrench, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { errorMessage } from "../../api/client";
import { useAiChat, useAiConversation, useApproveAiAction, useRejectAiAction } from "../../api/hooks";
import type { AiChatResult, AiContextKind, AiThreadMessage } from "../../api/types";
import { useSession } from "../../app/session";
import { StatusBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Textarea } from "../../components/Form";
import { JsonView } from "../../components/JsonView";
import { RelativeTime } from "../../components/RelativeTime";
import { SkeletonText } from "../../components/Skeleton";
import { TierBadge } from "../../components/TierBadge";
import { humanize } from "../../lib/format";
import { isOwnRequest } from "../response/ResponseActionsTable";

export interface AiContextRef {
  kind: AiContextKind;
  id?: string;
}

/** Starter prompts per context (product copy, not data). */
const SUGGESTIONS: Record<AiContextKind, string[]> = {
  incident: ["Summarize this incident and the most likely root cause", "Which assets and identities are affected, and how?", "Recommend containment actions with their risk", "Draft a customer update for this incident"],
  investigation: ["Summarize the evidence collected so far", "What gaps remain in this investigation?", "Build a timeline of attacker activity", "Recommend next investigative steps"],
  asset: ["Explain this asset's risk score", "Which attack paths reach this asset?", "Show recent suspicious activity on this host", "What should we patch first here?"],
  identity: ["Is this identity compromised?", "What can this identity access?", "Summarize risky sign-ins in the last 7 days", "Recommend identity hardening steps"],
  indicator: ["Where has this indicator been seen in our environment?", "What do we know about the associated actor?", "Should we block it? What would break?", "Hunt for related infrastructure"],
  alert: ["Is this alert a true positive?", "Explain what this detection means", "Find related alerts and events", "Suggest tuning to reduce false positives"],
  none: ["Summarize today's critical incidents", "Which assets have the highest exposure?", "Hunt for encoded PowerShell in the last 24 hours", "Write a Sigma rule for suspicious LSASS access"],
};

interface ToolCallView {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
  action: AiActionRecord | null;
}

/** Pair assistant tool calls with the gateway's action records (same tool, in order). */
export function pairToolCalls(messages: AiThreadMessage[], actions: AiActionRecord[]): { calls: Map<number, ToolCallView[]>; unmatched: AiActionRecord[] } {
  const queues = new Map<string, AiActionRecord[]>();
  for (const a of [...actions].sort((x, y) => x.at.localeCompare(y.at))) {
    const q = queues.get(a.tool) ?? [];
    q.push(a);
    queues.set(a.tool, q);
  }
  const calls = new Map<number, ToolCallView[]>();
  for (const m of messages) {
    if (m.message.role !== "assistant" || !m.message.toolCalls?.length) continue;
    calls.set(
      m.seq,
      m.message.toolCalls.map((c) => ({ ...c, action: queues.get(c.name)?.shift() ?? null })),
    );
  }
  const unmatched = [...queues.values()].flat();
  return { calls, unmatched };
}

function ActionDecision({ action, conversationId, organizationId }: { action: AiActionRecord; conversationId: string | null; organizationId: string | null }) {
  const session = useSession();
  const approve = useApproveAiAction();
  const reject = useRejectAiAction();
  if (action.status !== "pending_approval") return null;
  const canApprove = session.can("response:approve", organizationId);
  if (!canApprove) return <span className="text-xs text-fg-subtle">Waiting for an approver with response-approval rights.</span>;
  if (isOwnRequest(action, session.principal.id)) return <span className="text-xs text-fg-subtle">Requested in your session — a different approver must decide.</span>;
  const pending = approve.isPending || reject.isPending;
  const error = approve.error ?? reject.error;
  return (
    <div className="mt-1.5 flex flex-wrap items-center gap-1.5" data-testid="ai-action-decision">
      <Button size="xs" variant="success" icon={Check} disabled={pending} loading={approve.isPending} onClick={() => approve.mutate({ id: action.id, ...(conversationId ? { conversationId } : {}) })}>
        Approve
      </Button>
      <Button size="xs" icon={X} disabled={pending} loading={reject.isPending} onClick={() => reject.mutate({ id: action.id, reason: "Rejected by analyst", ...(conversationId ? { conversationId } : {}) })}>
        Reject
      </Button>
      {approve.isSuccess ? <span className="text-xs text-healthy">Approved</span> : null}
      {reject.isSuccess ? <span className="text-xs text-fg-muted">Rejected</span> : null}
      {error ? (
        <span role="alert" className="text-xs text-sev-critical">
          {errorMessage(error)}
        </span>
      ) : null}
    </div>
  );
}

function ToolCallCard({ call, conversationId, organizationId }: { call: ToolCallView; conversationId: string | null; organizationId: string | null }) {
  const [open, setOpen] = useState(false);
  const a = call.action;
  const pending = a?.status === "pending_approval";
  return (
    <div className={clsx("rounded border px-2.5 py-1.5 text-sm", pending ? "border-sev-high/50 bg-sev-high/5" : "border-line bg-surface-2")} data-testid="ai-tool-call">
      <div className="flex flex-wrap items-center gap-1.5">
        <Wrench size={12} aria-hidden className="text-fg-muted" />
        <span className="font-mono text-xs font-semibold">{call.name}</span>
        {a ? <TierBadge tier={a.tier} /> : null}
        {a ? <StatusBadge status={a.status} size="xs" /> : null}
        <button type="button" onClick={() => setOpen((v) => !v)} className="ml-auto inline-flex items-center gap-0.5 text-xs text-fg-muted hover:text-fg" aria-expanded={open}>
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />} Details
        </button>
      </div>
      {pending ? (
        <p className="mt-1 flex items-start gap-1 text-xs text-fg">
          <ShieldAlert size={12} className="mt-0.5 shrink-0 text-sev-high" aria-hidden />
          The assistant requested an action above its permitted tier. Nothing runs until a human approves it.
        </p>
      ) : null}
      {a ? <ActionDecision action={a} conversationId={conversationId} organizationId={organizationId} /> : null}
      {open ? (
        <div className="mt-1.5 space-y-1.5">
          <JsonView value={call.arguments} maxHeight="10rem" />
          {a && a.result !== null && a.result !== undefined ? <JsonView value={a.result} maxHeight="12rem" /> : null}
        </div>
      ) : null}
    </div>
  );
}

function MessageBubble({ message, at }: { message: AiMessage; at: string | null }) {
  const user = message.role === "user";
  return (
    <div className={clsx("flex gap-2", user && "flex-row-reverse")}>
      <span className={clsx("mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full", user ? "bg-primary text-white" : "bg-brand-soft text-brand")} aria-hidden>
        {user ? <User size={13} /> : <Bot size={13} />}
      </span>
      <div className={clsx("max-w-[85%] rounded-md px-3 py-2 text-base", user ? "bg-primary-soft text-fg" : "border border-line bg-surface text-fg")}>
        <div className="whitespace-pre-wrap break-words">{message.content || (message.toolCalls?.length ? <span className="text-fg-muted">Using tools…</span> : null)}</div>
        {at ? <RelativeTime value={at} className="mt-1 block text-2xs text-fg-subtle" /> : null}
      </div>
    </div>
  );
}

function ToolResult({ message }: { message: AiMessage }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="ml-8 text-xs">
      <button type="button" onClick={() => setOpen((v) => !v)} className="inline-flex items-center gap-0.5 text-fg-muted hover:text-fg" aria-expanded={open}>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />} Tool result{message.toolCallId ? ` · ${message.toolCallId}` : ""}
      </button>
      {open ? <pre className="scrollbar-thin mt-1 max-h-48 overflow-auto rounded border border-line bg-surface-2 p-2 font-mono text-2xs">{message.content}</pre> : null}
    </div>
  );
}

export interface AiChatPanelProps {
  conversationId: string | null;
  onConversationChange: (id: string) => void;
  context: AiContextRef | null;
  organizationId: string | null;
  providerId?: string | null;
  compact?: boolean;
  className?: string;
}

interface LocalExchange {
  question: string;
  result: AiChatResult | null;
}

/**
 * AI SOC thread: messages, tool calls with their permission tier, pending approvals with
 * approve / reject, and a composer bound to the given context (incident, asset, IOC…).
 */
export function AiChatPanel({ conversationId, onConversationChange, context, organizationId, providerId, compact = false, className }: AiChatPanelProps) {
  const session = useSession();
  const detail = useAiConversation(conversationId);
  const chat = useAiChat();
  const [draft, setDraft] = useState("");
  const [local, setLocal] = useState<LocalExchange[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const canUse = organizationId !== null && session.can("ai:use", organizationId);

  useEffect(() => setLocal([]), [conversationId]);

  const messages = detail.data?.messages ?? [];
  const actions = useMemo(() => {
    const byId = new Map<string, AiActionRecord>();
    for (const a of detail.data?.actions ?? []) byId.set(a.id, a);
    for (const ex of local) for (const a of ex.result?.actions ?? []) if (!byId.has(a.id)) byId.set(a.id, a);
    return [...byId.values()];
  }, [detail.data, local]);
  const { calls, unmatched } = useMemo(() => pairToolCalls(messages, actions), [messages, actions]);
  const showLocal = messages.length === 0;

  useEffect(() => {
    const el = scrollRef.current;
    if (el && typeof el.scrollTo === "function") el.scrollTo({ top: el.scrollHeight });
  }, [messages.length, local.length, chat.isPending]);

  const send = (text: string) => {
    const message = text.trim();
    if (!message || !canUse || chat.isPending) return;
    setDraft("");
    setLocal((l) => [...l, { question: message, result: null }]);
    chat.mutate(
      {
        message,
        organizationId: organizationId!,
        ...(conversationId ? { conversationId } : {}),
        ...(providerId ? { providerId } : {}),
        context: context && context.kind !== "none" ? { kind: context.kind, ...(context.id ? { id: context.id } : {}) } : { kind: "none" },
      },
      {
        onSuccess: (res) => {
          setLocal((l) => l.map((ex, i) => (i === l.length - 1 ? { ...ex, result: res } : ex)));
          if (res.conversationId && res.conversationId !== conversationId) onConversationChange(res.conversationId);
        },
      },
    );
  };

  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      send(draft);
    }
  };

  const suggestions = SUGGESTIONS[context?.kind ?? "none"];
  const empty = messages.length === 0 && local.length === 0;

  return (
    <div className={clsx("flex min-h-0 flex-col", className)} data-testid="ai-chat-panel">
      <div ref={scrollRef} className="scrollbar-thin min-h-0 flex-1 space-y-3 overflow-y-auto p-3" aria-live="polite">
        {conversationId && detail.isPending ? (
          <SkeletonText lines={5} />
        ) : conversationId && detail.isError && local.length === 0 ? (
          <p className="text-sm text-sev-critical">{errorMessage(detail.error)}</p>
        ) : empty ? (
          <EmptyState
            icon={Bot}
            compact={compact}
            title={context && context.kind !== "none" ? `Ask about this ${context.kind}` : "Ask the AI SOC analyst"}
            description="Answers are grounded in your tenant's data. Tools run within the provider's permitted tier; anything above it waits for human approval."
            action={
              <div className="flex max-w-xl flex-wrap justify-center gap-1.5">
                {suggestions.map((s) => (
                  <button key={s} type="button" disabled={!canUse} onClick={() => send(s)} className="rounded-full border border-line-strong px-2.5 py-1 text-sm text-fg-muted hover:border-primary hover:text-fg disabled:opacity-50">
                    {s}
                  </button>
                ))}
              </div>
            }
          />
        ) : null}

        {!showLocal
          ? messages.map((m) =>
              m.message.role === "tool" ? (
                <ToolResult key={m.seq} message={m.message} />
              ) : (
                <div key={m.seq} className="space-y-1.5">
                  <MessageBubble message={m.message} at={m.at} />
                  {(calls.get(m.seq) ?? []).map((c) => (
                    <div key={c.id} className="ml-8">
                      <ToolCallCard call={c} conversationId={conversationId} organizationId={organizationId} />
                    </div>
                  ))}
                </div>
              ),
            )
          : local.map((ex, i) => (
              <div key={i} className="space-y-1.5">
                <MessageBubble message={{ role: "user", content: ex.question }} at={null} />
                {ex.result ? (
                  <>
                    <MessageBubble message={{ role: "assistant", content: ex.result.answer }} at={null} />
                    {ex.result.actions.map((a) => (
                      <div key={a.id} className="ml-8">
                        <ToolCallCard call={{ id: a.id, name: a.tool, arguments: a.arguments, action: a }} conversationId={ex.result!.conversationId || conversationId} organizationId={organizationId} />
                      </div>
                    ))}
                  </>
                ) : null}
              </div>
            ))}

        {!showLocal && local.some((ex) => ex.result === null) ? <MessageBubble message={{ role: "user", content: local[local.length - 1]!.question }} at={null} /> : null}

        {!showLocal && unmatched.length > 0 ? (
          <div className="space-y-1.5">
            <h4 className="text-2xs font-semibold uppercase tracking-wide text-fg-subtle">Tool activity</h4>
            {unmatched.map((a) => (
              <ToolCallCard key={a.id} call={{ id: a.id, name: a.tool, arguments: a.arguments, action: a }} conversationId={conversationId} organizationId={organizationId} />
            ))}
          </div>
        ) : null}

        {chat.isPending ? (
          <div className="flex items-center gap-2 text-sm text-fg-muted" role="status">
            <LoaderCircle size={14} className="animate-spin" aria-hidden /> Analyzing with permitted tools…
          </div>
        ) : null}
        {chat.isError ? (
          <p role="alert" className="text-sm text-sev-critical">
            {errorMessage(chat.error)}
          </p>
        ) : null}
      </div>

      <form
        className="border-t border-line p-2"
        onSubmit={(e) => {
          e.preventDefault();
          send(draft);
        }}
      >
        {!canUse ? (
          <p className="mb-1 text-xs text-fg-muted">{organizationId === null ? "Select an organization to ground the conversation." : "You don't have permission to use the AI SOC for this organization."}</p>
        ) : null}
        <div className="flex items-end gap-2">
          <Textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKey}
            rows={compact ? 2 : 3}
            maxLength={20_000}
            placeholder={context && context.kind !== "none" ? `Ask about this ${humanize(context.kind).toLowerCase()}… (Enter to send, Shift+Enter for a new line)` : "Ask the AI SOC analyst… (Enter to send, Shift+Enter for a new line)"}
            disabled={!canUse}
            aria-label="Message"
          />
          <Button type="submit" variant="primary" icon={Send} disabled={!canUse || !draft.trim()} loading={chat.isPending} aria-label="Send message">
            {compact ? null : "Send"}
          </Button>
        </div>
      </form>
    </div>
  );
}
