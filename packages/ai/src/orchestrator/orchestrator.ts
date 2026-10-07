import { AiChatRequest, principalCan, type AiActionRecord, type AiMessage, type AiToolTier, type Principal } from "@bloody/contracts";
import type { z } from "zod";
import { AiAbortError, AiAccessDeniedError, AiError, AiNotFoundError, AiQuotaExceededError, describeError } from "../errors.js";
import type { ProviderRegistryLike } from "./types.js";
import type { ServedBy } from "../providers/types.js";
import { classifyEgress } from "../safety/egress.js";
import { RedactionVault, emptyRedactionStats, mergeRedactionStats, scrubSecretsDeep, type RedactionStats } from "../safety/redact.js";
import type { ToolGateway } from "../tools/gateway.js";
import type { SocDataPort } from "../tools/soc-port.js";
import type { AiAuditEvent, AiAuditSink, SocScope, ToolDecision, ToolDenialCode, ToolInvocationContext, ToolInvocationResult } from "../tools/types.js";
import { systemClock, uuidGenerator, type Clock, type IdGenerator } from "../util/ids.js";
import { stableStringify, truncate } from "../util/json.js";
import { buildGrounding, fitToContext, type GroundingInfo } from "./context.js";
import type { AiConversation, ConversationStore, StoredAiMessage } from "./conversation-store.js";
import { BLOODY_SOC_POLICY_VERSION, buildSystemPrompt } from "./policy.js";
import type { AiQuotaGuard, AiUsageMeter } from "./usage.js";

export interface AiOrchestratorLimits {
  /** Model round-trips per run (the last one is forced to answer without tools). */
  maxSteps: number;
  /** Cumulative input+output tokens per run. */
  tokenBudget: number;
  maxToolCallsPerStep: number;
  /** Prior messages loaded from the conversation. */
  maxHistoryMessages: number;
  maxGroundingChars: number;
}

export const DEFAULT_ORCHESTRATOR_LIMITS: AiOrchestratorLimits = {
  maxSteps: 8,
  tokenBudget: 150_000,
  maxToolCallsPerStep: 6,
  maxHistoryMessages: 30,
  maxGroundingChars: 16_000,
};

export interface AiOrchestratorDeps {
  providers: ProviderRegistryLike;
  gateway: ToolGateway;
  soc: SocDataPort;
  store: ConversationStore;
  audit: AiAuditSink;
  usage?: AiUsageMeter;
  quota?: AiQuotaGuard;
  clock?: Clock;
  ids?: IdGenerator;
  limits?: Partial<AiOrchestratorLimits>;
  organizationName?: (tenantId: string, organizationId: string) => Promise<string | null>;
  /** Called when a non-critical write (usage meter, post-run audit) fails. */
  onBackgroundError?: (err: unknown, where: string) => void;
}

export type AiRunEvent =
  | { type: "run_started"; conversationId: string; providerId: string; model: string; maxToolTier: AiToolTier; grounding: GroundingInfo }
  | { type: "step_started"; step: number; finalize: boolean }
  | { type: "delta"; step: number; text: string }
  | { type: "tool_call"; step: number; callId: string; tool: string; arguments: Record<string, unknown> }
  | { type: "tool_result"; step: number; callId: string; tool: string; status: string; decision: ToolDecision; reason: string | null }
  | { type: "approval_required"; step: number; action: AiActionRecord }
  | { type: "completed"; result: AiRunResult };

export interface AiRunInput {
  principal: Principal;
  request: AiChatRequest;
  signal?: AbortSignal;
  onEvent?: (event: AiRunEvent) => void;
  requestId?: string;
  limits?: Partial<AiOrchestratorLimits>;
}

export interface ToolTraceEntry {
  step: number;
  callId: string;
  tool: string;
  tier: AiToolTier | null;
  decision: ToolDecision;
  status: string;
  code: ToolDenialCode | null;
  reason: string | null;
  durationMs: number;
  actionId: string | null;
  /** Arguments with secrets scrubbed (safe for UI and logs). */
  arguments: Record<string, unknown>;
}

export type AiRunFinishReason = "completed" | "max_steps" | "token_budget" | "length" | "content_filter";

export interface AiRunResult {
  conversationId: string;
  providerId: string;
  model: string;
  answer: string;
  finishReason: AiRunFinishReason;
  steps: number;
  usage: { inputTokens: number; outputTokens: number; totalTokens: number; requests: number; estimated: boolean };
  toolTrace: ToolTraceEntry[];
  actions: AiActionRecord[];
  pendingApprovals: AiActionRecord[];
  grounding: GroundingInfo;
  redactions: RedactionStats;
  maxToolTier: AiToolTier;
  servedBy: ServedBy[];
  fallbackUsed: boolean;
  retained: boolean;
  policyVersion: string;
  startedAt: string;
  completedAt: string;
}

type ParsedChatRequest = z.output<typeof AiChatRequest>;

/**
 * AI SOC agent loop: provider resolution (tenant-scoped, governed, with fallback), grounding on
 * the entity the analyst is viewing, tool use exclusively through the {@link ToolGateway},
 * step/token budgets, conversation persistence with retention, usage metering and audit.
 */
export class AiOrchestrator {
  private readonly clock: Clock;
  private readonly ids: IdGenerator;
  private readonly limits: AiOrchestratorLimits;

  constructor(private readonly deps: AiOrchestratorDeps) {
    this.clock = deps.clock ?? systemClock;
    this.ids = deps.ids ?? uuidGenerator;
    this.limits = { ...DEFAULT_ORCHESTRATOR_LIMITS, ...deps.limits };
  }

  private emit(onEvent: AiRunInput["onEvent"], event: AiRunEvent): void {
    if (!onEvent) return;
    try {
      onEvent(event);
    } catch {
      /* a broken listener must never break the run */
    }
  }

  private async background(where: string, fn: () => Promise<unknown>): Promise<void> {
    try {
      await fn();
    } catch (err) {
      this.deps.onBackgroundError?.(err, where);
    }
  }

  private audit(principal: Principal, organizationId: string | null, partial: Omit<AiAuditEvent, "id" | "at" | "tenantId" | "organizationId" | "actor">): AiAuditEvent {
    return {
      id: this.ids(),
      at: this.clock.now().toISOString(),
      tenantId: principal.tenantId,
      organizationId,
      actor: { kind: principal.kind, id: principal.id, ...(principal.email ? { email: principal.email } : {}) },
      ...partial,
    };
  }

  async run(input: AiRunInput): Promise<AiRunResult> {
    const startedAt = this.clock.now();
    const parsed = AiChatRequest.safeParse(input.request);
    if (!parsed.success) throw new AiError("invalid_request", `Invalid AI chat request: ${parsed.error.issues[0]?.message ?? "invalid"}`);
    const req: ParsedChatRequest = parsed.data;
    const principal = input.principal;
    const tenantId = principal.tenantId;
    const organizationId = req.organizationId;
    const limits: AiOrchestratorLimits = { ...this.limits, ...input.limits };
    const requestMeta = input.requestId ? { requestId: input.requestId } : {};

    if (!principalCan(principal, "ai:use", organizationId)) {
      await this.background("audit", () => this.deps.audit.record(this.audit(principal, organizationId, { action: "ai.chat.denied", code: "ai_use_not_permitted", reason: "Principal lacks ai:use", ...requestMeta })));
      throw new AiAccessDeniedError("ai_use_not_permitted", "You do not have permission to use the AI SOC analyst in this organization");
    }

    // Conversation ownership is checked before any model call or quota consumption.
    let conversation: AiConversation | null = null;
    if (req.conversationId) {
      conversation = await this.deps.store.get(tenantId, req.conversationId);
      if (!conversation || conversation.organizationId !== organizationId) throw new AiNotFoundError("conversation_not_found", "Conversation not found");
      if (conversation.principalId !== principal.id) throw new AiAccessDeniedError("conversation_forbidden", "Conversations are private to the analyst who started them");
    }

    if (this.deps.quota) {
      const decision = await this.deps.quota.consume({ tenantId, organizationId, units: 1 });
      if (!decision.allowed) {
        await this.background("audit", () =>
          this.deps.audit.record(this.audit(principal, organizationId, { action: "ai.chat.denied", code: "quota_exceeded", reason: `Daily AI quota of ${decision.limit} requests reached`, ...requestMeta })),
        );
        throw new AiQuotaExceededError("quota_exceeded", `Daily AI request quota reached (${decision.limit}); resets at ${decision.resetsAt}`, {
          details: { limit: decision.limit, resetsAt: decision.resetsAt },
        });
      }
    }

    const resolved = await this.deps.providers.resolve({ tenantId, organizationId }, req.providerId ?? null);
    const config = resolved.config;
    const now = this.clock.now();
    const retain = config.retentionDays > 0;
    const expiresAt = retain ? new Date(now.getTime() + config.retentionDays * 86_400_000).toISOString() : null;

    if (!conversation) {
      conversation = {
        id: this.ids(),
        tenantId,
        organizationId,
        principalId: principal.id,
        providerId: config.id,
        title: truncate(req.message.replace(/\s+/g, " ").trim(), 80),
        context: { kind: req.context.kind, ...(req.context.id ? { id: req.context.id } : {}) },
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        expiresAt,
        retainMessages: retain,
        messageCount: 0,
        usage: { inputTokens: 0, outputTokens: 0, requests: 0 },
      };
      await this.deps.store.create(conversation);
    }
    const conversationId = conversation.id;

    const history = conversation.retainMessages
      ? (await this.deps.store.listMessages(tenantId, conversationId, { limit: limits.maxHistoryMessages * 3 }))
          .map((m) => m.message)
          // Only user turns and final answers are replayed; tool traffic stays in the transcript.
          .filter((m) => m.role === "user" || (m.role === "assistant" && !(m.toolCalls && m.toolCalls.length > 0) && m.content.trim().length > 0))
          .slice(-limits.maxHistoryMessages)
      : [];
    while (history.length > 0 && history[0]!.role !== "user") history.shift();

    const scope: SocScope = { tenantId, organizationId, principalId: principal.id, principalKind: principal.kind, conversationId, via: "ai", approvedBy: null };
    const grounding = await buildGrounding(this.deps.soc, principal, scope, { kind: req.context.kind, id: req.context.id }, limits.maxGroundingChars);

    const toolCtx: ToolInvocationContext = {
      principal,
      tenantId,
      organizationId,
      providerMaxTier: resolved.effectiveMaxToolTier,
      conversationId,
      providerId: config.id,
      ...(input.requestId ? { requestId: input.requestId } : {}),
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const tools = this.deps.gateway.specsFor(toolCtx);
    const organizationName = (await this.deps.organizationName?.(tenantId, organizationId).catch(() => null)) ?? null;
    const system: AiMessage = {
      role: "system",
      content: buildSystemPrompt({
        tenantPolicy: config.systemPolicy,
        organizationId,
        organizationName,
        now,
        maxToolTier: resolved.effectiveMaxToolTier,
        toolNames: tools.map((t) => t.name),
      }),
    };
    const userMessage: AiMessage = { role: "user", content: req.message };
    const run: AiMessage[] = [];
    const vault = new RedactionVault();
    const toolTrace: ToolTraceEntry[] = [];
    const actions: AiActionRecord[] = [];
    const pendingApprovals: AiActionRecord[] = [];
    const servedBy: ServedBy[] = [];
    const callCache = new Map<string, { content: string; result: ToolInvocationResult }>();
    let redactions = emptyRedactionStats();
    let usage = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requests: 0, estimated: false };
    let fallbackUsed = false;
    let answer = "";
    let finishReason: AiRunFinishReason = "max_steps";
    let steps = 0;
    let model = config.model;

    this.emit(input.onEvent, { type: "run_started", conversationId, providerId: config.id, model: config.model, maxToolTier: resolved.effectiveMaxToolTier, grounding: grounding.info });

    try {
      for (let step = 1; step <= limits.maxSteps; step++) {
        if (input.signal?.aborted) throw new AiAbortError();
        steps = step;
        const finalize = step === limits.maxSteps || usage.totalTokens >= limits.tokenBudget * 0.85;
        this.emit(input.onEvent, { type: "step_started", step, finalize });
        const { messages } = fitToContext({ system, history, grounding: grounding.message, user: userMessage, run }, config.contextWindow, config.maxOutputTokens);
        const res = await resolved.provider.chat({
          messages,
          ...(tools.length > 0 ? { tools, toolChoice: finalize ? ("none" as const) : ("auto" as const) } : {}),
          dataClass: "tenant",
          redactionVault: vault,
          ...(input.signal ? { signal: input.signal } : {}),
          ...(input.onEvent ? { onDelta: (text: string) => this.emit(input.onEvent, { type: "delta", step, text }) } : {}),
        });
        model = res.model;
        servedBy.push(res.servedBy);
        fallbackUsed ||= res.fallbackUsed ?? false;
        if (res.redactions) redactions = mergeRedactionStats(redactions, res.redactions);
        usage = {
          inputTokens: usage.inputTokens + res.usage.inputTokens,
          outputTokens: usage.outputTokens + res.usage.outputTokens,
          totalTokens: usage.totalTokens + res.usage.inputTokens + res.usage.outputTokens,
          requests: usage.requests + 1,
          estimated: usage.estimated || (res.usage.estimated ?? false),
        };
        const servedConfig = resolved.chain.find((c) => c.id === res.servedBy.providerId) ?? config;
        if (this.deps.usage) {
          const meter = this.deps.usage;
          await this.background("usage", () =>
            meter.record({
              id: this.ids(),
              at: this.clock.now().toISOString(),
              tenantId,
              organizationId,
              principalId: principal.id,
              conversationId,
              providerId: res.servedBy.providerId,
              providerKind: res.servedBy.kind,
              model: res.model,
              egress: classifyEgress(servedConfig.kind, servedConfig.endpoint),
              purpose: "chat",
              inputTokens: res.usage.inputTokens,
              outputTokens: res.usage.outputTokens,
              estimated: res.usage.estimated ?? false,
              latencyMs: res.latencyMs,
              fallbackUsed: res.fallbackUsed ?? false,
            }),
          );
        }

        const calls = finalize ? [] : (res.message.toolCalls ?? []);
        if (calls.length === 0) {
          answer = res.message.content;
          run.push({ role: "assistant", content: answer });
          // The model wanted more tools but was forced to conclude → report which limit applied.
          const ignoredCalls = finalize && (res.message.toolCalls?.length ?? 0) > 0;
          finishReason =
            res.finishReason === "length"
              ? "length"
              : res.finishReason === "content_filter"
                ? "content_filter"
                : ignoredCalls
                  ? step === limits.maxSteps
                    ? "max_steps"
                    : "token_budget"
                  : "completed";
          break;
        }

        run.push({ role: "assistant", content: res.message.content, toolCalls: calls });
        for (const [index, call] of calls.entries()) {
          if (input.signal?.aborted) throw new AiAbortError();
          const safeArgs = scrubSecretsDeep(call.arguments);
          if (index >= limits.maxToolCallsPerStep) {
            const content = JSON.stringify({ tool: call.name, status: "denied", error: { code: "call_limit_exceeded", message: `At most ${limits.maxToolCallsPerStep} tool calls per step` } });
            run.push({ role: "tool", toolCallId: call.id, content });
            toolTrace.push({ step, callId: call.id, tool: call.name, tier: null, decision: "denied", status: "denied", code: "call_limit_exceeded", reason: "Too many tool calls in one step", durationMs: 0, actionId: null, arguments: safeArgs });
            continue;
          }
          const key = `${call.name}\u0000${stableStringify(call.arguments)}`;
          const cached = callCache.get(key);
          if (cached) {
            run.push({ role: "tool", toolCallId: call.id, content: cached.content });
            toolTrace.push({
              step,
              callId: call.id,
              tool: call.name,
              tier: cached.result.tier,
              decision: cached.result.decision,
              status: cached.result.status,
              code: "duplicate_call",
              reason: "Identical call already executed in this run; previous result reused",
              durationMs: 0,
              actionId: cached.result.action.id,
              arguments: safeArgs,
            });
            continue;
          }
          this.emit(input.onEvent, { type: "tool_call", step, callId: call.id, tool: call.name, arguments: safeArgs });
          const result = await this.deps.gateway.invoke(toolCtx, { id: call.id, name: call.name, arguments: call.arguments });
          const content = this.deps.gateway.toModelContent(result);
          callCache.set(key, { content, result });
          actions.push(result.action);
          run.push({ role: "tool", toolCallId: call.id, content });
          toolTrace.push({
            step,
            callId: call.id,
            tool: call.name,
            tier: result.tier,
            decision: result.decision,
            status: result.status,
            code: result.code,
            reason: result.reason,
            durationMs: result.durationMs,
            actionId: result.action.id,
            arguments: safeArgs,
          });
          this.emit(input.onEvent, { type: "tool_result", step, callId: call.id, tool: call.name, status: result.status, decision: result.decision, reason: result.reason });
          if (result.status === "pending_approval") {
            pendingApprovals.push(result.action);
            this.emit(input.onEvent, { type: "approval_required", step, action: result.action });
          }
        }
        if (usage.totalTokens >= limits.tokenBudget) {
          finishReason = "token_budget";
          answer = res.message.content;
          break;
        }
      }
    } catch (err) {
      await this.background("audit", () =>
        this.deps.audit.record(
          this.audit(principal, organizationId, {
            action: "ai.chat.failed",
            conversationId,
            providerId: config.id,
            model,
            code: describeError(err).code,
            reason: describeError(err).message,
            ...requestMeta,
            metadata: { steps, toolCalls: toolTrace.length, policyVersion: BLOODY_SOC_POLICY_VERSION },
          }),
        ),
      );
      if (actions.length > 0) await this.background("store", () => this.deps.store.saveActions(tenantId, conversationId, actions));
      throw err;
    }

    if (!answer.trim()) {
      answer =
        finishReason === "token_budget"
          ? "I stopped because this request reached its AI token budget. The tool results gathered so far are listed in the trace; narrow the question to continue."
          : pendingApprovals.length > 0
            ? `I queued ${pendingApprovals.length} action(s) for human approval; nothing has been executed yet.`
            : "The model did not return an answer. Review the tool trace or retry with a more specific question.";
    }
    const last = run[run.length - 1];
    if (!last || last.role !== "assistant" || (last.toolCalls?.length ?? 0) > 0) run.push({ role: "assistant", content: answer });
    else if (last.content !== answer) last.content = answer;

    const completedAt = this.clock.now();
    if (retain) {
      const at = completedAt.toISOString();
      const messageExpiry = new Date(completedAt.getTime() + config.retentionDays * 86_400_000).toISOString();
      const stored: StoredAiMessage[] = [userMessage, ...run].map((message, i) => ({ seq: conversation!.messageCount + i + 1, at, expiresAt: messageExpiry, message }));
      await this.deps.store.appendMessages(tenantId, conversationId, stored);
      conversation.messageCount += stored.length;
    }
    if (actions.length > 0) await this.deps.store.saveActions(tenantId, conversationId, actions);
    await this.deps.store.update(tenantId, conversationId, {
      updatedAt: completedAt.toISOString(),
      messageCount: conversation.messageCount,
      retainMessages: retain,
      expiresAt,
      usage: {
        inputTokens: conversation.usage.inputTokens + usage.inputTokens,
        outputTokens: conversation.usage.outputTokens + usage.outputTokens,
        requests: conversation.usage.requests + usage.requests,
      },
    });

    const result: AiRunResult = {
      conversationId,
      providerId: config.id,
      model,
      answer,
      finishReason,
      steps,
      usage,
      toolTrace,
      actions,
      pendingApprovals,
      grounding: grounding.info,
      redactions,
      maxToolTier: resolved.effectiveMaxToolTier,
      servedBy,
      fallbackUsed,
      retained: retain,
      policyVersion: BLOODY_SOC_POLICY_VERSION,
      startedAt: startedAt.toISOString(),
      completedAt: completedAt.toISOString(),
    };
    await this.background("audit", () =>
      this.deps.audit.record(
        this.audit(principal, organizationId, {
          action: "ai.chat.completed",
          conversationId,
          providerId: config.id,
          model,
          status: finishReason,
          durationMs: completedAt.getTime() - startedAt.getTime(),
          ...requestMeta,
          metadata: {
            steps,
            usage,
            toolCalls: toolTrace.map((t) => ({ tool: t.tool, status: t.status, decision: t.decision })),
            pendingApprovals: pendingApprovals.map((a) => a.id),
            redactions: redactions.total,
            fallbackUsed,
            servedBy,
            grounding: grounding.info,
            policyVersion: BLOODY_SOC_POLICY_VERSION,
            maxToolTier: resolved.effectiveMaxToolTier,
          },
        }),
      ),
    );
    this.emit(input.onEvent, { type: "completed", result });
    return result;
  }

  /** Approve and execute a pending AI action (`POST /ai/actions/:id/approve`). */
  async approveAction(input: { approver: Principal; actionId: string; signal?: AbortSignal }): Promise<ToolInvocationResult> {
    const found = await this.deps.store.getAction(input.approver.tenantId, input.actionId);
    if (!found) throw new AiNotFoundError("action_not_found", "AI action not found");
    const result = await this.deps.gateway.executeApproved({
      action: found.action,
      approver: input.approver,
      tenantId: input.approver.tenantId,
      organizationId: found.organizationId,
      ...(input.signal ? { signal: input.signal } : {}),
    });
    if (result.decision === "denied") throw new AiAccessDeniedError(result.code ?? "denied", result.reason ?? "Approval denied");
    await this.deps.store.saveActions(input.approver.tenantId, found.action.conversationId, [result.action]);
    await this.appendTranscriptNote(input.approver.tenantId, found.action.conversationId, `Action ${found.action.tool} (${found.action.id}) approved by ${input.approver.id}: ${result.status}${result.reason ? ` — ${result.reason}` : ""}.`);
    return result;
  }

  /** Reject a pending AI action. */
  async rejectAction(input: { approver: Principal; actionId: string; reason: string }): Promise<AiActionRecord> {
    const found = await this.deps.store.getAction(input.approver.tenantId, input.actionId);
    if (!found) throw new AiNotFoundError("action_not_found", "AI action not found");
    if (found.action.status !== "pending_approval") throw new AiError("invalid_state", `Action is '${found.action.status}', not pending approval`);
    const record = await this.deps.gateway.reject({ action: found.action, approver: input.approver, tenantId: input.approver.tenantId, organizationId: found.organizationId, reason: input.reason });
    await this.deps.store.saveActions(input.approver.tenantId, found.action.conversationId, [record]);
    await this.appendTranscriptNote(input.approver.tenantId, found.action.conversationId, `Action ${found.action.tool} (${found.action.id}) rejected by ${input.approver.id}: ${truncate(input.reason, 500)}`);
    return record;
  }

  private async appendTranscriptNote(tenantId: string, conversationId: string, text: string): Promise<void> {
    const conv = await this.deps.store.get(tenantId, conversationId);
    if (!conv || !conv.retainMessages) return;
    const at = this.clock.now().toISOString();
    await this.deps.store.appendMessages(tenantId, conversationId, [{ seq: conv.messageCount + 1, at, expiresAt: conv.expiresAt, message: { role: "assistant", content: `[system note] ${text}` } }]);
    await this.deps.store.update(tenantId, conversationId, { messageCount: conv.messageCount + 1, updatedAt: at });
  }

  /** Conversation with transcript and actions; owners, or reviewers holding `audit:read`. */
  async getConversation(principal: Principal, conversationId: string): Promise<{ conversation: AiConversation; messages: StoredAiMessage[]; actions: AiActionRecord[] }> {
    const conversation = await this.deps.store.get(principal.tenantId, conversationId);
    if (!conversation) throw new AiNotFoundError("conversation_not_found", "Conversation not found");
    const isOwner = conversation.principalId === principal.id;
    if (!isOwner && !principalCan(principal, "audit:read", conversation.organizationId)) throw new AiNotFoundError("conversation_not_found", "Conversation not found");
    const [messages, actions] = await Promise.all([this.deps.store.listMessages(principal.tenantId, conversationId), this.deps.store.listActions(principal.tenantId, conversationId)]);
    return { conversation, messages, actions };
  }
}
