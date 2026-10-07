import { AI_TIER_RANK, principalCan, type ActionRisk, type AiActionRecord, type AiToolTier, type Principal } from "@bloody/contracts";
import { AiAccessDeniedError, describeError } from "../errors.js";
import { INVALID_TOOL_ARGUMENTS_KEY } from "../providers/messages.js";
import type { ToolSpec } from "../providers/types.js";
import { scrubSecretsDeep } from "../safety/redact.js";
import { systemClock, uuidGenerator, type Clock, type IdGenerator } from "../util/ids.js";
import { safeStringify, truncate } from "../util/json.js";
import { zodToJsonSchema } from "./json-schema.js";
import type {
  AiAuditEvent,
  AiAuditSink,
  AnyToolDefinition,
  ApprovalSink,
  SocScope,
  ToolCallRequest,
  ToolDecision,
  ToolDenialCode,
  ToolInvocationContext,
  ToolInvocationResult,
} from "./types.js";

/**
 * The only path from a model to Bloody data and actions. For every call it:
 *   1. resolves the tool (unknown tools are denied — models cannot invent capabilities);
 *   2. checks the principal's tenant and RBAC (`ai:use` + the tool's permission, per org);
 *   3. validates arguments with the tool's zod schema;
 *   4. applies the tier policy against the serving model's `maxToolTier`:
 *        read / investigate / recommend → allowed iff tier ≤ maxToolTier, else denied;
 *        require_approval              → needs maxToolTier ≥ require_approval, always queued for a human;
 *        execute                       → needs maxToolTier ≥ require_approval; runs autonomously only when
 *                                         maxToolTier = execute AND the action is low-risk, else queued;
 *   5. writes an audit record BEFORE executing (fail closed if the audit sink is down) and another
 *      with the outcome; queues approvals through the injected {@link ApprovalSink}.
 * Approved actions are executed later with {@link ToolGateway.executeApproved} (four-eyes by default).
 */

export const TOOL_NAME_RE = /^[a-z][a-z0-9_]{1,63}$/;

export interface ToolGatewayOptions {
  approvals: ApprovalSink;
  audit: AiAuditSink;
  clock?: Clock;
  ids?: IdGenerator;
  /** Cap on the serialized tool result handed back to the model. Default 24 000 chars. */
  maxResultChars?: number;
  /** Default handler timeout. Default 30 s. */
  defaultTimeoutMs?: number;
  /** Approver must differ from the requesting principal. Default true. */
  requireDistinctApprover?: boolean;
  /** Called when the post-execution audit write fails (the action already happened). */
  onAuditError?: (err: unknown, event: AiAuditEvent) => void;
}

interface Decision {
  decision: ToolDecision;
  code: ToolDenialCode | null;
  reason: string | null;
}

function defaultRisk(tier: AiToolTier): ActionRisk {
  return tier === "read" || tier === "investigate" || tier === "recommend" ? "low" : "high";
}

export class ToolGateway {
  private readonly tools = new Map<string, AnyToolDefinition>();
  private readonly specCache = new Map<string, ToolSpec>();
  private readonly clock: Clock;
  private readonly ids: IdGenerator;
  private readonly maxResultChars: number;
  private readonly defaultTimeoutMs: number;
  private readonly requireDistinctApprover: boolean;

  constructor(
    tools: readonly AnyToolDefinition[],
    private readonly options: ToolGatewayOptions,
  ) {
    this.clock = options.clock ?? systemClock;
    this.ids = options.ids ?? uuidGenerator;
    this.maxResultChars = options.maxResultChars ?? 24_000;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 30_000;
    this.requireDistinctApprover = options.requireDistinctApprover ?? true;
    for (const t of tools) this.register(t);
  }

  register(tool: AnyToolDefinition): void {
    if (!TOOL_NAME_RE.test(tool.name)) throw new Error(`Invalid tool name '${tool.name}'`);
    if (this.tools.has(tool.name)) throw new Error(`Tool '${tool.name}' is already registered`);
    this.tools.set(tool.name, tool);
  }

  get(name: string): AnyToolDefinition | undefined {
    return this.tools.get(name);
  }

  list(): AnyToolDefinition[] {
    return [...this.tools.values()];
  }

  spec(tool: AnyToolDefinition): ToolSpec {
    let spec = this.specCache.get(tool.name);
    if (!spec) {
      const tierNote = tool.tier === "require_approval" ? " [Requires human approval: the action is queued, not executed.]" : "";
      spec = { name: tool.name, description: `${tool.description}${tierNote}`, parameters: zodToJsonSchema(tool.parameters) };
      this.specCache.set(tool.name, spec);
    }
    return spec;
  }

  /** Tools the model may be offered in this context (permission held and tier reachable). */
  specsFor(ctx: ToolInvocationContext): ToolSpec[] {
    if (ctx.principal.tenantId !== ctx.tenantId || !principalCan(ctx.principal, "ai:use", ctx.organizationId)) return [];
    return this.list()
      .filter((t) => principalCan(ctx.principal, t.permission, ctx.organizationId) && this.tierDecision(t.tier, ctx.providerMaxTier, "low").decision !== "denied")
      .map((t) => this.spec(t));
  }

  private tierDecision(tier: AiToolTier, maxTier: AiToolTier, risk: ActionRisk): Decision {
    const rank = AI_TIER_RANK;
    if (tier === "read" || tier === "investigate" || tier === "recommend") {
      return rank[tier] <= rank[maxTier]
        ? { decision: "allowed", code: null, reason: null }
        : { decision: "denied", code: "tier_exceeds_provider_max", reason: `Tool tier '${tier}' exceeds this model's maximum tier '${maxTier}'` };
    }
    if (rank[maxTier] < rank.require_approval) {
      return { decision: "denied", code: "tier_exceeds_provider_max", reason: `Tool tier '${tier}' requires the model's maximum tier to be at least 'require_approval' (is '${maxTier}')` };
    }
    if (tier === "execute" && maxTier === "execute" && risk === "low") return { decision: "allowed", code: null, reason: null };
    return {
      decision: "pending_approval",
      code: null,
      reason: tier === "execute" ? `Execute-tier action with ${risk} risk requires human approval (model max tier '${maxTier}')` : "Tool requires human approval",
    };
  }

  private riskOf(tool: AnyToolDefinition, args: unknown): ActionRisk {
    if (typeof tool.risk === "function") {
      try {
        return tool.risk(args);
      } catch {
        return "high";
      }
    }
    return tool.risk ?? defaultRisk(tool.tier);
  }

  private describe(tool: AnyToolDefinition, args: unknown): string {
    if (tool.describe) {
      try {
        return tool.describe(args);
      } catch {
        /* fall through */
      }
    }
    return `${tool.name}(${truncate(safeStringify(scrubSecretsDeep(args)), 300)})`;
  }

  private record(ctx: ToolInvocationContext, call: ToolCallRequest, tier: AiToolTier, status: AiActionRecord["status"], result: unknown, actionId: string): AiActionRecord {
    return {
      id: actionId,
      conversationId: ctx.conversationId,
      tool: call.name,
      tier,
      arguments: call.arguments,
      status,
      result: result ?? null,
      requestedBy: ctx.principal.id,
      approvedBy: null,
      at: this.clock.now().toISOString(),
    };
  }

  private auditEvent(ctx: ToolInvocationContext, partial: Omit<AiAuditEvent, "id" | "at" | "tenantId" | "organizationId" | "actor">): AiAuditEvent {
    return {
      id: this.ids(),
      at: this.clock.now().toISOString(),
      tenantId: ctx.tenantId,
      organizationId: ctx.organizationId,
      actor: { kind: "ai", id: ctx.providerId ?? "ai" },
      onBehalfOf: ctx.principal.id,
      conversationId: ctx.conversationId,
      providerId: ctx.providerId ?? null,
      ...(ctx.requestId ? { requestId: ctx.requestId } : {}),
      ...partial,
    };
  }

  private async auditAfter(event: AiAuditEvent): Promise<void> {
    try {
      await this.options.audit.record(event);
    } catch (err) {
      this.options.onAuditError?.(err, event);
    }
  }

  /** Model-facing serialization of a result (bounded, JSON, explicit status). */
  toModelContent(res: ToolInvocationResult): string {
    const payload: Record<string, unknown> = { tool: res.tool, status: res.status };
    if (res.status === "completed") payload.data = res.result;
    else if (res.status === "pending_approval") {
      payload.actionId = res.action.id;
      payload.message = "Queued for human approval. It has NOT been executed. Tell the analyst it awaits approval.";
    } else {
      payload.error = { code: res.code, message: res.reason };
    }
    const text = safeStringify(payload);
    if (text.length <= this.maxResultChars) return text;
    return safeStringify({
      tool: res.tool,
      status: res.status,
      truncated: true,
      note: `Result truncated to ${this.maxResultChars} characters; narrow the query (filters, smaller limit) for complete data.`,
      partial: text.slice(0, this.maxResultChars - 400),
    });
  }

  async invoke(ctx: ToolInvocationContext, call: ToolCallRequest): Promise<ToolInvocationResult> {
    const started = this.clock.now().getTime();
    const actionId = this.ids();
    const tool = this.tools.get(call.name);
    const elapsed = (): number => this.clock.now().getTime() - started;

    const deny = async (code: ToolDenialCode, reason: string, tier: AiToolTier | null, status: AiActionRecord["status"] = "denied"): Promise<ToolInvocationResult> => {
      const action = this.record(ctx, call, tier ?? "read", status, null, actionId);
      await this.auditAfter(
        this.auditEvent(ctx, {
          action: status === "failed" ? "ai.tool.failed" : "ai.tool.denied",
          tool: call.name,
          ...(tier ? { tier } : {}),
          decision: "denied",
          status,
          code,
          reason,
          actionId,
          arguments: scrubSecretsDeep(call.arguments),
          durationMs: elapsed(),
        }),
      );
      return { callId: call.id, tool: call.name, tier, risk: null, decision: "denied", status, code, reason, result: null, action, approvalId: null, durationMs: elapsed() };
    };

    if (!tool) return deny("unknown_tool", `Unknown tool '${call.name}'`, null);
    if (ctx.principal.tenantId !== ctx.tenantId) return deny("tenant_mismatch", "Principal does not belong to this tenant", tool.tier);
    if (!principalCan(ctx.principal, "ai:use", ctx.organizationId)) return deny("ai_use_not_permitted", "Principal lacks 'ai:use' for this organization", tool.tier);
    if (!principalCan(ctx.principal, tool.permission, ctx.organizationId)) {
      return deny("permission_denied", `Principal lacks '${tool.permission}' for this organization`, tool.tier);
    }
    if (INVALID_TOOL_ARGUMENTS_KEY in call.arguments) return deny("invalid_arguments", "Tool arguments were not valid JSON", tool.tier, "failed");
    const parsed = tool.parameters.safeParse(call.arguments);
    if (!parsed.success) {
      const issues = parsed.error.issues.slice(0, 8).map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
      return deny("invalid_arguments", `Invalid arguments: ${issues}`, tool.tier, "failed");
    }
    const args: unknown = parsed.data;
    const risk = this.riskOf(tool, args);
    const tierVerdict = this.tierDecision(tool.tier, ctx.providerMaxTier, risk);
    if (tierVerdict.decision === "denied") return deny(tierVerdict.code!, tierVerdict.reason!, tool.tier);
    const normalizedCall: ToolCallRequest = { ...call, arguments: (args ?? {}) as Record<string, unknown> };

    if (tierVerdict.decision === "pending_approval") {
      const summary = this.describe(tool, args);
      let approvalId: string;
      try {
        const ticket = await this.options.approvals.requestApproval({
          actionId,
          tenantId: ctx.tenantId,
          organizationId: ctx.organizationId,
          conversationId: ctx.conversationId,
          providerId: ctx.providerId ?? null,
          tool: tool.name,
          tier: tool.tier,
          risk,
          arguments: normalizedCall.arguments,
          summary,
          reason: tierVerdict.reason!,
          requestedBy: { id: ctx.principal.id, kind: ctx.principal.kind, ...(ctx.principal.email ? { email: ctx.principal.email } : {}) },
          requestedAt: this.clock.now().toISOString(),
        });
        approvalId = ticket.approvalId;
      } catch (err) {
        return deny("approval_unavailable", `Approval queue unavailable: ${describeError(err).message}`, tool.tier, "failed");
      }
      const action = this.record(ctx, normalizedCall, tool.tier, "pending_approval", { approvalId, summary, risk }, actionId);
      await this.auditAfter(
        this.auditEvent(ctx, {
          action: "ai.tool.approval_requested",
          tool: tool.name,
          tier: tool.tier,
          risk,
          decision: "pending_approval",
          status: "pending_approval",
          reason: tierVerdict.reason,
          actionId,
          arguments: scrubSecretsDeep(normalizedCall.arguments),
          metadata: { approvalId, summary },
        }),
      );
      return {
        callId: call.id,
        tool: tool.name,
        tier: tool.tier,
        risk,
        decision: "pending_approval",
        status: "pending_approval",
        code: null,
        reason: tierVerdict.reason,
        result: null,
        action,
        approvalId,
        durationMs: elapsed(),
      };
    }

    // Allowed: audit first (fail closed), then execute.
    try {
      await this.options.audit.record(
        this.auditEvent(ctx, {
          action: "ai.tool.invoked",
          tool: tool.name,
          tier: tool.tier,
          risk,
          decision: "allowed",
          status: "started",
          actionId,
          arguments: scrubSecretsDeep(normalizedCall.arguments),
        }),
      );
    } catch (err) {
      return {
        callId: call.id,
        tool: tool.name,
        tier: tool.tier,
        risk,
        decision: "denied",
        status: "failed",
        code: "audit_unavailable",
        reason: `Audit log unavailable; action not executed (${describeError(err).message})`,
        result: null,
        action: this.record(ctx, normalizedCall, tool.tier, "failed", null, actionId),
        approvalId: null,
        durationMs: elapsed(),
      };
    }
    const scope = this.scopeFor(ctx.tenantId, ctx.organizationId, ctx.principal, ctx.conversationId, null);
    const outcome = await this.runHandler(tool, scope, actionId, args, ctx.signal);
    const status: AiActionRecord["status"] = outcome.ok ? "completed" : "failed";
    const action = this.record(ctx, normalizedCall, tool.tier, status, outcome.ok ? outcome.value : null, actionId);
    await this.auditAfter(
      this.auditEvent(ctx, {
        action: outcome.ok ? "ai.tool.invoked" : "ai.tool.failed",
        tool: tool.name,
        tier: tool.tier,
        risk,
        decision: "allowed",
        status,
        ...(outcome.ok ? {} : { code: outcome.code, reason: outcome.message }),
        actionId,
        durationMs: elapsed(),
      }),
    );
    return {
      callId: call.id,
      tool: tool.name,
      tier: tool.tier,
      risk,
      decision: "allowed",
      status,
      code: outcome.ok ? null : outcome.code,
      reason: outcome.ok ? null : outcome.message,
      result: outcome.ok ? outcome.value : null,
      action,
      approvalId: null,
      durationMs: elapsed(),
    };
  }

  private scopeFor(tenantId: string, organizationId: string, principal: Pick<Principal, "id" | "kind">, conversationId: string, approvedBy: string | null): SocScope {
    return { tenantId, organizationId, principalId: principal.id, principalKind: principal.kind, conversationId, via: "ai", approvedBy };
  }

  private async runHandler(
    tool: AnyToolDefinition,
    scope: SocScope,
    actionId: string,
    args: unknown,
    parentSignal: AbortSignal | undefined,
  ): Promise<{ ok: true; value: unknown } | { ok: false; code: ToolDenialCode; message: string }> {
    const controller = new AbortController();
    const timeoutMs = tool.timeoutMs ?? this.defaultTimeoutMs;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onParentAbort = (): void => controller.abort(parentSignal?.reason);
    parentSignal?.addEventListener("abort", onParentAbort, { once: true });
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort(new Error("timeout"));
          reject(Object.assign(new Error(`Tool '${tool.name}' timed out after ${timeoutMs} ms`), { code: "timeout" }));
        }, timeoutMs);
      });
      const value = await Promise.race([tool.handler({ scope, actionId, now: this.clock.now(), signal: controller.signal }, args), timeout]);
      return { ok: true, value };
    } catch (err) {
      const isTimeout = (err as { code?: string }).code === "timeout";
      return { ok: false, code: isTimeout ? "timeout" : "handler_error", message: describeError(err).message };
    } finally {
      if (timer) clearTimeout(timer);
      parentSignal?.removeEventListener("abort", onParentAbort);
    }
  }

  /**
   * Execute an action a human approved (`POST /ai/actions/:id/approve`). The approver needs
   * `response:approve` in the organization and — by default — must not be the requester.
   * Arguments are re-validated against the current tool schema before execution.
   */
  async executeApproved(input: {
    action: AiActionRecord;
    approver: Principal;
    tenantId: string;
    organizationId: string;
    providerId?: string | null;
    signal?: AbortSignal;
  }): Promise<ToolInvocationResult> {
    const started = this.clock.now().getTime();
    const { action, approver } = input;
    const tool = this.tools.get(action.tool);
    const requester: Principal = { kind: "user", id: action.requestedBy, tenantId: input.tenantId, bindings: [] };
    const ctx: ToolInvocationContext = {
      principal: requester,
      tenantId: input.tenantId,
      organizationId: input.organizationId,
      providerMaxTier: action.tier,
      conversationId: action.conversationId,
      providerId: input.providerId ?? null,
    };
    const call: ToolCallRequest = { id: action.id, name: action.tool, arguments: action.arguments };
    const finish = async (
      status: AiActionRecord["status"],
      decision: ToolDecision,
      code: ToolDenialCode | null,
      reason: string | null,
      result: unknown,
    ): Promise<ToolInvocationResult> => {
      const record: AiActionRecord = { ...action, status, result: result ?? null, approvedBy: status === "denied" ? null : approver.id, at: this.clock.now().toISOString() };
      await this.auditAfter({
        ...this.auditEvent(ctx, {
          action: status === "completed" ? "ai.tool.approved_executed" : status === "denied" ? "ai.tool.denied" : "ai.tool.failed",
          tool: action.tool,
          tier: action.tier,
          decision,
          status,
          code,
          reason,
          actionId: action.id,
          durationMs: this.clock.now().getTime() - started,
          metadata: { approvedBy: approver.id },
        }),
        actor: { kind: approver.kind, id: approver.id, ...(approver.email ? { email: approver.email } : {}) },
      });
      return {
        callId: action.id,
        tool: action.tool,
        tier: action.tier,
        risk: tool ? this.riskOf(tool, action.arguments) : null,
        decision,
        status,
        code,
        reason,
        result: result ?? null,
        action: record,
        approvalId: null,
        durationMs: this.clock.now().getTime() - started,
      };
    };

    if (action.status !== "pending_approval") return finish("denied", "denied", "invalid_arguments", `Action is '${action.status}', not pending approval`, null);
    if (!tool) return finish("denied", "denied", "unknown_tool", `Unknown tool '${action.tool}'`, null);
    if (approver.tenantId !== input.tenantId) return finish("denied", "denied", "tenant_mismatch", "Approver does not belong to this tenant", null);
    if (!principalCan(approver, "response:approve", input.organizationId)) return finish("denied", "denied", "permission_denied", "Approver lacks 'response:approve'", null);
    if (this.requireDistinctApprover && approver.id === action.requestedBy) {
      return finish("denied", "denied", "permission_denied", "Four-eyes policy: the requester cannot approve their own AI action", null);
    }
    if (AI_TIER_RANK[tool.tier] < AI_TIER_RANK.require_approval) return finish("denied", "denied", "invalid_arguments", "Tool does not use the approval flow", null);
    const parsed = tool.parameters.safeParse(action.arguments);
    if (!parsed.success) return finish("failed", "denied", "invalid_arguments", `Stored arguments no longer valid: ${parsed.error.issues[0]?.message ?? "invalid"}`, null);

    const scope = this.scopeFor(input.tenantId, input.organizationId, requester, action.conversationId, approver.id);
    const outcome = await this.runHandler(tool, scope, action.id, parsed.data, input.signal);
    if (!outcome.ok) return finish("failed", "allowed", outcome.code, outcome.message, null);
    return finish("completed", "allowed", null, null, outcome.value);
  }

  /** Record a human rejection of a pending AI action. */
  async reject(input: { action: AiActionRecord; approver: Principal; tenantId: string; organizationId: string; reason: string }): Promise<AiActionRecord> {
    const { action, approver } = input;
    if (approver.tenantId !== input.tenantId || !principalCan(approver, "response:approve", input.organizationId)) {
      throw new AiAccessDeniedError("permission_denied", "Approver is not allowed to reject this action");
    }
    const record: AiActionRecord = { ...action, status: "rejected", approvedBy: approver.id, at: this.clock.now().toISOString() };
    await this.options.audit.record({
      id: this.ids(),
      at: record.at,
      action: "ai.tool.rejected",
      tenantId: input.tenantId,
      organizationId: input.organizationId,
      actor: { kind: approver.kind, id: approver.id, ...(approver.email ? { email: approver.email } : {}) },
      onBehalfOf: action.requestedBy,
      conversationId: action.conversationId,
      tool: action.tool,
      tier: action.tier,
      decision: "denied",
      status: "rejected",
      reason: input.reason,
      actionId: action.id,
    });
    return record;
  }
}
