import type { ActionRisk, AiActionRecord, AiToolTier, Permission, Principal } from "@bloody/contracts";
import type { z } from "zod";

/** Tenant scope handed to every data-port call — derived from the authenticated principal,
 * never from model output. */
export interface SocScope {
  tenantId: string;
  organizationId: string;
  /** Principal on whose behalf the AI acts (the requesting analyst). */
  principalId: string;
  principalKind: "user" | "service";
  conversationId: string;
  /** Always "ai" for calls made through the gateway. */
  via: "ai";
  /** Human approver, for actions executed after an approval gate. */
  approvedBy: string | null;
}

/** Context of one tool invocation (built by the orchestrator / API from the session). */
export interface ToolInvocationContext {
  principal: Principal;
  tenantId: string;
  organizationId: string;
  /** Highest tier the serving model may use without a human (provider config `maxToolTier`). */
  providerMaxTier: AiToolTier;
  conversationId: string;
  providerId?: string | null;
  requestId?: string;
  signal?: AbortSignal;
}

export interface ToolHandlerContext {
  scope: SocScope;
  actionId: string;
  now: Date;
  signal: AbortSignal;
}

export interface ToolDefinition<S extends z.ZodTypeAny = z.ZodTypeAny, R = unknown> {
  /** ^[a-z][a-z0-9_]{1,63}$ — portable across every provider's function-name rules. */
  name: string;
  description: string;
  tier: AiToolTier;
  /** RBAC permission the requesting principal must hold in the organization. */
  permission: Permission;
  parameters: S;
  /** Action risk for approval decisions (default: low for read/investigate/recommend, high otherwise). */
  risk?: ActionRisk | ((args: z.output<S>) => ActionRisk);
  /** One-line human summary for the approval queue / audit trail. */
  describe?: (args: z.output<S>) => string;
  timeoutMs?: number;
  handler: (ctx: ToolHandlerContext, args: z.output<S>) => Promise<R>;
}

/** Erased form stored in the gateway registry (arguments are validated by `parameters` first). */
export interface AnyToolDefinition {
  name: string;
  description: string;
  tier: AiToolTier;
  permission: Permission;
  parameters: z.ZodTypeAny;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  risk?: ActionRisk | ((args: any) => ActionRisk);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  describe?: (args: any) => string;
  timeoutMs?: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handler: (ctx: ToolHandlerContext, args: any) => Promise<unknown>;
}

export function defineTool<S extends z.ZodTypeAny, R>(def: ToolDefinition<S, R>): ToolDefinition<S, R> {
  return def;
}

export type ToolDecision = "allowed" | "denied" | "pending_approval";

export type ToolDenialCode =
  | "unknown_tool"
  | "tenant_mismatch"
  | "ai_use_not_permitted"
  | "permission_denied"
  | "tier_exceeds_provider_max"
  | "invalid_arguments"
  | "approval_unavailable"
  | "audit_unavailable"
  | "handler_error"
  | "timeout"
  | "duplicate_call"
  | "call_limit_exceeded";

export interface ToolCallRequest {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolInvocationResult {
  callId: string;
  tool: string;
  tier: AiToolTier | null;
  risk: ActionRisk | null;
  decision: ToolDecision;
  status: AiActionRecord["status"];
  /** Machine code + human reason for denials / failures / approval requirements. */
  code: ToolDenialCode | null;
  reason: string | null;
  result: unknown;
  action: AiActionRecord;
  approvalId: string | null;
  durationMs: number;
}

export interface AiApprovalRequest {
  actionId: string;
  tenantId: string;
  organizationId: string;
  conversationId: string;
  providerId: string | null;
  tool: string;
  tier: AiToolTier;
  risk: ActionRisk;
  arguments: Record<string, unknown>;
  summary: string;
  /** Why a human is required (tier policy). */
  reason: string;
  requestedBy: { id: string; kind: "user" | "service"; email?: string };
  requestedAt: string;
}

export interface AiApprovalTicket {
  approvalId: string;
  expiresAt?: string | null;
}

/** Approval queue (implemented by the API on top of response_actions / ai_actions). */
export interface ApprovalSink {
  requestApproval(req: AiApprovalRequest): Promise<AiApprovalTicket>;
}

export type AiAuditAction =
  | "ai.tool.invoked"
  | "ai.tool.denied"
  | "ai.tool.failed"
  | "ai.tool.approval_requested"
  | "ai.tool.approved_executed"
  | "ai.tool.rejected"
  | "ai.chat.completed"
  | "ai.chat.denied"
  | "ai.chat.failed"
  | "ai.provider.fallback"
  | "ai.narrative.generated";

/** Append-only AI audit record — authenticated, authorized, tenant-scoped, attributable, reviewable. */
export interface AiAuditEvent {
  id: string;
  at: string;
  action: AiAuditAction;
  tenantId: string;
  organizationId: string | null;
  actor: { kind: "user" | "service" | "ai"; id: string; email?: string };
  /** Human on whose behalf the AI acted. */
  onBehalfOf?: string;
  conversationId?: string;
  providerId?: string | null;
  model?: string;
  tool?: string;
  tier?: AiToolTier;
  risk?: ActionRisk;
  decision?: ToolDecision;
  status?: string;
  code?: string | null;
  reason?: string | null;
  actionId?: string;
  /** Arguments with secrets redacted. */
  arguments?: Record<string, unknown>;
  durationMs?: number;
  requestId?: string;
  metadata?: Record<string, unknown>;
}

export interface AiAuditSink {
  record(event: AiAuditEvent): Promise<void>;
}
