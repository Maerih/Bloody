import { actionRisk, principalCan, type ActionRisk, type Principal, type ResponseActionKey } from "@bloody/contracts";
import { safeAudit, type AuditSink } from "../util/audit.js";
import { AutomationError, ConcurrencyError } from "../util/errors.js";
import { systemClock, uuidIds, type Clock, type IdGenerator } from "../util/runtime.js";
import type { ApprovalKind, ApprovalRequest, ApprovalRequester, ApprovalStore } from "./types.js";

export type ApprovalErrorCode =
  | "not_found"
  | "forbidden"
  | "self_approval"
  | "duplicate_approver"
  | "not_pending"
  | "expired"
  | "invalid_request";

export class ApprovalError extends AutomationError {
  declare readonly code: ApprovalErrorCode;

  constructor(code: ApprovalErrorCode, message: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = "ApprovalError";
  }
}

/**
 * Tenant / organization approval policy. High-risk actions are ALWAYS gated — a policy can add
 * more risk levels to the gate or require more approvers, never remove the high-risk gate.
 */
export interface ApprovalPolicy {
  /** Additional risk levels that require approval (high is always included). */
  requireApprovalFor: ActionRisk[];
  /** Distinct approvers required for high-risk actions (four-eyes = 2). Default 1. */
  highRiskApprovals: number;
  /** Default time-to-live for a pending request. */
  ttlMinutes: number;
}

export const DEFAULT_APPROVAL_POLICY: ApprovalPolicy = { requireApprovalFor: ["high"], highRiskApprovals: 1, ttlMinutes: 240 };

export interface ApprovalRequirement {
  required: boolean;
  risk: ActionRisk;
  reasons: string[];
}

/** Does this action need a human approval? High risk → always, regardless of any flag. */
export function approvalRequirement(action: ResponseActionKey, opts: { forced?: boolean; policy?: Partial<ApprovalPolicy> } = {}): ApprovalRequirement {
  const risk = actionRisk(action);
  const reasons: string[] = [];
  if (risk === "high") reasons.push(`"${action}" is a high-risk action; high-risk actions always require approval`);
  const extra = opts.policy?.requireApprovalFor ?? [];
  if (risk !== "high" && extra.includes(risk)) reasons.push(`policy requires approval for ${risk}-risk actions`);
  if (opts.forced) reasons.push("the playbook step is configured to require approval");
  return { required: reasons.length > 0, risk, reasons };
}

export interface ApprovalRequestInput {
  tenantId: string;
  organizationId: string;
  kind: ApprovalKind;
  action: ResponseActionKey;
  reason: string;
  subject?: ApprovalRequest["subject"];
  parameters?: Record<string, unknown>;
  requestedBy: ApprovalRequester;
  /** Force the gate for a low/medium action (playbook step `requireApproval`). */
  forced?: boolean;
  ttlMinutes?: number;
}

export type ApprovalListener = (request: ApprovalRequest) => Promise<void> | void;

export interface ApprovalGateDeps {
  store: ApprovalStore;
  clock?: Clock;
  ids?: IdGenerator;
  audit?: AuditSink;
  policy?: Partial<ApprovalPolicy>;
}

const MAX_TTL_MINUTES = 7 * 24 * 60;

/**
 * Approval gate for dangerous actions (isolate endpoint, block IP, disable identity, revoke…).
 *
 * Rules enforced on every decision:
 *  - the decider must be a human user (service principals / API keys can never approve);
 *  - same tenant (otherwise the request is reported as not found — no existence oracle);
 *  - `response:approve` permission for the request's organization;
 *  - no self-approval: neither the requester nor the human a playbook/AI acted on behalf of;
 *  - each approver counts once (four-eyes policies need distinct people);
 *  - the request must be pending and unexpired (expired requests are closed on touch).
 * Every decision and every denied attempt is written to the audit sink.
 */
export class ApprovalGate {
  private readonly store: ApprovalStore;
  private readonly clock: Clock;
  private readonly ids: IdGenerator;
  private readonly audit: AuditSink | undefined;
  private readonly policy: ApprovalPolicy;
  private readonly listeners = new Set<ApprovalListener>();

  constructor(deps: ApprovalGateDeps) {
    this.store = deps.store;
    this.clock = deps.clock ?? systemClock;
    this.ids = deps.ids ?? uuidIds;
    this.audit = deps.audit;
    const p = { ...DEFAULT_APPROVAL_POLICY, ...deps.policy };
    this.policy = {
      requireApprovalFor: [...new Set<ActionRisk>(["high", ...p.requireApprovalFor])],
      highRiskApprovals: Math.max(1, Math.min(5, Math.floor(p.highRiskApprovals))),
      ttlMinutes: Math.max(1, Math.min(MAX_TTL_MINUTES, Math.floor(p.ttlMinutes))),
    };
  }

  get effectivePolicy(): Readonly<ApprovalPolicy> {
    return this.policy;
  }

  requirement(action: ResponseActionKey, forced = false): ApprovalRequirement {
    return approvalRequirement(action, { forced, policy: this.policy });
  }

  /** Subscribe to final decisions (approved / rejected / expired / cancelled). Returns an unsubscribe fn. */
  onDecision(listener: ApprovalListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  async request(input: ApprovalRequestInput): Promise<ApprovalRequest> {
    const reason = input.reason.trim();
    if (reason.length < 3 || reason.length > 2000) throw new ApprovalError("invalid_request", "reason must be 3-2000 characters");
    if (!input.requestedBy.id) throw new ApprovalError("invalid_request", "requestedBy is required");
    const req = this.requirement(input.action, input.forced ?? false);
    const now = this.clock.now();
    const ttl = Math.max(1, Math.min(MAX_TTL_MINUTES, Math.floor(input.ttlMinutes ?? this.policy.ttlMinutes)));
    const record: ApprovalRequest = {
      id: this.ids(),
      tenantId: input.tenantId,
      organizationId: input.organizationId,
      kind: input.kind,
      action: input.action,
      risk: req.risk,
      reason,
      gateReasons: req.reasons.length > 0 ? req.reasons : ["approval explicitly requested"],
      subject: input.subject ?? {},
      parameters: input.parameters ?? {},
      requestedBy: input.requestedBy,
      status: "pending",
      requiredApprovals: req.risk === "high" ? this.policy.highRiskApprovals : 1,
      approvals: [],
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttl * 60_000).toISOString(),
      decidedAt: null,
      decidedBy: null,
      decisionComment: null,
      version: 1,
    };
    await this.store.insert(record);
    await safeAudit(this.audit, {
      tenantId: record.tenantId,
      organizationId: record.organizationId,
      actor: { kind: input.requestedBy.kind, id: input.requestedBy.id },
      action: "approval.requested",
      target: { kind: "approval", id: record.id },
      outcome: "success",
      at: record.createdAt,
      details: { action: record.action, risk: record.risk, gateReasons: record.gateReasons, subject: record.subject },
    });
    return record;
  }

  /** Read a request, closing it as expired if its deadline passed. */
  async get(tenantId: string, id: string): Promise<ApprovalRequest | null> {
    const r = await this.store.get(tenantId, id);
    if (!r) return null;
    if (r.status === "pending" && this.isExpired(r)) return (await this.closeExpired(r)) ?? (await this.store.get(tenantId, id));
    return r;
  }

  async listPending(tenantId: string, filter?: { organizationId?: string; organizationIds?: readonly string[] }): Promise<ApprovalRequest[]> {
    const rows = await this.store.listPending(tenantId, filter);
    const out: ApprovalRequest[] = [];
    for (const r of rows) {
      if (this.isExpired(r)) await this.closeExpired(r);
      else out.push(r);
    }
    return out;
  }

  /** Can this principal decide this request? Explains why not (for disabling UI buttons). */
  canDecide(principal: Principal, request: ApprovalRequest): { allowed: true } | { allowed: false; code: ApprovalErrorCode; reason: string } {
    if (principal.tenantId !== request.tenantId) return { allowed: false, code: "not_found", reason: "approval request not found" };
    if (principal.kind !== "user") return { allowed: false, code: "forbidden", reason: "only human users can approve or reject actions" };
    if (!principalCan(principal, "response:approve", request.organizationId)) {
      return { allowed: false, code: "forbidden", reason: "missing permission response:approve for this organization" };
    }
    if (principal.id === request.requestedBy.id || (request.requestedBy.onBehalfOf !== undefined && principal.id === request.requestedBy.onBehalfOf)) {
      return { allowed: false, code: "self_approval", reason: "the requester cannot decide their own request" };
    }
    if (request.approvals.some((a) => a.principalId === principal.id)) {
      return { allowed: false, code: "duplicate_approver", reason: "you have already approved this request" };
    }
    if (request.status !== "pending") return { allowed: false, code: "not_pending", reason: `request is already ${request.status}` };
    if (this.isExpired(request)) return { allowed: false, code: "expired", reason: "approval request has expired" };
    return { allowed: true };
  }

  async approve(tenantId: string, id: string, principal: Principal, comment?: string): Promise<ApprovalRequest> {
    return this.decide(tenantId, id, principal, "approve", comment);
  }

  async reject(tenantId: string, id: string, principal: Principal, comment?: string): Promise<ApprovalRequest> {
    return this.decide(tenantId, id, principal, "reject", comment);
  }

  /** Withdraw a pending request (requester, playbook cancellation, incident closed…). */
  async cancel(tenantId: string, id: string, actor: { kind: "user" | "service" | "system"; id: string }, reason: string): Promise<ApprovalRequest> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const cur = await this.store.get(tenantId, id);
      if (!cur) throw new ApprovalError("not_found", "approval request not found");
      if (cur.status !== "pending") throw new ApprovalError("not_pending", `request is already ${cur.status}`);
      const next: ApprovalRequest = {
        ...cur,
        status: "cancelled",
        decidedAt: this.clock.now().toISOString(),
        decidedBy: actor.id,
        decisionComment: reason.slice(0, 2000),
        version: cur.version + 1,
      };
      if (await this.store.compareAndSet(next, cur.version)) {
        await this.finalize(next, { kind: actor.kind, id: actor.id }, "approval.cancelled");
        return next;
      }
    }
    throw new ConcurrencyError("approval request changed concurrently; retry");
  }

  /** Close every pending request past its deadline. Run periodically by the API scheduler. */
  async expireDue(tenantId?: string): Promise<ApprovalRequest[]> {
    const due = await this.store.listExpired(this.clock.now(), tenantId);
    const closed: ApprovalRequest[] = [];
    for (const r of due) {
      const c = await this.closeExpired(r);
      if (c) closed.push(c);
    }
    return closed;
  }

  private isExpired(r: ApprovalRequest): boolean {
    return Date.parse(r.expiresAt) <= this.clock.now().getTime();
  }

  private async closeExpired(r: ApprovalRequest): Promise<ApprovalRequest | null> {
    const next: ApprovalRequest = { ...r, status: "expired", decidedAt: this.clock.now().toISOString(), decidedBy: null, version: r.version + 1 };
    if (!(await this.store.compareAndSet(next, r.version))) return null;
    await this.finalize(next, { kind: "system", id: "approval-expiry" }, "approval.expired");
    return next;
  }

  private async decide(tenantId: string, id: string, principal: Principal, decision: "approve" | "reject", comment?: string): Promise<ApprovalRequest> {
    const cleanComment = comment?.trim() ? comment.trim().slice(0, 2000) : null;
    for (let attempt = 0; attempt < 3; attempt++) {
      const cur = await this.store.get(tenantId, id);
      if (!cur || cur.tenantId !== principal.tenantId) throw new ApprovalError("not_found", "approval request not found");
      if (cur.status === "pending" && this.isExpired(cur)) {
        await this.closeExpired(cur);
        await this.denied(cur, principal, decision, "expired", "approval request has expired");
        throw new ApprovalError("expired", "approval request has expired");
      }
      const check = this.canDecide(principal, cur);
      if (!check.allowed) {
        await this.denied(cur, principal, decision, check.code, check.reason);
        throw new ApprovalError(check.code, check.reason);
      }
      const now = this.clock.now().toISOString();
      let next: ApprovalRequest;
      if (decision === "reject") {
        next = { ...cur, status: "rejected", decidedAt: now, decidedBy: principal.id, decisionComment: cleanComment, version: cur.version + 1 };
      } else {
        const approvals = [...cur.approvals, { principalId: principal.id, ...(principal.displayName ? { displayName: principal.displayName } : {}), at: now, comment: cleanComment }];
        const done = approvals.length >= cur.requiredApprovals;
        next = {
          ...cur,
          approvals,
          status: done ? "approved" : "pending",
          decidedAt: done ? now : null,
          decidedBy: done ? principal.id : null,
          decisionComment: done ? cleanComment : cur.decisionComment,
          version: cur.version + 1,
        };
      }
      if (!(await this.store.compareAndSet(next, cur.version))) continue;
      const action = decision === "reject" ? "approval.rejected" : next.status === "approved" ? "approval.approved" : "approval.partially_approved";
      if (next.status === "pending") {
        await safeAudit(this.audit, {
          tenantId: next.tenantId,
          organizationId: next.organizationId,
          actor: { kind: "user", id: principal.id },
          action,
          target: { kind: "approval", id: next.id },
          outcome: "success",
          at: now,
          details: { action: next.action, approvals: next.approvals.length, required: next.requiredApprovals },
        });
      } else {
        await this.finalize(next, { kind: "user", id: principal.id }, action);
      }
      return next;
    }
    throw new ConcurrencyError("approval request changed concurrently; retry");
  }

  private async denied(r: ApprovalRequest, principal: Principal, decision: string, code: string, reason: string): Promise<void> {
    await safeAudit(this.audit, {
      tenantId: principal.tenantId,
      organizationId: r.tenantId === principal.tenantId ? r.organizationId : null,
      actor: { kind: principal.kind === "user" ? "user" : "service", id: principal.id },
      action: `approval.${decision}`,
      target: { kind: "approval", id: r.id },
      outcome: "denied",
      at: this.clock.now().toISOString(),
      details: { code, reason },
    });
  }

  private async finalize(r: ApprovalRequest, actor: { kind: "user" | "service" | "system"; id: string }, action: string): Promise<void> {
    await safeAudit(this.audit, {
      tenantId: r.tenantId,
      organizationId: r.organizationId,
      actor,
      action,
      target: { kind: "approval", id: r.id },
      outcome: "success",
      at: r.decidedAt ?? this.clock.now().toISOString(),
      details: { action: r.action, risk: r.risk, status: r.status, comment: r.decisionComment, approvers: r.approvals.map((a) => a.principalId), subject: r.subject },
    });
    for (const l of this.listeners) {
      try {
        await l(r);
      } catch {
        // A failing listener (e.g. playbook resume) must not undo a recorded decision; the
        // execution stays in waiting_approval and can be resumed explicitly.
      }
    }
  }
}
