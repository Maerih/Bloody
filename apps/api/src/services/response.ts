import { randomUUID } from "node:crypto";
import {
  RESPONSE_ACTIONS,
  ROLE_PERMISSIONS,
  agentCanFix,
  hardeningCheck,
  actionRisk,
  type RoleKey,
  type ActionRisk,
  type Principal,
  type ResponseActionKey,
  type ResponseActionRecord,
  type ResponseActionStatus,
  type Severity,
} from "@bloody/contracts";
import {
  ActionExecutionError,
  ApprovalError,
  type ActionExecutionRequest,
  type ActionExecutionResult,
  type ActionExecutor,
  type ApprovalGate,
  type ApprovalRequest,
  type ApprovalRequester,
  type PlaybookEngine,
} from "@bloody/automation";
import { ResponseGuardError, buildIsolationPolicy, isIpOrCidr, isolationScriptArgs, type ResponseExecutionRequest, type ResponseExecutionResult } from "@bloody/adapters";
import type { RiskEngine } from "@bloody/engines";
import { SYSTEM_ACTOR, writeAudit, type AuditActor } from "../audit/audit.js";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, badRequest, forbidden, notFound } from "../http/errors.js";
import type { PipelineLogger } from "../pipeline/analytics.js";
import type { Row } from "../repo/mappers.js";
import type { DomainEventBus } from "./domain-events.js";
import { createIncident } from "./incidents.js";
import type { IntegrationService } from "./integrations.js";
import { insertInApp, type NotificationService } from "./notifications.js";

/**
 * Response actions (SOAR containment) — the only path to dangerous actions.
 *
 *   request → validation (target belongs to the organization) → response_actions row →
 *   ApprovalGate (high-risk actions ALWAYS; policy may add more) → approve / reject by a different
 *   human with response:approve → execution through the `ActionExecutor`: engine response
 *   connectors (@bloody/adapters: Wazuh active response, Velociraptor, signed block relay) or
 *   built-in platform actions (case, investigation, notification) → result + audit.
 *
 * Executions are claimed atomically (approved → running), so a double click, a concurrent
 * approval or a playbook retry can never run an action twice. Connectors re-check the approval
 * invariants themselves (defence in depth).
 */

export const ACTION_TARGET: Record<ResponseActionKey, "asset" | "identity" | "indicator" | "incident"> = Object.fromEntries(
  RESPONSE_ACTIONS.map((a) => [a.key, a.target]),
) as Record<ResponseActionKey, "asset" | "identity" | "indicator" | "incident">;

/** Actions SCIAT executes itself (no engine connector needed). */
export const INTERNAL_ACTIONS: ReadonlySet<ResponseActionKey> = new Set(["create_case", "notify_analyst", "launch_investigation", "send_email"]);
/** Actions that need an engine response connector (integration). */
export const CONNECTOR_ACTIONS: ReadonlySet<ResponseActionKey> = new Set(RESPONSE_ACTIONS.map((a) => a.key).filter((k) => !INTERNAL_ACTIONS.has(k)));

export interface ResponseTargetInput {
  kind: "asset" | "identity" | "indicator" | "incident";
  id: string;
  label?: string | undefined;
}

export interface ResponseRequestInput {
  tenantId: string;
  organizationId: string;
  action: ResponseActionKey;
  incidentId?: string | null | undefined;
  target: ResponseTargetInput;
  parameters: Record<string, unknown>;
  reason: string;
  /** Who asked: principal id for users/services/AI (the analyst behind an AI request), `playbook:<id>` for playbooks. */
  requestedBy: ApprovalRequester;
  via: "user" | "playbook" | "ai";
  aiActionId?: string | undefined;
  /** AI conversation behind an AI-requested action. */
  conversationId?: string | undefined;
  playbookRunId?: string | undefined;
  playbookStepId?: string | undefined;
  idempotencyKey?: string | undefined;
  /** Already approved upstream (playbook step approval). */
  preApproved?: { approvalId: string | null; approvedBy: string[] } | undefined;
  /** Force the approval gate even for a low/medium action. */
  forceApproval?: boolean | undefined;
  /**
   * Break-glass: execute without prior approval. The route has already checked the action
   * (EMERGENCY_ACTIONS), the requester (a user with response:emergency) and the written reason.
   */
  emergency?: boolean | undefined;
}

export interface ResponseActionView extends ResponseActionRecord {
  risk: ActionRisk;
  approvalId: string | null;
  aiActionId: string | null;
  playbookRunId: string | null;
  playbookStepId: string | null;
  integrationId: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  error: unknown;
  organizationName?: string | null;
  incidentNumber?: number | null;
}

export function toResponseAction(r: Row): ResponseActionView {
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: String(r.organization_id),
    incidentId: (r.incident_id as string | null) ?? null,
    action: r.action as ResponseActionKey,
    target: r.target as ResponseActionRecord["target"],
    parameters: (r.parameters as Record<string, unknown>) ?? {},
    reason: String(r.reason),
    status: r.status as ResponseActionStatus,
    requestedBy: String(r.requested_by),
    requestedVia: r.requested_via as ResponseActionRecord["requestedVia"],
    approvedBy: (r.approved_by as string | null) ?? null,
    executor: (r.executor as string | null) ?? null,
    result: r.result ?? null,
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
    risk: r.risk as ActionRisk,
    approvalId: (r.approval_id as string | null) ?? null,
    aiActionId: (r.ai_action_id as string | null) ?? null,
    playbookRunId: (r.playbook_run_id as string | null) ?? null,
    playbookStepId: (r.playbook_step_id as string | null) ?? null,
    integrationId: (r.integration_id as string | null) ?? null,
    decidedAt: (r.decided_at as string | null) ?? null,
    decisionComment: (r.decision_comment as string | null) ?? null,
    startedAt: (r.started_at as string | null) ?? null,
    finishedAt: (r.finished_at as string | null) ?? null,
    error: r.error ?? null,
    emergency: Boolean(r.emergency),
    review: r.review_status
      ? {
          status: r.review_status as "pending" | "reviewed",
          reviewedBy: (r.reviewed_by as string | null) ?? null,
          reviewedAt: r.reviewed_at ? String(r.reviewed_at) : null,
          comment: (r.review_comment as string | null) ?? null,
        }
      : null,
    ...(r.organization_name !== undefined ? { organizationName: (r.organization_name as string | null) ?? null } : {}),
    ...(r.incident_number !== undefined ? { incidentNumber: (r.incident_number as number | null) ?? null } : {}),
  };
}

/** Map automation ApprovalError codes onto the API error model. */
export function approvalHttpError(err: unknown): unknown {
  if (!(err instanceof ApprovalError)) return err;
  switch (err.code) {
    case "not_found":
      return new HttpError(404, "not_found", "Approval request not found");
    case "forbidden":
      return new HttpError(403, "forbidden", err.message);
    case "self_approval":
      return new HttpError(403, "self_approval", "You cannot approve or reject your own request (four-eyes principle)");
    case "duplicate_approver":
      return new HttpError(409, "duplicate_approver", err.message);
    case "not_pending":
      return new HttpError(409, "not_pending", err.message);
    case "expired":
      return new HttpError(409, "approval_expired", err.message);
    default:
      return new HttpError(400, "invalid_request", err.message);
  }
}

/** Minimum justification when the only approver approves their own request. */
export const SELF_APPROVAL_REASON_MIN = 20;

interface ExecutionOutcome {
  /** "dispatched": handed to a SCIAT Agent; the action stays running until the agent reports. */
  status: "succeeded" | "failed" | "dispatched";
  executor: string;
  integrationId: string | null;
  result: Record<string, unknown>;
  error: { code: string; message: string; retryable: boolean } | null;
}

/** Executes lock_device / wipe_device on an enrolled phone (the Android service). */
export interface MobileExecutor {
  deviceForAsset(tx: Queryable, assetId: string): Promise<{ name: string } | null>;
  lock(tenantId: string, assetId: string): Promise<{ summary: string; executor: string }>;
  wipe(tenantId: string, assetId: string, reason: string): Promise<{ summary: string; executor: string }>;
}

/** Actions run on a managed phone through its MDM (no engine connector). */
export const MOBILE_ACTIONS: ReadonlySet<ResponseActionKey> = new Set(["lock_device", "wipe_device"]);

type AiDecider = (principal: Principal, aiActionId: string, decision: "approve" | "reject", comment: string | undefined) => Promise<void>;
type AiApprovalHook = (approval: ApprovalRequest) => Promise<void>;

export interface ResponseServiceDeps {
  db: Database;
  gate: ApprovalGate;
  integrations: IntegrationService;
  notifications: NotificationService;
  events: DomainEventBus;
  risk: RiskEngine;
  log: PipelineLogger;
  now: () => number;
}

export class ResponseService {
  private playbooks: PlaybookEngine | null = null;
  private aiDecider: AiDecider | null = null;
  private aiApprovalHook: AiApprovalHook | null = null;
  private mobile: MobileExecutor | null = null;

  constructor(private readonly deps: ResponseServiceDeps) {
    deps.gate.onDecision((approval) => this.onDecision(approval));
  }

  /** Late wiring (the playbook engine and the AI service depend on this service). */
  attachPlaybookEngine(engine: PlaybookEngine): void {
    this.playbooks = engine;
  }

  attachMobile(executor: MobileExecutor): void {
    this.mobile = executor;
  }

  attachAi(decider: AiDecider, onApproval: AiApprovalHook): void {
    this.aiDecider = decider;
    this.aiApprovalHook = onApproval;
  }

  // ─── Catalog ─────────────────────────────────────────────────────────────

  async catalog(tx: Queryable, organizationId: string | null) {
    const connectors = await this.deps.integrations.availableActions(tx, organizationId);
    return RESPONSE_ACTIONS.map((a) => {
      const req = this.deps.gate.requirement(a.key);
      const internal = INTERNAL_ACTIONS.has(a.key) || a.key === "harden_endpoint" || MOBILE_ACTIONS.has(a.key);
      const via = connectors.get(a.key) ?? [];
      return {
        key: a.key,
        label: a.label,
        risk: a.risk,
        target: a.target,
        approvalRequired: req.required,
        approvalReasons: req.reasons,
        executable: internal || via.length > 0,
        executor: internal ? "bloody" : via.length > 0 ? "integration" : null,
        integrations: via,
        unavailableReason: internal || via.length > 0 ? null : "No enabled integration can perform this action for the organization (configure Wazuh active response, Velociraptor or a block relay)",
      };
    });
  }

  // ─── Request ─────────────────────────────────────────────────────────────

  /** Validate a target against the organization (out-of-org references are refused). */
  private async validateTarget(tx: Queryable, organizationId: string, action: ResponseActionKey, target: ResponseTargetInput, incidentId: string | null): Promise<ResponseTargetInput> {
    const expected = ACTION_TARGET[action];
    if (target.kind !== expected) throw badRequest(`${action} targets a ${expected}, not a ${target.kind}`);
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(target.id);
    switch (target.kind) {
      case "asset": {
        if (!isUuid) throw badRequest("target.id must be an asset id");
        const { rows } = await tx.query<Row>("SELECT id, name, organization_id FROM assets WHERE id = $1", [target.id]);
        if (!rows[0] || rows[0].organization_id !== organizationId) throw badRequest("The target asset does not belong to the organization");
        return { kind: "asset", id: target.id, label: target.label ?? String(rows[0].name) };
      }
      case "identity": {
        if (!isUuid) throw badRequest("target.id must be an identity id");
        const { rows } = await tx.query<Row>("SELECT id, principal, organization_id FROM identities WHERE id = $1", [target.id]);
        if (!rows[0] || rows[0].organization_id !== organizationId) throw badRequest("The target identity does not belong to the organization");
        return { kind: "identity", id: target.id, label: target.label ?? String(rows[0].principal) };
      }
      case "incident": {
        if (!isUuid) throw badRequest("target.id must be an incident id");
        const { rows } = await tx.query<Row>("SELECT id, number, title, organization_id FROM incidents WHERE id = $1", [target.id]);
        if (!rows[0] || rows[0].organization_id !== organizationId) throw badRequest("The target incident does not belong to the organization");
        return { kind: "incident", id: target.id, label: target.label ?? `#${String(rows[0].number)} ${String(rows[0].title)}` };
      }
      case "indicator": {
        if (isUuid) {
          const { rows } = await tx.query<Row>("SELECT id, type, value, organization_id FROM indicators WHERE id = $1", [target.id]);
          if (!rows[0] || (rows[0].organization_id !== null && rows[0].organization_id !== organizationId)) throw badRequest("The target indicator is not visible to the organization");
          return { kind: "indicator", id: target.id, label: target.label ?? `${String(rows[0].type)}:${String(rows[0].value)}` };
        }
        const value = target.id.trim();
        if (value.length < 1 || value.length > 2048 || /[\s\0]/.test(value)) throw badRequest("target.id must be an indicator id or an IP / domain value");
        void incidentId;
        return { kind: "indicator", id: value, label: target.label ?? value };
      }
    }
  }

  /** harden_endpoint: one Attack Reduction check the target's SCIAT Agent can fix itself. */
  private async validateHardening(tx: Queryable, target: ResponseTargetInput, parameters: Record<string, unknown>): Promise<Record<string, unknown>> {
    const check = typeof parameters.check === "string" ? parameters.check : "";
    if (!hardeningCheck(check)) throw badRequest("parameters.check must be an Attack Reduction check");
    const { rows } = await tx.query<Row>("SELECT platform FROM agents WHERE asset_id = $1 AND engine = 'sciat' AND agent_token_hash IS NOT NULL ORDER BY last_checkin_at DESC NULLS LAST LIMIT 1", [target.id]);
    if (!rows[0]) throw badRequest("The asset has no SCIAT Agent to apply the fix");
    if (!agentCanFix(check, String(rows[0].platform))) throw badRequest(`The SCIAT Agent cannot apply "${hardeningCheck(check)!.title}" on this computer — apply it by hand or by policy`);
    return { check };
  }

  /** Create a response action; gate it or execute it immediately. Returns the stored record. */
  async request(input: ResponseRequestInput, actor: AuditActor): Promise<ResponseActionView> {
    const risk = actionRisk(input.action);
    const requirement = this.deps.gate.requirement(input.action, input.forceApproval ?? false);
    if (input.emergency && input.via !== "user") throw forbidden("Emergency actions can only be requested by a person", "emergency_not_allowed");
    const needsApproval = requirement.required && !input.preApproved && !input.emergency;
    const requestedBy = input.requestedBy.kind === "playbook" ? input.requestedBy.id : (input.requestedBy.onBehalfOf ?? input.requestedBy.id);

    const row = await this.deps.db.withTenant(input.tenantId, async (tx) => {
      if (input.idempotencyKey) {
        const { rows } = await tx.query<Row>("SELECT * FROM response_actions WHERE idempotency_key = $1", [input.idempotencyKey]);
        if (rows[0]) return rows[0];
      }
      const org = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [input.organizationId]);
      if ((org.rowCount ?? 0) === 0) throw notFound("Organization");
      if (input.incidentId) {
        const { rows } = await tx.query<Row>("SELECT organization_id FROM incidents WHERE id = $1", [input.incidentId]);
        if (!rows[0] || rows[0].organization_id !== input.organizationId) throw badRequest("incidentId must reference an incident of the organization");
      }
      const target = await this.validateTarget(tx, input.organizationId, input.action, input.target, input.incidentId ?? null);
      const parameters = input.action === "harden_endpoint" ? await this.validateHardening(tx, target, input.parameters) : input.parameters;
      if (MOBILE_ACTIONS.has(input.action) && !(await this.mobile?.deviceForAsset(tx, target.id))) throw badRequest("The asset is not an enrolled mobile device");
      const status: ResponseActionStatus = needsApproval ? "pending_approval" : "approved";
      const { rows } = await tx.query<Row>(
        `INSERT INTO response_actions (tenant_id, organization_id, incident_id, action, target, parameters, reason, status, risk, requested_by, requested_via,
                                       approved_by, approval_id, ai_action_id, playbook_run_id, playbook_step_id, idempotency_key, decided_at,
                                       emergency, review_status)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) RETURNING *`,
        [
          input.tenantId,
          input.organizationId,
          input.incidentId ?? null,
          input.action,
          JSON.stringify(target),
          JSON.stringify(parameters),
          input.reason.slice(0, 2000),
          status,
          risk,
          requestedBy,
          input.via,
          input.preApproved && input.preApproved.approvedBy.length > 0 ? input.preApproved.approvedBy.join(",") : null,
          input.preApproved?.approvalId ?? null,
          input.aiActionId ?? null,
          input.playbookRunId ?? null,
          input.playbookStepId ?? null,
          input.idempotencyKey ?? null,
          input.preApproved ? new Date(this.deps.now()).toISOString() : null,
          Boolean(input.emergency),
          input.emergency ? "pending" : null,
        ],
      );
      const created = rows[0]!;
      if (input.emergency) {
        await writeAudit(tx, actor, {
          action: "response.emergency",
          organizationId: input.organizationId,
          targetKind: "response_action",
          targetId: String(created.id),
          details: { action: input.action, target, reason: input.reason, parameters: input.parameters, approvalBypassed: requirement.required, gateReasons: requirement.reasons },
        });
      }
      await writeAudit(tx, actor, {
        action: "response.requested",
        organizationId: input.organizationId,
        targetKind: "response_action",
        targetId: String(created.id),
        details: { action: input.action, risk, via: input.via, target, approvalRequired: needsApproval, gateReasons: requirement.reasons, incidentId: input.incidentId ?? null },
      });
      return created;
    });
    if (row.status !== "pending_approval" && row.status !== "approved") return toResponseAction(row);

    if (needsApproval && !row.approval_id) {
      let approval: ApprovalRequest;
      try {
        approval = await this.deps.gate.request({
          tenantId: input.tenantId,
          organizationId: input.organizationId,
          kind: input.via === "ai" ? "ai_action" : "response_action",
          action: input.action,
          forced: input.forceApproval ?? false,
          reason: input.reason,
          subject: {
            responseActionId: String(row.id),
            ...(input.incidentId ? { incidentId: input.incidentId } : {}),
            target: row.target as { kind: string; id: string; label?: string },
            ...(input.conversationId ? { conversationId: input.conversationId } : {}),
          },
          parameters: input.parameters,
          requestedBy: input.requestedBy,
        });
      } catch (err) {
        await this.finish(input.tenantId, String(row.id), { status: "failed", executor: "approval-gate", integrationId: null, result: {}, error: { code: "approval_unavailable", message: err instanceof Error ? err.message : "approval request failed", retryable: true } });
        throw err;
      }
      const updated = await this.deps.db.withTenant(input.tenantId, async (tx) => (await tx.query<Row>("UPDATE response_actions SET approval_id = $2 WHERE id = $1 RETURNING *", [row.id, approval.id])).rows[0]!);
      this.deps.events.publish({
        tenantId: input.tenantId,
        organizationId: input.organizationId,
        event: "response.pending_approval",
        occurredAt: new Date(this.deps.now()).toISOString(),
        severity: risk === "high" ? "high" : "medium",
        subject: { kind: "response_action", id: String(row.id), label: `${input.action} → ${(row.target as { label?: string }).label ?? ""}` },
        dedupKey: `approval:${approval.id}`,
        data: { approvalId: approval.id, risk, gateReasons: approval.gateReasons, expiresAt: approval.expiresAt, requestedVia: input.via },
      });
      return toResponseAction(updated);
    }
    if (input.emergency) {
      this.deps.events.publish({
        tenantId: input.tenantId,
        organizationId: input.organizationId,
        event: "response.emergency",
        occurredAt: new Date(this.deps.now()).toISOString(),
        severity: "high",
        subject: { kind: "response_action", id: String(row.id), label: `EMERGENCY ${input.action} → ${(row.target as { label?: string }).label ?? ""}` },
        dedupKey: `emergency:${String(row.id)}`,
        data: { requestedBy, reason: input.reason, reviewRequired: true },
      });
    }
    if (row.status === "approved") return this.execute(input.tenantId, String(row.id), actor);
    return toResponseAction(row);
  }

  /**
   * After-the-fact review of a break-glass action by someone other than the requester. The
   * review records that a second person examined the justification; it does not undo the action
   * (release is its own action).
   */
  async review(principal: Principal, id: string, comment: string, actor: AuditActor): Promise<ResponseActionView> {
    return this.deps.db.withTenant(principal.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM response_actions WHERE id = $1 FOR UPDATE", [id]);
      const row = rows[0];
      if (!row) throw notFound("Response action");
      if (!row.emergency) throw new HttpError(409, "not_emergency", "Only emergency (break-glass) actions need a review");
      if (row.review_status !== "pending") throw new HttpError(409, "already_reviewed", "This emergency action was already reviewed");
      if (String(row.requested_by) === principal.id) throw forbidden("The person who used break-glass cannot review their own action", "self_review");
      const { rows: updated } = await tx.query<Row>(
        "UPDATE response_actions SET review_status = 'reviewed', reviewed_by = $2, reviewed_at = $3, review_comment = $4 WHERE id = $1 RETURNING *",
        [id, principal.id, new Date(this.deps.now()).toISOString(), comment],
      );
      await writeAudit(tx, actor, { action: "response.emergency_reviewed", organizationId: String(row.organization_id), targetKind: "response_action", targetId: id, details: { comment } });
      return toResponseAction(updated[0]!);
    });
  }

  // ─── Decisions ───────────────────────────────────────────────────────────

  /** Approve or reject a response action (user-requested, playbook or AI). */
  async decide(principal: Principal, id: string, decision: "approve" | "reject", comment: string | undefined): Promise<ResponseActionView> {
    const row = await this.deps.db.withTenant(principal.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM response_actions WHERE id = $1", [id]);
      return rows[0] ?? null;
    });
    if (!row) throw notFound("Response action");
    if (row.status !== "pending_approval" || !row.approval_id) throw new HttpError(409, "not_pending", `The action is ${String(row.status)}, not pending approval`);
    if (row.requested_via === "ai" && row.ai_action_id && this.aiDecider) {
      await this.aiDecider(principal, String(row.ai_action_id), decision, comment);
    } else {
      // Four-eyes needs two people: an account with a single approver may approve its own user
      // request, with a written justification, recorded as a self-approval.
      const own = decision === "approve" && row.requested_via === "user" && String(row.requested_by) === principal.id;
      const sole = own && (await this.otherApprovers(principal.tenantId, String(row.organization_id), principal.id)) === 0;
      if (sole && (comment?.trim().length ?? 0) < SELF_APPROVAL_REASON_MIN) {
        throw new HttpError(400, "justification_required", `You are the only approver: explain why in at least ${SELF_APPROVAL_REASON_MIN} characters`);
      }
      try {
        if (decision === "approve") await this.deps.gate.approve(principal.tenantId, String(row.approval_id), principal, comment, { soleApprover: sole });
        else await this.deps.gate.reject(principal.tenantId, String(row.approval_id), principal, comment);
      } catch (err) {
        throw approvalHttpError(err);
      }
      if (sole) {
        await this.deps.db.withTenant(principal.tenantId, (tx) =>
          writeAudit(tx, { tenantId: principal.tenantId, actorKind: "user", actorId: principal.id, actorLabel: principal.displayName ?? null, ip: null, userAgent: null, requestId: null }, {
            action: "response.self_approved",
            organizationId: String(row.organization_id),
            targetKind: "response_action",
            targetId: id,
            outcome: "success",
            details: { reason: "no other approver for this organization", comment: comment?.trim() ?? null, action: row.action },
          }),
        );
      }
    }
    return this.get(principal.tenantId, id);
  }

  /** Other active users who may approve response actions for the organization. */
  async otherApprovers(tenantId: string, organizationId: string, excludeUserId: string): Promise<number> {
    const roles = (Object.keys(ROLE_PERMISSIONS) as RoleKey[]).filter((r) => ROLE_PERMISSIONS[r].includes("response:approve"));
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<{ n: number }>(
        `SELECT count(DISTINCT u.id)::int AS n FROM users u
          WHERE u.status = 'active' AND u.id::text <> $1
            AND EXISTS (SELECT 1 FROM role_bindings b
                         WHERE b.role = ANY($2::text[]) AND (b.organization_id IS NULL OR b.organization_id = $3)
                           AND ((b.principal_kind = 'user' AND b.principal_id = u.id)
                             OR (b.principal_kind = 'team' AND b.principal_id IN (SELECT team_id FROM team_members WHERE user_id = u.id))))`,
        [excludeUserId, roles, organizationId],
      );
      return rows[0]?.n ?? 0;
    });
  }

  /** Decide an approval request directly (unified approvals queue: response, playbook and AI). */
  async decideApproval(principal: Principal, approvalId: string, decision: "approve" | "reject", comment: string | undefined): Promise<ApprovalRequest> {
    const approval = await this.deps.gate.get(principal.tenantId, approvalId);
    if (!approval) throw notFound("Approval request");
    if (approval.kind === "ai_action") {
      // AI approvals run through the AI gateway (four-eyes, tier re-check, transcript).
      if (approval.subject.responseActionId) await this.decide(principal, approval.subject.responseActionId, decision, comment);
      else if (approval.subject.target?.kind === "ai_action" && this.aiDecider) await this.aiDecider(principal, approval.subject.target.id, decision, comment);
      else throw new HttpError(409, "not_supported", "This AI approval can only be decided from the AI SOC");
      return (await this.deps.gate.get(principal.tenantId, approvalId)) ?? approval;
    }
    try {
      if (decision === "approve") return await this.deps.gate.approve(principal.tenantId, approvalId, principal, comment);
      return await this.deps.gate.reject(principal.tenantId, approvalId, principal, comment);
    } catch (err) {
      throw approvalHttpError(err);
    }
  }

  /** ApprovalGate listener: executes approved response actions, resumes playbooks, closes AI actions. */
  private async onDecision(approval: ApprovalRequest): Promise<void> {
    try {
      if (approval.kind === "playbook_step") {
        await this.playbooks?.resumeFromApproval(approval);
        return;
      }
      if (approval.kind === "ai_action") {
        await this.aiApprovalHook?.(approval);
        if (approval.status === "approved") return; // executed through the AI gateway by the decider
      }
      const id = approval.subject.responseActionId;
      if (!id) return;
      const approvers = approval.approvals.map((a) => a.principalId).join(",") || null;
      if (approval.status === "approved") {
        const claimed = await this.deps.db.withTenant(approval.tenantId, async (tx) =>
          (
            await tx.query<Row>(
              "UPDATE response_actions SET status = 'approved', approved_by = $2, decided_at = $3, decision_comment = $4 WHERE id = $1 AND status = 'pending_approval' RETURNING id",
              [id, approvers, approval.decidedAt, approval.decisionComment],
            )
          ).rows[0],
        );
        if (claimed) await this.execute(approval.tenantId, id, SYSTEM_ACTOR(approval.tenantId, "soar"));
        return;
      }
      const status: ResponseActionStatus = approval.status === "rejected" ? "rejected" : "cancelled";
      await this.deps.db.withTenant(approval.tenantId, (tx) =>
        tx.query(
          "UPDATE response_actions SET status = $2, approved_by = CASE WHEN $2 = 'rejected' THEN $3 ELSE approved_by END, decided_at = $4, decision_comment = $5, finished_at = $4 WHERE id = $1 AND status = 'pending_approval'",
          [id, status, approval.decidedBy, approval.decidedAt ?? new Date(this.deps.now()).toISOString(), approval.decisionComment ?? (approval.status === "expired" ? "approval expired" : null)],
        ),
      );
    } catch (err) {
      this.deps.log.error({ tenantId: approval.tenantId, approvalId: approval.id, err: err instanceof Error ? err.message : String(err) }, "approval decision handling failed");
    }
  }

  async get(tenantId: string, id: string): Promise<ResponseActionView> {
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        "SELECT r.*, o.name AS organization_name, i.number AS incident_number FROM response_actions r JOIN organizations o ON o.id = r.organization_id LEFT JOIN incidents i ON i.id = r.incident_id WHERE r.id = $1",
        [id],
      );
      if (!rows[0]) throw notFound("Response action");
      return toResponseAction(rows[0]);
    });
  }

  /** Cancel a pending action (requester or approver). */
  async cancel(principal: Principal, id: string, reason: string): Promise<ResponseActionView> {
    const row = await this.deps.db.withTenant(principal.tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM response_actions WHERE id = $1", [id])).rows[0] ?? null);
    if (!row) throw notFound("Response action");
    if (row.status !== "pending_approval") throw new HttpError(409, "not_pending", `The action is ${String(row.status)}; only pending actions can be cancelled`);
    if (row.approval_id) {
      try {
        await this.deps.gate.cancel(principal.tenantId, String(row.approval_id), { kind: principal.kind === "user" ? "user" : "service", id: principal.id }, reason);
      } catch (err) {
        throw approvalHttpError(err);
      }
    } else {
      await this.deps.db.withTenant(principal.tenantId, (tx) => tx.query("UPDATE response_actions SET status = 'cancelled', decision_comment = $2, finished_at = now() WHERE id = $1 AND status = 'pending_approval'", [id, reason]));
    }
    return this.get(principal.tenantId, id);
  }

  // ─── Execution ───────────────────────────────────────────────────────────

  /** Execute an approved action exactly once (claim approved → running). */
  async execute(tenantId: string, id: string, actor: AuditActor): Promise<ResponseActionView> {
    const row = await this.deps.db.withTenant(tenantId, async (tx) =>
      (await tx.query<Row>("UPDATE response_actions SET status = 'running', started_at = now() WHERE id = $1 AND status IN ('approved', 'queued') RETURNING *", [id])).rows[0] ?? null,
    );
    if (!row) return this.get(tenantId, id);
    let outcome: ExecutionOutcome;
    try {
      outcome = await this.run(tenantId, row);
    } catch (err) {
      const code = err instanceof HttpError ? err.code : ((err as { code?: string }).code ?? "execution_error");
      outcome = { status: "failed", executor: "bloody", integrationId: null, result: {}, error: { code, message: err instanceof Error ? err.message.slice(0, 1000) : "execution failed", retryable: !(err instanceof HttpError) } };
    }
    if (outcome.status === "dispatched") {
      await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE response_actions SET executor = $2, result = $3::jsonb WHERE id = $1", [id, outcome.executor, JSON.stringify(outcome.result)]));
      return this.get(tenantId, id);
    }
    await this.finish(tenantId, id, outcome, actor, row);
    return this.get(tenantId, id);
  }

  private async finish(tenantId: string, id: string, outcome: ExecutionOutcome, actor?: AuditActor, row?: Row): Promise<void> {
    await this.deps.db.withTenant(tenantId, async (tx) => {
      await tx.query(
        "UPDATE response_actions SET status = $2, executor = $3, integration_id = $4, result = $5::jsonb, error = $6::jsonb, finished_at = now() WHERE id = $1",
        [id, outcome.status, outcome.executor, outcome.integrationId, JSON.stringify(outcome.result), outcome.error ? JSON.stringify(outcome.error) : null],
      );
      if (!row) return;
      const action = row.action as ResponseActionKey;
      const target = row.target as ResponseTargetInput;
      if (outcome.status === "succeeded") await this.applySideEffects(tx, row, action, target);
      // Timeline of every investigation of the incident.
      if (row.incident_id) {
        await tx.query(
          `INSERT INTO timeline_entries (tenant_id, organization_id, investigation_id, kind, at, actor_id, title, body, ref_id)
           SELECT v.tenant_id, v.organization_id, v.id, 'action', now(), $2, $3, $4, $5 FROM investigations v WHERE v.incident_id = $1`,
          [
            row.incident_id,
            `response:${String(row.requested_via)}`,
            `${RESPONSE_ACTIONS.find((a) => a.key === action)?.label ?? action} ${outcome.status === "succeeded" ? "succeeded" : "failed"}: ${target.label ?? target.id}`.slice(0, 500),
            String((outcome.result as { summary?: string }).summary ?? outcome.error?.message ?? ""),
            id,
          ],
        );
      }
      await writeAudit(tx, actor ?? SYSTEM_ACTOR(tenantId, "soar"), {
        action: `response.${action}`,
        organizationId: String(row.organization_id),
        targetKind: target.kind,
        targetId: target.id,
        outcome: outcome.status === "succeeded" ? "success" : "failure",
        details: {
          responseActionId: id,
          requestedBy: row.requested_by,
          requestedVia: row.requested_via,
          approvedBy: row.approved_by,
          executor: outcome.executor,
          integrationId: outcome.integrationId,
          summary: (outcome.result as { summary?: string }).summary ?? null,
          error: outcome.error,
        },
      });
    });
  }

  /** Mirror successful containment into inventory (agent isolation, identity disabled…). */
  private async applySideEffects(tx: Queryable, row: Row, action: ResponseActionKey, target: ResponseTargetInput): Promise<void> {
    if (target.kind === "asset" && action === "isolate_endpoint") {
      const params = (row.parameters ?? {}) as Record<string, unknown>;
      const mode = params.mode === "lan" ? "lan" : "full";
      await tx.query(
        "UPDATE agents SET status = 'isolated', isolation = jsonb_build_object('mode', $2::text, 'since', now(), 'actionId', $3::text) WHERE asset_id = $1 AND status <> 'pending'",
        [target.id, mode, String(row.id)],
      );
    }
    if (target.kind === "asset" && action === "release_endpoint") {
      await tx.query("UPDATE agents SET status = 'protected', isolation = NULL WHERE asset_id = $1 AND status <> 'pending'", [target.id]);
    }
    if (target.kind === "identity" && action === "disable_identity") {
      await tx.query("UPDATE identities SET enabled = false WHERE id = $1", [target.id]);
    }
    if (action === "isolate_endpoint" && row.incident_id) {
      await tx.query("UPDATE incidents SET status = 'contained', contained_at = coalesce(contained_at, now()), acknowledged_at = coalesce(acknowledged_at, now()) WHERE id = $1 AND status IN ('new', 'triage', 'investigating')", [row.incident_id]);
    }
  }

  private async run(tenantId: string, row: Row): Promise<ExecutionOutcome> {
    const action = row.action as ResponseActionKey;
    if (INTERNAL_ACTIONS.has(action)) return this.runInternal(tenantId, row, action);
    if (MOBILE_ACTIONS.has(action)) return this.runMobile(tenantId, row, action);
    return (await this.dispatchToAgent(tenantId, row, action)) ?? this.runConnector(tenantId, row, action);
  }

  /** lock_device / wipe_device: the command goes to Google (Android) or the device's MDM queue (Apple). */
  private async runMobile(tenantId: string, row: Row, action: ResponseActionKey): Promise<ExecutionOutcome> {
    const target = row.target as ResponseTargetInput;
    if (!this.mobile) throw new HttpError(409, "mdm_unavailable", "Mobile device management is not available");
    const done = action === "lock_device" ? await this.mobile.lock(tenantId, target.id) : await this.mobile.wipe(tenantId, target.id, String(row.reason ?? ""));
    return { status: "succeeded", executor: done.executor, integrationId: null, result: { summary: done.summary }, error: null };
  }

  /**
   * Endpoints running the SCIAT Agent isolate / release themselves: queue the command for the
   * agent (collected at its next check-in). The platform addresses the agent reported always stay
   * reachable, so the endpoint can be released later. Null when the target has no SCIAT Agent.
   */
  private async dispatchToAgent(tenantId: string, row: Row, action: ResponseActionKey): Promise<ExecutionOutcome | null> {
    if (action !== "isolate_endpoint" && action !== "release_endpoint" && action !== "harden_endpoint") return null;
    const target = row.target as ResponseTargetInput;
    if (target.kind !== "asset") return null;
    if (action === "harden_endpoint") return this.dispatchHardening(tenantId, row, target);
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        "SELECT id, organization_id, hostname, platform, host_info FROM agents WHERE asset_id = $1 AND engine = 'sciat' AND agent_token_hash IS NOT NULL ORDER BY last_checkin_at DESC NULLS LAST LIMIT 1",
        [target.id],
      );
      const agent = rows[0];
      if (!agent) return null;
      const fail = (code: string, message: string): ExecutionOutcome => ({ status: "failed", executor: "sciat:agent", integrationId: null, result: {}, error: { code, message, retryable: false } });
      let args: string[];
      if (action === "release_endpoint") args = isolationScriptArgs("release");
      else {
        const info = (agent.host_info ?? {}) as { platformIps?: unknown; dnsServers?: unknown };
        const ips = (v: unknown) => (Array.isArray(v) ? v.map(String).filter(isIpOrCidr).slice(0, 16) : []);
        const parameters: Record<string, unknown> = { ...((row.parameters as Record<string, unknown>) ?? {}) };
        if (parameters.mode === "full" && parameters.dns === undefined) parameters.dns = ips(info.dnsServers);
        const platform = ips(info.platformIps);
        if (platform.length === 0) return fail("agent_not_ready", `The SCIAT Agent on ${String(agent.hostname)} has not reported this platform's address yet. Wait a minute for its next check-in; if this persists the agent is an older version that cannot isolate — reinstall it from Download Agent.`);
        try {
          args = isolationScriptArgs(buildIsolationPolicy({ parameters }, platform));
        } catch (err) {
          if (err instanceof ResponseGuardError) return fail(err.code, err.message);
          throw err;
        }
      }
      const { rows: cmd } = await tx.query<Row>(
        `INSERT INTO agent_commands (tenant_id, organization_id, agent_id, response_action_id, kind, args, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + interval '30 minutes') RETURNING id`,
        [tenantId, agent.organization_id, agent.id, row.id, action === "release_endpoint" ? "release" : "isolate", args],
      );
      return {
        status: "dispatched",
        executor: "sciat:agent",
        integrationId: null,
        result: { summary: `Sent to the SCIAT Agent on ${String(agent.hostname)}; it runs at the next check-in (within a minute)`, commandId: String(cmd[0]!.id) },
        error: null,
      };
    });
  }

  /** Queue a built-in hardening fix for the target's SCIAT Agent (checked again at dispatch). */
  private async dispatchHardening(tenantId: string, row: Row, target: ResponseTargetInput): Promise<ExecutionOutcome> {
    const fail = (code: string, message: string): ExecutionOutcome => ({ status: "failed", executor: "sciat:agent", integrationId: null, result: {}, error: { code, message, retryable: false } });
    const check = String(((row.parameters ?? {}) as Record<string, unknown>).check ?? "");
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        "SELECT id, organization_id, hostname, platform FROM agents WHERE asset_id = $1 AND engine = 'sciat' AND agent_token_hash IS NOT NULL ORDER BY last_checkin_at DESC NULLS LAST LIMIT 1",
        [target.id],
      );
      const agent = rows[0];
      if (!agent) return fail("no_agent", "The asset has no SCIAT Agent to apply the fix");
      if (!agentCanFix(check, String(agent.platform))) return fail("not_fixable", `The SCIAT Agent cannot apply ${check} on ${String(agent.platform)}`);
      const { rows: cmd } = await tx.query<Row>(
        `INSERT INTO agent_commands (tenant_id, organization_id, agent_id, response_action_id, kind, args, expires_at)
         VALUES ($1, $2, $3, $4, 'harden', $5, now() + interval '30 minutes') RETURNING id`,
        [tenantId, agent.organization_id, agent.id, row.id, ["harden", check]],
      );
      return {
        status: "dispatched",
        executor: "sciat:agent",
        integrationId: null,
        result: { summary: `Sent "${hardeningCheck(check)?.title ?? check}" to the SCIAT Agent on ${String(agent.hostname)}; it runs at the next check-in (within a minute)`, commandId: String(cmd[0]!.id) },
        error: null,
      };
    });
  }

  /** A SCIAT Agent reported the result of a dispatched command. */
  async completeFromAgent(tenantId: string, actionId: string, ok: boolean, output: string): Promise<void> {
    const row = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM response_actions WHERE id = $1 AND status = 'running'", [actionId])).rows[0] ?? null);
    if (!row) return;
    const verb = row.action === "release_endpoint" ? "released" : "isolated";
    const check = hardeningCheck(String(((row.parameters ?? {}) as Record<string, unknown>).check ?? ""));
    const summary = !ok
      ? `The SCIAT Agent could not apply the change`
      : row.action === "harden_endpoint"
        ? `Hardening applied by the SCIAT Agent: ${check?.title ?? "fix"} (the next inventory re-grades it)`
        : `Endpoint ${verb} by the SCIAT Agent`;
    await this.finish(
      tenantId,
      actionId,
      { status: ok ? "succeeded" : "failed", executor: "sciat:agent", integrationId: null, result: { summary, output: output.slice(0, 4000) }, error: ok ? null : { code: "agent_failed", message: output.slice(0, 1000) || summary, retryable: true } },
      SYSTEM_ACTOR(tenantId, "sciat-agent"),
      row,
    );
  }

  /** Fail actions whose agent never collected or answered the command (scheduler). */
  async expireAgentCommands(tenantId: string): Promise<number> {
    const ids = await this.deps.db.withTenant(tenantId, async (tx) =>
      (
        await tx.query<{ response_action_id: string | null }>(
          "UPDATE agent_commands SET status = 'expired', finished_at = now() WHERE status IN ('pending', 'delivered') AND expires_at <= now() RETURNING response_action_id",
        )
      ).rows,
    );
    for (const { response_action_id: id } of ids) {
      if (!id) continue;
      const row = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM response_actions WHERE id = $1 AND status = 'running'", [id])).rows[0] ?? null);
      if (row) {
        await this.finish(
          tenantId,
          id,
          { status: "failed", executor: "sciat:agent", integrationId: null, result: {}, error: { code: "agent_unreachable", message: "The SCIAT Agent did not check in within 30 minutes; the command expired", retryable: true } },
          SYSTEM_ACTOR(tenantId, "sciat-agent"),
          row,
        );
      }
    }
    return ids.length;
  }

  private async runConnector(tenantId: string, row: Row, action: ResponseActionKey): Promise<ExecutionOutcome> {
    const organizationId = String(row.organization_id);
    const prepared = await this.deps.db.withTenant(tenantId, async (tx) => {
      const connector = await this.deps.integrations.connectorFor(tx, tenantId, organizationId, action);
      if (!connector) return null;
      const kind = String(connector.integration.kind);
      const target = row.target as ResponseTargetInput;
      const parameters: Record<string, unknown> = { ...((row.parameters as Record<string, unknown>) ?? {}) };
      let engineTarget: ResponseExecutionRequest["target"] = { kind: target.kind, id: target.id, ...(target.label ? { label: target.label } : {}) };
      const agentsOf = async (assetIds: string[]) =>
        assetIds.length ? (await tx.query<Row>("SELECT platform, engine_refs, engine, external_ref FROM agents WHERE asset_id = ANY($1::uuid[])", [assetIds])).rows : [];
      const incidentAssets = async (): Promise<string[]> => {
        if (!row.incident_id) return [];
        const { rows } = await tx.query<{ asset_ids: string[] }>("SELECT asset_ids FROM incidents WHERE id = $1", [row.incident_id]);
        return rows[0]?.asset_ids ?? [];
      };
      const wazuhIds = (agents: Row[]) => agents.map((a) => (a.engine_refs as Record<string, string> | null)?.wazuh).filter((x): x is string => typeof x === "string");
      if (target.kind === "asset") {
        const agents = await agentsOf([target.id]);
        if (kind === "wazuh") {
          const id = wazuhIds(agents)[0];
          if (!id && typeof parameters.agentId !== "string") return { error: "The asset has no Wazuh agent id (sync the agent through an integration or pass parameters.agentId)" } as const;
          if (id) parameters.agentId ??= id;
        } else if (kind === "velociraptor") {
          const a = agents.find((x) => typeof (x.engine_refs as Record<string, string> | null)?.velociraptor === "string");
          const clientId = (a?.engine_refs as Record<string, string> | undefined)?.velociraptor;
          if (!clientId && typeof parameters.clientId !== "string") return { error: "The asset has no Velociraptor client id (pass parameters.clientId)" } as const;
          if (clientId) parameters.clientId ??= clientId;
          if (a?.platform) parameters.platform ??= a.platform;
        }
      } else if (target.kind === "indicator") {
        if (/^[0-9a-f-]{36}$/i.test(target.id)) {
          const { rows } = await tx.query<Row>("SELECT value FROM indicators WHERE id = $1", [target.id]);
          if (rows[0]) engineTarget = { kind: "indicator", id: String(rows[0].value), label: target.label ?? String(rows[0].value) };
        }
        if (kind === "wazuh" && !Array.isArray(parameters.agents) && parameters.scope !== "all") {
          const ids = wazuhIds(await agentsOf(await incidentAssets()));
          if (ids.length === 0) return { error: "Wazuh active response needs target agents: link the action to an incident with managed hosts or pass parameters.agents" } as const;
          parameters.agents = ids;
        }
      } else if (target.kind === "identity") {
        const { rows } = await tx.query<Row>("SELECT principal FROM identities WHERE id = $1", [target.id]);
        const principal = rows[0] ? String(rows[0].principal) : (target.label ?? target.id);
        const username = principal.includes("\\") ? principal.split("\\").pop()! : principal.split("@")[0]!;
        parameters.username ??= username;
        engineTarget = { kind: "identity", id: target.id, label: principal };
        if (kind === "wazuh" && !Array.isArray(parameters.agents)) {
          const ids = wazuhIds(await agentsOf(await incidentAssets()));
          if (ids.length === 0) return { error: "Wazuh account disabling needs target agents: link the action to an incident with managed hosts or pass parameters.agents" } as const;
          parameters.agents = ids;
        }
      }
      const req: ResponseExecutionRequest = {
        actionId: String(row.id),
        tenantId,
        organizationId,
        action,
        target: engineTarget,
        parameters,
        reason: String(row.reason),
        requestedBy: String(row.requested_by),
        requestedVia: row.requested_via as "user" | "playbook" | "ai",
        approvedBy: (row.approved_by as string | null) ?? null,
        ...(row.emergency ? { emergency: { authorizedBy: String(row.requested_by) } } : {}),
      };
      return { connector, req, kind };
    });
    if (!prepared) {
      return {
        status: "failed",
        executor: "none",
        integrationId: null,
        result: { summary: `No connector available for ${action}` },
        error: { code: "no_connector", message: `No enabled integration can perform ${action} for this organization. Configure a response-capable integration (Wazuh active response, Velociraptor or the signed block relay).`, retryable: false },
      };
    }
    if ("error" in prepared) return { status: "failed", executor: "bloody", integrationId: null, result: {}, error: { code: "invalid_target", message: String(prepared.error), retryable: false } };
    let res: ResponseExecutionResult;
    try {
      res = await prepared.connector.execute(prepared.req);
    } catch (err) {
      const code = (err as { code?: string }).code ?? "connector_error";
      return { status: "failed", executor: prepared.kind, integrationId: String(prepared.connector.integration.id), result: {}, error: { code, message: err instanceof Error ? err.message.slice(0, 1000) : "connector failed", retryable: code !== "invalid_target" && code !== "invalid_parameters" && code !== "unsupported_action" } };
    }
    const ok = res.outcome === "succeeded" || res.outcome === "partial";
    return {
      status: ok ? "succeeded" : "failed",
      executor: `${res.engine}:${res.connector}`,
      integrationId: String(prepared.connector.integration.id),
      result: { summary: res.summary, outcome: res.outcome, engineRef: res.engineRef, affected: res.affected, failed: res.failed, call: res.call, durationMs: res.durationMs, reversal: res.reversal ?? null },
      error: ok ? null : { code: res.error?.code ?? res.outcome, message: res.error?.message ?? res.summary, retryable: false },
    };
  }

  private async runInternal(tenantId: string, row: Row, action: ResponseActionKey): Promise<ExecutionOutcome> {
    const p = (row.parameters as Record<string, unknown>) ?? {};
    const target = row.target as ResponseTargetInput;
    const organizationId = String(row.organization_id);
    const actor = SYSTEM_ACTOR(tenantId, "soar");
    const ok = (summary: string, extra: Record<string, unknown> = {}): ExecutionOutcome => ({ status: "succeeded", executor: "bloody", integrationId: null, result: { summary, ...extra }, error: null });
    const fail = (code: string, message: string): ExecutionOutcome => ({ status: "failed", executor: "bloody", integrationId: null, result: {}, error: { code, message, retryable: false } });
    const str = (k: string): string | null => (typeof p[k] === "string" && (p[k] as string).trim().length > 0 ? (p[k] as string).trim() : null);
    const incidentId = (target.kind === "incident" ? target.id : null) ?? (row.incident_id as string | null) ?? null;

    switch (action) {
      case "notify_analyst": {
        const roles = Array.isArray(p.roles) ? (p.roles as unknown[]).filter((x): x is string => typeof x === "string") : ["soc_analyst_t1", "soc_analyst_t2", "incident_responder"];
        const userIds = Array.isArray(p.userIds) ? (p.userIds as unknown[]).filter((x): x is string => typeof x === "string") : [];
        const title = (str("title") ?? `Analyst attention requested: ${target.label ?? target.id}`).slice(0, 300);
        const severity = (["info", "low", "medium", "high", "critical"].includes(String(p.severity)) ? p.severity : "medium") as Severity;
        await this.deps.db.withTenant(tenantId, (tx) =>
          insertInApp(
            tx,
            {
              id: randomUUID(),
              tenantId,
              organizationId,
              recipients: { userIds, roles },
              event: "response.notify_analyst",
              severity,
              title,
              body: str("message") ?? String(row.reason),
              facts: [],
              link: incidentId ? { url: `/incidents/${incidentId}`, label: "Open incident" } : null,
              createdAt: new Date(this.deps.now()).toISOString(),
              readBy: [],
            },
            "system",
            { kind: target.kind, id: target.id },
          ),
        );
        return ok(`Notified ${userIds.length > 0 ? `${userIds.length} analyst(s)` : roles.join(", ")}`);
      }
      case "create_case": {
        return this.deps.db.withTenant(tenantId, async (tx) => {
          if (target.kind === "incident" && /^[0-9a-f-]{36}$/i.test(target.id)) {
            const { rows } = await tx.query<Row>("SELECT id, number FROM incidents WHERE id = $1", [target.id]);
            if (rows[0]) return ok(`Case #${String(rows[0].number)} already exists`, { incidentId: rows[0].id, created: false });
          }
          const alertIds = Array.isArray(p.alertIds) ? (p.alertIds as unknown[]).filter((x): x is string => typeof x === "string" && /^[0-9a-f-]{36}$/i.test(x)) : str("alertId") ? [str("alertId")!] : [];
          const alerts = alertIds.length ? (await tx.query<Row>("SELECT id, title, severity, incident_id FROM alerts WHERE id = ANY($1::uuid[]) AND organization_id = $2", [alertIds, organizationId])).rows : [];
          const linked = alerts.find((a) => a.incident_id);
          if (linked) return ok("The alert is already part of a case", { incidentId: linked.incident_id, created: false });
          const severity = (["info", "low", "medium", "high", "critical"].includes(String(p.severity)) ? p.severity : (alerts[0]?.severity ?? "medium")) as Severity;
          const title = (str("title") ?? (alerts[0] ? `Case: ${String(alerts[0].title)}` : `Case: ${String(row.reason)}`)).slice(0, 300);
          const view = await createIncident(
            tx,
            this.deps.risk,
            actor,
            { tenantId, organizationId, title: title.length >= 3 ? title : `Case ${title}`, summary: String(row.reason), severity, alertIds: alerts.map((a) => String(a.id)), assetIds: [], identityIds: [], attack: [], createdBy: `response:${String(row.id)}` },
            () => undefined,
          );
          this.deps.events.publish({ tenantId, organizationId, event: "incident.created", occurredAt: new Date(this.deps.now()).toISOString(), severity: view.severity, subject: { kind: "incident", id: view.id, label: view.title }, data: { number: view.number, source: "soar" } });
          return ok(`Created case #${view.number}`, { incidentId: view.id, created: true });
        });
      }
      case "launch_investigation": {
        if (!incidentId) return fail("invalid_target", "launch_investigation needs an incident");
        return this.deps.db.withTenant(tenantId, async (tx) => {
          const { rows: inc } = await tx.query<Row>("SELECT * FROM incidents WHERE id = $1", [incidentId]);
          if (!inc[0]) return fail("invalid_target", "Incident not found");
          const existing = await tx.query<Row>("SELECT id FROM investigations WHERE incident_id = $1 AND status <> 'closed' LIMIT 1", [incidentId]);
          if (existing.rows[0]) return ok("An investigation is already open", { investigationId: existing.rows[0].id, created: false });
          const { rows } = await tx.query<Row>(
            "INSERT INTO investigations (tenant_id, organization_id, incident_id, title, hypothesis, status, created_by) VALUES ($1, $2, $3, $4, $5, 'open', $6) RETURNING *",
            [tenantId, organizationId, incidentId, (str("title") ?? `Investigation of #${String(inc[0].number)}: ${String(inc[0].title)}`).slice(0, 300), str("hypothesis"), `response:${String(row.id)}`],
          );
          const inv = rows[0]!;
          await tx.query(
            `INSERT INTO timeline_entries (tenant_id, organization_id, investigation_id, kind, at, actor_id, title, body, ref_id)
             SELECT a.tenant_id, a.organization_id, $1, 'alert', a.first_seen_at, 'system:pipeline', left(a.title, 500), a.severity || ' · ' || coalesce(a.rule_id, a.source), a.id::text
             FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = $2 ORDER BY a.first_seen_at LIMIT 500`,
            [inv.id, incidentId],
          );
          await tx.query("UPDATE incidents SET status = 'investigating', acknowledged_at = coalesce(acknowledged_at, now()) WHERE id = $1 AND status IN ('new', 'triage')", [incidentId]);
          await writeAudit(tx, actor, { action: "investigation.created", organizationId, targetKind: "investigation", targetId: String(inv.id), details: { incidentId, source: "soar" } });
          return ok("Investigation launched", { investigationId: inv.id, created: true });
        });
      }
      case "send_email": {
        const channelIds = Array.isArray(p.channelIds) ? (p.channelIds as unknown[]).filter((x): x is string => typeof x === "string" && /^[0-9a-f-]{36}$/i.test(x)) : [];
        if (channelIds.length === 0) return fail("invalid_parameters", "parameters.channelIds (notification channel ids) is required");
        const subject = (str("subject") ?? `[SCIAT] ${target.label ?? "Security notification"}`).replace(/[\r\n]+/g, " ").slice(0, 200);
        const outcomes = await this.deps.notifications.engine.deliver(
          {
            id: randomUUID(),
            tenantId,
            organizationId,
            event: "response.send_email",
            severity: "info",
            subject,
            text: str("body") ?? String(row.reason),
            facts: [],
            ...(incidentId ? { link: this.deps.notifications.link(`/incidents/${incidentId}`)! } : {}),
            occurredAt: new Date(this.deps.now()).toISOString(),
            dedupKey: `response:${String(row.id)}`,
            origin: { kind: "system", id: String(row.id), name: "SOAR send_email" },
          },
          channelIds,
          { tenantId, organizationId },
        );
        const sent = outcomes.filter((o) => o.status === "sent").length;
        if (sent === 0) return { status: "failed", executor: "bloody", integrationId: null, result: { deliveries: outcomes }, error: { code: "delivery_failed", message: outcomes.map((o) => o.reason).filter(Boolean).join("; ") || "no channel accepted the message", retryable: true } };
        return ok(`Delivered to ${sent} of ${channelIds.length} channel(s)`, { deliveries: outcomes });
      }
      default:
        return fail("unsupported_action", `${action} is not a built-in action`);
    }
  }

  // ─── ActionExecutor (playbook steps) ───────────────────────────────────────

  /** Resolve the target of a playbook step from its parameters and the triggering subject. */
  private async resolveStepTarget(req: ActionExecutionRequest): Promise<{ target: ResponseTargetInput; incidentId: string | null }> {
    const kind = ACTION_TARGET[req.action];
    const p = req.parameters;
    const s = (k: string) => (typeof p[k] === "string" && (p[k] as string).length > 0 ? (p[k] as string) : null);
    const subject = req.subjectRef;
    return this.deps.db.withTenant(req.tenantId, async (tx) => {
      let incidentId = subject?.kind === "incident" ? subject.id : s("incidentId");
      if (!incidentId && subject?.kind === "alert") {
        const { rows } = await tx.query<{ incident_id: string | null }>("SELECT incident_id FROM alerts WHERE id = $1", [subject.id]);
        incidentId = rows[0]?.incident_id ?? null;
      }
      const incident = incidentId ? (await tx.query<Row>("SELECT asset_ids, identity_ids, organization_id FROM incidents WHERE id = $1", [incidentId])).rows[0] : undefined;
      if (incident && incident.organization_id !== req.organizationId) incidentId = null;
      const fail = (msg: string) => new ActionExecutionError("invalid_target", msg, false);
      switch (kind) {
        case "incident":
          if (subject?.kind === "alert" && req.action === "create_case") return { target: { kind: "incident", id: subject.id, label: subject.label }, incidentId };
          if (!incidentId) throw fail(`${req.action} needs an incident (trigger on incident events or set parameters.incidentId)`);
          return { target: { kind: "incident", id: incidentId }, incidentId };
        case "asset": {
          let assetId = s("assetId") ?? (subject?.kind === "asset" && /^[0-9a-f-]{36}$/i.test(subject.id) ? subject.id : null);
          if (!assetId && s("hostname")) {
            const { rows } = await tx.query<{ id: string }>("SELECT id FROM assets WHERE organization_id = $1 AND lower(hostname) = lower($2) LIMIT 1", [req.organizationId, s("hostname")]);
            assetId = rows[0]?.id ?? null;
          }
          assetId ??= ((incident?.asset_ids as string[] | undefined) ?? [])[0] ?? null;
          if (!assetId) throw fail(`${req.action} needs an asset (parameters.assetId / hostname, or an incident with affected assets)`);
          return { target: { kind: "asset", id: assetId }, incidentId };
        }
        case "identity": {
          const identityId = s("identityId") ?? ((incident?.identity_ids as string[] | undefined) ?? [])[0] ?? null;
          if (!identityId) throw fail(`${req.action} needs an identity (parameters.identityId, or an incident with affected identities)`);
          return { target: { kind: "identity", id: identityId }, incidentId };
        }
        case "indicator": {
          const value = s("indicatorId") ?? s("value") ?? s("ip") ?? s("domain");
          if (!value) throw fail(`${req.action} needs parameters.value (IP / domain) or parameters.indicatorId`);
          return { target: { kind: "indicator", id: value }, incidentId };
        }
      }
    });
  }

  /** ActionExecutor: one response_actions row per (execution, step) idempotency key. */
  async executeStep(req: ActionExecutionRequest): Promise<ActionExecutionResult> {
    const existing = await this.deps.db.withTenant(req.tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM response_actions WHERE idempotency_key = $1", [req.idempotencyKey])).rows[0] ?? null);
    let id: string;
    if (existing) {
      id = String(existing.id);
      if (existing.status === "succeeded") return { output: existing.result, externalRef: id };
      if (existing.status === "running") throw new ActionExecutionError("in_progress", "the action is already running", true);
      if (existing.status === "failed") {
        await this.deps.db.withTenant(req.tenantId, (tx) => tx.query("UPDATE response_actions SET status = 'approved', error = NULL WHERE id = $1 AND status = 'failed'", [id]));
      }
    } else {
      const { target, incidentId } = await this.resolveStepTarget(req);
      const view = await this.request(
        {
          tenantId: req.tenantId,
          organizationId: req.organizationId,
          action: req.action,
          incidentId,
          target,
          parameters: req.parameters,
          reason: `Playbook "${req.playbook.name}" v${req.playbook.version} step "${req.stepId}"`,
          requestedBy: { kind: "playbook", id: `playbook:${req.playbook.id}` },
          via: "playbook",
          playbookRunId: req.executionId,
          playbookStepId: req.stepId,
          idempotencyKey: req.idempotencyKey,
          // The engine already passed the approval gate for this step when required.
          preApproved: { approvalId: req.approval?.id ?? null, approvedBy: req.approval?.approvedBy ?? [] },
        },
        SYSTEM_ACTOR(req.tenantId, `playbook:${req.playbook.id}`),
      );
      id = view.id;
      if (view.status === "succeeded") return { output: view.result, externalRef: id };
      if (view.status === "failed") throw new ActionExecutionError(String((view.error as { code?: string } | null)?.code ?? "failed"), String((view.error as { message?: string } | null)?.message ?? "action failed"), Boolean((view.error as { retryable?: boolean } | null)?.retryable));
    }
    const done = await this.execute(req.tenantId, id, SYSTEM_ACTOR(req.tenantId, `playbook:${req.playbook.id}`));
    if (done.status === "succeeded") return { output: done.result, externalRef: id };
    // Handed to the endpoint's SCIAT Agent: it applies the change at its next check-in.
    if (done.status === "running" && done.executor === "sciat:agent") return { output: done.result, externalRef: id };
    const e = (done.error as { code?: string; message?: string; retryable?: boolean } | null) ?? {};
    throw new ActionExecutionError(e.code ?? "failed", e.message ?? `action ${done.status}`, Boolean(e.retryable));
  }

  /** ActionExecutor interface for the PlaybookEngine. */
  readonly executor: ActionExecutor = { execute: (req) => this.executeStep(req) };
}
