import { actionRisk, principalCan, type Principal } from "@bloody/contracts";
import type { ApprovalGate } from "../approvals/gate.js";
import type { ApprovalRequest } from "../approvals/types.js";
import { evaluateConditions } from "../conditions.js";
import { firesBetween } from "../scheduling/cron.js";
import { renderParameters } from "../template.js";
import { safeAudit, type AuditSink } from "../util/audit.js";
import { AutomationError } from "../util/errors.js";
import {
  backoffDelay,
  DEFAULT_RETRY,
  defaultSleep,
  errorMessage,
  stableHash,
  systemClock,
  uuidIds,
  type Clock,
  type IdGenerator,
  type RandomFn,
  type RetryPolicy,
  type SleepFn,
} from "../util/runtime.js";
import { resolveEffectivePlaybooks, type EffectivePlaybook, type PlaybookRepository } from "./repository.js";
import {
  ActionExecutionError,
  type ActionExecutor,
  type ExecutionLogEntry,
  type ExecutionStatus,
  type PlaybookEvent,
  type PlaybookExecution,
  type PlaybookStep,
  type StepState,
  type ExecutionStore,
} from "./types.js";

export interface PlaybookEngineDeps {
  playbooks: PlaybookRepository;
  executions: ExecutionStore;
  executor: ActionExecutor;
  approvals: ApprovalGate;
  clock?: Clock;
  ids?: IdGenerator;
  sleep?: SleepFn;
  random?: RandomFn;
  audit?: AuditSink;
  retry?: Partial<RetryPolicy>;
  /** Per-attempt timeout for an action (default 5 minutes). */
  stepTimeoutMs?: number;
}

export interface PlaybookMatch {
  playbookId: string;
  playbookName: string;
  source: EffectivePlaybook["source"];
  matched: boolean;
  /** Why it did (not) run — trigger mismatch, disabled, conditions, duplicate. */
  reasons: string[];
  execution: PlaybookExecution | null;
  deduplicated: boolean;
}

export interface EventHandlingResult {
  event: { type: PlaybookEvent["type"]; tenantId: string; organizationId: string };
  matches: PlaybookMatch[];
}

const TERMINAL: ReadonlySet<ExecutionStatus> = new Set(["succeeded", "partially_succeeded", "failed", "rejected", "cancelled"]);

/**
 * SOAR playbook engine.
 *
 * Trigger → conditions → ordered steps. Each step is executed through the injected
 * {@link ActionExecutor} (which talks to engine adapters and records response actions) with:
 *  - approval gates: high-risk actions ALWAYS stop at the {@link ApprovalGate}; low/medium
 *    actions stop when the step sets `requireApproval` (or the tenant policy says so);
 *  - idempotency: one execution per (tenant, idempotency key) and a stable per-step key the
 *    executor de-duplicates on, so retries, resumes and duplicate events never act twice;
 *  - retries with exponential backoff + jitter for retryable failures, per-attempt timeout;
 *  - `continueOnError` to carry on past a failed / rejected step;
 *  - an append-only execution log (step, status, attempt, start/finish, output/error);
 *  - optimistic concurrency on the execution record, so two concurrent resumes cannot both run.
 * The execution keeps a frozen snapshot of the playbook version that started it.
 */
export class PlaybookEngine {
  private readonly deps: PlaybookEngineDeps;
  private readonly clock: Clock;
  private readonly ids: IdGenerator;
  private readonly sleep: SleepFn;
  private readonly random: RandomFn;
  private readonly retry: RetryPolicy;
  private readonly stepTimeoutMs: number;

  constructor(deps: PlaybookEngineDeps) {
    this.deps = deps;
    this.clock = deps.clock ?? systemClock;
    this.ids = deps.ids ?? uuidIds;
    this.sleep = deps.sleep ?? defaultSleep;
    this.random = deps.random ?? Math.random;
    const r = { ...DEFAULT_RETRY, ...deps.retry };
    this.retry = { ...r, maxAttempts: Math.max(1, Math.min(10, Math.floor(r.maxAttempts))) };
    this.stepTimeoutMs = deps.stepTimeoutMs ?? 5 * 60_000;
  }

  /** Effective playbooks (globals + organization overrides) for an organization. */
  async effectivePlaybooks(tenantId: string, organizationId: string): Promise<EffectivePlaybook[]> {
    const rows = await this.deps.playbooks.listForOrganization(tenantId, organizationId);
    return resolveEffectivePlaybooks(rows, tenantId, organizationId);
  }

  /** Offer an event (incident.created, alert.created, indicator.matched, escalation.overdue…). */
  async handleEvent(event: PlaybookEvent): Promise<EventHandlingResult> {
    if (event.type === "manual" || event.type === "schedule") {
      throw new AutomationError("invalid_event", `"${event.type}" playbooks are started with runManual / runDueSchedules`);
    }
    const effective = await this.effectivePlaybooks(event.tenantId, event.organizationId);
    const matches: PlaybookMatch[] = [];
    for (const ep of effective) {
      const p = ep.playbook;
      if (p.trigger.on !== event.type) continue;
      matches.push(await this.consider(ep, event, event.initiatedBy ?? { kind: "system", id: "event-bus" }));
    }
    return { event: { type: event.type, tenantId: event.tenantId, organizationId: event.organizationId }, matches };
  }

  /** Run a playbook on demand (analyst "Run playbook" button). Requires response:request. */
  async runManual(input: { principal: Principal; organizationId: string; playbookId: string; subject?: Record<string, unknown>; subjectRef?: PlaybookEvent["subjectRef"]; idempotencyKey?: string }): Promise<PlaybookMatch> {
    const { principal } = input;
    if (!principalCan(principal, "response:request", input.organizationId)) {
      throw new AutomationError("forbidden", "missing permission response:request for this organization");
    }
    const effective = await this.effectivePlaybooks(principal.tenantId, input.organizationId);
    const ep = effective.find((e) => e.playbook.id === input.playbookId);
    if (!ep) throw new AutomationError("not_found", "playbook not found for this organization (it may be overridden)");
    const now = this.clock.now().toISOString();
    const event: PlaybookEvent = {
      tenantId: principal.tenantId,
      organizationId: input.organizationId,
      type: "manual",
      subject: input.subject ?? {},
      ...(input.subjectRef ? { subjectRef: input.subjectRef } : {}),
      occurredAt: now,
      idempotencyKey: input.idempotencyKey ?? `manual:${this.ids()}`,
      initiatedBy: { kind: principal.kind === "user" ? "user" : "service", id: principal.id },
    };
    return this.consider(ep, event, event.initiatedBy!, { ignoreTrigger: true });
  }

  /**
   * Start scheduled playbooks whose cron fired in (from, to]. Missed fires are coalesced into one
   * run for the latest slot; the slot is part of the idempotency key so replicas never double-run.
   */
  async runDueSchedules(input: { tenantId: string; organizationIds: readonly string[]; from: Date; to: Date; timeZone?: string }): Promise<PlaybookMatch[]> {
    const out: PlaybookMatch[] = [];
    for (const organizationId of input.organizationIds) {
      const effective = await this.effectivePlaybooks(input.tenantId, organizationId);
      for (const ep of effective) {
        const p = ep.playbook;
        if (p.trigger.on !== "schedule" || !p.trigger.cron || !p.enabled) continue;
        let fires: Date[];
        try {
          fires = firesBetween(p.trigger.cron, input.from, input.to, { limit: 500, ...(input.timeZone ? { timeZone: input.timeZone } : {}) });
        } catch (err) {
          out.push({ playbookId: p.id, playbookName: p.name, source: ep.source, matched: false, reasons: [`invalid cron: ${errorMessage(err)}`], execution: null, deduplicated: false });
          continue;
        }
        const slot = fires[fires.length - 1];
        if (!slot) continue;
        const event: PlaybookEvent = {
          tenantId: input.tenantId,
          organizationId,
          type: "schedule",
          subject: { schedule: { cron: p.trigger.cron, firedAt: slot.toISOString(), missedRuns: fires.length - 1 } },
          subjectRef: { kind: "schedule", id: `${p.id}@${slot.toISOString()}` },
          occurredAt: slot.toISOString(),
          idempotencyKey: `schedule:${p.id}:v${p.version}:${organizationId}:${slot.toISOString()}`,
          initiatedBy: { kind: "system", id: "scheduler" },
        };
        out.push(await this.consider(ep, event, event.initiatedBy!));
      }
    }
    return out;
  }

  /** Continue an execution after its approval was decided (wire to `ApprovalGate.onDecision`). */
  async resumeFromApproval(approval: ApprovalRequest): Promise<PlaybookExecution | null> {
    if (approval.status === "pending") return null;
    const exec = await this.deps.executions.findByApproval(approval.tenantId, approval.id);
    if (!exec || exec.status !== "waiting_approval") return exec;
    const idx = exec.steps.findIndex((s) => s.approvalId === approval.id);
    const step = exec.steps[idx];
    if (!step || step.status !== "pending_approval") return exec;
    const next = this.clone(exec);
    const st = next.steps[idx]!;
    const now = this.clock.now().toISOString();
    if (approval.status === "approved") {
      st.status = "approved";
      st.approvedBy = approval.approvals.map((a) => a.principalId);
      next.status = "running";
      this.log(next, { stepId: st.stepId, action: st.action, status: "approved", attempt: st.attempts, startedAt: now, finishedAt: now, message: `approved by ${st.approvedBy.join(", ")}`, approvalId: approval.id });
    } else {
      st.status = approval.status === "rejected" ? "rejected" : approval.status === "expired" ? "expired" : "cancelled";
      const why = approval.status === "rejected" ? `rejected by ${approval.decidedBy ?? "approver"}${approval.decisionComment ? `: ${approval.decisionComment}` : ""}` : `approval ${approval.status}`;
      this.log(next, { stepId: st.stepId, action: st.action, status: st.status, attempt: st.attempts, startedAt: now, finishedAt: now, message: why, approvalId: approval.id });
      const def = next.playbook.steps[idx];
      if (def?.continueOnError) {
        next.status = "running";
      } else {
        next.status = approval.status === "rejected" ? "rejected" : "cancelled";
        this.skipRemaining(next, idx + 1, `not run: step "${st.stepId}" was ${st.status}`);
        next.finishedAt = now;
      }
    }
    const saved = await this.save(next, exec.version);
    if (!saved) return this.deps.executions.get(exec.tenantId, exec.id);
    await this.auditExecution(saved, `playbook.step_${st.status}`);
    if (saved.status !== "running") return saved;
    return this.runSteps(saved, idx);
  }

  /** Convenience: resume by approval id (API callback after POST /response/actions/:id/approve). */
  async resumeByApprovalId(tenantId: string, approvalId: string): Promise<PlaybookExecution | null> {
    const approval = await this.deps.approvals.get(tenantId, approvalId);
    if (!approval) return null;
    return this.resumeFromApproval(approval);
  }

  /** Cancel a running / waiting execution (and withdraw its pending approval). */
  async cancel(tenantId: string, executionId: string, actor: { kind: "user" | "service" | "system"; id: string }, reason: string): Promise<PlaybookExecution> {
    const exec = await this.deps.executions.get(tenantId, executionId);
    if (!exec) throw new AutomationError("not_found", "execution not found");
    if (TERMINAL.has(exec.status)) return exec;
    const next = this.clone(exec);
    const now = this.clock.now().toISOString();
    const pendingApprovals: string[] = [];
    for (const s of next.steps) {
      if (s.status === "pending_approval" && s.approvalId) pendingApprovals.push(s.approvalId);
      if (s.status === "pending" || s.status === "pending_approval" || s.status === "approved") s.status = "cancelled";
    }
    next.status = "cancelled";
    next.finishedAt = now;
    this.log(next, { stepId: null, action: null, status: "info", attempt: 0, startedAt: now, finishedAt: now, message: `cancelled by ${actor.id}: ${reason}` });
    // Persist the cancellation first: approval listeners that fire below then see a terminal execution.
    const saved = await this.save(next, exec.version);
    if (!saved) throw new AutomationError("concurrent_modification", "execution changed concurrently; retry");
    for (const approvalId of pendingApprovals) {
      try {
        await this.deps.approvals.cancel(tenantId, approvalId, actor, `playbook execution cancelled: ${reason}`);
      } catch {
        // already decided — the execution state above is authoritative
      }
    }
    await this.auditExecution(saved, "playbook.cancelled", actor);
    return saved;
  }

  async getExecution(tenantId: string, id: string): Promise<PlaybookExecution | null> {
    return this.deps.executions.get(tenantId, id);
  }

  // ─── internals ────────────────────────────────────────────────────────────

  private async consider(ep: EffectivePlaybook, event: PlaybookEvent, initiatedBy: PlaybookExecution["initiatedBy"], opts: { ignoreTrigger?: boolean } = {}): Promise<PlaybookMatch> {
    const p = ep.playbook;
    const base = { playbookId: p.id, playbookName: p.name, source: ep.source };
    if (!p.enabled) {
      const why = ep.source === "override" ? "disabled for this organization by an override" : "playbook is disabled";
      return { ...base, matched: false, reasons: [why], execution: null, deduplicated: false };
    }
    if (p.tenantId !== event.tenantId) return { ...base, matched: false, reasons: ["tenant mismatch"], execution: null, deduplicated: false };
    const context = this.buildContext(event);
    const evaluation = evaluateConditions(p.conditions, context);
    const reasons = [opts.ignoreTrigger ? `started manually by ${initiatedBy.id}` : `trigger ${p.trigger.on} matched`, ...evaluation.results.map((r) => r.explanation)];
    if (!evaluation.matched) return { ...base, matched: false, reasons, execution: null, deduplicated: false };

    const subjectKey = event.subjectRef ? `${event.subjectRef.kind}:${event.subjectRef.id}` : stableHash(event.subject, 24);
    const idempotencyKey = event.idempotencyKey ? `${event.idempotencyKey}:${p.id}` : `${p.id}:v${p.version}:${event.type}:${subjectKey}`;
    const existing = await this.deps.executions.findByIdempotencyKey(event.tenantId, idempotencyKey);
    if (existing) return { ...base, matched: true, reasons: [...reasons, `duplicate event — execution ${existing.id} already exists`], execution: existing, deduplicated: true };

    const now = this.clock.now().toISOString();
    const exec: PlaybookExecution = {
      id: this.ids(),
      tenantId: event.tenantId,
      organizationId: event.organizationId,
      playbookId: p.id,
      playbookName: p.name,
      playbookVersion: p.version,
      playbook: structuredClone(p),
      trigger: { type: event.type, occurredAt: event.occurredAt, subjectRef: event.subjectRef ?? null },
      context,
      idempotencyKey,
      status: "running",
      steps: p.steps.map((s) => ({ stepId: s.id, action: s.action, status: "pending", attempts: 0, approvalId: null, approvedBy: [], externalRef: null })),
      log: [],
      conditionResults: evaluation.results,
      initiatedBy,
      startedAt: now,
      updatedAt: now,
      finishedAt: null,
      version: 1,
    };
    this.log(exec, { stepId: null, action: null, status: "info", attempt: 0, startedAt: now, finishedAt: now, message: `execution started (playbook v${p.version}, ${ep.source}${ep.overrides ? ` overriding global v${ep.overrides.version}` : ""})` });
    const inserted = await this.deps.executions.insert(exec);
    if (!inserted) {
      const dup = await this.deps.executions.findByIdempotencyKey(event.tenantId, idempotencyKey);
      return { ...base, matched: true, reasons: [...reasons, "duplicate event — execution already exists"], execution: dup, deduplicated: true };
    }
    await this.auditExecution(exec, "playbook.started");
    const finished = await this.runSteps(exec, 0);
    return { ...base, matched: true, reasons, execution: finished, deduplicated: false };
  }

  private buildContext(event: PlaybookEvent): Record<string, unknown> {
    return {
      ...event.subject,
      event: { type: event.type, occurredAt: event.occurredAt, subjectRef: event.subjectRef ?? null },
      organizationId: event.organizationId,
    };
  }

  private async runSteps(start: PlaybookExecution, fromIndex: number): Promise<PlaybookExecution> {
    let exec = start;
    const steps = exec.playbook.steps;
    for (let i = fromIndex; i < steps.length; i++) {
      const def = steps[i]!;
      const state = exec.steps[i]!;
      if (state.status === "succeeded" || state.status === "skipped" || state.status === "failed" || state.status === "rejected" || state.status === "expired" || state.status === "cancelled") continue;

      // 1. approval gate
      const requirement = this.deps.approvals.requirement(def.action, def.requireApproval);
      if (requirement.required && state.status !== "approved") {
        const next = this.clone(exec);
        const approval = await this.deps.approvals.request({
          tenantId: exec.tenantId,
          organizationId: exec.organizationId,
          kind: "playbook_step",
          action: def.action,
          forced: def.requireApproval,
          reason: `Playbook "${exec.playbookName}" v${exec.playbookVersion} step "${def.id}" (${def.action})`,
          subject: {
            playbookId: exec.playbookId,
            playbookName: exec.playbookName,
            executionId: exec.id,
            stepId: def.id,
            ...(exec.trigger.subjectRef ? { target: exec.trigger.subjectRef } : {}),
            ...(exec.trigger.subjectRef?.kind === "incident" ? { incidentId: exec.trigger.subjectRef.id } : {}),
          },
          parameters: this.renderStepParameters(def, exec),
          requestedBy: {
            kind: "playbook",
            id: `playbook:${exec.playbookId}`,
            ...(exec.initiatedBy.kind === "user" ? { onBehalfOf: exec.initiatedBy.id } : {}),
          },
        });
        const st = next.steps[i]!;
        st.status = "pending_approval";
        st.approvalId = approval.id;
        next.status = "waiting_approval";
        const now = this.clock.now().toISOString();
        this.log(next, { stepId: def.id, action: def.action, status: "pending_approval", attempt: 0, startedAt: now, finishedAt: null, message: `waiting for approval: ${requirement.reasons.join("; ")}`, approvalId: approval.id });
        const saved = await this.save(next, exec.version);
        if (!saved) {
          await this.safeCancelApproval(exec.tenantId, approval.id);
          return (await this.deps.executions.get(exec.tenantId, exec.id)) ?? exec;
        }
        await this.auditExecution(saved, "playbook.waiting_approval");
        return saved;
      }

      // 2. claim the step (CAS) so a concurrent resume cannot execute it too
      const claim = this.clone(exec);
      claim.steps[i]!.status = "running";
      const claimed = await this.save(claim, exec.version);
      if (!claimed) return (await this.deps.executions.get(exec.tenantId, exec.id)) ?? exec;
      exec = claimed;

      // 3. execute with retries
      const outcome = await this.executeWithRetries(exec, i);
      const next = this.clone(exec);
      for (const entry of outcome.log) this.log(next, entry);
      const st = next.steps[i]!;
      st.attempts = outcome.attempts;
      if (outcome.ok) {
        st.status = "succeeded";
        st.externalRef = outcome.externalRef;
      } else {
        st.status = "failed";
        if (!def.continueOnError) {
          next.status = "failed";
          next.finishedAt = this.clock.now().toISOString();
          this.skipRemaining(next, i + 1, `not run: step "${def.id}" failed`);
        }
      }
      const saved = await this.save(next, exec.version);
      if (!saved) return (await this.deps.executions.get(exec.tenantId, exec.id)) ?? exec;
      exec = saved;
      if (exec.status === "failed") {
        await this.auditExecution(exec, "playbook.failed");
        return exec;
      }
    }
    const done = this.clone(exec);
    const anyFailed = done.steps.some((s) => s.status === "failed" || s.status === "rejected" || s.status === "expired" || s.status === "cancelled");
    done.status = anyFailed ? "partially_succeeded" : "succeeded";
    done.finishedAt = this.clock.now().toISOString();
    this.log(done, { stepId: null, action: null, status: "info", attempt: 0, startedAt: done.finishedAt, finishedAt: done.finishedAt, message: `execution ${done.status}` });
    const saved = await this.save(done, exec.version);
    if (!saved) return (await this.deps.executions.get(exec.tenantId, exec.id)) ?? exec;
    await this.auditExecution(saved, `playbook.${saved.status}`);
    return saved;
  }

  private renderStepParameters(def: PlaybookStep, exec: PlaybookExecution): Record<string, unknown> {
    return renderParameters(def.parameters, exec.context);
  }

  private async executeWithRetries(exec: PlaybookExecution, index: number): Promise<{ ok: boolean; attempts: number; externalRef: string | null; log: Omit<ExecutionLogEntry, "seq">[] }> {
    const def = exec.playbook.steps[index]!;
    const state = exec.steps[index]!;
    const log: Omit<ExecutionLogEntry, "seq">[] = [];
    const parameters = this.renderStepParameters(def, exec);
    const idempotencyKey = `${exec.idempotencyKey}:${def.id}`;
    let attempt = state.attempts;
    for (let n = 0; n < this.retry.maxAttempts; n++) {
      attempt += 1;
      const startedAt = this.clock.now().toISOString();
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const timeout = new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            controller.abort(new Error("step timed out"));
            reject(new ActionExecutionError("timeout", `action timed out after ${this.stepTimeoutMs} ms`, true));
          }, this.stepTimeoutMs);
        });
        const result = await Promise.race([
          this.deps.executor.execute({
            tenantId: exec.tenantId,
            organizationId: exec.organizationId,
            action: def.action,
            risk: actionRisk(def.action),
            parameters,
            idempotencyKey,
            attempt,
            playbook: { id: exec.playbookId, name: exec.playbookName, version: exec.playbookVersion },
            executionId: exec.id,
            stepId: def.id,
            subjectRef: exec.trigger.subjectRef,
            approval: state.approvalId ? { id: state.approvalId, approvedBy: state.approvedBy } : null,
            signal: controller.signal,
          }),
          timeout,
        ]);
        log.push({ stepId: def.id, action: def.action, status: "succeeded", attempt, startedAt, finishedAt: this.clock.now().toISOString(), message: `${def.action} succeeded`, ...(result.output !== undefined ? { output: result.output } : {}) });
        return { ok: true, attempts: attempt, externalRef: result.externalRef ?? null, log };
      } catch (err) {
        const retryable = err instanceof ActionExecutionError ? err.retryable : true;
        const code = err instanceof ActionExecutionError ? err.code : "execution_error";
        const last = n === this.retry.maxAttempts - 1 || !retryable;
        log.push({
          stepId: def.id,
          action: def.action,
          status: "failed",
          attempt,
          startedAt,
          finishedAt: this.clock.now().toISOString(),
          message: last ? `${def.action} failed${retryable ? ` after ${attempt} attempt(s)` : " (not retryable)"}${def.continueOnError ? "; continuing (continueOnError)" : ""}` : `${def.action} attempt ${attempt} failed; retrying`,
          error: { code, message: errorMessage(err).slice(0, 2000), retryable },
        });
        if (last) return { ok: false, attempts: attempt, externalRef: null, log };
        await this.sleep(backoffDelay(this.retry, n + 1, this.random));
      } finally {
        if (timer) clearTimeout(timer);
      }
    }
    return { ok: false, attempts: attempt, externalRef: null, log };
  }

  private skipRemaining(exec: PlaybookExecution, from: number, why: string): void {
    const now = this.clock.now().toISOString();
    for (let j = from; j < exec.steps.length; j++) {
      const s = exec.steps[j]!;
      if (s.status === "pending" || s.status === "approved") {
        s.status = "skipped";
        this.log(exec, { stepId: s.stepId, action: s.action, status: "skipped", attempt: 0, startedAt: now, finishedAt: now, message: why });
      }
    }
  }

  private log(exec: PlaybookExecution, entry: Omit<ExecutionLogEntry, "seq">): void {
    exec.log.push({ seq: exec.log.length + 1, ...entry });
  }

  private clone(exec: PlaybookExecution): PlaybookExecution {
    return structuredClone(exec);
  }

  private async save(next: PlaybookExecution, expectedVersion: number): Promise<PlaybookExecution | null> {
    next.version = expectedVersion + 1;
    next.updatedAt = this.clock.now().toISOString();
    return (await this.deps.executions.compareAndSet(next, expectedVersion)) ? next : null;
  }

  private async safeCancelApproval(tenantId: string, approvalId: string): Promise<void> {
    try {
      await this.deps.approvals.cancel(tenantId, approvalId, { kind: "system", id: "playbook-engine" }, "superseded by a concurrent execution update");
    } catch {
      // already decided
    }
  }

  private async auditExecution(exec: PlaybookExecution, action: string, actor?: { kind: "user" | "service" | "system"; id: string }): Promise<void> {
    await safeAudit(this.deps.audit, {
      tenantId: exec.tenantId,
      organizationId: exec.organizationId,
      actor: actor ?? { kind: "playbook", id: `playbook:${exec.playbookId}` },
      action,
      target: { kind: "playbook_execution", id: exec.id },
      outcome: exec.status === "failed" ? "failure" : "success",
      at: this.clock.now().toISOString(),
      details: {
        playbookId: exec.playbookId,
        playbookVersion: exec.playbookVersion,
        status: exec.status,
        steps: exec.steps.map((s: StepState) => ({ id: s.stepId, action: s.action, status: s.status })),
        initiatedBy: exec.initiatedBy,
      },
    });
  }
}

