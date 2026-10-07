import type { ActionRisk, Playbook, ResponseActionKey } from "@bloody/contracts";
import type { ConditionResult } from "../conditions.js";

export type PlaybookTriggerType = Playbook["trigger"]["on"];
export type PlaybookStep = Playbook["steps"][number];

/**
 * An event offered to the playbook engine. `subject` is the condition/template context, e.g.
 * `{ incident: {...}, severity: "high", organization: {...} }` — conditions address it with
 * dotted paths ("incident.severity").
 */
export interface PlaybookEvent {
  tenantId: string;
  organizationId: string;
  type: PlaybookTriggerType;
  subject: Record<string, unknown>;
  /** Primary entity — used for idempotency, audit and the response-action record. */
  subjectRef?: { kind: string; id: string; label?: string };
  occurredAt: string;
  /** Caller-supplied idempotency key (e.g. the outbox event id). */
  idempotencyKey?: string;
  initiatedBy?: { kind: "user" | "service" | "ai" | "system"; id: string };
}

/** What the engine asks the executor (the API's response-action service → engine adapters) to do. */
export interface ActionExecutionRequest {
  tenantId: string;
  organizationId: string;
  action: ResponseActionKey;
  risk: ActionRisk;
  parameters: Record<string, unknown>;
  /** Stable across retries and resumes: the executor MUST de-duplicate on it. */
  idempotencyKey: string;
  attempt: number;
  playbook: { id: string; name: string; version: number };
  executionId: string;
  stepId: string;
  subjectRef: PlaybookEvent["subjectRef"] | null;
  approval: { id: string; approvedBy: string[] } | null;
  /** Aborted when the step times out. */
  signal: AbortSignal;
}

export interface ActionExecutionResult {
  output?: unknown;
  /** Id of the response-action record / external job created by the executor. */
  externalRef?: string;
}

export interface ActionExecutor {
  execute(request: ActionExecutionRequest): Promise<ActionExecutionResult>;
}

/** Throw from an executor to control retry behaviour. Unknown errors are treated as retryable. */
export class ActionExecutionError extends Error {
  readonly retryable: boolean;
  readonly code: string;

  constructor(code: string, message: string, retryable: boolean) {
    super(message);
    this.name = "ActionExecutionError";
    this.code = code;
    this.retryable = retryable;
  }
}

export type ExecutionStatus = "running" | "waiting_approval" | "succeeded" | "partially_succeeded" | "failed" | "rejected" | "cancelled";

export type StepStatus = "pending" | "pending_approval" | "approved" | "running" | "succeeded" | "failed" | "skipped" | "rejected" | "expired" | "cancelled";

export interface ExecutionLogEntry {
  seq: number;
  stepId: string | null;
  action: ResponseActionKey | null;
  status: StepStatus | "info";
  attempt: number;
  startedAt: string;
  finishedAt: string | null;
  message: string;
  output?: unknown;
  error?: { code: string; message: string; retryable: boolean };
  approvalId?: string;
}

export interface StepState {
  stepId: string;
  action: ResponseActionKey;
  status: StepStatus;
  attempts: number;
  approvalId: string | null;
  approvedBy: string[];
  externalRef: string | null;
}

export interface PlaybookExecution {
  id: string;
  tenantId: string;
  organizationId: string;
  playbookId: string;
  playbookName: string;
  playbookVersion: number;
  /** Frozen copy of the playbook as it was when the run started (resumes use it, not the latest version). */
  playbook: Playbook;
  trigger: { type: PlaybookTriggerType; occurredAt: string; subjectRef: PlaybookEvent["subjectRef"] | null };
  /** Condition/template context captured at trigger time. */
  context: Record<string, unknown>;
  idempotencyKey: string;
  status: ExecutionStatus;
  steps: StepState[];
  log: ExecutionLogEntry[];
  conditionResults: ConditionResult[];
  initiatedBy: { kind: "user" | "service" | "ai" | "system"; id: string };
  startedAt: string;
  updatedAt: string;
  finishedAt: string | null;
  version: number;
}

export interface ExecutionStore {
  /** Insert unless an execution with the same (tenantId, idempotencyKey) exists. Returns false on duplicate. */
  insert(execution: PlaybookExecution): Promise<boolean>;
  get(tenantId: string, id: string): Promise<PlaybookExecution | null>;
  findByIdempotencyKey(tenantId: string, key: string): Promise<PlaybookExecution | null>;
  findByApproval(tenantId: string, approvalId: string): Promise<PlaybookExecution | null>;
  /** Replace iff stored version === expectedVersion. Returns false on conflict. */
  compareAndSet(next: PlaybookExecution, expectedVersion: number): Promise<boolean>;
  list(tenantId: string, filter?: { organizationId?: string; playbookId?: string; status?: ExecutionStatus; limit?: number }): Promise<PlaybookExecution[]>;
}

export class InMemoryExecutionStore implements ExecutionStore {
  private readonly rows = new Map<string, PlaybookExecution>();

  async insert(execution: PlaybookExecution): Promise<boolean> {
    for (const r of this.rows.values()) {
      if (r.tenantId === execution.tenantId && r.idempotencyKey === execution.idempotencyKey) return false;
    }
    this.rows.set(execution.id, structuredClone(execution));
    return true;
  }

  async get(tenantId: string, id: string): Promise<PlaybookExecution | null> {
    const r = this.rows.get(id);
    return r && r.tenantId === tenantId ? structuredClone(r) : null;
  }

  async findByIdempotencyKey(tenantId: string, key: string): Promise<PlaybookExecution | null> {
    for (const r of this.rows.values()) if (r.tenantId === tenantId && r.idempotencyKey === key) return structuredClone(r);
    return null;
  }

  async findByApproval(tenantId: string, approvalId: string): Promise<PlaybookExecution | null> {
    for (const r of this.rows.values()) {
      if (r.tenantId === tenantId && r.steps.some((s) => s.approvalId === approvalId)) return structuredClone(r);
    }
    return null;
  }

  async compareAndSet(next: PlaybookExecution, expectedVersion: number): Promise<boolean> {
    const cur = this.rows.get(next.id);
    if (!cur || cur.tenantId !== next.tenantId || cur.version !== expectedVersion) return false;
    this.rows.set(next.id, structuredClone(next));
    return true;
  }

  async list(tenantId: string, filter: { organizationId?: string; playbookId?: string; status?: ExecutionStatus; limit?: number } = {}): Promise<PlaybookExecution[]> {
    return [...this.rows.values()]
      .filter((r) => r.tenantId === tenantId)
      .filter((r) => (filter.organizationId ? r.organizationId === filter.organizationId : true))
      .filter((r) => (filter.playbookId ? r.playbookId === filter.playbookId : true))
      .filter((r) => (filter.status ? r.status === filter.status : true))
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
      .slice(0, filter.limit ?? 100)
      .map((r) => structuredClone(r));
  }
}
