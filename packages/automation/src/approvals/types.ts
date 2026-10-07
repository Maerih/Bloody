import type { ActionRisk, ResponseActionKey } from "@bloody/contracts";

export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "cancelled";

export type ApprovalKind = "playbook_step" | "response_action" | "ai_action";

/** Who asked for the action. `onBehalfOf` is the human behind a playbook/AI request. */
export interface ApprovalRequester {
  kind: "user" | "service" | "playbook" | "ai";
  id: string;
  /** Human principal that initiated a playbook / AI conversation — also barred from approving. */
  onBehalfOf?: string;
}

export interface ApprovalVote {
  principalId: string;
  displayName?: string;
  at: string;
  comment: string | null;
}

/**
 * An approval request for a dangerous action. Persisted by the API in `approval_requests`;
 * `version` is an optimistic-concurrency counter so two approvers clicking at once cannot both
 * flip the state (and a playbook cannot be resumed twice).
 */
export interface ApprovalRequest {
  id: string;
  tenantId: string;
  organizationId: string;
  kind: ApprovalKind;
  action: ResponseActionKey;
  risk: ActionRisk;
  reason: string;
  /** Why an approval is needed (explainability): "high-risk action", "step requires approval"… */
  gateReasons: string[];
  subject: {
    playbookId?: string;
    playbookName?: string;
    executionId?: string;
    stepId?: string;
    responseActionId?: string;
    incidentId?: string;
    conversationId?: string;
    target?: { kind: string; id: string; label?: string };
  };
  parameters: Record<string, unknown>;
  requestedBy: ApprovalRequester;
  status: ApprovalStatus;
  requiredApprovals: number;
  approvals: ApprovalVote[];
  createdAt: string;
  expiresAt: string;
  decidedAt: string | null;
  decidedBy: string | null;
  decisionComment: string | null;
  version: number;
}

export interface ApprovalStore {
  insert(request: ApprovalRequest): Promise<void>;
  get(tenantId: string, id: string): Promise<ApprovalRequest | null>;
  /** Replace the record iff its stored version equals `expectedVersion`. Returns false on conflict. */
  compareAndSet(next: ApprovalRequest, expectedVersion: number): Promise<boolean>;
  listPending(tenantId: string, filter?: { organizationId?: string; organizationIds?: readonly string[] }): Promise<ApprovalRequest[]>;
  /** Pending requests whose `expiresAt` is at or before `now` (all tenants when tenantId omitted — sweeper). */
  listExpired(now: Date, tenantId?: string): Promise<ApprovalRequest[]>;
}

/** Reference in-memory store (tests, single-process dev). */
export class InMemoryApprovalStore implements ApprovalStore {
  private readonly rows = new Map<string, ApprovalRequest>();

  async insert(request: ApprovalRequest): Promise<void> {
    if (this.rows.has(request.id)) throw new Error(`approval ${request.id} already exists`);
    this.rows.set(request.id, structuredClone(request));
  }

  async get(tenantId: string, id: string): Promise<ApprovalRequest | null> {
    const r = this.rows.get(id);
    return r && r.tenantId === tenantId ? structuredClone(r) : null;
  }

  async compareAndSet(next: ApprovalRequest, expectedVersion: number): Promise<boolean> {
    const cur = this.rows.get(next.id);
    if (!cur || cur.tenantId !== next.tenantId || cur.version !== expectedVersion) return false;
    this.rows.set(next.id, structuredClone(next));
    return true;
  }

  async listPending(tenantId: string, filter: { organizationId?: string; organizationIds?: readonly string[] } = {}): Promise<ApprovalRequest[]> {
    return [...this.rows.values()]
      .filter((r) => r.tenantId === tenantId && r.status === "pending")
      .filter((r) => (filter.organizationId ? r.organizationId === filter.organizationId : true))
      .filter((r) => (filter.organizationIds ? filter.organizationIds.includes(r.organizationId) : true))
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .map((r) => structuredClone(r));
  }

  async listExpired(now: Date, tenantId?: string): Promise<ApprovalRequest[]> {
    return [...this.rows.values()]
      .filter((r) => r.status === "pending" && Date.parse(r.expiresAt) <= now.getTime())
      .filter((r) => (tenantId ? r.tenantId === tenantId : true))
      .map((r) => structuredClone(r));
  }
}
