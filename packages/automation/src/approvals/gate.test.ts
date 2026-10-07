import { describe, expect, it, vi } from "vitest";
import { MemoryAuditSink } from "../util/audit.js";
import { FakeClock, ORG_A, ORG_B, OTHER_TENANT, principal, sequentialIds, TENANT } from "../test-support/fixtures.js";
import { ApprovalError, ApprovalGate, approvalRequirement } from "./gate.js";
import { InMemoryApprovalStore } from "./types.js";

function setup(policy: ConstructorParameters<typeof ApprovalGate>[0]["policy"] = {}) {
  const clock = new FakeClock();
  const audit = new MemoryAuditSink();
  const gate = new ApprovalGate({ store: new InMemoryApprovalStore(), clock, ids: sequentialIds(), audit, policy });
  return { clock, audit, gate };
}

const requester = principal("alice", "soc_analyst_t1", { organizationId: ORG_A });
const responder = principal("bob", "incident_responder");
const ciso = principal("carol", "ciso", { organizationId: ORG_A });

async function requestIsolation(gate: ApprovalGate, overrides: Partial<Parameters<ApprovalGate["request"]>[0]> = {}) {
  return gate.request({
    tenantId: TENANT,
    organizationId: ORG_A,
    kind: "response_action",
    action: "isolate_endpoint",
    reason: "Ransomware precursor on FIN-WS-042",
    requestedBy: { kind: "user", id: requester.id },
    subject: { target: { kind: "asset", id: "asset-1", label: "FIN-WS-042" } },
    ...overrides,
  });
}

describe("approval requirements", () => {
  it("always gates high-risk actions, regardless of flags or policy", () => {
    expect(approvalRequirement("isolate_endpoint").required).toBe(true);
    expect(approvalRequirement("disable_identity", { forced: false, policy: { requireApprovalFor: [] } }).required).toBe(true);
    expect(approvalRequirement("block_ip").reasons[0]).toMatch(/high-risk/);
    const { gate } = setup({ requireApprovalFor: [] });
    expect(gate.effectivePolicy.requireApprovalFor).toContain("high");
    expect(gate.requirement("revoke_sessions").required).toBe(true);
  });

  it("gates low/medium actions only when forced or by policy", () => {
    expect(approvalRequirement("create_case").required).toBe(false);
    expect(approvalRequirement("create_case", { forced: true }).required).toBe(true);
    expect(approvalRequirement("kill_process", { policy: { requireApprovalFor: ["medium"] } }).required).toBe(true);
    expect(approvalRequirement("notify_analyst", { policy: { requireApprovalFor: ["medium"] } }).required).toBe(false);
  });
});

describe("ApprovalGate decisions", () => {
  it("approves by a different principal with response:approve and audits it", async () => {
    const { gate, audit } = setup();
    const req = await requestIsolation(gate);
    expect(req.status).toBe("pending");
    expect(req.risk).toBe("high");
    const listener = vi.fn();
    gate.onDecision(listener);
    const done = await gate.approve(TENANT, req.id, responder, "Confirmed malicious");
    expect(done.status).toBe("approved");
    expect(done.decidedBy).toBe("bob");
    expect(done.approvals).toHaveLength(1);
    expect(listener).toHaveBeenCalledOnce();
    expect(audit.entries.map((e) => e.action)).toEqual(["approval.requested", "approval.approved"]);
  });

  it("forbids self-approval, including by the human a playbook acted for", async () => {
    const { gate, audit } = setup();
    const userAsApprover = principal("alice", "incident_responder");
    const req = await requestIsolation(gate);
    await expect(gate.approve(TENANT, req.id, userAsApprover)).rejects.toMatchObject({ code: "self_approval" });
    const pb = await requestIsolation(gate, { kind: "playbook_step", requestedBy: { kind: "playbook", id: "playbook:1", onBehalfOf: "dave" } });
    await expect(gate.approve(TENANT, pb.id, principal("dave", "incident_responder"))).rejects.toMatchObject({ code: "self_approval" });
    expect(audit.entries.filter((e) => e.outcome === "denied")).toHaveLength(2);
    // Still pending — a denied attempt changes nothing.
    expect((await gate.get(TENANT, req.id))!.status).toBe("pending");
  });

  it("requires response:approve for the request's organization and a human principal", async () => {
    const { gate } = setup();
    const req = await requestIsolation(gate);
    await expect(gate.approve(TENANT, req.id, principal("t1", "soc_analyst_t1"))).rejects.toMatchObject({ code: "forbidden" });
    await expect(gate.approve(TENANT, req.id, principal("other-org-ciso", "ciso", { organizationId: ORG_B }))).rejects.toMatchObject({ code: "forbidden" });
    await expect(gate.approve(TENANT, req.id, principal("svc", "mssp_admin", { kind: "service" }))).rejects.toMatchObject({ code: "forbidden" });
    expect((await gate.approve(TENANT, req.id, ciso)).status).toBe("approved");
  });

  it("hides requests from other tenants", async () => {
    const { gate } = setup();
    const req = await requestIsolation(gate);
    const foreign = principal("eve", "mssp_admin", { tenantId: OTHER_TENANT });
    await expect(gate.approve(OTHER_TENANT, req.id, foreign)).rejects.toMatchObject({ code: "not_found" });
    await expect(gate.approve(TENANT, req.id, foreign)).rejects.toMatchObject({ code: "not_found" });
  });

  it("rejects, and cannot be decided twice", async () => {
    const { gate } = setup();
    const req = await requestIsolation(gate);
    const rejected = await gate.reject(TENANT, req.id, responder, "False positive — backup software");
    expect(rejected.status).toBe("rejected");
    expect(rejected.decisionComment).toMatch(/False positive/);
    await expect(gate.approve(TENANT, req.id, ciso)).rejects.toMatchObject({ code: "not_pending" });
  });

  it("expires pending requests", async () => {
    const { gate, clock } = setup({ ttlMinutes: 30 });
    const req = await requestIsolation(gate);
    clock.advance(31 * 60_000);
    await expect(gate.approve(TENANT, req.id, responder)).rejects.toBeInstanceOf(ApprovalError);
    expect((await gate.get(TENANT, req.id))!.status).toBe("expired");
    const req2 = await requestIsolation(gate);
    clock.advance(31 * 60_000);
    const closed = await gate.expireDue(TENANT);
    expect(closed.map((r) => r.id)).toEqual([req2.id]);
    expect(await gate.listPending(TENANT)).toEqual([]);
  });

  it("supports four-eyes approval for high-risk actions with distinct approvers", async () => {
    const { gate } = setup({ highRiskApprovals: 2 });
    const req = await requestIsolation(gate);
    expect(req.requiredApprovals).toBe(2);
    const first = await gate.approve(TENANT, req.id, responder);
    expect(first.status).toBe("pending");
    await expect(gate.approve(TENANT, req.id, responder)).rejects.toMatchObject({ code: "duplicate_approver" });
    const second = await gate.approve(TENANT, req.id, ciso);
    expect(second.status).toBe("approved");
    expect(second.approvals.map((a) => a.principalId)).toEqual(["bob", "carol"]);
    // Low-risk forced approvals need only one approver.
    const low = await gate.request({ tenantId: TENANT, organizationId: ORG_A, kind: "playbook_step", action: "create_case", forced: true, reason: "policy", requestedBy: { kind: "playbook", id: "p" } });
    expect(low.requiredApprovals).toBe(1);
  });

  it("explains whether a principal can decide (for UI buttons)", async () => {
    const { gate } = setup();
    const req = await requestIsolation(gate);
    expect(gate.canDecide(responder, req)).toEqual({ allowed: true });
    expect(gate.canDecide(principal("alice", "mssp_admin"), req)).toMatchObject({ allowed: false, code: "self_approval" });
  });

  it("validates the request reason", async () => {
    const { gate } = setup();
    await expect(requestIsolation(gate, { reason: "x" })).rejects.toMatchObject({ code: "invalid_request" });
  });
});
