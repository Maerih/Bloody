import type { AiAuditEvent } from "./types.js";
import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import { FixedClock, ORG_A1, ORG_A2, TENANT_A, TENANT_B, principal, sequentialIds } from "../test-support/fixtures.js";
import { ToolGateway } from "./gateway.js";
import { defineTool, type AiApprovalRequest, type ToolInvocationContext } from "./types.js";

function setup(opts: { auditFails?: boolean; approvalFails?: boolean } = {}) {
  const audit: AiAuditEvent[] = [];
  const approvals: AiApprovalRequest[] = [];
  const handlers = { lookup: vi.fn(async (_c: unknown, a: { id: string }) => ({ found: a.id })), contain: vi.fn(async () => ({ queued: true })), notify: vi.fn(async () => ({ sent: 1 })), slow: vi.fn(() => new Promise(() => undefined)) };
  const tools = [
    defineTool({ name: "lookup", description: "Read", tier: "read", permission: "incident:read", parameters: z.object({ id: z.string().min(1) }).strict(), handler: handlers.lookup }),
    defineTool({ name: "hunt_it", description: "Investigate", tier: "investigate", permission: "event:read", parameters: z.object({}).strict(), handler: async () => ({}) }),
    defineTool({
      name: "contain",
      description: "Isolate",
      tier: "require_approval",
      permission: "response:request",
      parameters: z.object({ host: z.string(), password: z.string().optional() }).strict(),
      risk: "high",
      describe: (a) => `Isolate ${a.host}`,
      handler: handlers.contain,
    }),
    defineTool({ name: "notify", description: "Notify", tier: "execute", permission: "response:request", parameters: z.object({ risky: z.boolean().default(false) }).strict(), risk: (a) => (a.risky ? "high" : "low"), handler: handlers.notify }),
    defineTool({ name: "slow", description: "Slow", tier: "read", permission: "incident:read", parameters: z.object({}).strict(), timeoutMs: 20, handler: handlers.slow }),
  ];
  const gateway = new ToolGateway(tools, {
    approvals: {
      requestApproval: async (req) => {
        if (opts.approvalFails) throw new Error("queue down");
        approvals.push(req);
        return { approvalId: `appr-${approvals.length}` };
      },
    },
    audit: {
      record: async (e) => {
        if (opts.auditFails) throw new Error("audit db down");
        audit.push(e);
      },
    },
    clock: new FixedClock(),
    ids: sequentialIds(),
  });
  return { gateway, audit, approvals, handlers };
}

const ctx = (over: Partial<ToolInvocationContext> = {}): ToolInvocationContext => ({
  principal: principal("soc_analyst_t2"),
  tenantId: TENANT_A,
  organizationId: ORG_A1,
  providerMaxTier: "recommend",
  conversationId: "c0000000-0000-4000-8000-000000000001",
  providerId: "p-1",
  ...over,
});

describe("ToolGateway", () => {
  it("executes permitted read tools, audits before and after, and attributes the action", async () => {
    const { gateway, audit, handlers } = setup();
    const res = await gateway.invoke(ctx(), { id: "call-1", name: "lookup", arguments: { id: "inc-7" } });
    expect(res).toMatchObject({ decision: "allowed", status: "completed", result: { found: "inc-7" }, tier: "read" });
    expect(res.action).toMatchObject({ tool: "lookup", status: "completed", requestedBy: "user-soc_analyst_t2", conversationId: "c0000000-0000-4000-8000-000000000001" });
    const scope = handlers.lookup.mock.calls[0]![0] as { scope: Record<string, unknown> };
    expect(scope.scope).toMatchObject({ tenantId: TENANT_A, organizationId: ORG_A1, principalId: "user-soc_analyst_t2", via: "ai", approvedBy: null });
    expect(audit.map((a) => [a.action, a.status])).toEqual([
      ["ai.tool.invoked", "started"],
      ["ai.tool.invoked", "completed"],
    ]);
    expect(audit[0]).toMatchObject({ tenantId: TENANT_A, organizationId: ORG_A1, actor: { kind: "ai", id: "p-1" }, onBehalfOf: "user-soc_analyst_t2" });
  });

  it("denies unknown tools, other tenants, missing ai:use and missing permissions", async () => {
    const { gateway, handlers } = setup();
    expect((await gateway.invoke(ctx(), { id: "1", name: "drop_tables", arguments: {} })).code).toBe("unknown_tool");
    expect((await gateway.invoke(ctx({ tenantId: TENANT_B }), { id: "2", name: "lookup", arguments: { id: "x" } })).code).toBe("tenant_mismatch");
    expect((await gateway.invoke(ctx({ principal: principal("executive") }), { id: "3", name: "lookup", arguments: { id: "x" } })).code).toBe("ai_use_not_permitted");
    expect((await gateway.invoke(ctx({ principal: principal("soc_analyst_t1", { organizationId: ORG_A2 }) }), { id: "4", name: "lookup", arguments: { id: "x" } })).code).toBe("ai_use_not_permitted");
    expect((await gateway.invoke(ctx({ principal: principal("ciso") }), { id: "5", name: "contain", arguments: { host: "h" } })).code).toBe("permission_denied");
    expect(handlers.lookup).not.toHaveBeenCalled();
  });

  it("validates arguments with the tool schema", async () => {
    const { gateway, audit } = setup();
    const res = await gateway.invoke(ctx(), { id: "1", name: "lookup", arguments: { id: "", extra: true } });
    expect(res).toMatchObject({ status: "failed", code: "invalid_arguments", decision: "denied" });
    expect(res.reason).toMatch(/id/);
    expect(audit[0]).toMatchObject({ action: "ai.tool.failed", code: "invalid_arguments" });
    expect((await gateway.invoke(ctx(), { id: "2", name: "lookup", arguments: { __invalid_json__: "{" } })).code).toBe("invalid_arguments");
  });

  it("denies tools above the provider's tier", async () => {
    const { gateway } = setup();
    const res = await gateway.invoke(ctx({ providerMaxTier: "read" }), { id: "1", name: "hunt_it", arguments: {} });
    expect(res).toMatchObject({ decision: "denied", code: "tier_exceeds_provider_max" });
    const approval = await gateway.invoke(ctx({ providerMaxTier: "recommend" }), { id: "2", name: "contain", arguments: { host: "h" } });
    expect(approval.code).toBe("tier_exceeds_provider_max");
  });

  it("queues require_approval tools without executing them", async () => {
    const { gateway, approvals, handlers, audit } = setup();
    const res = await gateway.invoke(ctx({ providerMaxTier: "require_approval" }), { id: "1", name: "contain", arguments: { host: "fin-ws-01", password: "hunter22" } });
    expect(res).toMatchObject({ decision: "pending_approval", status: "pending_approval", approvalId: "appr-1", risk: "high" });
    expect(handlers.contain).not.toHaveBeenCalled();
    expect(approvals[0]).toMatchObject({ tool: "contain", summary: "Isolate fin-ws-01", tier: "require_approval", risk: "high", tenantId: TENANT_A, organizationId: ORG_A1, requestedBy: { id: "user-soc_analyst_t2" } });
    expect(audit[0]).toMatchObject({ action: "ai.tool.approval_requested", decision: "pending_approval" });
    expect(JSON.stringify(audit[0]!.arguments)).not.toContain("hunter22");
    expect(gateway.toModelContent(res)).toContain("NOT been executed");
  });

  it("runs execute-tier tools autonomously only for low risk with execute trust", async () => {
    const { gateway, handlers } = setup();
    expect((await gateway.invoke(ctx({ providerMaxTier: "execute" }), { id: "1", name: "notify", arguments: {} })).status).toBe("completed");
    expect(handlers.notify).toHaveBeenCalledTimes(1);
    expect((await gateway.invoke(ctx({ providerMaxTier: "execute" }), { id: "2", name: "notify", arguments: { risky: true } })).status).toBe("pending_approval");
    expect((await gateway.invoke(ctx({ providerMaxTier: "require_approval" }), { id: "3", name: "notify", arguments: {} })).status).toBe("pending_approval");
    expect((await gateway.invoke(ctx({ providerMaxTier: "recommend" }), { id: "4", name: "notify", arguments: {} })).decision).toBe("denied");
    expect(handlers.notify).toHaveBeenCalledTimes(1);
  });

  it("fails closed when the audit log or approval queue is unavailable", async () => {
    const a = setup({ auditFails: true });
    expect(await a.gateway.invoke(ctx(), { id: "1", name: "lookup", arguments: { id: "x" } })).toMatchObject({ status: "failed", code: "audit_unavailable" });
    expect(a.handlers.lookup).not.toHaveBeenCalled();
    const b = setup({ approvalFails: true });
    expect(await b.gateway.invoke(ctx({ providerMaxTier: "require_approval" }), { id: "1", name: "contain", arguments: { host: "h" } })).toMatchObject({ status: "failed", code: "approval_unavailable" });
  });

  it("times out slow handlers", async () => {
    const { gateway } = setup();
    expect(await gateway.invoke(ctx(), { id: "1", name: "slow", arguments: {} })).toMatchObject({ status: "failed", code: "timeout" });
  });

  it("offers the model only tools it could use", () => {
    const { gateway } = setup();
    expect(gateway.specsFor(ctx({ providerMaxTier: "read" })).map((t) => t.name)).toEqual(["lookup", "slow"]);
    expect(gateway.specsFor(ctx({ providerMaxTier: "execute" })).map((t) => t.name)).toEqual(["lookup", "hunt_it", "contain", "notify", "slow"]);
    expect(gateway.specsFor(ctx({ principal: principal("customer_viewer") }))).toEqual([]);
    const contain = gateway.specsFor(ctx({ providerMaxTier: "require_approval" })).find((t) => t.name === "contain")!;
    expect(contain.description).toMatch(/human approval/);
    expect(contain.parameters).toMatchObject({ type: "object", required: ["host"] });
  });

  it("executes approved actions with four-eyes and approver permission checks", async () => {
    const { gateway, handlers, audit } = setup();
    const pending = await gateway.invoke(ctx({ providerMaxTier: "require_approval" }), { id: "1", name: "contain", arguments: { host: "fin-ws-01" } });
    const base = { action: pending.action, tenantId: TENANT_A, organizationId: ORG_A1 };
    expect((await gateway.executeApproved({ ...base, approver: principal("soc_analyst_t2") })).reason).toMatch(/approve/);
    expect((await gateway.executeApproved({ ...base, approver: principal("incident_responder", { id: "user-soc_analyst_t2" }) })).reason).toMatch(/Four-eyes/);
    expect((await gateway.executeApproved({ ...base, approver: principal("incident_responder", { tenantId: TENANT_B }) })).code).toBe("tenant_mismatch");
    expect(handlers.contain).not.toHaveBeenCalled();
    const ok = await gateway.executeApproved({ ...base, approver: principal("incident_responder", { id: "boss" }) });
    expect(ok).toMatchObject({ status: "completed", result: { queued: true } });
    expect(ok.action).toMatchObject({ status: "completed", approvedBy: "boss", requestedBy: "user-soc_analyst_t2" });
    const handlerCtx = handlers.contain.mock.calls[0] as unknown as [{ scope: { approvedBy: string; principalId: string } }];
    expect(handlerCtx[0].scope).toMatchObject({ approvedBy: "boss", principalId: "user-soc_analyst_t2" });
    expect(audit.at(-1)).toMatchObject({ action: "ai.tool.approved_executed", actor: { id: "boss" } });
    expect((await gateway.executeApproved({ ...base, action: ok.action, approver: principal("incident_responder", { id: "boss" }) })).reason).toMatch(/not pending/);
  });

  it("records rejections", async () => {
    const { gateway, audit } = setup();
    const pending = await gateway.invoke(ctx({ providerMaxTier: "require_approval" }), { id: "1", name: "contain", arguments: { host: "h" } });
    const rejected = await gateway.reject({ action: pending.action, approver: principal("ciso", { id: "ciso-1" }), tenantId: TENANT_A, organizationId: ORG_A1, reason: "Business hours" });
    expect(rejected).toMatchObject({ status: "rejected", approvedBy: "ciso-1" });
    expect(audit.at(-1)).toMatchObject({ action: "ai.tool.rejected", reason: "Business hours" });
    await expect(gateway.reject({ action: pending.action, approver: principal("soc_analyst_t1"), tenantId: TENANT_A, organizationId: ORG_A1, reason: "x" })).rejects.toThrow(/not allowed/);
  });

  it("rejects invalid tool names and duplicates", () => {
    const { gateway } = setup();
    expect(() => gateway.register(defineTool({ name: "Bad-Name", description: "", tier: "read", permission: "incident:read", parameters: z.object({}), handler: async () => null }))).toThrow(/Invalid tool name/);
    expect(() => gateway.register(defineTool({ name: "lookup", description: "", tier: "read", permission: "incident:read", parameters: z.object({}), handler: async () => null }))).toThrow(/already/);
  });
});
