import type { AiMessage, AiProviderConfig } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { AiAccessDeniedError, AiNotFoundError, AiQuotaExceededError } from "../errors.js";
import { DefaultAiProviderRegistry, type AiProviderRegistry } from "../providers/registry.js";
import type { AiProvider, ChatRequest, ChatResponse } from "../providers/types.js";
import { fakeFetch } from "../test-support/fake-fetch.js";
import { FakeSocPort, IDS } from "../test-support/fake-soc.js";
import { FixedClock, ORG_A1, TENANT_A, TENANT_B, noSleep, principal, providerConfig, sequentialIds } from "../test-support/fixtures.js";
import { createStandardSocTools } from "../tools/catalog.js";
import { ToolGateway } from "../tools/gateway.js";
import type { AiAuditEvent } from "../tools/types.js";
import { InMemoryConversationStore } from "./conversation-store.js";
import { AiOrchestrator, type AiOrchestratorLimits, type AiRunEvent } from "./orchestrator.js";
import { BLOODY_BASE_SOC_POLICY } from "./policy.js";
import { InMemoryQuotaCounterStore, InMemoryUsageMeter, PlanQuotaGuard } from "./usage.js";

type Step = (req: ChatRequest) => Partial<ChatResponse> & { message: AiMessage };

class ScriptedProvider implements AiProvider {
  readonly kind = "ollama" as const;
  readonly model = "scripted-model";
  readonly requests: ChatRequest[] = [];
  constructor(
    readonly id: string,
    private readonly script: Step[],
  ) {}
  async chat(req: ChatRequest): Promise<ChatResponse> {
    this.requests.push({ ...req, messages: req.messages.map((m) => ({ ...m })) });
    const step = this.script[Math.min(this.requests.length - 1, this.script.length - 1)];
    if (!step) throw new Error("script exhausted");
    const r = step(req);
    return {
      usage: { inputTokens: 100, outputTokens: 20 },
      model: this.model,
      finishReason: r.message.toolCalls?.length ? "tool_calls" : "stop",
      servedBy: { providerId: this.id, kind: this.kind, model: this.model },
      latencyMs: 5,
      ...r,
    };
  }
  async listModels() {
    return [];
  }
  async healthCheck() {
    return { ok: true, kind: this.kind, providerId: this.id, model: this.model, latencyMs: 0, modelAvailable: null, modelsListed: null, checkedAt: "" };
  }
}

const toolCall = (id: string, name: string, args: Record<string, unknown>): AiMessage => ({ role: "assistant", content: "", toolCalls: [{ id, name, arguments: args }] });

function setup(opts: { config?: Partial<AiProviderConfig>; script: Step[]; limits?: Partial<AiOrchestratorLimits>; quotaLimit?: number }) {
  const config = providerConfig({ kind: "ollama", endpoint: "http://localhost:11434", maxToolTier: "require_approval", systemPolicy: "Never isolate domain controllers without the CISO.", ...opts.config });
  const provider = new ScriptedProvider(config.id, opts.script);
  const registry: AiProviderRegistry = { resolve: async () => ({ config, chain: [config], provider, effectiveMaxToolTier: config.maxToolTier, skipped: [] }) };
  const audit: AiAuditEvent[] = [];
  const auditSink = { record: async (e: AiAuditEvent) => void audit.push(e) };
  const soc = new FakeSocPort();
  const clock = new FixedClock();
  const ids = sequentialIds();
  const gateway = new ToolGateway(createStandardSocTools(soc), { approvals: { requestApproval: async (r) => ({ approvalId: `appr-${r.actionId}` }) }, audit: auditSink, clock, ids });
  const store = new InMemoryConversationStore();
  const usage = new InMemoryUsageMeter();
  const quota =
    opts.quotaLimit !== undefined ? new PlanQuotaGuard({ planFor: async () => "trial", counters: new InMemoryQuotaCounterStore(clock), clock, overrideLimit: async () => opts.quotaLimit ?? null }) : undefined;
  const orchestrator = new AiOrchestrator({
    providers: registry,
    gateway,
    soc,
    store,
    audit: auditSink,
    usage,
    ...(quota ? { quota } : {}),
    clock,
    ids,
    ...(opts.limits ? { limits: opts.limits } : {}),
    organizationName: async () => "Acme Corp",
  });
  return { orchestrator, provider, audit, soc, store, usage, config };
}

const analyst = principal("soc_analyst_t2", { id: "analyst-1" });

describe("AiOrchestrator", () => {
  it("runs the agent loop: grounding, tools through the gateway, approvals, persistence, metering and audit", async () => {
    const { orchestrator, provider, audit, soc, store, usage } = setup({
      script: [
        () => ({
          message: {
            role: "assistant",
            content: "Checking the incident.",
            toolCalls: [
              { id: "c1", name: "get_incident", arguments: { incidentId: IDS.incident } },
              { id: "c2", name: "request_response_action", arguments: { action: "isolate_endpoint", target: { kind: "asset", id: IDS.asset, label: "FIN-WS-01" }, incidentId: IDS.incident, reason: "Active credential theft" } },
            ],
          },
        }),
        () => ({ message: { role: "assistant", content: "**Summary** Credential theft on FIN-WS-01. Isolation is queued for approval." } }),
      ],
    });
    const events: AiRunEvent[] = [];
    const result = await orchestrator.run({
      principal: analyst,
      request: { organizationId: ORG_A1, message: "What happened in incident 1042 and contain it", context: { kind: "incident", id: IDS.incident } },
      onEvent: (e) => events.push(e),
      requestId: "req-1",
    });

    expect(result.answer).toContain("Isolation is queued");
    expect(result.finishReason).toBe("completed");
    expect(result.steps).toBe(2);
    expect(result.usage).toMatchObject({ inputTokens: 200, outputTokens: 40, totalTokens: 240, requests: 2 });
    expect(result.grounding).toMatchObject({ kind: "incident", found: true, reason: "ok" });
    expect(result.toolTrace.map((t) => [t.tool, t.status])).toEqual([
      ["get_incident", "completed"],
      ["request_response_action", "pending_approval"],
    ]);
    expect(result.pendingApprovals).toHaveLength(1);
    expect(result.pendingApprovals[0]).toMatchObject({ tool: "request_response_action", tier: "require_approval", requestedBy: "analyst-1" });
    expect(soc.submitted).toHaveLength(0);

    const first = provider.requests[0]!;
    const system = first.messages[0]!;
    expect(system.role).toBe("system");
    expect(system.content.startsWith(BLOODY_BASE_SOC_POLICY)).toBe(true);
    expect(system.content).toContain("Never isolate domain controllers without the CISO.");
    expect(system.content).toContain("Acme Corp");
    expect(first.messages.some((m) => m.role === "user" && m.content.includes('<context kind="incident"'))).toBe(true);
    expect(first.messages.at(-1)).toEqual({ role: "user", content: "What happened in incident 1042 and contain it" });
    expect(first.tools!.map((t) => t.name)).toContain("request_response_action");
    expect(first.toolChoice).toBe("auto");
    expect(first.dataClass).toBe("tenant");
    const second = provider.requests[1]!;
    const toolMsgs = second.messages.filter((m) => m.role === "tool");
    expect(toolMsgs.map((m) => m.toolCallId)).toEqual(["c1", "c2"]);
    expect(toolMsgs[1]!.content).toContain("pending_approval");
    expect(first.redactionVault).toBe(second.redactionVault);

    const conv = await store.get(TENANT_A, result.conversationId);
    expect(conv).toMatchObject({ title: "What happened in incident 1042 and contain it", principalId: "analyst-1", retainMessages: true, messageCount: 5, usage: { inputTokens: 200, outputTokens: 40, requests: 2 } });
    expect((await store.listMessages(TENANT_A, result.conversationId)).map((m) => m.message.role)).toEqual(["user", "assistant", "tool", "tool", "assistant"]);
    expect(await store.listActions(TENANT_A, result.conversationId)).toHaveLength(2);
    expect(usage.records).toHaveLength(2);
    expect(usage.records[0]).toMatchObject({ tenantId: TENANT_A, organizationId: ORG_A1, purpose: "chat", egress: "local", conversationId: result.conversationId });
    expect(audit.map((a) => a.action)).toEqual(["ai.tool.invoked", "ai.tool.invoked", "ai.tool.approval_requested", "ai.chat.completed"]);
    expect(audit.at(-1)).toMatchObject({ actor: { id: "analyst-1" }, requestId: "req-1", status: "completed" });
    expect(events.map((e) => e.type)).toEqual(["run_started", "step_started", "tool_call", "tool_result", "tool_call", "tool_result", "approval_required", "step_started", "completed"]);
  });

  it("replays only user turns and final answers as history on follow-ups", async () => {
    const { orchestrator, provider } = setup({
      script: [() => ({ message: toolCall("c1", "get_incident", { incidentId: IDS.incident }) }), () => ({ message: { role: "assistant", content: "First answer" } }), () => ({ message: { role: "assistant", content: "Second answer" } })],
    });
    const first = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "first question" } });
    const second = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, conversationId: first.conversationId, message: "follow-up" } });
    expect(second.conversationId).toBe(first.conversationId);
    const msgs = provider.requests[2]!.messages;
    expect(msgs.map((m) => m.role)).toEqual(["system", "user", "assistant", "user"]);
    expect(msgs[2]).toEqual({ role: "assistant", content: "First answer" });
  });

  it("forces a final answer on the last step and reports max_steps", async () => {
    const { orchestrator, provider } = setup({ script: [(req) => ({ message: { ...toolCall(`c${req.messages.length}`, "list_incidents", { limit: req.messages.length }), content: "still digging" } })], limits: { maxSteps: 3 } });
    const result = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "list everything" } });
    expect(provider.requests).toHaveLength(3);
    expect(provider.requests.map((r) => r.toolChoice)).toEqual(["auto", "auto", "none"]);
    expect(result.finishReason).toBe("max_steps");
    expect(result.answer).toBe("still digging");
    expect(result.toolTrace).toHaveLength(2);
  });

  it("stops at the token budget", async () => {
    const { orchestrator, provider } = setup({ script: [() => ({ message: toolCall("c1", "list_incidents", {}) }), () => ({ message: { ...toolCall("c2", "list_incidents", { limit: 2 }), content: "partial view" } })], limits: { tokenBudget: 130 } });
    const result = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "big question" } });
    expect(provider.requests[1]!.toolChoice).toBe("none");
    expect(result.finishReason).toBe("token_budget");
    expect(result.answer).toBe("partial view");
  });

  it("de-duplicates identical tool calls and caps calls per step", async () => {
    const { orchestrator, soc } = setup({
      script: [
        () => ({
          message: {
            role: "assistant",
            content: "",
            toolCalls: [
              { id: "a", name: "get_incident", arguments: { incidentId: IDS.incident } },
              { id: "b", name: "get_incident", arguments: { incidentId: IDS.incident } },
              { id: "c", name: "list_incidents", arguments: {} },
            ],
          },
        }),
        () => ({ message: { role: "assistant", content: "done" } }),
      ],
      limits: { maxToolCallsPerStep: 2 },
    });
    const before = soc.scopes.length;
    const result = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "dup" } });
    expect(result.toolTrace.map((t) => t.code)).toEqual([null, "duplicate_call", "call_limit_exceeded"]);
    expect(soc.scopes.length - before).toBe(2); // incident + alerts lookups for one get_incident call only
  });

  it("enforces RBAC, conversation ownership and tenant isolation", async () => {
    const { orchestrator, provider, audit } = setup({ script: [() => ({ message: { role: "assistant", content: "hi" } })] });
    await expect(orchestrator.run({ principal: principal("customer_viewer"), request: { organizationId: ORG_A1, message: "x" } })).rejects.toBeInstanceOf(AiAccessDeniedError);
    expect(audit.at(-1)).toMatchObject({ action: "ai.chat.denied", code: "ai_use_not_permitted" });
    expect(provider.requests).toHaveLength(0);
    const own = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "mine" } });
    await expect(orchestrator.run({ principal: principal("soc_analyst_t2", { id: "someone-else" }), request: { organizationId: ORG_A1, conversationId: own.conversationId, message: "peek" } })).rejects.toBeInstanceOf(AiAccessDeniedError);
    await expect(
      orchestrator.run({ principal: principal("soc_analyst_t2", { id: "analyst-1", tenantId: TENANT_B, organizationId: null }), request: { organizationId: ORG_A1, conversationId: own.conversationId, message: "x" } }),
    ).rejects.toBeInstanceOf(AiNotFoundError);
    await expect(orchestrator.getConversation(principal("soc_analyst_t2", { id: "someone-else" }), own.conversationId)).rejects.toBeInstanceOf(AiNotFoundError);
    expect((await orchestrator.getConversation(principal("ciso", { id: "ciso-1" }), own.conversationId)).messages).toHaveLength(2);
  });

  it("does not retain message content when retentionDays is 0", async () => {
    const { orchestrator, store } = setup({ config: { retentionDays: 0 }, script: [() => ({ message: toolCall("c1", "list_incidents", {}) }), () => ({ message: { role: "assistant", content: "ok" } })] });
    const result = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "secret stuff" } });
    expect(result.retained).toBe(false);
    expect(await store.listMessages(TENANT_A, result.conversationId)).toEqual([]);
    expect(await store.listActions(TENANT_A, result.conversationId)).toHaveLength(1);
  });

  it("enforces the daily AI quota", async () => {
    const { orchestrator } = setup({ quotaLimit: 1, script: [() => ({ message: { role: "assistant", content: "ok" } })] });
    await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "one" } });
    await expect(orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "two" } })).rejects.toBeInstanceOf(AiQuotaExceededError);
  });

  it("streams deltas and reports grounding problems without failing", async () => {
    const { orchestrator } = setup({
      script: [
        (req) => {
          req.onDelta?.("Hel");
          req.onDelta?.("lo");
          return { message: { role: "assistant", content: "Hello" } };
        },
      ],
    });
    const deltas: string[] = [];
    const result = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "hi", context: { kind: "asset", id: "20000000-0000-4000-8000-00000000ffff" } }, onEvent: (e) => e.type === "delta" && deltas.push(e.text) });
    expect(deltas).toEqual(["Hel", "lo"]);
    expect(result.grounding).toMatchObject({ kind: "asset", found: false, reason: "not_found" });
    const missing = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "hi", context: { kind: "incident" } } });
    expect(missing.grounding.reason).toBe("missing_id");
  });

  it("audits provider failures and rethrows", async () => {
    const config = providerConfig({ kind: "ollama" });
    const failing: AiProvider = { kind: "ollama", id: config.id, model: "m", chat: async () => Promise.reject(new Error("boom")), listModels: async () => [], healthCheck: async () => ({}) as never };
    const audit: AiAuditEvent[] = [];
    const soc = new FakeSocPort();
    const sink = { record: async (e: AiAuditEvent) => void audit.push(e) };
    const orchestrator = new AiOrchestrator({
      providers: { resolve: async () => ({ config, chain: [config], provider: failing, effectiveMaxToolTier: "read", skipped: [] }) },
      gateway: new ToolGateway(createStandardSocTools(soc), { approvals: { requestApproval: async () => ({ approvalId: "x" }) }, audit: sink }),
      soc,
      store: new InMemoryConversationStore(),
      audit: sink,
    });
    await expect(orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "x" } })).rejects.toThrow("boom");
    expect(audit.at(-1)).toMatchObject({ action: "ai.chat.failed", reason: "boom" });
  });

  it("approves pending AI actions with four-eyes and records the outcome in the transcript", async () => {
    const { orchestrator, soc, store } = setup({
      script: [
        () => ({ message: toolCall("c1", "request_response_action", { action: "revoke_sessions", target: { kind: "identity", id: IDS.identity }, reason: "Token theft suspected" }) }),
        () => ({ message: { role: "assistant", content: "Queued revoke_sessions for approval." } }),
      ],
    });
    const result = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "revoke" } });
    const actionId = result.pendingApprovals[0]!.id;
    await expect(orchestrator.approveAction({ approver: principal("incident_responder", { id: "analyst-1" }), actionId })).rejects.toThrow(/Four-eyes/);
    const executed = await orchestrator.approveAction({ approver: principal("incident_responder", { id: "ir-lead" }), actionId });
    expect(executed.status).toBe("completed");
    expect(soc.submitted[0]!.input).toMatchObject({ action: "revoke_sessions", requestedVia: "ai" });
    expect((await store.getAction(TENANT_A, actionId))!.action).toMatchObject({ status: "completed", approvedBy: "ir-lead" });
    const transcript = await store.listMessages(TENANT_A, result.conversationId);
    expect(transcript.at(-1)!.message.content).toContain("approved by ir-lead");
    await expect(orchestrator.rejectAction({ approver: principal("incident_responder", { id: "ir-lead" }), actionId, reason: "late" })).rejects.toThrow(/not pending/);
  });
});

describe("AiOrchestrator end-to-end with a governed provider", () => {
  it("redacts secrets from tool results before they reach a cloud model", async () => {
    const config = providerConfig({ kind: "openai", isDefault: true, maxToolTier: "investigate", allowCloudData: true, redactSensitive: true });
    const { fetch, requests } = fakeFetch([
      { json: { choices: [{ finish_reason: "tool_calls", message: { content: null, tool_calls: [{ id: "s1", type: "function", function: { name: "search_events", arguments: '{"query":"process.name:rundll32.exe"}' } }] } }], usage: { prompt_tokens: 900, completion_tokens: 30 } } },
      { json: { choices: [{ finish_reason: "stop", message: { content: "LSASS was dumped with comsvcs.dll on fin-ws-01 (event 80000000-0000-4000-8000-000000000001)." } }], usage: { prompt_tokens: 1300, completion_tokens: 60 } } },
    ]);
    const registry = new DefaultAiProviderRegistry({ configs: { listProviders: async () => [config] }, secrets: { resolve: async () => "sk-live" }, fetch, hostResolver: false, runtime: { sleep: noSleep } });
    const soc = new FakeSocPort();
    const audit: AiAuditEvent[] = [];
    const sink = { record: async (e: AiAuditEvent) => void audit.push(e) };
    const orchestrator = new AiOrchestrator({
      providers: registry,
      gateway: new ToolGateway(createStandardSocTools(soc), { approvals: { requestApproval: async () => ({ approvalId: "x" }) }, audit: sink }),
      soc,
      store: new InMemoryConversationStore(),
      audit: sink,
    });
    const result = await orchestrator.run({ principal: analyst, request: { organizationId: ORG_A1, message: "Was LSASS dumped on fin-ws-01?" } });
    expect(result.answer).toContain("LSASS was dumped");
    expect(result.redactions.byKind.password).toBeGreaterThan(0);
    const toolNames = ((requests[0]!.body as { tools: Array<{ function: { name: string } }> }).tools ?? []).map((t) => t.function.name);
    expect(toolNames).toContain("search_events");
    expect(toolNames).not.toContain("request_response_action");
    const secondBody = requests[1]!.rawBody!;
    expect(secondBody).toContain("rundll32.exe");
    expect(secondBody).not.toContain("Winter2026!");
    expect(secondBody).toContain("[REDACTED:password:");
    expect(result.usage).toMatchObject({ inputTokens: 2200, outputTokens: 90, requests: 2 });
  });
});
