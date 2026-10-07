import type { AiActionRecord } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { AiOutputError, AiPolicyError } from "../errors.js";
import type { AiConversation } from "../orchestrator/conversation-store.js";
import { InMemoryUsageMeter, type AiUsageRecord } from "../orchestrator/usage.js";
import { createProvider } from "../providers/factory.js";
import type { AiProvider, ChatRequest, ChatResponse } from "../providers/types.js";
import { fakeFetch } from "../test-support/fake-fetch.js";
import { ORG_A1, TENANT_A, noSleep, providerConfig } from "../test-support/fixtures.js";
import type { AiAuditEvent } from "../tools/types.js";
import { aggregateAiUsage, estimateAiCost, summarizeAiActivity } from "./activity.js";
import { audienceForReport, draftNotification, draftReportNarrative, extractJsonObject, renderPlainTextAsHtml, sanitizeSubject } from "./narrative.js";

function scripted(outputs: string[]): AiProvider & { requests: ChatRequest[] } {
  const requests: ChatRequest[] = [];
  return {
    kind: "ollama",
    id: "prov-1",
    model: "llama3.1",
    requests,
    async chat(req: ChatRequest): Promise<ChatResponse> {
      requests.push(req);
      const content = outputs[Math.min(requests.length - 1, outputs.length - 1)]!;
      return { message: { role: "assistant", content }, usage: { inputTokens: 500, outputTokens: 120 }, model: "llama3.1", finishReason: "stop", servedBy: { providerId: "prov-1", kind: "ollama", model: "llama3.1" }, latencyMs: 40 };
    },
    listModels: async () => [],
    healthCheck: async () => ({}) as never,
  };
}

const scope = { tenantId: TENANT_A, organizationId: ORG_A1, requestedBy: { kind: "service" as const, id: "report-scheduler" } };
const narrative = { headline: "Risk down 12% this month", summary: "Twelve incidents were handled with a median time to respond of 95 minutes.", keyFindings: ["12 incidents, 2 critical"], recommendations: [{ action: "Enforce MFA for admins", priority: "high" }] };

describe("AI report narratives", () => {
  it("maps every report type to an audience", () => {
    expect(audienceForReport("executive")).toBe("business");
    expect(audienceForReport("soc_operations")).toBe("soc");
    expect(audienceForReport("mssp_portfolio")).toBe("mssp");
    expect(audienceForReport("customer_monthly")).toBe("customer");
  });

  it("drafts a grounded narrative, meters usage and audits", async () => {
    const provider = scripted(["Here you go:\n```json\n" + JSON.stringify(narrative) + "\n```"]);
    const usage = new InMemoryUsageMeter();
    const audit: AiAuditEvent[] = [];
    const res = await draftReportNarrative(
      provider,
      { scope, reportType: "executive", organizationName: "Acme Corp", period: { from: "2026-09-01", to: "2026-09-30" }, data: { incidents: 12, mttrMinutes: 95 } },
      { usage, audit: { record: async (e) => void audit.push(e) } },
    );
    expect(res.content).toEqual(narrative);
    expect(res).toMatchObject({ audience: "business", aiGenerated: true, attempts: 1, usage: { inputTokens: 500, outputTokens: 120 } });
    const req = provider.requests[0]!;
    expect(req.dataClass).toBe("tenant");
    expect(req.messages[0]!.content).toMatch(/executives and the CISO/);
    expect(req.messages[1]!.content).toContain('"mttrMinutes":95');
    expect(usage.records[0]).toMatchObject({ purpose: "report_narrative", tenantId: TENANT_A, principalId: "report-scheduler" });
    expect(audit[0]).toMatchObject({ action: "ai.narrative.generated", metadata: { reportType: "executive", audience: "business" } });
  });

  it("retries once on invalid structured output and then fails clearly", async () => {
    const recovered = scripted(["not json", JSON.stringify(narrative)]);
    const res = await draftReportNarrative(recovered, { scope, reportType: "customer_monthly", organizationName: "Acme", period: { from: "a", to: "b" }, data: {} });
    expect(res.attempts).toBe(2);
    expect(recovered.requests[1]!.messages.at(-1)!.content).toMatch(/invalid/);
    expect(recovered.requests[0]!.messages[0]!.content).toMatch(/customer's stakeholders/);
    await expect(draftReportNarrative(scripted(['{"headline":"x"}']), { scope, reportType: "sla", organizationName: null, period: { from: "a", to: "b" }, data: {} })).rejects.toBeInstanceOf(AiOutputError);
  });

  it("respects the cloud-data policy of the governed provider", async () => {
    const p = createProvider(providerConfig({ kind: "openai", allowCloudData: false }), "k", fakeFetch([]).fetch, { sleep: noSleep });
    await expect(draftReportNarrative(p, { scope, reportType: "executive", organizationName: null, period: { from: "a", to: "b" }, data: {} })).rejects.toBeInstanceOf(AiPolicyError);
  });
});

describe("AI notification drafts", () => {
  it("produces a safe single-line subject and escaped HTML body", async () => {
    const provider = scripted([JSON.stringify({ subject: "Incident #1042\r\nBcc: attacker@evil.test", body: "We contained <script>alert(1)</script> the threat.\n\n- Reset your password\n- Review sign-ins" })]);
    const res = await draftNotification(provider, { scope, event: "incident.created", audience: "customer", channel: "email", data: { incident: 1042 } });
    expect(res.content.subject).toBe("Incident #1042 Bcc: attacker@evil.test");
    expect(res.content.subject).not.toMatch(/[\r\n]/);
    expect(res.content.html).toBe("<p>We contained &lt;script&gt;alert(1)&lt;/script&gt; the threat.</p>\n<ul><li>Reset your password</li><li>Review sign-ins</li></ul>");
    expect(provider.requests[0]!.messages[0]!.content).toMatch(/e-mail body/);
  });

  it("helpers", () => {
    expect(extractJsonObject('prefix {"a":1} suffix')).toEqual({ a: 1 });
    expect(extractJsonObject("nothing")).toBeNull();
    expect(sanitizeSubject("  a\tb\u0000c  ")).toBe("a b c");
    expect(renderPlainTextAsHtml('Line "1"\nLine 2')).toBe("<p>Line &quot;1&quot;<br>Line 2</p>");
  });
});

describe("AI activity and usage reporting", () => {
  const action = (over: Partial<AiActionRecord>): AiActionRecord => ({
    id: "x",
    conversationId: "c",
    tool: "get_incident",
    tier: "read",
    arguments: {},
    status: "completed",
    result: null,
    requestedBy: "u1",
    approvedBy: null,
    at: "2026-10-07T10:00:00.000Z",
    ...over,
  });
  const conv = (id: string, principalId: string): AiConversation => ({
    id,
    tenantId: TENANT_A,
    organizationId: ORG_A1,
    principalId,
    providerId: null,
    title: "t",
    context: { kind: "none" },
    createdAt: "2026-10-07T09:00:00.000Z",
    updatedAt: "2026-10-07T09:00:00.000Z",
    expiresAt: null,
    retainMessages: true,
    messageCount: 0,
    usage: { inputTokens: 0, outputTokens: 0, requests: 0 },
  });

  it("summarizes AI activity for the Command Center widget", () => {
    const s = summarizeAiActivity({
      conversations: [conv("c1", "u1"), conv("c2", "u2"), conv("c3", "u1")],
      actions: [
        action({ id: "1" }),
        action({ id: "2", tool: "request_response_action", tier: "require_approval", status: "completed", approvedBy: "lead" }),
        action({ id: "3", tool: "request_response_action", tier: "require_approval", status: "rejected", approvedBy: "lead" }),
        action({ id: "4", tool: "request_response_action", tier: "require_approval", status: "pending_approval" }),
        action({ id: "5", tool: "search_events", tier: "investigate", status: "denied" }),
      ],
    });
    expect(s).toMatchObject({ conversations: 3, actionsProposed: 3, actionsApproved: 1, actionsRejected: 1, pendingApprovals: 1, actionsDenied: 1, approvalRate: 0.5, activeAnalysts: 2 });
    expect(s.byTool[0]).toEqual({ tool: "request_response_action", count: 3 });
  });

  it("aggregates metered usage and estimates cost", () => {
    const rec = (over: Partial<AiUsageRecord>): AiUsageRecord => ({
      id: "r",
      at: "2026-10-07T10:00:00.000Z",
      tenantId: TENANT_A,
      organizationId: ORG_A1,
      principalId: "u1",
      conversationId: null,
      providerId: "p1",
      providerKind: "openai",
      model: "gpt-4.1",
      egress: "cloud",
      purpose: "chat",
      inputTokens: 1_000_000,
      outputTokens: 100_000,
      estimated: false,
      latencyMs: 100,
      fallbackUsed: false,
      ...over,
    });
    const records = [rec({}), rec({ latencyMs: 300, fallbackUsed: true }), rec({ providerKind: "ollama", model: "llama3.1", egress: "local", inputTokens: 10, outputTokens: 5, at: "2026-10-08T00:00:00.000Z" })];
    const byModel = aggregateAiUsage(records, "model");
    expect(byModel[0]).toMatchObject({ key: "openai:gpt-4.1", requests: 2, totalTokens: 2_200_000, cloudRequests: 2, fallbackRequests: 1, avgLatencyMs: 200 });
    expect(aggregateAiUsage(records, "day").map((r) => r.key)).toEqual(["2026-10-07", "2026-10-08"]);
    expect(aggregateAiUsage(records, "egress").find((r) => r.key === "local")!.requests).toBe(1);
    const cost = estimateAiCost(records, { "openai:*": { inputPerMTok: 2, outputPerMTok: 8 } });
    expect(cost).toEqual({ total: 5.6, unpriced: 0, byModel: [{ model: "openai:gpt-4.1", cost: 5.6, tokens: 2_200_000 }, { model: "ollama:llama3.1", cost: 0, tokens: 15 }] });
  });
});
