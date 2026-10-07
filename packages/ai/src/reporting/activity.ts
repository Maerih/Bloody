import type { AiActionRecord, AiToolTier, CommandCenterSummary } from "@bloody/contracts";
import type { AiConversation } from "../orchestrator/conversation-store.js";
import type { AiUsageRecord } from "../orchestrator/usage.js";

/**
 * Report-ready AI aggregates for every audience: Command Center `aiActivity` widget, SOC
 * operations reports (what the AI analyst did), MSSP/billing reports (usage per tenant,
 * organization, provider, model) and customer reviews (AI-assisted actions on their behalf).
 */

type CommandCenterAiActivity = CommandCenterSummary["aiActivity"];

export interface AiActivitySummary extends CommandCenterAiActivity {
  actionsCompleted: number;
  actionsRejected: number;
  actionsDenied: number;
  actionsFailed: number;
  pendingApprovals: number;
  approvalRate: number | null;
  byTool: Array<{ tool: string; count: number }>;
  byTier: Partial<Record<AiToolTier, number>>;
  activeAnalysts: number;
}

export function summarizeAiActivity(input: { conversations: readonly AiConversation[]; actions: readonly AiActionRecord[]; window?: { from: string; to: string } }): AiActivitySummary {
  const inWindow = (at: string): boolean => !input.window || (at >= input.window.from && at <= input.window.to);
  const conversations = input.conversations.filter((c) => inWindow(c.createdAt));
  const actions = input.actions.filter((a) => inWindow(a.at));
  const approvalTier = actions.filter((a) => a.tier === "require_approval" || a.tier === "execute");
  const count = (status: AiActionRecord["status"]): number => actions.filter((a) => a.status === status).length;
  const approved = approvalTier.filter((a) => a.approvedBy !== null && a.status !== "rejected").length;
  const rejected = count("rejected");
  const byTool = new Map<string, number>();
  const byTier: Partial<Record<AiToolTier, number>> = {};
  for (const a of actions) {
    byTool.set(a.tool, (byTool.get(a.tool) ?? 0) + 1);
    byTier[a.tier] = (byTier[a.tier] ?? 0) + 1;
  }
  return {
    conversations: conversations.length,
    actionsProposed: approvalTier.length,
    actionsApproved: approved,
    actionsCompleted: count("completed"),
    actionsRejected: rejected,
    actionsDenied: count("denied"),
    actionsFailed: count("failed"),
    pendingApprovals: count("pending_approval"),
    approvalRate: approved + rejected > 0 ? Math.round((approved / (approved + rejected)) * 1000) / 1000 : null,
    byTool: [...byTool.entries()].map(([tool, n]) => ({ tool, count: n })).sort((a, b) => b.count - a.count || a.tool.localeCompare(b.tool)),
    byTier,
    activeAnalysts: new Set(conversations.map((c) => c.principalId)).size,
  };
}

export type AiUsageGroupBy = "tenant" | "organization" | "provider" | "model" | "day" | "purpose" | "egress";

export interface AiUsageSummaryRow {
  key: string;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cloudRequests: number;
  localRequests: number;
  fallbackRequests: number;
  estimatedRequests: number;
  avgLatencyMs: number;
}

function keyOf(r: AiUsageRecord, by: AiUsageGroupBy): string {
  switch (by) {
    case "tenant":
      return r.tenantId;
    case "organization":
      return r.organizationId ?? "(tenant)";
    case "provider":
      return r.providerId ?? r.providerKind;
    case "model":
      return `${r.providerKind}:${r.model}`;
    case "day":
      return r.at.slice(0, 10);
    case "purpose":
      return r.purpose;
    case "egress":
      return r.egress;
  }
}

/** Group metered AI usage for billing / MSSP / customer reports. */
export function aggregateAiUsage(records: readonly AiUsageRecord[], by: AiUsageGroupBy): AiUsageSummaryRow[] {
  const rows = new Map<string, AiUsageSummaryRow & { latencyTotal: number }>();
  for (const r of records) {
    const key = keyOf(r, by);
    const row =
      rows.get(key) ??
      { key, requests: 0, inputTokens: 0, outputTokens: 0, totalTokens: 0, cloudRequests: 0, localRequests: 0, fallbackRequests: 0, estimatedRequests: 0, avgLatencyMs: 0, latencyTotal: 0 };
    row.requests += 1;
    row.inputTokens += r.inputTokens;
    row.outputTokens += r.outputTokens;
    row.totalTokens += r.inputTokens + r.outputTokens;
    if (r.egress === "cloud") row.cloudRequests += 1;
    else row.localRequests += 1;
    if (r.fallbackUsed) row.fallbackRequests += 1;
    if (r.estimated) row.estimatedRequests += 1;
    row.latencyTotal += r.latencyMs;
    rows.set(key, row);
  }
  return [...rows.values()]
    .map(({ latencyTotal, ...row }) => ({ ...row, avgLatencyMs: row.requests ? Math.round(latencyTotal / row.requests) : 0 }))
    .sort((a, b) => b.totalTokens - a.totalTokens || a.key.localeCompare(b.key));
}

/** Price per million tokens, keyed by "<providerKind>:<model>" or "<providerKind>:*". Supplied by billing config. */
export type AiPriceTable = Record<string, { inputPerMTok: number; outputPerMTok: number }>;

export function estimateAiCost(records: readonly AiUsageRecord[], prices: AiPriceTable): { total: number; unpriced: number; byModel: Array<{ model: string; cost: number; tokens: number }> } {
  const byModel = new Map<string, { cost: number; tokens: number }>();
  let total = 0;
  let unpriced = 0;
  for (const r of records) {
    const key = `${r.providerKind}:${r.model}`;
    const price = prices[key] ?? prices[`${r.providerKind}:*`] ?? (r.egress === "local" ? { inputPerMTok: 0, outputPerMTok: 0 } : undefined);
    if (!price) {
      unpriced += 1;
      continue;
    }
    const cost = (r.inputTokens * price.inputPerMTok + r.outputTokens * price.outputPerMTok) / 1_000_000;
    total += cost;
    const entry = byModel.get(key) ?? { cost: 0, tokens: 0 };
    entry.cost += cost;
    entry.tokens += r.inputTokens + r.outputTokens;
    byModel.set(key, entry);
  }
  return {
    total: Math.round(total * 1e6) / 1e6,
    unpriced,
    byModel: [...byModel.entries()].map(([model, v]) => ({ model, cost: Math.round(v.cost * 1e6) / 1e6, tokens: v.tokens })).sort((a, b) => b.cost - a.cost),
  };
}
