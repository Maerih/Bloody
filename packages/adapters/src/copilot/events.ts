import { techniquesInText } from "../core/attack.js";
import { defineAdapter, skip, type Adapter, type AdapterExtras, type MapOutput } from "../core/adapter.js";
import { ObservableSet } from "../core/indicators.js";
import { isRecord, str } from "../core/json.js";
import { severityFromWord } from "../core/severity.js";
import { toIso } from "../core/time.js";
import type { EngineClient } from "../http/client.js";
import { runHealthCheck, type HealthCheckResult } from "../http/health.js";
import { CoPilotAlert } from "./schemas.js";

/**
 * CoPilot alert → canonical detection event. Complements the entity sync: alerts pushed by a
 * CoPilot notification/webhook (or read from the alerts API) also land on the SIEM timeline
 * and feed Bloody's own correlation. Entities (orgs, agents, cases) come from the sync plan.
 */
export const COPILOT_EVENT_ADAPTER_VERSION = "1.0.0";

function mapAlert(record: unknown): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const parsed = CoPilotAlert.safeParse(record);
  if (!parsed.success) return skip("not a CoPilot alert");
  const a = parsed.data;
  const obs = new ObservableSet();
  for (const ioc of a.iocs ?? []) {
    const t = ioc.type.toUpperCase();
    if (t === "IP") obs.add("ip", ioc.value);
    else if (t === "DOMAIN") obs.add("domain", ioc.value);
    else if (t === "URL") obs.add("url", ioc.value);
    else if (t === "HASH") obs.addHash(ioc.value);
  }
  const firstAsset = (a.assets ?? [])[0];
  const severity = severityFromWord(a.severity ?? undefined) ?? "high";
  const tags = (a.tags ?? []).map((t) => t.tag);
  return {
    timestamp: toIso(a.alert_creation_time ?? undefined),
    category: "detection",
    eventType: `copilot.alert.${(a.source ?? "unknown").toLowerCase().replace(/[^a-z0-9_]+/g, "_")}`,
    action: a.status.toLowerCase(),
    message: a.alert_name,
    severity,
    asset: firstAsset ? { hostname: str(firstAsset.asset_name), agentId: str(firstAsset.agent_id) } : undefined,
    indicators: obs.toArray(),
    detection: { ruleId: `copilot:${a.source ?? "unknown"}`, ruleName: a.alert_name, engine: "copilot" },
    attack: techniquesInText(tags, a.alert_name),
    labels: {
      severity_basis: a.severity ? `CoPilot severity ${a.severity}` : "no CoPilot severity; CoPilot default High",
      "copilot.alert_id": a.id,
      "copilot.customer_code": a.customer_code,
      "copilot.status": a.status,
      "copilot.assigned_to": a.assigned_to ?? undefined,
      "copilot.verdict": a.verdict ?? undefined,
      "copilot.escalated": a.escalated ?? undefined,
      "copilot.tags": tags.join(",") || undefined,
    },
    dedupKey: `alert:${a.id}`,
    raw: { ...record, comments: undefined },
  };
}

/** Probe a CoPilot API through a token-authenticated EngineClient (`CoPilotClient.http`). */
export function copilotHealthCheck(client: EngineClient): Promise<HealthCheckResult> {
  return runHealthCheck("copilot", async () => {
    const res = await client.get<unknown>("/api/auth/me/customers");
    const codes = isRecord(res.data) && Array.isArray(res.data["customer_codes"]) ? res.data["customer_codes"].length : 0;
    return { status: "healthy", details: { customerCodes: codes } };
  });
}

export function createCoPilotAlertAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    healthCheck: copilotHealthCheck,
    ...extras,
    key: "copilot",
    version: COPILOT_EVENT_ADAPTER_VERSION,
    name: "SOCFortress CoPilot alerts",
    sourceKind: "custom",
    vendor: "SOCFortress",
    consumes: ["CoPilot incident alerts (alerts API / notification webhooks)"],
    map: mapAlert,
  });
}
