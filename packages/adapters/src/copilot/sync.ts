import {
  CreateOrganizationInput,
  Criticality,
  RiskFactor,
  SEVERITY_RANK,
  UpsertAssetInput,
  maxSeverity,
  type AgentStatus,
  type AlertStatus,
  type AssetKind,
  type AttackTechnique,
  type IncidentStatus,
  type Severity,
} from "@bloody/contracts";
import type { z } from "zod";
import { mergeTechniques, techniquesInText } from "../core/attack.js";
import { sha256Hex } from "../core/hash.js";
import { ObservableSet, type Observable } from "../core/indicators.js";
import { signal, type AdapterSignal, type SignalAudience } from "../core/signals.js";
import { severityFromWord } from "../core/severity.js";
import { latestIso, parseTimestamp, toIso } from "../core/time.js";
import type { CoPilotClient, CoPilotSnapshot, SnapshotOptions } from "./client.js";
import type { CoPilotAgent, CoPilotAlert, CoPilotCase, CoPilotCustomer } from "./schemas.js";

/**
 * CoPilot → Bloody synchronisation planner.
 *
 * Pure function of a {@link CoPilotSnapshot}: it never writes anywhere. It returns a typed
 * {@link CoPilotSyncPlan} that the control plane persists inside one tenant transaction,
 * upserting every record on `(tenant_id, integration_id, externalRef)`:
 *
 *   customers   → organizations   copilot:customer:<code>   (parent_customer_code → parent)
 *   agents      → assets + agents copilot:asset:<agent_id> / copilot:agent:<agent_id>
 *   alerts      → alerts          copilot:alert:<id>
 *   cases       → incidents       copilot:case:<id>
 *   PENDING_CUSTOMER / escalated → escalations copilot:escalation:<alert|case>:<id>
 *   portal users → customer_viewer role bindings copilot:binding:<user_id>:<code>
 *
 * Tenant isolation: records whose customer is not part of this snapshot's organizations are
 * dropped with a warning — they are never attached to a default or neighbouring
 * organization. Staff accounts (admin/analyst) are never granted roles automatically.
 * Every score carries `RiskFactor[]`; every mapping decision carries an explanation.
 */

export const COPILOT_SYNC_PLAN_VERSION = 1 as const;

export const copilotRef = {
  customer: (code: string): string => `copilot:customer:${code}`,
  asset: (agentId: string): string => `copilot:asset:${agentId}`,
  agent: (agentId: string): string => `copilot:agent:${agentId}`,
  alert: (id: string): string => `copilot:alert:${id}`,
  case: (id: string): string => `copilot:case:${id}`,
  escalation: (kind: "alert" | "case", id: string): string => `copilot:escalation:${kind}:${id}`,
  user: (id: string): string => `copilot:user:${id}`,
  binding: (userId: string, code: string): string => `copilot:binding:${userId}:${code}`,
};

type OrgInput = z.output<typeof CreateOrganizationInput>;
type RiskFactorT = z.infer<typeof RiskFactor>;

export interface OrganizationUpsert {
  externalRef: string;
  /** Map onto an existing Bloody organization instead of creating one (customer-side). */
  organizationId: string | null;
  parentExternalRef: string | null;
  data: Omit<OrgInput, "parentOrganizationId">;
  /** Non-secret contact facts, used for customer report headers and notification routing. */
  contact: { name: string | null; phone: string | null; country: string | null };
  meta: { customerCode: string; customerType: string | null; provisioned: boolean | null };
}

export interface AssetUpsert {
  externalRef: string;
  organizationRef: string;
  data: z.output<typeof UpsertAssetInput>;
  lastSeenAt: string | null;
  explanation: string[];
}

export interface AgentUpsert {
  externalRef: string;
  organizationRef: string;
  assetRef: string;
  data: {
    hostname: string;
    platform: "windows" | "macos" | "linux";
    version: string;
    engine: string;
    status: AgentStatus;
    lastCheckinAt: string | null;
    /** Omitted: CoPilot does not report AV/firewall state — the API keeps existing values. */
    antivirusStatus?: "protected" | "unhealthy" | "unmanaged" | "incompatible";
    firewallEnabled?: boolean;
  };
  statusReason: string;
  engines: { wazuhAgentId: string; velociraptorClientId: string | null; velociraptorLastSeenAt: string | null };
}

export interface AlertUpsert {
  externalRef: string;
  organizationRef: string;
  assetRefs: string[];
  /** Hostnames CoPilot attached to the alert, for assets not known as agents. */
  assetHints: string[];
  incidentRef: string | null;
  data: {
    title: string;
    description: string | null;
    severity: Severity;
    status: z.infer<typeof AlertStatus>;
    ruleId: string | null;
    source: string;
    attack: AttackTechnique[];
    confidence: number;
    riskScore: number;
    firstSeenAt: string;
    lastSeenAt: string;
  };
  riskFactors: RiskFactorT[];
  indicators: Observable[];
  assignee: string | null;
  tags: string[];
  escalated: boolean;
  verdict: "true_positive" | "false_positive" | null;
  upstreamStatus: string;
  explanation: string[];
}

export interface IncidentUpsert {
  externalRef: string;
  organizationRef: string;
  alertRefs: string[];
  assetRefs: string[];
  data: {
    title: string;
    summary: string | null;
    severity: Severity;
    status: IncidentStatus;
    riskScore: number;
    attack: AttackTechnique[];
    detectedAt: string;
    closedAt: string | null;
  };
  riskFactors: RiskFactorT[];
  assignee: string | null;
  escalated: boolean;
  upstreamStatus: string;
  explanation: string[];
}

export interface EscalationUpsert {
  externalRef: string;
  organizationRef: string;
  incidentRef: string | null;
  alertRef: string | null;
  kind: "customer_action" | "soc_escalation";
  data: { title: string; severity: Severity; status: "open" | "acknowledged" | "resolved"; dueAt: string; resolvedAt: string | null };
  reason: string;
}

export interface RoleBindingUpsert {
  externalRef: string;
  organizationRef: string;
  role: "customer_viewer";
  user: { externalRef: string; username: string; email: string | null };
  reason: string;
}

export interface SyncWarning {
  code: string;
  message: string;
  ref?: string;
}

export interface OrganizationSyncSummary {
  organizationRef: string;
  name: string;
  agents: { total: number; protected: number; unresponsive: number; outdated: number; isolated: number; pending: number };
  /** Share of agents reporting healthy (0..1); null when the customer has no agents. */
  coverage: number | null;
  criticalAssets: number;
  openAlerts: number;
  openAlertsBySeverity: Record<Severity, number>;
  openIncidents: number;
  awaitingCustomer: number;
  headline: string;
}

export interface CoPilotSyncReport {
  generatedAt: string;
  headline: string;
  totals: { organizations: number; assets: number; agents: number; alerts: number; incidents: number; escalations: number; roleBindings: number; warnings: number };
  agents: Record<AgentStatus, number>;
  openAlertsBySeverity: Record<Severity, number>;
  perOrganization: OrganizationSyncSummary[];
}

export interface CoPilotSyncPlan {
  planVersion: typeof COPILOT_SYNC_PLAN_VERSION;
  tenantId: string;
  source: { engine: "copilot"; baseUrl: string; portal: "main" | "customer"; fetchedAt: string; integrationId: string | null };
  /** Parents always precede children, so the API can resolve parentOrganizationId in order. */
  organizations: OrganizationUpsert[];
  assets: AssetUpsert[];
  agents: AgentUpsert[];
  alerts: AlertUpsert[];
  incidents: IncidentUpsert[];
  escalations: EscalationUpsert[];
  roleBindings: RoleBindingUpsert[];
  signals: AdapterSignal[];
  warnings: SyncWarning[];
  report: CoPilotSyncReport;
}

export interface CoPilotSyncOptions {
  tenantId: string;
  integrationId?: string;
  /** customer_code → existing Bloody organization id (customer-side or pre-provisioned orgs). */
  organizationOverrides?: Record<string, string>;
  /** Criticality for CoPilot "critical assets". Default "crown_jewel". */
  criticalAssetCriticality?: "crown_jewel" | "high";
  /** Agents "active" in Wazuh but silent for longer than this are unresponsive. Default 24 h. */
  staleAfterHours?: number;
  /** Agents below this Wazuh version are "outdated" (e.g. "4.7.0"). */
  minWazuhVersion?: string;
  /** Severity for alerts CoPilot has no severity for. Default "high" (CoPilot's own default). */
  defaultAlertSeverity?: Severity;
  /** Hours until an escalation is due, per severity. */
  escalationSlaHours?: Partial<Record<Severity, number>>;
  retentionDays?: number;
}

const DEFAULT_SLA_HOURS: Record<Severity, number> = { critical: 4, high: 24, medium: 72, low: 168, info: 336 };
const SEVERITY_BASE: Record<Severity, number> = { critical: 85, high: 65, medium: 45, low: 25, info: 10 };
const SLUG_RE = /^[a-z0-9-]{2,63}$/;

function emptySeverity(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

/** Deterministic, contract-valid organization slug from a CoPilot customer code. */
export function slugFromCustomerCode(code: string, taken: Set<string> = new Set()): string {
  let base = code
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (base.length < 2) base = `${base || "c"}-cust`;
  base = base.slice(0, 63).replace(/-+$/, "");
  let slug = base;
  if (taken.has(slug) || !SLUG_RE.test(slug)) slug = `${base.slice(0, 56).replace(/-+$/, "")}-${sha256Hex(code).slice(0, 6)}`;
  taken.add(slug);
  return slug;
}

function parseVersion(v: string | null | undefined): number[] | null {
  const m = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(v ?? "");
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? "0")] : null;
}

export function versionBelow(v: string | null | undefined, min: string): boolean {
  const a = parseVersion(v);
  const b = parseVersion(min);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) < (b[i] ?? 0)) return true;
    if ((a[i] ?? 0) > (b[i] ?? 0)) return false;
  }
  return false;
}

export function mapAgentStatus(a: CoPilotAgent, now: Date, opts: Pick<CoPilotSyncOptions, "staleAfterHours" | "minWazuhVersion">): { status: AgentStatus; reason: string } {
  if (a.quarantined) return { status: "isolated", reason: "agent is quarantined in CoPilot" };
  const s = (a.wazuh_agent_status ?? "").trim().toLowerCase();
  const last = parseTimestamp(a.wazuh_last_seen ?? undefined);
  const staleH = opts.staleAfterHours ?? 24;
  if (s === "active") {
    if (last && now.getTime() - last.getTime() > staleH * 3_600_000) {
      return { status: "unresponsive", reason: `Wazuh reports active but last check-in was ${Math.round((now.getTime() - last.getTime()) / 3_600_000)} h ago (threshold ${staleH} h)` };
    }
    if (opts.minWazuhVersion && versionBelow(a.wazuh_agent_version, opts.minWazuhVersion)) {
      return { status: "outdated", reason: `Wazuh agent ${a.wazuh_agent_version ?? "?"} is below the required ${opts.minWazuhVersion}` };
    }
    return { status: "protected", reason: "Wazuh agent active" };
  }
  if (s === "disconnected") return { status: "unresponsive", reason: "Wazuh agent disconnected" };
  if (s === "never_connected" || s === "pending") return { status: "pending", reason: `Wazuh agent ${s.replace("_", " ")}` };
  return { status: "unresponsive", reason: s ? `Wazuh agent status "${s}"` : "Wazuh agent status unknown to CoPilot" };
}

function platformOf(os: string | null | undefined): { platform: "windows" | "macos" | "linux"; known: boolean } {
  const o = (os ?? "").toLowerCase();
  if (o.includes("windows")) return { platform: "windows", known: true };
  if (/mac|darwin|os x/.test(o)) return { platform: "macos", known: true };
  if (/linux|ubuntu|debian|centos|rhel|red hat|fedora|suse|alma|rocky|amazon|oracle|arch|alpine|bsd/.test(o)) return { platform: "linux", known: true };
  return { platform: "linux", known: false };
}

function assetKindOf(a: CoPilotAgent, platform: "windows" | "macos" | "linux"): { kind: AssetKind; why: string } {
  const hint = `${a.label ?? ""} ${a.hostname ?? ""}`.toLowerCase();
  if (/domain.?controller|\bdc\d*\b|-dc\d*\b/.test(hint)) return { kind: "domain_controller", why: "label/hostname indicates a domain controller" };
  if ((a.os ?? "").toLowerCase().includes("server")) return { kind: "server", why: "server operating system" };
  if (platform === "linux") return { kind: "server", why: "Linux host (treated as server)" };
  return { kind: "endpoint", why: `${platform} workstation` };
}

function alertSeverity(a: CoPilotAlert, fallback: Severity): { severity: Severity; why: string } {
  const s = severityFromWord(a.severity ?? undefined);
  if (s) return { severity: s, why: `CoPilot severity ${a.severity}` };
  return { severity: fallback, why: `no CoPilot severity; default ${fallback} for unmapped sources` };
}

function factor(key: string, label: string, value: number, weight: number, contribution: number, explanation: string): RiskFactorT {
  return { key, label, value: Math.max(0, Math.min(1, value)), weight, contribution: Math.round(contribution * 10) / 10, explanation };
}

function clampScore(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function iocObservables(a: CoPilotAlert): Observable[] {
  const set = new ObservableSet();
  for (const ioc of a.iocs ?? []) {
    const t = ioc.type.toUpperCase();
    if (t === "IP") set.add("ip", ioc.value);
    else if (t === "DOMAIN") set.add("domain", ioc.value);
    else if (t === "URL") set.add("url", ioc.value);
    else if (t === "HASH") set.addHash(ioc.value);
  }
  return set.toArray();
}

const isOpenAlert = (s: z.infer<typeof AlertStatus>): boolean => s === "new" || s === "triaged";
const OPEN_INCIDENT: IncidentStatus[] = ["new", "triage", "investigating", "contained"];

/** Build the sync plan. Pure and deterministic for a given snapshot + options + clock. */
export function planCoPilotSync(snapshot: CoPilotSnapshot, options: CoPilotSyncOptions): CoPilotSyncPlan {
  const now = new Date(snapshot.fetchedAt);
  const warnings: SyncWarning[] = snapshot.warnings.map((m) => ({ code: "snapshot", message: m }));
  const signals: AdapterSignal[] = [];
  const push = (s: AdapterSignal | undefined): void => {
    if (s) signals.push(s);
  };
  const sla = { ...DEFAULT_SLA_HOURS, ...options.escalationSlaHours };

  // ── Organizations (parents first, cycles broken) ──────────────────────────
  const byCode = new Map<string, CoPilotCustomer>();
  for (const c of snapshot.customers) {
    if (byCode.has(c.customer_code)) warnings.push({ code: "duplicate_customer", message: `duplicate customer code ${c.customer_code}`, ref: copilotRef.customer(c.customer_code) });
    else byCode.set(c.customer_code, c);
  }
  const ordered: CoPilotCustomer[] = [];
  const state = new Map<string, "visiting" | "done">();
  const parentOf = new Map<string, string | null>();
  const visit = (c: CoPilotCustomer): void => {
    const st = state.get(c.customer_code);
    if (st === "done") return;
    if (st === "visiting") return;
    state.set(c.customer_code, "visiting");
    let parent = c.parent_customer_code ?? null;
    if (parent && parent === c.customer_code) parent = null;
    if (parent && !byCode.has(parent)) {
      warnings.push({ code: "missing_parent", message: `customer ${c.customer_code}: parent ${parent} not visible to this integration; imported as top-level`, ref: copilotRef.customer(c.customer_code) });
      parent = null;
    }
    if (parent) {
      const p = byCode.get(parent)!;
      if (state.get(parent) === "visiting") {
        warnings.push({ code: "parent_cycle", message: `customer hierarchy cycle at ${c.customer_code}; parent link dropped`, ref: copilotRef.customer(c.customer_code) });
        parent = null;
      } else visit(p);
    }
    parentOf.set(c.customer_code, parent);
    state.set(c.customer_code, "done");
    ordered.push(c);
  };
  for (const c of [...byCode.values()].sort((a, b) => a.customer_code.localeCompare(b.customer_code))) visit(c);

  const taken = new Set<string>();
  const organizations: OrganizationUpsert[] = [];
  for (const c of ordered) {
    const name = (c.customer_name ?? c.customer_code).trim().slice(0, 200) || c.customer_code;
    const data = CreateOrganizationInput.parse({ name, slug: slugFromCustomerCode(c.customer_code, taken), retentionDays: options.retentionDays ?? 90 });
    const parent = parentOf.get(c.customer_code) ?? null;
    const contactName = [c.contact_first_name, c.contact_last_name].filter((x): x is string => typeof x === "string" && x.trim() !== "").join(" ");
    organizations.push({
      externalRef: copilotRef.customer(c.customer_code),
      organizationId: options.organizationOverrides?.[c.customer_code] ?? null,
      parentExternalRef: parent ? copilotRef.customer(parent) : null,
      data: { name: data.name, slug: data.slug, retentionDays: data.retentionDays },
      contact: { name: contactName || null, phone: c.phone ?? null, country: c.country ?? null },
      meta: { customerCode: c.customer_code, customerType: c.customer_type ?? null, provisioned: c.is_provisioned ?? null },
    });
  }
  const orgRefs = new Set(organizations.map((o) => o.externalRef));
  const orgName = new Map(organizations.map((o) => [o.externalRef, o.data.name]));
  const orgFor = (code: string | null | undefined, what: string, ref: string): string | null => {
    if (!code) {
      warnings.push({ code: "missing_customer", message: `${what} has no customer_code; skipped`, ref });
      return null;
    }
    const r = copilotRef.customer(code);
    if (!orgRefs.has(r)) {
      warnings.push({ code: "unknown_customer", message: `${what} belongs to customer ${code}, which is outside this integration's scope; skipped`, ref });
      return null;
    }
    return r;
  };

  // ── Agents → assets + agents ───────────────────────────────────────────────
  const assets: AssetUpsert[] = [];
  const agents: AgentUpsert[] = [];
  const agentById = new Map<string, { orgRef: string; critical: boolean; hostname: string }>();
  const agentByHost = new Map<string, string>();
  for (const a of snapshot.agents) {
    const ref = copilotRef.agent(a.agent_id);
    if (agentById.has(a.agent_id)) {
      warnings.push({ code: "duplicate_agent", message: `duplicate agent id ${a.agent_id}`, ref });
      continue;
    }
    const orgRef = orgFor(a.customer_code, `agent ${a.agent_id}`, ref);
    if (!orgRef) continue;
    const hostname = (a.hostname ?? "").trim() || `agent-${a.agent_id}`;
    const { platform, known } = platformOf(a.os);
    if (!known) warnings.push({ code: "unknown_platform", message: `agent ${a.agent_id} (${hostname}): OS "${a.os ?? ""}" not recognised; platform recorded as linux`, ref });
    const kind = assetKindOf(a, platform);
    const critical = a.critical_asset === true;
    const criticality: z.infer<typeof Criticality> = critical ? options.criticalAssetCriticality ?? "crown_jewel" : "medium";
    const lastSeen = latestIso(a.wazuh_last_seen, a.velociraptor_last_seen) ?? null;
    const ip = a.ip_address && a.ip_address !== "any" ? [a.ip_address] : [];
    const assetData = UpsertAssetInput.parse({
      kind: kind.kind,
      name: hostname,
      hostname,
      ipAddresses: ip,
      os: a.os ?? null,
      criticality,
      internetFacing: false,
      tags: ["copilot", `copilot-customer:${a.customer_code}`, ...(a.label ? [`label:${a.label}`] : []), ...(a.velociraptor_id ? ["velociraptor"] : [])],
    });
    const assetRef = copilotRef.asset(a.agent_id);
    assets.push({
      externalRef: assetRef,
      organizationRef: orgRef,
      data: assetData,
      lastSeenAt: lastSeen,
      explanation: [
        `kind ${kind.kind}: ${kind.why}`,
        critical ? `criticality ${criticality}: CoPilot marks this agent as a critical asset` : "criticality medium: default (not marked critical in CoPilot)",
      ],
    });
    const status = mapAgentStatus(a, now, options);
    agents.push({
      externalRef: ref,
      organizationRef: orgRef,
      assetRef,
      data: {
        hostname,
        platform,
        version: a.wazuh_agent_version ?? "unknown",
        engine: a.velociraptor_id ? "wazuh+velociraptor" : "wazuh",
        status: status.status,
        lastCheckinAt: toIso(a.wazuh_last_seen ?? undefined) ?? null,
      },
      statusReason: status.reason,
      engines: { wazuhAgentId: a.agent_id, velociraptorClientId: a.velociraptor_id ?? null, velociraptorLastSeenAt: toIso(a.velociraptor_last_seen ?? undefined) ?? null },
    });
    agentById.set(a.agent_id, { orgRef, critical, hostname });
    agentByHost.set(`${orgRef}|${hostname.toLowerCase()}`, a.agent_id);
    if (status.status === "unresponsive" || status.status === "isolated") {
      const audience: SignalAudience[] = critical ? ["soc", "customer", "mssp"] : ["soc", "customer"];
      push(
        signal({
          event: "agent.unresponsive",
          severity: critical ? "high" : "medium",
          at: snapshot.fetchedAt,
          dedupKey: `copilot-agent-status:${a.agent_id}:${status.status}`,
          emit: "on_change",
          organizationRef: orgRef,
          subject: { kind: "agent", ref, label: hostname },
          title: status.status === "isolated" ? `${hostname} is isolated` : `${hostname} stopped reporting`,
          summary: `${orgName.get(orgRef) ?? ""}: ${status.reason}.${critical ? " This host is marked as a critical asset." : ""}`.trim(),
          facts: { hostname, status: status.status, reason: status.reason, critical, lastSeen: lastSeen ?? "never", customerCode: a.customer_code ?? "" },
          audience,
        }),
      );
    }
  }

  // ── Alerts ──────────────────────────────────────────────────────────────────
  const alerts: AlertUpsert[] = [];
  const alertByRef = new Map<string, AlertUpsert>();
  const fallbackSeverity = options.defaultAlertSeverity ?? "high";
  const casesFromAlerts = new Map<string, Set<string>>();
  for (const a of snapshot.alerts) {
    const ref = copilotRef.alert(a.id);
    const orgRef = orgFor(a.customer_code, `alert ${a.id}`, ref);
    if (!orgRef || alertByRef.has(ref)) continue;
    const sev = alertSeverity(a, fallbackSeverity);
    const verdict = a.verdict === "TRUE_POSITIVE" ? "true_positive" : a.verdict === "FALSE_POSITIVE" ? "false_positive" : null;
    const upstream = a.status.toUpperCase();
    const linked = (a.linked_cases ?? []).map((c) => c.id);
    let status: z.infer<typeof AlertStatus>;
    let statusWhy: string;
    if (verdict === "false_positive") [status, statusWhy] = ["false_positive", "analyst verdict FALSE_POSITIVE"];
    else if (linked.length > 0) [status, statusWhy] = ["promoted", `linked to case ${linked.join(", ")}`];
    else if (upstream === "OPEN") [status, statusWhy] = a.assigned_to ? ["triaged", "open and assigned"] : ["new", "open and unassigned"];
    else if (upstream === "CLOSED") [status, statusWhy] = ["triaged", "closed in CoPilot without a false-positive verdict"];
    else [status, statusWhy] = ["triaged", `CoPilot status ${upstream}`];

    const assetRefs: string[] = [];
    const assetHints: string[] = [];
    let critical = false;
    for (const asset of a.assets ?? []) {
      const agentId: string | undefined = asset.agent_id ?? (asset.asset_name ? agentByHost.get(`${orgRef}|${asset.asset_name.toLowerCase()}`) : undefined);
      const known: { orgRef: string; critical: boolean; hostname: string } | undefined = agentId ? agentById.get(agentId) : undefined;
      if (known && known.orgRef === orgRef) {
        assetRefs.push(copilotRef.asset(agentId as string));
        critical ||= known.critical;
      } else if (asset.asset_name) assetHints.push(asset.asset_name);
    }
    const tags = (a.tags ?? []).map((t) => t.tag);
    const attack = techniquesInText(tags, a.alert_name);
    const factors: RiskFactorT[] = [factor("severity", "Alert severity", SEVERITY_RANK[sev.severity] / 4, 1, SEVERITY_BASE[sev.severity], `${sev.why} → base ${SEVERITY_BASE[sev.severity]}`)];
    if (a.escalated) factors.push(factor("escalated", "Escalated by the SOC", 1, 10, 10, "alert escalated in CoPilot"));
    if (critical) factors.push(factor("critical_asset", "Critical asset involved", 1, 10, 10, "an affected agent is a CoPilot critical asset"));
    if (verdict === "true_positive") factors.push(factor("verdict", "Confirmed true positive", 1, 5, 5, "analyst verdict TRUE_POSITIVE"));
    if (verdict === "false_positive") factors.push(factor("verdict", "False positive", 1, -100, -100, "analyst verdict FALSE_POSITIVE"));
    const riskScore = clampScore(factors.reduce((s, f) => s + f.contribution, 0));
    const created = toIso(a.alert_creation_time ?? undefined) ?? snapshot.fetchedAt;
    const lastSeen = latestIso(created, a.time_closed, a.verdict_at, ...(a.comments ?? []).map((c) => c.created_at)) ?? created;
    const upsert: AlertUpsert = {
      externalRef: ref,
      organizationRef: orgRef,
      assetRefs: [...new Set(assetRefs)],
      assetHints: [...new Set(assetHints)],
      incidentRef: linked[0] ? copilotRef.case(linked[0]) : null,
      data: {
        title: a.alert_name.slice(0, 500),
        description: a.alert_description ?? null,
        severity: sev.severity,
        status,
        ruleId: null,
        source: `copilot:${(a.source ?? "unknown").toLowerCase()}`,
        attack,
        confidence: verdict === "true_positive" ? 0.95 : verdict === "false_positive" ? 0.05 : 0.6,
        riskScore,
        firstSeenAt: created,
        lastSeenAt: lastSeen,
      },
      riskFactors: factors,
      indicators: iocObservables(a),
      assignee: a.assigned_to ?? null,
      tags,
      escalated: a.escalated === true,
      verdict,
      upstreamStatus: upstream,
      explanation: [`status ${status}: ${statusWhy}`, `severity ${sev.severity}: ${sev.why}`],
    };
    alerts.push(upsert);
    alertByRef.set(ref, upsert);
    for (const caseId of linked) {
      const set = casesFromAlerts.get(caseId) ?? new Set<string>();
      set.add(ref);
      casesFromAlerts.set(caseId, set);
    }
  }

  // ── Cases → incidents ───────────────────────────────────────────────────────
  const incidents: IncidentUpsert[] = [];
  const escalations: EscalationUpsert[] = [];
  const seenCases = new Set<string>();
  for (const c of snapshot.cases) {
    const ref = copilotRef.case(c.id);
    if (seenCases.has(ref)) continue;
    seenCases.add(ref);
    const orgRef = orgFor(c.customer_code, `case ${c.id}`, ref);
    if (!orgRef) continue;
    const alertRefs = [...new Set([...(c.alerts ?? []).map((a) => copilotRef.alert(a.id)), ...(casesFromAlerts.get(c.id) ?? [])])];
    const linkedAlerts = alertRefs.map((r) => alertByRef.get(r)).filter((x): x is AlertUpsert => x !== undefined);
    // Alerts embedded in the case but absent from the alert listing still inform severity.
    const embedded = (c.alerts ?? []).filter((a) => !alertByRef.has(copilotRef.alert(a.id)));
    let severity: Severity;
    let sevWhy: string;
    const caseSev = severityFromWord(c.severity ?? undefined);
    if (caseSev) [severity, sevWhy] = [caseSev, `case severity ${c.severity}`];
    else if (linkedAlerts.length + embedded.length > 0) {
      severity = [...linkedAlerts.map((a) => a.data.severity), ...embedded.map((a) => alertSeverity(a, fallbackSeverity).severity)].reduce((m, s) => maxSeverity(m, s), "info" as Severity);
      sevWhy = "highest severity among linked alerts";
    } else [severity, sevWhy] = ["medium", "no case or alert severity available; default medium"];

    const upstream = (c.case_status ?? "OPEN").toUpperCase();
    const allFalsePositive = linkedAlerts.length > 0 && linkedAlerts.every((a) => a.verdict === "false_positive");
    let status: IncidentStatus;
    if (upstream === "CLOSED") status = allFalsePositive ? "false_positive" : "closed";
    else if (upstream === "IN_PROGRESS" || upstream === "PENDING_CUSTOMER") status = "investigating";
    else status = c.assigned_to ? "triage" : "new";

    const assetRefs = [...new Set(linkedAlerts.flatMap((a) => a.assetRefs))];
    const attack = mergeTechniques(...linkedAlerts.map((a) => a.data.attack));
    const maxAlertRisk = linkedAlerts.reduce((m, a) => Math.max(m, a.data.riskScore), 0);
    const factors: RiskFactorT[] = [factor("severity", "Incident severity", SEVERITY_RANK[severity] / 4, 1, SEVERITY_BASE[severity], `${sevWhy} → base ${SEVERITY_BASE[severity]}`)];
    if (maxAlertRisk > SEVERITY_BASE[severity]) factors.push(factor("alert_risk", "Riskiest linked alert", maxAlertRisk / 100, 1, maxAlertRisk - SEVERITY_BASE[severity], `a linked alert scores ${maxAlertRisk}`));
    if (linkedAlerts.length > 1) {
      const breadth = Math.min(10, Math.round(Math.log2(linkedAlerts.length) * 4));
      factors.push(factor("alert_count", "Correlated alerts", Math.min(1, linkedAlerts.length / 10), 10, breadth, `${linkedAlerts.length} alerts linked to the case`));
    }
    if (c.escalated) factors.push(factor("escalated", "Escalated by the SOC", 1, 5, 5, "case escalated in CoPilot"));
    if (status === "false_positive") factors.push(factor("verdict", "All alerts false positive", 1, -100, -100, "every linked alert carries a FALSE_POSITIVE verdict"));
    const riskScore = clampScore(factors.reduce((s, f) => s + f.contribution, 0));
    const detectedAt = toIso(c.case_creation_time ?? undefined) ?? linkedAlerts.map((a) => a.data.firstSeenAt).sort()[0] ?? snapshot.fetchedAt;
    let closedAt: string | null = null;
    const explanation = [`status ${status}: CoPilot case status ${upstream}`, `severity ${severity}: ${sevWhy}`];
    if (status === "closed" || status === "false_positive") {
      closedAt = latestIso(...(c.alerts ?? []).map((a) => a.time_closed), ...linkedAlerts.map((a) => a.data.lastSeenAt)) ?? snapshot.fetchedAt;
      explanation.push("closedAt: CoPilot does not expose case closure time; latest linked-alert closure (or sync time) used");
    }
    incidents.push({
      externalRef: ref,
      organizationRef: orgRef,
      alertRefs,
      assetRefs,
      data: {
        title: c.case_name.slice(0, 300).padEnd(3, "."),
        summary: c.case_description ?? null,
        severity,
        status,
        riskScore,
        attack,
        detectedAt,
        closedAt,
      },
      riskFactors: factors,
      assignee: c.assigned_to ?? null,
      escalated: c.escalated === true,
      upstreamStatus: upstream,
      explanation,
    });
    if (OPEN_INCIDENT.includes(status)) {
      const notifyCustomer = SEVERITY_RANK[severity] >= SEVERITY_RANK.high;
      push(
        signal({
          event: "incident.created",
          severity,
          at: detectedAt,
          dedupKey: `copilot-case:${c.id}`,
          emit: "on_create",
          organizationRef: orgRef,
          subject: { kind: "incident", ref, label: c.case_name },
          title: `[${severity.toUpperCase()}] ${c.case_name}`,
          summary: `${orgName.get(orgRef) ?? ""} — ${c.case_description ?? c.case_name}\n${linkedAlerts.length} linked alert(s); risk ${riskScore}/100.`.trim(),
          facts: { severity, riskScore, alerts: linkedAlerts.length, assignee: c.assigned_to ?? "unassigned", customerCode: c.customer_code ?? "" },
          audience: notifyCustomer ? ["soc", "customer"] : ["soc"],
        }),
      );
    }
    if (upstream === "PENDING_CUSTOMER" || (c.escalated && OPEN_INCIDENT.includes(status))) {
      escalations.push(escalationFor("case", c.id, orgRef, ref, null, c.case_name, severity, upstream, detectedAt, sla, closedAt));
    }
  }

  // Escalations for alerts awaiting the customer / escalated and not already covered by a case
  for (const a of alerts) {
    if (a.incidentRef && seenCases.has(a.incidentRef)) continue;
    const pending = a.upstreamStatus === "PENDING_CUSTOMER";
    if (!pending && !(a.escalated && isOpenAlert(a.data.status))) continue;
    const id = a.externalRef.slice("copilot:alert:".length);
    escalations.push(escalationFor("alert", id, a.organizationRef, null, a.externalRef, a.data.title, a.data.severity, a.upstreamStatus, a.data.firstSeenAt, sla, a.upstreamStatus === "CLOSED" ? a.data.lastSeenAt : null));
  }
  for (const e of escalations) {
    if (e.data.status !== "open") continue;
    push(
      signal({
        event: "escalation.created",
        severity: e.data.severity,
        at: snapshot.fetchedAt,
        dedupKey: e.externalRef,
        emit: "on_create",
        organizationRef: e.organizationRef,
        subject: { kind: "escalation", ref: e.externalRef, label: e.data.title },
        title: e.kind === "customer_action" ? `Action required: ${e.data.title}` : `Escalated: ${e.data.title}`,
        summary: `${e.reason}. Due ${e.data.dueAt.slice(0, 16).replace("T", " ")} UTC.`,
        facts: { kind: e.kind, severity: e.data.severity, dueAt: e.data.dueAt, organization: orgName.get(e.organizationRef) ?? "" },
        audience: e.kind === "customer_action" ? ["customer", "soc"] : ["soc", "mssp"],
      }),
    );
  }

  // ── Customer-portal users → customer_viewer bindings ──────────────────────
  const roleBindings: RoleBindingUpsert[] = [];
  let staffSkipped = 0;
  for (const u of snapshot.users) {
    const isCustomerUser = u.role_id === 4 || (u.role_name ?? "").toLowerCase() === "customer_user";
    if (!isCustomerUser) {
      staffSkipped++;
      continue;
    }
    if (u.customerCodes.includes("*")) {
      warnings.push({ code: "wildcard_customer_user", message: `portal user ${u.username} has deployment-wide access in CoPilot; no binding created (customer roles are never tenant-wide)`, ref: copilotRef.user(u.id) });
      continue;
    }
    for (const code of u.customerCodes) {
      const orgRef = copilotRef.customer(code);
      if (!orgRefs.has(orgRef)) {
        warnings.push({ code: "unknown_customer", message: `portal user ${u.username} references customer ${code} outside this integration's scope`, ref: copilotRef.user(u.id) });
        continue;
      }
      roleBindings.push({
        externalRef: copilotRef.binding(u.id, code),
        organizationRef: orgRef,
        role: "customer_viewer",
        user: { externalRef: copilotRef.user(u.id), username: u.username, email: u.email ?? null },
        reason: `CoPilot customer-portal user with access to ${code}`,
      });
    }
  }
  if (staffSkipped > 0) warnings.push({ code: "staff_users_not_mapped", message: `${staffSkipped} CoPilot staff account(s) not mapped: Bloody roles for analysts/admins are granted in Bloody only` });

  const report = buildReport(snapshot.fetchedAt, organizations, assets, agents, alerts, incidents, escalations, roleBindings, warnings.length);
  return {
    planVersion: COPILOT_SYNC_PLAN_VERSION,
    tenantId: options.tenantId,
    source: { engine: "copilot", baseUrl: snapshot.baseUrl, portal: snapshot.portal, fetchedAt: snapshot.fetchedAt, integrationId: options.integrationId ?? null },
    organizations,
    assets,
    agents,
    alerts,
    incidents,
    escalations,
    roleBindings,
    signals,
    warnings,
    report,
  };
}

function escalationFor(
  kind: "alert" | "case",
  id: string,
  orgRef: string,
  incidentRef: string | null,
  alertRef: string | null,
  title: string,
  severity: Severity,
  upstream: string,
  since: string,
  sla: Record<Severity, number>,
  closedAt: string | null,
): EscalationUpsert {
  const pending = upstream === "PENDING_CUSTOMER";
  const due = new Date(new Date(since).getTime() + sla[severity] * 3_600_000).toISOString();
  const resolved = upstream === "CLOSED";
  return {
    externalRef: copilotRef.escalation(kind, id),
    organizationRef: orgRef,
    incidentRef,
    alertRef,
    kind: pending ? "customer_action" : "soc_escalation",
    data: { title: title.slice(0, 300), severity, status: resolved ? "resolved" : "open", dueAt: due, resolvedAt: resolved ? closedAt ?? since : null },
    reason: pending ? `The SOC is waiting on the customer for this ${kind} (CoPilot PENDING_CUSTOMER)` : `The ${kind} was escalated in CoPilot`,
  };
}

function buildReport(
  generatedAt: string,
  organizations: OrganizationUpsert[],
  assets: AssetUpsert[],
  agents: AgentUpsert[],
  alerts: AlertUpsert[],
  incidents: IncidentUpsert[],
  escalations: EscalationUpsert[],
  roleBindings: RoleBindingUpsert[],
  warnings: number,
): CoPilotSyncReport {
  const agentTotals: Record<AgentStatus, number> = { protected: 0, unresponsive: 0, outdated: 0, isolated: 0, pending: 0 };
  for (const a of agents) agentTotals[a.data.status]++;
  const openBySev = emptySeverity();
  for (const a of alerts) if (isOpenAlert(a.data.status)) openBySev[a.data.severity]++;
  const perOrganization: OrganizationSyncSummary[] = organizations.map((o) => {
    const ag = agents.filter((a) => a.organizationRef === o.externalRef);
    const counts = { total: ag.length, protected: 0, unresponsive: 0, outdated: 0, isolated: 0, pending: 0 };
    for (const a of ag) counts[a.data.status]++;
    const sev = emptySeverity();
    const open = alerts.filter((a) => a.organizationRef === o.externalRef && isOpenAlert(a.data.status));
    for (const a of open) sev[a.data.severity]++;
    const openIncidents = incidents.filter((i) => i.organizationRef === o.externalRef && OPEN_INCIDENT.includes(i.data.status)).length;
    const awaiting = escalations.filter((e) => e.organizationRef === o.externalRef && e.kind === "customer_action" && e.data.status === "open").length;
    const critical = assets.filter((a) => a.organizationRef === o.externalRef && (a.data.criticality === "crown_jewel" || a.data.criticality === "high")).length;
    const coverage = counts.total > 0 ? Math.round((counts.protected / counts.total) * 1000) / 1000 : null;
    const parts = [
      `${counts.total} agent${counts.total === 1 ? "" : "s"}${coverage !== null ? ` (${Math.round(coverage * 100)}% healthy)` : ""}`,
      `${open.length} open alert${open.length === 1 ? "" : "s"}${sev.critical + sev.high > 0 ? ` (${sev.critical + sev.high} high/critical)` : ""}`,
      `${openIncidents} open incident${openIncidents === 1 ? "" : "s"}`,
    ];
    if (awaiting > 0) parts.push(`${awaiting} awaiting customer action`);
    return {
      organizationRef: o.externalRef,
      name: o.data.name,
      agents: counts,
      coverage,
      criticalAssets: critical,
      openAlerts: open.length,
      openAlertsBySeverity: sev,
      openIncidents,
      awaitingCustomer: awaiting,
      headline: `${o.data.name}: ${parts.join(", ")}`,
    };
  });
  const openAlerts = alerts.filter((a) => isOpenAlert(a.data.status)).length;
  const openIncidents = incidents.filter((i) => OPEN_INCIDENT.includes(i.data.status)).length;
  return {
    generatedAt,
    headline: `CoPilot sync: ${organizations.length} customers, ${agents.length} agents (${agentTotals.unresponsive + agentTotals.isolated} need attention), ${openAlerts} open alerts, ${openIncidents} open incidents`,
    totals: {
      organizations: organizations.length,
      assets: assets.length,
      agents: agents.length,
      alerts: alerts.length,
      incidents: incidents.length,
      escalations: escalations.length,
      roleBindings: roleBindings.length,
      warnings,
    },
    agents: agentTotals,
    openAlertsBySeverity: openBySev,
    perOrganization,
  };
}

/**
 * Orchestrates a sync run: snapshot (reads only) → plan. Persisting the plan is the API's
 * job (single tenant transaction, audit entry `integration.sync` with `plan.report`).
 */
export class CoPilotSync {
  constructor(
    private readonly client: CoPilotClient,
    private readonly options: CoPilotSyncOptions & { snapshot?: SnapshotOptions },
  ) {}

  async run(): Promise<{ snapshot: CoPilotSnapshot; plan: CoPilotSyncPlan }> {
    const snapshot = await this.client.snapshot(this.options.snapshot ?? {});
    return { snapshot, plan: planCoPilotSync(snapshot, this.options) };
  }
}
