import { z } from "zod";

/**
 * Product modules. Customers see these names — never the engine behind them.
 * Each module is a licensable entitlement.
 */
export const MODULES = [
  { key: "command_center", short: "Home", name: "Command Center", group: "core" },
  { key: "edr", short: "EDR", name: "Endpoint Detection & Response", group: "detect" },
  { key: "xdr", short: "XDR", name: "Extended Detection & Response", group: "detect" },
  { key: "itdr", short: "ITDR", name: "Identity Threat Detection & Response", group: "detect" },
  { key: "ndr", short: "NDR", name: "Network Detection & Response", group: "detect" },
  { key: "siem", short: "SIEM", name: "Security Information & Event Management", group: "detect" },
  { key: "asm", short: "ASM", name: "Attack Surface Management", group: "expose" },
  { key: "espm", short: "ESPM", name: "Exposure & Security Posture Management", group: "expose" },
  { key: "ispm", short: "ISPM", name: "Identity Security Posture Management", group: "expose" },
  { key: "cspm", short: "CSPM", name: "Cloud Security Posture Management", group: "expose" },
  { key: "ciem", short: "CIEM", name: "Cloud Infrastructure Entitlement Management", group: "expose" },
  { key: "sspm", short: "SSPM", name: "SaaS Security Posture Management", group: "expose" },
  { key: "vuln", short: "VM", name: "Vulnerability Management", group: "expose" },
  { key: "container", short: "K8S", name: "Container & Kubernetes Security", group: "expose" },
  { key: "cti", short: "CTI", name: "Threat Intelligence", group: "intel" },
  { key: "dfir", short: "DFIR", name: "Digital Forensics & Incident Response", group: "respond" },
  { key: "soar", short: "SOAR", name: "Security Orchestration, Automation & Response", group: "respond" },
  { key: "email", short: "MAIL", name: "Email Security", group: "detect" },
  { key: "deception", short: "DECOY", name: "Deception", group: "detect" },
  { key: "ai_soc", short: "AI", name: "AI SOC Analyst", group: "core" },
] as const;

export type ModuleKey = (typeof MODULES)[number]["key"];
export const ModuleKey = z.enum(MODULES.map((m) => m.key) as [ModuleKey, ...ModuleKey[]]);

export const PlanKey = z.enum(["trial", "essentials", "professional", "enterprise", "mssp"]);
export type PlanKey = z.infer<typeof PlanKey>;

export interface PlanDefinition {
  key: PlanKey;
  name: string;
  modules: ModuleKey[] | "all";
  limits: { endpoints: number; organizations: number; users: number; eventsPerDay: number; retentionDays: number; aiRequestsPerDay: number };
}

export const PLANS: Record<PlanKey, PlanDefinition> = {
  trial: {
    key: "trial",
    name: "Trial",
    modules: ["command_center", "edr", "itdr", "siem", "ai_soc"],
    limits: { endpoints: 25, organizations: 1, users: 5, eventsPerDay: 1_000_000, retentionDays: 14, aiRequestsPerDay: 200 },
  },
  essentials: {
    key: "essentials",
    name: "Essentials",
    modules: ["command_center", "edr", "itdr", "siem", "vuln"],
    limits: { endpoints: 250, organizations: 1, users: 15, eventsPerDay: 10_000_000, retentionDays: 30, aiRequestsPerDay: 500 },
  },
  professional: {
    key: "professional",
    name: "Professional",
    modules: ["command_center", "edr", "xdr", "itdr", "ndr", "siem", "asm", "espm", "ispm", "vuln", "cti", "soar", "ai_soc"],
    limits: { endpoints: 2_500, organizations: 5, users: 50, eventsPerDay: 100_000_000, retentionDays: 90, aiRequestsPerDay: 5_000 },
  },
  enterprise: {
    key: "enterprise",
    name: "Enterprise",
    modules: "all",
    limits: { endpoints: 100_000, organizations: 50, users: 1_000, eventsPerDay: 2_000_000_000, retentionDays: 365, aiRequestsPerDay: 50_000 },
  },
  mssp: {
    key: "mssp",
    name: "MSSP / MDR",
    modules: "all",
    limits: { endpoints: 1_000_000, organizations: 5_000, users: 5_000, eventsPerDay: 20_000_000_000, retentionDays: 365, aiRequestsPerDay: 500_000 },
  },
};

export function planIncludes(plan: PlanKey, module: ModuleKey): boolean {
  const mods = PLANS[plan].modules;
  return mods === "all" || mods.includes(module);
}

export const ModuleState = z.enum(["active", "trial", "trial_ended", "available", "locked"]);
export type ModuleState = z.infer<typeof ModuleState>;

export const Entitlement = z.object({
  module: ModuleKey,
  state: ModuleState,
  trialEndsAt: z.string().datetime({ offset: true }).nullable(),
});
export type Entitlement = z.infer<typeof Entitlement>;
