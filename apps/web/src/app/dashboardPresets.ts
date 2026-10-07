import { DashboardRole, type ReportType, type RoleBinding, type RoleKey } from "@bloody/contracts";

/** Command Center widgets (rendered by pages/command-center/widgets.tsx). */
export const WIDGET_KEYS = [
  "activeIncidents",
  "socActions",
  "escalations",
  "antivirus",
  "agents",
  "firewall",
  "mttr",
  "identityRisk",
  "exposure",
  "vulnerabilities",
  "cloudPosture",
  "networkHealth",
  "intelMatches",
  "attackPaths",
  "recommendations",
  "aiActivity",
  "automation",
  "reportSchedules",
] as const;
export type WidgetKey = (typeof WIDGET_KEYS)[number];

export interface DashboardPreset {
  label: string;
  description: string;
  widgets: WidgetKey[];
  /** Show the right-hand Triage Feed column. */
  showTriage: boolean;
  /** Default report offered in the page's Reports menu. */
  defaultReport: ReportType;
  /** Reports offered to this audience. */
  reports: ReportType[];
}

const SOC_REPORTS: ReportType[] = ["soc_operations", "incident", "vulnerability", "threat_intel", "analyst_activity"];
const BUSINESS_REPORTS: ReportType[] = ["executive", "compliance", "vulnerability", "sla", "customer_monthly"];

export const DASHBOARD_PRESETS: Record<DashboardRole, DashboardPreset> = {
  soc_analyst: {
    label: "SOC analyst",
    description: "Balanced operational view: incidents, SOC pipeline, health and posture.",
    widgets: ["activeIncidents", "socActions", "escalations", "antivirus", "agents", "firewall", "mttr", "intelMatches", "networkHealth", "identityRisk", "attackPaths", "vulnerabilities", "exposure", "cloudPosture", "recommendations", "automation", "aiActivity", "reportSchedules"],
    showTriage: true,
    defaultReport: "soc_operations",
    reports: SOC_REPORTS,
  },
  tier1: {
    label: "Tier 1 analyst",
    description: "Triage first: active incidents, escalations, SOC pipeline and endpoint health.",
    widgets: ["activeIncidents", "escalations", "socActions", "agents", "antivirus", "firewall", "intelMatches", "mttr", "automation", "aiActivity"],
    showTriage: true,
    defaultReport: "soc_operations",
    reports: SOC_REPORTS,
  },
  tier2: {
    label: "Tier 2 analyst",
    description: "Investigation focus: incidents, intel matches, identity and network signals.",
    widgets: ["activeIncidents", "socActions", "escalations", "mttr", "intelMatches", "identityRisk", "networkHealth", "attackPaths", "agents", "antivirus", "firewall", "automation", "aiActivity", "recommendations"],
    showTriage: true,
    defaultReport: "soc_operations",
    reports: SOC_REPORTS,
  },
  tier3_hunter: {
    label: "Tier 3 / threat hunter",
    description: "Hunting focus: intel matches, attack paths, network and identity anomalies.",
    widgets: ["intelMatches", "attackPaths", "networkHealth", "identityRisk", "activeIncidents", "socActions", "vulnerabilities", "cloudPosture", "aiActivity", "recommendations"],
    showTriage: true,
    defaultReport: "threat_intel",
    reports: SOC_REPORTS,
  },
  incident_responder: {
    label: "Incident responder",
    description: "Response focus: active incidents, MTTR, automation and approvals.",
    widgets: ["activeIncidents", "escalations", "mttr", "automation", "attackPaths", "agents", "identityRisk", "aiActivity", "socActions", "firewall", "antivirus"],
    showTriage: true,
    defaultReport: "incident",
    reports: SOC_REPORTS,
  },
  ciso: {
    label: "CISO",
    description: "Risk first: exposure, identity risk, MTTR, attack paths and posture trends.",
    widgets: ["exposure", "identityRisk", "mttr", "attackPaths", "activeIncidents", "vulnerabilities", "cloudPosture", "escalations", "recommendations", "reportSchedules", "socActions", "automation", "aiActivity", "networkHealth"],
    showTriage: true,
    defaultReport: "executive",
    reports: BUSINESS_REPORTS,
  },
  security_engineer: {
    label: "Security engineer",
    description: "Coverage & posture: agents, controls, cloud, vulnerabilities and automation.",
    widgets: ["agents", "antivirus", "firewall", "networkHealth", "cloudPosture", "vulnerabilities", "automation", "recommendations", "socActions", "intelMatches", "activeIncidents"],
    showTriage: true,
    defaultReport: "vulnerability",
    reports: ["vulnerability", "compliance", "soc_operations", "threat_intel"],
  },
  mssp_admin: {
    label: "MSSP administrator",
    description: "Service delivery: incidents, escalations, SLA drivers, automation and reporting.",
    widgets: ["activeIncidents", "escalations", "socActions", "mttr", "agents", "exposure", "automation", "reportSchedules", "aiActivity", "recommendations", "antivirus", "firewall"],
    showTriage: true,
    defaultReport: "mssp_portfolio",
    reports: ["mssp_portfolio", "sla", "analyst_activity", "customer_monthly", "executive", "soc_operations"],
  },
  org_admin: {
    label: "Organization administrator",
    description: "Your organization: incidents, escalations to act on, coverage and posture.",
    widgets: ["activeIncidents", "escalations", "agents", "antivirus", "firewall", "exposure", "identityRisk", "vulnerabilities", "mttr", "recommendations", "reportSchedules", "automation"],
    showTriage: true,
    defaultReport: "customer_monthly",
    reports: ["customer_monthly", "executive", "incident", "vulnerability", "compliance"],
  },
  executive: {
    label: "Executive",
    description: "Business view: exposure, response times, identity risk and attack paths.",
    widgets: ["exposure", "mttr", "identityRisk", "attackPaths", "activeIncidents", "vulnerabilities", "cloudPosture", "escalations", "recommendations", "reportSchedules"],
    showTriage: false,
    defaultReport: "executive",
    reports: BUSINESS_REPORTS,
  },
};

export const DASHBOARD_ROLES = DashboardRole.options;

const ROLE_TO_DASHBOARD: Record<RoleKey, DashboardRole> = {
  platform_admin: "mssp_admin",
  mssp_admin: "mssp_admin",
  org_admin: "org_admin",
  ciso: "ciso",
  executive: "executive",
  soc_analyst_t1: "tier1",
  soc_analyst_t2: "tier2",
  threat_hunter: "tier3_hunter",
  incident_responder: "incident_responder",
  security_engineer: "security_engineer",
  customer_viewer: "executive",
  api_service: "soc_analyst",
};

/** Precedence when a principal holds several roles: most operationally specific first. */
const ROLE_PRECEDENCE: RoleKey[] = [
  "mssp_admin",
  "platform_admin",
  "incident_responder",
  "threat_hunter",
  "soc_analyst_t2",
  "soc_analyst_t1",
  "security_engineer",
  "ciso",
  "org_admin",
  "executive",
  "customer_viewer",
  "api_service",
];

export function defaultDashboardRole(bindings: RoleBinding[]): DashboardRole {
  const held = new Set(bindings.map((b) => b.role));
  for (const role of ROLE_PRECEDENCE) if (held.has(role)) return ROLE_TO_DASHBOARD[role];
  return "soc_analyst";
}
