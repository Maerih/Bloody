import type { Alert } from "@bloody/contracts";

/**
 * Security domain of an alert for cross-domain (XDR) correlation, derived from the producing
 * source and the entities it involves. The rule is explainable and shown in the UI.
 */
export const DOMAINS = ["endpoint", "network", "identity", "cloud", "email", "deception", "vulnerability"] as const;
export type SecurityDomain = (typeof DOMAINS)[number];

export const DOMAIN_LABELS: Record<SecurityDomain, string> = {
  endpoint: "Endpoint",
  network: "Network",
  identity: "Identity",
  cloud: "Cloud",
  email: "Email",
  deception: "Deception",
  vulnerability: "Exposure",
};

const SOURCE_DOMAINS: [RegExp, SecurityDomain][] = [
  [/opencanary|canary|honeypot|decoy/i, "deception"],
  [/zeek|suricata|arkime|ndr|network|firewall/i, "network"],
  [/keycloak|entra|azure[\s_-]?ad|okta|ldap|idp|identity|google[\s_-]?workspace/i, "identity"],
  [/cloudtrail|aws|azure|gcp|falco|kubernetes|k8s|trivy|cspm/i, "cloud"],
  [/mail|smtp|phish|exchange/i, "email"],
  [/greenbone|openvas|nuclei|vuln/i, "vulnerability"],
  [/wazuh|osquery|velociraptor|sysmon|edr|endpoint|yara|defender/i, "endpoint"],
];

export function alertDomain(alert: Pick<Alert, "source" | "assetId" | "identityId" | "ruleId">): SecurityDomain {
  const hay = `${alert.source} ${alert.ruleId ?? ""}`;
  for (const [re, domain] of SOURCE_DOMAINS) if (re.test(hay)) return domain;
  if (alert.identityId && !alert.assetId) return "identity";
  return "endpoint";
}

export interface CorrelationGroup {
  incidentId: string;
  alerts: Alert[];
  domains: SecurityDomain[];
  sources: string[];
  techniques: string[];
  firstSeenAt: string;
  lastSeenAt: string;
}

/** Group alerts by incident with the domains, sources and ATT&CK techniques they span. */
export function correlationGroups(alerts: Alert[]): CorrelationGroup[] {
  const map = new Map<string, Alert[]>();
  for (const a of alerts) {
    if (!a.incidentId) continue;
    map.set(a.incidentId, [...(map.get(a.incidentId) ?? []), a]);
  }
  return [...map.entries()].map(([incidentId, list]) => ({
    incidentId,
    alerts: list,
    domains: DOMAINS.filter((d) => list.some((a) => alertDomain(a) === d)),
    sources: [...new Set(list.map((a) => a.source))].sort(),
    techniques: [...new Set(list.flatMap((a) => a.attack.map((t) => t.id)))].sort(),
    firstSeenAt: list.reduce((m, a) => (a.firstSeenAt < m ? a.firstSeenAt : m), list[0]!.firstSeenAt),
    lastSeenAt: list.reduce((m, a) => (a.lastSeenAt > m ? a.lastSeenAt : m), list[0]!.lastSeenAt),
  }));
}
