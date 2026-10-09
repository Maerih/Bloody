import { ROLE_KEYS, ROLE_PERMISSIONS, type RoleBinding, type RoleKey } from "@bloody/contracts";

/** Display names for role keys (contracts RBAC). */
export const ROLE_LABELS: Record<RoleKey, string> = {
  platform_admin: "Platform admin",
  mssp_admin: "MSSP admin",
  org_admin: "Organization admin",
  ciso: "CISO",
  executive: "Executive",
  soc_analyst_t1: "SOC analyst (tier 1)",
  soc_analyst_t2: "SOC analyst (tier 2)",
  threat_hunter: "Threat hunter",
  incident_responder: "Incident responder",
  security_engineer: "Security engineer",
  customer_viewer: "Customer viewer",
  api_service: "API service",
};

/** Roles offered to people (service roles are for API keys; platform_admin is operator-only). */
export const USER_ROLES: RoleKey[] = ROLE_KEYS.filter((r) => r !== "platform_admin" && r !== "api_service");
/** Roles an API key can carry. */
export const API_KEY_ROLES: RoleKey[] = ROLE_KEYS.filter((r) => r !== "platform_admin");

export function roleLabel(role: string): string {
  return (ROLE_LABELS as Record<string, string>)[role] ?? role;
}

export function permissionCount(role: RoleKey): number {
  return ROLE_PERMISSIONS[role].length;
}

export function bindingLabel(b: RoleBinding, orgName: (id: string) => string | null | undefined): string {
  return `${roleLabel(b.role)} · ${b.organizationId ? (orgName(b.organizationId) ?? "organization") : "all organizations"}`;
}

export function sameBinding(a: RoleBinding, b: RoleBinding): boolean {
  return a.role === b.role && (a.organizationId ?? null) === (b.organizationId ?? null);
}
