import { z } from "zod";

/**
 * Permissions are `resource:action` strings. Roles are bundles of permissions.
 * Role bindings are scoped either to the whole tenant (organizationId = null) or
 * to a single organization (delegated administration / customer roles).
 */
export const PERMISSIONS = [
  "org:read",
  "org:write",
  "user:read",
  "user:write",
  "team:write",
  "asset:read",
  "asset:write",
  "identity:read",
  "incident:read",
  "incident:write",
  "investigation:read",
  "investigation:write",
  "escalation:read",
  "escalation:write",
  "alert:read",
  "event:read",
  "event:ingest",
  "detection:read",
  "detection:write",
  "graph:read",
  "risk:read",
  "intel:read",
  "intel:write",
  "vuln:read",
  "vuln:write",
  "response:request",
  "response:approve",
  "response:execute",
  "playbook:read",
  "playbook:write",
  "ai:use",
  "ai:configure",
  "integration:read",
  "integration:write",
  "report:read",
  "report:write",
  "audit:read",
  "apikey:write",
  "billing:read",
  "billing:write",
  "settings:write",
] as const;

export const Permission = z.enum(PERMISSIONS);
export type Permission = z.infer<typeof Permission>;

export const ROLE_KEYS = [
  "platform_admin",
  "mssp_admin",
  "org_admin",
  "ciso",
  "executive",
  "soc_analyst_t1",
  "soc_analyst_t2",
  "threat_hunter",
  "incident_responder",
  "security_engineer",
  "customer_viewer",
  "api_service",
] as const;

export const RoleKey = z.enum(ROLE_KEYS);
export type RoleKey = z.infer<typeof RoleKey>;

const READ_ALL: Permission[] = [
  "org:read",
  "user:read",
  "asset:read",
  "identity:read",
  "incident:read",
  "investigation:read",
  "escalation:read",
  "alert:read",
  "event:read",
  "detection:read",
  "graph:read",
  "risk:read",
  "intel:read",
  "vuln:read",
  "playbook:read",
  "integration:read",
  "report:read",
];

const ANALYST_T1: Permission[] = [
  ...READ_ALL,
  "incident:write",
  "investigation:write",
  "escalation:write",
  "response:request",
  "ai:use",
];

const ANALYST_T2: Permission[] = [...ANALYST_T1, "response:execute", "intel:write", "report:write"];

export const ROLE_PERMISSIONS: Record<RoleKey, readonly Permission[]> = {
  platform_admin: PERMISSIONS,
  mssp_admin: PERMISSIONS,
  org_admin: PERMISSIONS.filter((p) => p !== "billing:write"),
  ciso: [...READ_ALL, "report:write", "audit:read", "billing:read", "response:approve", "ai:use"],
  executive: ["org:read", "incident:read", "risk:read", "report:read", "vuln:read"],
  soc_analyst_t1: ANALYST_T1,
  soc_analyst_t2: ANALYST_T2,
  threat_hunter: [...ANALYST_T2, "detection:write"],
  incident_responder: [...ANALYST_T2, "response:approve"],
  security_engineer: [
    ...READ_ALL,
    "detection:write",
    "playbook:write",
    "integration:write",
    "vuln:write",
    "asset:write",
    "ai:use",
    "ai:configure",
  ],
  customer_viewer: ["org:read", "incident:read", "escalation:read", "escalation:write", "report:read", "asset:read"],
  api_service: ["event:ingest", "asset:read", "asset:write", "alert:read"],
};

export function roleHasPermission(role: RoleKey, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}

export const RoleBinding = z.object({
  role: RoleKey,
  /** null = applies to every organization in the tenant. */
  organizationId: z.string().uuid().nullable(),
});
export type RoleBinding = z.infer<typeof RoleBinding>;

/** Authenticated principal attached to every request. */
export interface Principal {
  kind: "user" | "service";
  id: string;
  tenantId: string;
  email?: string;
  displayName?: string;
  bindings: RoleBinding[];
  sessionId?: string;
}

/** True if the principal holds `permission` for `organizationId` (or tenant-wide when null). */
export function principalCan(p: Principal, permission: Permission, organizationId: string | null = null): boolean {
  // A tenant-wide binding covers every organization; an org binding covers only that org
  // and never grants tenant-level (organizationId = null) actions.
  return p.bindings.some(
    (b) =>
      (b.organizationId === null || b.organizationId === organizationId) &&
      roleHasPermission(b.role, permission),
  );
}

/** Organizations a principal may see; "all" when any binding is tenant-wide. */
export function principalOrgScope(p: Principal): "all" | string[] {
  if (p.bindings.some((b) => b.organizationId === null)) return "all";
  return [...new Set(p.bindings.map((b) => b.organizationId as string))];
}
