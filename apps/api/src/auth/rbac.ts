import { principalCan, ROLE_PERMISSIONS, type Permission, type Principal, type RoleKey } from "@bloody/contracts";
import type { FastifyRequest } from "fastify";
import { forbidden, notFound, unauthorized } from "../http/errors.js";
import type { AuthContext } from "./types.js";

/** The authenticated context, or 401. */
export function requireAuth(request: FastifyRequest): AuthContext {
  if (!request.auth) throw unauthorized();
  return request.auth;
}

/**
 * Permission gate. `organizationId = null` asks for a tenant-level permission (only
 * tenant-wide bindings satisfy it). Org-bound API keys can never act outside their org.
 */
export function requirePermission(request: FastifyRequest, permission: Permission, organizationId: string | null): AuthContext {
  const auth = requireAuth(request);
  if (auth.boundOrganizationId !== null && organizationId !== auth.boundOrganizationId) {
    throw forbidden(`This API key is restricted to organization ${auth.boundOrganizationId}`);
  }
  if (!principalCan(auth.principal, permission, organizationId)) {
    request.auditState.details = { ...(request.auditState.details ?? {}), deniedPermission: permission, organizationId };
    throw forbidden(`Missing permission ${permission}${organizationId ? " for this organization" : ""}`);
  }
  return auth;
}

/** True when the caller may use `permission` somewhere (any org or tenant-wide). */
export function canAnywhere(principal: Principal, permission: Permission): boolean {
  return principal.bindings.some((b) => ROLE_PERMISSIONS[b.role].includes(permission));
}

/**
 * Organizations where the caller holds `permission`: "all" for a tenant-wide grant, else the
 * explicit list (possibly empty). Org-bound API keys are narrowed to their org.
 */
export function orgScopeFor(auth: AuthContext, permission: Permission): "all" | string[] {
  const p = auth.principal;
  let scope: "all" | string[];
  if (p.bindings.some((b) => b.organizationId === null && ROLE_PERMISSIONS[b.role].includes(permission))) scope = "all";
  else scope = [...new Set(p.bindings.filter((b) => b.organizationId !== null && ROLE_PERMISSIONS[b.role].includes(permission)).map((b) => b.organizationId as string))];
  if (auth.boundOrganizationId) {
    const bound = auth.boundOrganizationId;
    scope = scope === "all" || scope.includes(bound) ? [bound] : [];
  }
  return scope;
}

/**
 * Resolve the org filter of a list/summary endpoint: an explicit `organizationId` must be in
 * scope (403 otherwise); without one, the caller's whole scope is used. Returns null for "all".
 */
export function resolveOrgFilter(request: FastifyRequest, permission: Permission, organizationId: string | undefined | null): string[] | null {
  const auth = requireAuth(request);
  const scope = orgScopeFor(auth, permission);
  if (organizationId) {
    if (scope !== "all" && !scope.includes(organizationId)) throw forbidden(`Missing permission ${permission} for this organization`);
    return [organizationId];
  }
  if (scope === "all") return null;
  if (scope.length === 0) throw forbidden(`Missing permission ${permission}`);
  return scope;
}

/**
 * Check a loaded record's organization against the caller's scope. Out-of-scope records are
 * reported as 404 (not 403) so existence is not disclosed across organizations.
 */
export function assertRecordAccess(request: FastifyRequest, permission: Permission, organizationId: string, what = "Resource"): AuthContext {
  const auth = requireAuth(request);
  const scope = orgScopeFor(auth, permission);
  if (scope !== "all" && !scope.includes(organizationId)) {
    if (canAnywhere(auth.principal, permission)) throw notFound(what);
    throw forbidden(`Missing permission ${permission}`);
  }
  return auth;
}

/** A principal may only grant roles whose permissions it holds itself in the same scope. */
export function canGrantRole(principal: Principal, role: RoleKey, organizationId: string | null): boolean {
  if ((role === "platform_admin" || role === "mssp_admin") && !principal.bindings.some((b) => b.organizationId === null && (b.role === "platform_admin" || b.role === "mssp_admin"))) return false;
  return ROLE_PERMISSIONS[role].every((perm) => principalCan(principal, perm, organizationId));
}

export function actorId(auth: AuthContext): string {
  return `${auth.principal.kind}:${auth.principal.id}`;
}
