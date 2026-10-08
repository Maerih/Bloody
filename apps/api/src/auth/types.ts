import type { ModuleKey, Principal } from "@bloody/contracts";

export type AuthMethod = "session" | "bearer" | "api_key";

/** Authenticated caller of a request. Tenant is ALWAYS taken from here, never from input. */
export interface AuthContext {
  principal: Principal;
  method: AuthMethod;
  tenantId: string;
  /** API keys bound to one organization may only act there. */
  boundOrganizationId: string | null;
  sessionId: string | null;
  /** Cookie-authenticated unsafe requests must carry a valid CSRF token. */
  csrfProtected: boolean;
}

export interface AuditState {
  recorded: boolean;
  /** Tenant to attribute an unauthenticated attempt to (e.g. failed login of a known user). */
  tenantId?: string;
  organizationId?: string | null;
  action?: string;
  targetKind?: string;
  targetId?: string;
  details?: Record<string, unknown>;
  actorLabel?: string;
}

declare module "fastify" {
  interface FastifyRequest {
    auth: AuthContext | null;
    auditState: AuditState;
  }
  interface FastifyContextConfig {
    /** Route needs no authentication (login, health, OIDC). */
    public?: boolean;
    /** Audit action name for the generic mutation audit hook; false disables it. */
    audit?: string | false;
    /** Product module the route belongs to: 402 ENTITLEMENT_REQUIRED unless the tenant is entitled. */
    module?: ModuleKey;
  }
}

export const SESSION_COOKIE = "bloody_session";
export const CSRF_COOKIE = "bloody_csrf";
export const CSRF_HEADER = "x-csrf-token";
export const OIDC_STATE_COOKIE = "bloody_oidc";
