import type { EventCategory, Severity } from "@bloody/contracts";
import { technique } from "../core/attack.js";
import { defineAdapter, skip, type Adapter, type AdapterExtras, type EventDraft, type MapOutput } from "../core/adapter.js";
import { ObservableSet } from "../core/indicators.js";
import { arr, field, isRecord, rec, redactKeys, str, type JsonRecord } from "../core/json.js";
import { isSensitiveKey } from "../core/severity.js";
import { toIso } from "../core/time.js";

/**
 * Keycloak / OIDC adapter — consumes the Admin REST API event feeds:
 *   GET /admin/realms/{realm}/events        (user/login events)
 *   GET /admin/realms/{realm}/admin-events  (admin operations)
 * and the same JSON delivered by event-listener webhooks.
 *
 * Login failures, MFA removal, lockouts, impersonation, privilege grants, identity-provider
 * and authentication-flow changes get ITDR-relevant severities and ATT&CK techniques.
 * Admin `representation` bodies are never stored (they can carry credentials / secrets).
 */
export const KEYCLOAK_ADAPTER_VERSION = "1.0.0";

interface UserEventSpec {
  category: EventCategory;
  severity: Severity;
  attack?: string;
}

const USER_EVENTS: Record<string, UserEventSpec> = {
  LOGIN: { category: "authentication", severity: "info" },
  LOGIN_ERROR: { category: "authentication", severity: "low", attack: "T1110" },
  LOGOUT: { category: "authentication", severity: "info" },
  LOGOUT_ERROR: { category: "authentication", severity: "info" },
  CODE_TO_TOKEN: { category: "authentication", severity: "info" },
  CODE_TO_TOKEN_ERROR: { category: "authentication", severity: "low" },
  REFRESH_TOKEN: { category: "authentication", severity: "info" },
  REFRESH_TOKEN_ERROR: { category: "authentication", severity: "low", attack: "T1550" },
  CLIENT_LOGIN: { category: "authentication", severity: "info" },
  CLIENT_LOGIN_ERROR: { category: "authentication", severity: "low", attack: "T1110" },
  TOKEN_EXCHANGE: { category: "authentication", severity: "low" },
  TOKEN_EXCHANGE_ERROR: { category: "authentication", severity: "low" },
  IDENTITY_PROVIDER_LOGIN: { category: "authentication", severity: "info" },
  IDENTITY_PROVIDER_LOGIN_ERROR: { category: "authentication", severity: "low" },
  IDENTITY_PROVIDER_FIRST_LOGIN: { category: "authentication", severity: "low" },
  IMPERSONATE: { category: "identity", severity: "high", attack: "T1078" },
  IMPERSONATE_ERROR: { category: "identity", severity: "medium", attack: "T1078" },
  REGISTER: { category: "identity", severity: "info", attack: "T1136" },
  UPDATE_PASSWORD: { category: "identity", severity: "low", attack: "T1098" },
  RESET_PASSWORD: { category: "identity", severity: "low", attack: "T1098" },
  SEND_RESET_PASSWORD: { category: "identity", severity: "info" },
  UPDATE_EMAIL: { category: "identity", severity: "low", attack: "T1098" },
  UPDATE_PROFILE: { category: "identity", severity: "info" },
  UPDATE_TOTP: { category: "identity", severity: "low" },
  UPDATE_CREDENTIAL: { category: "identity", severity: "low" },
  REMOVE_TOTP: { category: "identity", severity: "medium", attack: "T1556.006" },
  REMOVE_CREDENTIAL: { category: "identity", severity: "medium", attack: "T1556.006" },
  USER_DISABLED_BY_PERMANENT_LOCKOUT: { category: "identity", severity: "medium", attack: "T1110" },
  USER_DISABLED_BY_TEMPORARY_LOCKOUT: { category: "identity", severity: "low", attack: "T1110" },
  FEDERATED_IDENTITY_LINK: { category: "identity", severity: "low" },
  REMOVE_FEDERATED_IDENTITY: { category: "identity", severity: "low" },
  GRANT_CONSENT: { category: "identity", severity: "info" },
  REVOKE_GRANT: { category: "identity", severity: "info" },
  VERIFY_EMAIL: { category: "identity", severity: "info" },
};

interface AdminSpec {
  category: EventCategory;
  severity: Severity;
  attack?: string;
  why: string;
}

function adminSpec(resourceType: string, operation: string, path: string, roleNames: string[]): AdminSpec {
  const rt = resourceType.toUpperCase();
  const op = operation.toUpperCase();
  if (rt.endsWith("ROLE_MAPPING") && op === "CREATE") {
    const admin = roleNames.some((r) => /admin|manage-|realm-management|owner/i.test(r));
    return { category: "identity", severity: admin ? "high" : "medium", attack: "T1098", why: admin ? "administrative role granted" : "role granted" };
  }
  if (rt === "GROUP_MEMBERSHIP" && op === "CREATE") return { category: "identity", severity: "low", attack: "T1098", why: "group membership added" };
  if (rt === "USER" && op === "CREATE") return { category: "identity", severity: "low", attack: "T1136", why: "user created" };
  if (rt === "USER" && op === "DELETE") return { category: "identity", severity: "low", attack: "T1531", why: "user deleted" };
  if (rt === "USER" && op === "ACTION" && /reset-password|execute-actions-email/.test(path)) return { category: "identity", severity: "low", attack: "T1098", why: "credential reset by administrator" };
  if (rt === "IDENTITY_PROVIDER" || rt === "IDENTITY_PROVIDER_MAPPER") return { category: "configuration", severity: op === "DELETE" ? "medium" : "high", attack: "T1484", why: "federation trust changed" };
  if (rt === "AUTH_FLOW" || rt === "AUTH_EXECUTION" || rt === "AUTH_EXECUTION_FLOW" || rt === "AUTHENTICATOR_CONFIG" || rt === "REQUIRED_ACTION") {
    return { category: "configuration", severity: "high", attack: "T1556", why: "authentication flow modified" };
  }
  if (rt === "REALM" && /events-config/.test(path)) return { category: "configuration", severity: "high", attack: "T1562", why: "event logging configuration changed" };
  if (rt === "CLIENT" || rt === "CLIENT_SCOPE" || rt === "CLIENT_SCOPE_MAPPING") {
    return { category: "configuration", severity: op === "CREATE" || /client-secret/.test(path) ? "medium" : "low", attack: "T1098.001", why: "OAuth client changed" };
  }
  if (rt === "REALM") return { category: "configuration", severity: "medium", why: "realm settings changed" };
  if (rt === "COMPONENT") return { category: "configuration", severity: "medium", why: "user federation / key provider changed" };
  return { category: "audit", severity: "info", why: "administrative change" };
}

function roleNamesFrom(representation: unknown): string[] {
  if (typeof representation !== "string") return [];
  try {
    const parsed: unknown = JSON.parse(representation);
    return arr(parsed)
      .map((r) => (isRecord(r) ? str(r["name"]) : undefined))
      .filter((n): n is string => n !== undefined)
      .slice(0, 20);
  } catch {
    return [];
  }
}

function mapUserEvent(r: JsonRecord, realmHint?: string): EventDraft {
  const type = str(r["type"]) ?? "UNKNOWN";
  const spec = USER_EVENTS[type] ?? { category: type.includes("LOGIN") ? "authentication" : "identity", severity: type.endsWith("_ERROR") ? "low" : "info" };
  const failure = type.endsWith("_ERROR") || str(r["error"]) !== undefined;
  const details = rec(r["details"]) ?? {};
  const username = str(details["username"]);
  const userId = str(r["userId"]);
  const clientId = str(r["clientId"]);
  const ip = str(r["ipAddress"]);
  const realm = str(r["realmName"]) ?? str(r["realmId"]) ?? realmHint;
  const principal = type.startsWith("CLIENT_LOGIN") ? clientId : username ?? userId;
  const t = spec.attack ? technique(spec.attack) : undefined;
  const ts = toIso(r["time"], { epochUnit: "ms" });
  return {
    timestamp: ts,
    category: spec.category,
    eventType: `keycloak.${type.toLowerCase()}`,
    action: type.toLowerCase(),
    outcome: failure ? "failure" : "success",
    message: `Keycloak ${type}${principal ? ` for ${principal}` : ""}${clientId ? ` via ${clientId}` : ""}${str(r["error"]) ? ` (${str(r["error"])})` : ""}`,
    severity: spec.severity,
    user: principal ? { name: principal, email: str(details["email"]) } : undefined,
    identity: {
      provider: realm ? `keycloak:${realm}` : "keycloak",
      principal,
      sourceIp: ip,
      outcome: failure ? "failure" : "success",
    },
    network: ip ? { srcIp: ip } : undefined,
    indicators: new ObservableSet().add("ip", ip).toArray(),
    attack: t ? [t] : [],
    labels: {
      severity_basis: `keycloak event ${type}`,
      "keycloak.realm": realm,
      "keycloak.client_id": clientId,
      "keycloak.user_id": userId,
      "keycloak.session_id": str(r["sessionId"]),
      "keycloak.error": str(r["error"]),
      "keycloak.auth_method": str(details["auth_method"]),
      "keycloak.auth_type": str(details["auth_type"]),
      "keycloak.identity_provider": str(details["identity_provider"]),
      "keycloak.redirect_uri": str(details["redirect_uri"]),
    },
    dedupKey: str(r["id"]) ?? `user:${realm ?? ""}:${str(r["time"]) ?? ""}:${type}:${userId ?? ""}:${str(r["sessionId"]) ?? ""}`,
    source: { kind: "identity" },
    raw: r,
  };
}

function mapAdminEvent(r: JsonRecord, realmHint?: string): EventDraft {
  const op = str(r["operationType"]) ?? "ACTION";
  const resourceType = str(r["resourceType"]) ?? "UNKNOWN";
  const path = str(r["resourcePath"]) ?? "";
  const roles = resourceType.toUpperCase().endsWith("ROLE_MAPPING") ? roleNamesFrom(r["representation"]) : [];
  const spec = adminSpec(resourceType, op, path, roles);
  const actorId = str(field(r, "authDetails.userId"));
  const actorClient = str(field(r, "authDetails.clientId"));
  const ip = str(field(r, "authDetails.ipAddress"));
  const realm = str(r["realmName"]) ?? str(r["realmId"]) ?? realmHint;
  const targetUser = /^users\/([^/]+)/.exec(path)?.[1];
  const failed = str(r["error"]) !== undefined;
  const t = spec.attack ? technique(spec.attack) : undefined;
  const ts = toIso(r["time"], { epochUnit: "ms" });
  return {
    timestamp: ts,
    category: spec.category,
    eventType: `keycloak.admin.${resourceType.toLowerCase()}.${op.toLowerCase()}`,
    action: `${op.toLowerCase()}:${resourceType.toLowerCase()}`,
    outcome: failed ? "failure" : "success",
    message: `Keycloak admin ${op} ${resourceType} ${path}${roles.length ? ` (roles: ${roles.join(", ")})` : ""} — ${spec.why}`,
    severity: failed ? "low" : spec.severity,
    user: targetUser ? { name: targetUser } : undefined,
    identity: { provider: realm ? `keycloak:${realm}` : "keycloak", principal: actorId, sourceIp: ip, privileged: true, outcome: failed ? "failure" : "success" },
    network: ip ? { srcIp: ip } : undefined,
    indicators: new ObservableSet().add("ip", ip).toArray(),
    attack: t ? [t] : [],
    labels: {
      severity_basis: `keycloak admin ${op} ${resourceType}: ${spec.why}`,
      "keycloak.realm": realm,
      "keycloak.actor_user_id": actorId,
      "keycloak.actor_client_id": actorClient,
      "keycloak.resource_type": resourceType,
      "keycloak.resource_path": path,
      "keycloak.roles": roles.join(",") || undefined,
      "keycloak.error": str(r["error"]),
    },
    dedupKey: str(r["id"]) ?? `admin:${realm ?? ""}:${str(r["time"]) ?? ""}:${op}:${path}:${actorId ?? ""}`,
    source: { kind: "identity" },
    // `representation` deliberately dropped: it may contain passwords or client secrets.
    raw: { ...r, representation: undefined },
  };
}

function mapKeycloak(record: unknown, ctx: { options: Record<string, unknown> }): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const realm = str(ctx.options["realm"]);
  if (str(record["operationType"]) || str(record["resourceType"])) return mapAdminEvent(record, realm);
  if (str(record["type"])) return mapUserEvent(record, realm);
  return skip("not a Keycloak event (no type / operationType)");
}

export function createKeycloakAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "keycloak",
    version: KEYCLOAK_ADAPTER_VERSION,
    name: "Keycloak login & admin events",
    sourceKind: "identity",
    vendor: "Keycloak",
    consumes: ["Admin REST /admin/realms/{realm}/events", "Admin REST /admin/realms/{realm}/admin-events", "event-listener webhook JSON"],
    map: mapKeycloak,
    redactRaw: (r) => redactKeys(r, isSensitiveKey),
  });
}
