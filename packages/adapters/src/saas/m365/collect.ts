import { GraphError, type GraphClient } from "./graph.js";

/**
 * Read-only snapshot of a Microsoft 365 tenant's security configuration. Every section is
 * collected independently: a missing permission or licence makes that section unavailable (with
 * the reason) instead of failing the whole assessment.
 */

export type Section<T> = { ok: true; data: T } | { ok: false; error: string; permission?: string };

export interface CaPolicy {
  id: string;
  displayName: string;
  state: "enabled" | "disabled" | "enabledForReportingButNotEnforced";
  conditions?: {
    users?: { includeUsers?: string[]; excludeUsers?: string[]; includeRoles?: string[]; excludeRoles?: string[]; includeGroups?: string[] };
    applications?: { includeApplications?: string[] };
    clientAppTypes?: string[];
    signInRiskLevels?: string[];
    userRiskLevels?: string[];
  };
  grantControls?: { builtInControls?: string[]; authenticationStrength?: { id?: string; displayName?: string } | null } | null;
}

export interface DirectoryUser {
  id: string;
  userPrincipalName: string;
  displayName?: string;
  accountEnabled?: boolean;
  userType?: string;
  mail?: string | null;
  onPremisesSyncEnabled?: boolean | null;
}

export interface InboxRule {
  user: string;
  name: string;
  enabled: boolean;
  forwardTo: string[];
  delete: boolean;
  markAsRead: boolean;
  moveToFolder: string | null;
}

export interface MailDnsRecords {
  domain: string;
  spf: string[];
  dmarc: string[];
  dkimSelectors: string[];
}

export interface M365Snapshot {
  collectedAt: string;
  organization: Section<{ displayName: string; verifiedDomains: string[] }>;
  securityDefaults: Section<{ isEnabled: boolean }>;
  conditionalAccess: Section<CaPolicy[]>;
  authorizationPolicy: Section<{ allowedToCreateApps: boolean | null; permissionGrantPolicies: string[]; guestUserRoleId: string | null; allowInvitesFrom: string | null }>;
  privilegedRoles: Section<Array<{ roleTemplateId: string; roleName: string; members: DirectoryUser[] }>>;
  registration: Section<Array<{ userPrincipalName: string; isAdmin: boolean; isMfaRegistered: boolean; methods: string[] }>>;
  domains: Section<Array<{ id: string; isVerified: boolean; passwordValidityPeriodInDays: number | null }>>;
  oauthGrants: Section<Array<{ app: string; publisher: string | null; firstParty: boolean; consentType: string; scopes: string[] }>>;
  inboxRules: Section<{ mailboxesScanned: number; rules: InboxRule[] }>;
  riskyUsers: Section<Array<{ userPrincipalName: string; riskLevel: string }>>;
  mailDns: Section<MailDnsRecords[]>;
}

export interface DnsResolver {
  resolveTxt(name: string): Promise<string[][]>;
  resolveCname(name: string): Promise<string[]>;
}

/** Well-known Entra role template IDs of privileged roles. */
export const PRIVILEGED_ROLES: Record<string, string> = {
  "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
  "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
  "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
  "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
  "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
  "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
  "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
  "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
  "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
  "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
  "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
};
export const GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10";
/** Microsoft's own tenant: apps it publishes are first-party. */
const MICROSOFT_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";

async function section<T>(permission: string, fn: () => Promise<T>, licence?: string): Promise<Section<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    if (err instanceof GraphError && err.isPermission) {
      return { ok: false, permission, error: `Microsoft Graph refused the request: grant the ${permission} application permission (with admin consent)${licence ? ` — this also needs ${licence}` : ""}. ${err.message}` };
    }
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

const recipients = (list: unknown): string[] =>
  Array.isArray(list) ? list.map((r) => String((r as { emailAddress?: { address?: string } }).emailAddress?.address ?? "")).filter(Boolean) : [];

export async function collectM365(graph: GraphClient, opts: { dns?: DnsResolver; maxMailboxes?: number; now?: () => number } = {}): Promise<M365Snapshot> {
  const now = opts.now ?? Date.now;
  const organization = await section("Directory.Read.All", async () => {
    const orgs = await graph.list<{ displayName: string; verifiedDomains?: Array<{ name: string }> }>("/organization");
    const o = orgs[0];
    return { displayName: o?.displayName ?? "", verifiedDomains: (o?.verifiedDomains ?? []).map((d) => d.name.toLowerCase()) };
  });
  const verified = organization.ok ? organization.data.verifiedDomains : [];

  const [securityDefaults, conditionalAccess, authorizationPolicy, domains, registration, riskyUsers] = await Promise.all([
    section("Policy.Read.All", async () => ({ isEnabled: Boolean((await graph.get<{ isEnabled?: boolean }>("/policies/identitySecurityDefaultsEnforcementPolicy")).isEnabled) })),
    section("Policy.Read.All", () => graph.list<CaPolicy>("/identity/conditionalAccess/policies"), "Entra ID P1"),
    section("Policy.Read.All", async () => {
      const raw = await graph.get<Record<string, unknown> & { value?: Record<string, unknown>[] }>("/policies/authorizationPolicy");
      const p = (Array.isArray(raw.value) ? raw.value[0] : raw) ?? {};
      const d = (p.defaultUserRolePermissions ?? {}) as { allowedToCreateApps?: boolean; permissionGrantPoliciesAssigned?: string[] };
      return {
        allowedToCreateApps: typeof d.allowedToCreateApps === "boolean" ? d.allowedToCreateApps : null,
        permissionGrantPolicies: Array.isArray(d.permissionGrantPoliciesAssigned) ? d.permissionGrantPoliciesAssigned : [],
        guestUserRoleId: typeof p.guestUserRoleId === "string" ? p.guestUserRoleId : null,
        allowInvitesFrom: typeof p.allowInvitesFrom === "string" ? p.allowInvitesFrom : null,
      };
    }),
    section("Directory.Read.All", async () =>
      (await graph.list<{ id: string; isVerified?: boolean; passwordValidityPeriodInDays?: number }>("/domains")).map((d) => ({ id: d.id.toLowerCase(), isVerified: Boolean(d.isVerified), passwordValidityPeriodInDays: d.passwordValidityPeriodInDays ?? null })),
    ),
    section(
      "AuditLog.Read.All",
      async () =>
        (await graph.list<{ userPrincipalName: string; isAdmin?: boolean; isMfaRegistered?: boolean; methodsRegistered?: string[] }>("/reports/authenticationMethods/userRegistrationDetails")).map((r) => ({
          userPrincipalName: r.userPrincipalName,
          isAdmin: Boolean(r.isAdmin),
          isMfaRegistered: Boolean(r.isMfaRegistered),
          methods: r.methodsRegistered ?? [],
        })),
      "Entra ID P1",
    ),
    section(
      "IdentityRiskyUser.Read.All",
      async () =>
        (await graph.list<{ userPrincipalName: string; riskLevel?: string }>("/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'")).map((u) => ({ userPrincipalName: u.userPrincipalName, riskLevel: u.riskLevel ?? "unknown" })),
      "Entra ID P2",
    ),
  ]);

  const privilegedRoles = await section("RoleManagement.Read.Directory", async () => {
    const roles = await graph.list<{ roleTemplateId: string; displayName: string; members?: Array<{ "@odata.type"?: string; id: string; userPrincipalName?: string; displayName?: string }> }>("/directoryRoles?$expand=members");
    const out: Array<{ roleTemplateId: string; roleName: string; members: DirectoryUser[] }> = [];
    const cache = new Map<string, DirectoryUser>();
    for (const r of roles) {
      if (!PRIVILEGED_ROLES[r.roleTemplateId]) continue;
      const members: DirectoryUser[] = [];
      for (const m of r.members ?? []) {
        if (m["@odata.type"] && m["@odata.type"] !== "#microsoft.graph.user") continue;
        let u = cache.get(m.id);
        if (!u) {
          u = await graph.get<DirectoryUser>(`/users/${encodeURIComponent(m.id)}?$select=id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled`).catch(() => ({ id: m.id, userPrincipalName: m.userPrincipalName ?? m.id }));
          cache.set(m.id, u);
        }
        members.push(u);
      }
      out.push({ roleTemplateId: r.roleTemplateId, roleName: PRIVILEGED_ROLES[r.roleTemplateId]!, members });
    }
    return out;
  });

  const oauthGrants = await section("Application.Read.All", async () => {
    const grants = await graph.list<{ clientId: string; consentType: string; scope?: string }>("/oauth2PermissionGrants");
    const apps = new Map<string, { displayName: string; publisher: string | null; firstParty: boolean }>();
    for (const id of [...new Set(grants.map((g) => g.clientId))].slice(0, 500)) {
      const sp = await graph.get<{ displayName?: string; appOwnerOrganizationId?: string; publisherName?: string }>(`/servicePrincipals/${encodeURIComponent(id)}?$select=id,displayName,appOwnerOrganizationId,publisherName`).catch(() => null);
      apps.set(id, { displayName: sp?.displayName ?? id, publisher: sp?.publisherName ?? null, firstParty: sp?.appOwnerOrganizationId === MICROSOFT_TENANT });
    }
    return grants.map((g) => {
      const a = apps.get(g.clientId);
      return { app: a?.displayName ?? g.clientId, publisher: a?.publisher ?? null, firstParty: a?.firstParty ?? false, consentType: g.consentType, scopes: (g.scope ?? "").split(" ").filter(Boolean) };
    });
  });

  const inboxRules = await section("MailboxSettings.Read", async () => {
    const users = (await graph.list<DirectoryUser>("/users?$select=id,userPrincipalName,accountEnabled,userType,mail")).filter((u) => u.accountEnabled !== false && u.userType !== "Guest" && u.mail);
    const rules: InboxRule[] = [];
    let scanned = 0;
    for (const u of users.slice(0, opts.maxMailboxes ?? 300)) {
      try {
        const list = await graph.list<{ displayName?: string; isEnabled?: boolean; actions?: Record<string, unknown> }>(`/users/${encodeURIComponent(u.id)}/mailFolders/inbox/messageRules`, 200);
        scanned++;
        for (const r of list) {
          const a = r.actions ?? {};
          rules.push({
            user: u.userPrincipalName,
            name: r.displayName ?? "(unnamed rule)",
            enabled: r.isEnabled !== false,
            forwardTo: [...recipients(a.forwardTo), ...recipients(a.redirectTo), ...recipients(a.forwardAsAttachmentTo)],
            delete: a.delete === true || a.permanentDelete === true,
            markAsRead: a.markAsRead === true,
            moveToFolder: typeof a.moveToFolder === "string" ? a.moveToFolder : null,
          });
        }
      } catch (err) {
        if (err instanceof GraphError && err.isPermission) throw err;
        // Mailbox without an Exchange licence, or not provisioned yet: skip it.
      }
    }
    return { mailboxesScanned: scanned, rules };
  });

  const mailDns = await section("public DNS", async () => {
    const dns = opts.dns;
    if (!dns) throw new Error("DNS lookups are not available on this platform");
    const names = verified.filter((d) => !d.endsWith(".onmicrosoft.com")).slice(0, 25);
    const txt = async (n: string) => (await dns.resolveTxt(n).catch(() => [] as string[][])).map((parts) => parts.join(""));
    return Promise.all(
      names.map(async (domain) => {
        const selectors: string[] = [];
        for (const s of ["selector1", "selector2"]) if ((await dns.resolveCname(`${s}._domainkey.${domain}`).catch(() => [])).length > 0) selectors.push(s);
        return { domain, spf: (await txt(domain)).filter((t) => /^v=spf1/i.test(t)), dmarc: (await txt(`_dmarc.${domain}`)).filter((t) => /^v=DMARC1/i.test(t)), dkimSelectors: selectors };
      }),
    );
  });

  return { collectedAt: new Date(now()).toISOString(), organization, securityDefaults, conditionalAccess, authorizationPolicy, privilegedRoles, registration, domains, oauthGrants, inboxRules, riskyUsers, mailDns };
}
