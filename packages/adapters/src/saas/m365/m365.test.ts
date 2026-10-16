import { describe, expect, it } from "vitest";
import { collectM365 } from "./collect.js";
import { evaluateM365, scoreM365 } from "./checks.js";
import { createGraphClient, GraphError } from "./graph.js";

const GA = "62e90394-69f5-4237-9190-012177145e10";
type Handler = (path: string) => { status?: number; body: unknown };

/** Fake Microsoft identity + Graph endpoints for a deliberately weak tenant. */
function fakeTenant(over: Record<string, Handler> = {}) {
  const calls: string[] = [];
  const routes: Record<string, Handler> = {
    "/organization": () => ({ body: { value: [{ displayName: "Kilimanjaro Bank", verifiedDomains: [{ name: "kb.example" }, { name: "kbank.onmicrosoft.com" }] }] } }),
    "/policies/identitySecurityDefaultsEnforcementPolicy": () => ({ body: { isEnabled: false } }),
    "/identity/conditionalAccess/policies": () => ({
      body: {
        value: [
          { id: "1", displayName: "Require MFA for everyone", state: "enabled", conditions: { users: { includeUsers: ["All"], excludeUsers: ["bg1"] }, applications: { includeApplications: ["All"] } }, grantControls: { builtInControls: ["mfa"] } },
          { id: "2", displayName: "Block legacy auth", state: "enabledForReportingButNotEnforced", conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, clientAppTypes: ["exchangeActiveSync", "other"] }, grantControls: { builtInControls: ["block"] } },
        ],
      },
    }),
    "/policies/authorizationPolicy": () => ({ body: { defaultUserRolePermissions: { allowedToCreateApps: true, permissionGrantPoliciesAssigned: ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"] }, guestUserRoleId: "10dae51f-b6af-4016-8d66-8c2a99b929b3", allowInvitesFrom: "everyone" } }),
    "/domains": () => ({ body: { value: [{ id: "kb.example", isVerified: true, passwordValidityPeriodInDays: 90 }] } }),
    "/reports/authenticationMethods/userRegistrationDetails": () => ({ status: 403, body: { error: { code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", message: "Tenant does not have a premium licence" } } }),
    "/identityProtection/riskyUsers": () => ({ status: 403, body: { error: { code: "Forbidden", message: "Missing scope" } } }),
    "/directoryRoles": () => ({ body: { value: [{ roleTemplateId: GA, displayName: "Global Administrator", members: [{ "@odata.type": "#microsoft.graph.user", id: "u1" }] }] } }),
    "/users/u1": () => ({ body: { id: "u1", userPrincipalName: "admin@kb.example", onPremisesSyncEnabled: true } }),
    "/oauth2PermissionGrants": () => ({ body: { value: [{ clientId: "sp1", consentType: "Principal", scope: "openid Mail.Read offline_access" }, { clientId: "sp2", consentType: "AllPrincipals", scope: "User.Read" }] } }),
    "/servicePrincipals/sp1": () => ({ body: { displayName: "PDF Viewer Pro", appOwnerOrganizationId: "11111111-1111-1111-1111-111111111111", publisherName: "Unknown" } }),
    "/servicePrincipals/sp2": () => ({ body: { displayName: "Microsoft Teams", appOwnerOrganizationId: "f8cdef31-a31e-4b4a-93e4-5f571e91255a" } }),
    "/users": () => ({ body: { value: [{ id: "u2", userPrincipalName: "amina@kb.example", accountEnabled: true, userType: "Member", mail: "amina@kb.example" }, { id: "u3", userPrincipalName: "nolicence@kb.example", accountEnabled: true, mail: "nolicence@kb.example" }] } }),
    "/users/u2/mailFolders/inbox/messageRules": () => ({
      body: {
        value: [
          { displayName: ".", isEnabled: true, actions: { forwardTo: [{ emailAddress: { address: "payments@evil.example" } }], markAsRead: true, moveToFolder: "RSS" } },
          { displayName: "Team", isEnabled: true, actions: { forwardTo: [{ emailAddress: { address: "boss@kb.example" } }] } },
        ],
      },
    }),
    "/users/u3/mailFolders/inbox/messageRules": () => ({ status: 404, body: { error: { code: "MailboxNotEnabledForRESTAPI", message: "no mailbox" } } }),
    ...over,
  };
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    calls.push(`${init?.method ?? "GET"} ${url.host}${url.pathname}`);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.host === "login.microsoftonline.com") {
      const form = new URLSearchParams(String(init?.body));
      return form.get("client_secret") === "right-secret" ? json(200, { access_token: "tok", expires_in: 3600 }) : json(401, { error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided." });
    }
    const path = url.pathname.replace(/^\/v1\.0/, "");
    const h = routes[path];
    if (!h) return json(404, { error: { code: "NotFound", message: path } });
    const r = h(path);
    return json(r.status ?? 200, r.body);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const dns = {
  resolveTxt: async (n: string) => (n === "kb.example" ? [["v=spf1 include:spf.protection.outlook.com ", "-all"]] : n === "_dmarc.kb.example" ? [["v=DMARC1; p=none; rua=mailto:d@kb.example"]] : []),
  resolveCname: async (n: string) => (n === "selector1._domainkey.kb.example" ? ["selector1-kb-example._domainkey.kbank.onmicrosoft.com"] : []),
};

describe("Microsoft 365 posture", () => {
  it("grades a weak tenant: explains each failure and what could not be read", async () => {
    const { fetchImpl, calls } = fakeTenant();
    const graph = createGraphClient({ directoryTenantId: "kbank.onmicrosoft.com", clientId: "00000000-0000-0000-0000-000000000001", clientSecret: "right-secret", fetch: fetchImpl });
    const snap = await collectM365(graph, { dns });
    const results = evaluateM365(snap);
    const by = Object.fromEntries(results.map((r) => [r.id, r]));
    expect(by["m365.mfa_all_users"]).toMatchObject({ status: "pass" });
    expect(by["m365.mfa_all_users"]!.evidence[0]).toMatch(/1 exclusion\(s\) — keep these to break-glass/);
    expect(by["m365.legacy_auth_blocked"]).toMatchObject({ status: "warn", summary: expect.stringContaining("report-only") });
    expect(by["m365.mfa_phishing_resistant_admins"]!.status).toBe("fail");
    expect(by["m365.mfa_registration"]).toMatchObject({ status: "unknown" });
    expect(by["m365.mfa_registration"]!.evidence[0]).toMatch(/AuditLog\.Read\.All.*Entra ID P1/);
    expect(by["m365.risky_users"]!.evidence[0]).toMatch(/IdentityRiskyUser\.Read\.All/);
    expect(by["m365.global_admin_count"]).toMatchObject({ status: "fail", summary: expect.stringContaining("Only 1") });
    expect(by["m365.admins_cloud_only"]).toMatchObject({ status: "fail", evidence: ["admin@kb.example (Global Administrator)"] });
    expect(by["m365.user_app_registration"]!.status).toBe("fail");
    expect(by["m365.user_consent"]!.status).toBe("fail");
    expect(by["m365.guest_access_restricted"]!.status).toBe("pass");
    expect(by["m365.guest_invites"]!.status).toBe("fail");
    expect(by["m365.password_expiration"]).toMatchObject({ status: "fail", evidence: ["kb.example: every 90 days"] });
    expect(by["m365.inbox_rules_external_forwarding"]).toMatchObject({ status: "fail", evidence: ['amina@kb.example: "." → payments@evil.example'] });
    expect(by["m365.inbox_rules_hiding"]!.status).toBe("warn");
    expect(by["m365.spf"]!.status).toBe("pass"); // TXT chunks are joined
    expect(by["m365.dkim"]!.status).toBe("pass");
    expect(by["m365.dmarc"]).toMatchObject({ status: "fail", summary: expect.stringContaining("p=none") });
    expect(by["m365.risky_oauth_grants"]).toMatchObject({ status: "fail" });
    expect(by["m365.risky_oauth_grants"]!.evidence[0]).toMatch(/PDF Viewer Pro .*consented by a user: Mail\.Read/);
    expect(by["m365.audit_log"]!.status).toBe("manual");
    for (const r of results) {
      expect(r.why.length).toBeGreaterThan(20);
      expect(r.howToFix.length).toBeGreaterThan(0);
      expect(r.references.length).toBeGreaterThan(0);
    }
    const { score, counts } = scoreM365(results);
    expect(counts.manual).toBe(2);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(50);
    // Only Microsoft endpoints were contacted, and the token was requested once.
    expect(calls.every((c) => c.includes("login.microsoftonline.com/") || c.includes("graph.microsoft.com/"))).toBe(true);
    expect(calls.filter((c) => c.startsWith("POST")).length).toBe(1);
  });

  it("security defaults satisfy MFA and legacy-auth checks", async () => {
    const { fetchImpl } = fakeTenant({ "/policies/identitySecurityDefaultsEnforcementPolicy": () => ({ body: { isEnabled: true } }), "/identity/conditionalAccess/policies": () => ({ body: { value: [] } }) });
    const graph = createGraphClient({ directoryTenantId: "kbank.onmicrosoft.com", clientId: "00000000-0000-0000-0000-000000000001", clientSecret: "right-secret", fetch: fetchImpl });
    const by = Object.fromEntries(evaluateM365(await collectM365(graph, { dns })).map((r) => [r.id, r.status]));
    expect(by["m365.mfa_all_users"]).toBe("pass");
    expect(by["m365.legacy_auth_blocked"]).toBe("pass");
    expect(by["m365.mfa_phishing_resistant_admins"]).toBe("fail"); // security defaults do not give phishing-resistant MFA
  });

  it("reports a wrong secret clearly and refuses odd tenant IDs or foreign paging links", async () => {
    const { fetchImpl } = fakeTenant({ "/domains": () => ({ body: { value: [], "@odata.nextLink": "https://evil.example/steal" } }) });
    const bad = createGraphClient({ directoryTenantId: "kbank.onmicrosoft.com", clientId: "00000000-0000-0000-0000-000000000001", clientSecret: "wrong", fetch: fetchImpl });
    await expect(bad.get("/organization")).rejects.toMatchObject({ code: "invalid_client", message: expect.stringContaining("AADSTS7000215") });
    expect(() => createGraphClient({ directoryTenantId: "evil.example/../x", clientId: "x", clientSecret: "x", fetch: fetchImpl })).toThrow(GraphError);
    const good = createGraphClient({ directoryTenantId: "kbank.onmicrosoft.com", clientId: "00000000-0000-0000-0000-000000000001", clientSecret: "right-secret", fetch: fetchImpl });
    expect(await good.list("/domains")).toEqual([]); // the foreign nextLink is not followed
  });
});
