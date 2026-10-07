import {
  DashboardRole,
  planIncludes,
  principalCan,
  principalOrgScope,
  type Account,
  type ModuleKey,
  type ModuleState,
  type Organization,
  type Permission,
  type PlanKey,
  type Principal,
} from "@bloody/contracts";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import type { EntitlementView, MeResponse } from "../api/types";
import { isOneOf, readStorage, writeStorage } from "../lib/storage";
import { defaultDashboardRole } from "./dashboardPresets";
import { OrgScopeContext } from "./orgScope";

/**
 * Session & tenancy context: who is signed in, which account (tenant) and which organization
 * they are looking at, what they may do (RBAC from role bindings) and which modules the tenant
 * is entitled to. The server remains the authority for every check — this only shapes the UI.
 */

export const ORG_PARAM = "org";
export const ALL_ORGS_PARAM = "all";

export interface SessionValue {
  me: MeResponse;
  principal: Principal;
  account: Account;
  plan: PlanKey;
  organizations: Organization[];
  entitlements: EntitlementView[];
  /** Selected organization id; null = "All organizations". */
  organizationId: string | null;
  organization: Organization | null;
  setOrganizationId: (id: string | null) => void;
  /** Whether "All organizations" is a valid selection for this principal. */
  canSelectAll: boolean;
  isMssp: boolean;
  /** RBAC check; defaults to the selected organization (tenant-wide when "All"). */
  can: (permission: Permission, organizationId?: string | null) => boolean;
  /** True when any binding grants the permission (for showing entry points). */
  canAnywhere: (permission: Permission) => boolean;
  moduleState: (module: ModuleKey) => ModuleState;
  isModuleEnabled: (module: ModuleKey) => boolean;
  entitlement: (module: ModuleKey) => EntitlementView | null;
  dashboardRole: DashboardRole;
  setDashboardRole: (role: DashboardRole) => void;
  organizationName: (id: string | null | undefined) => string | null;
}

const SessionContext = createContext<SessionValue | null>(null);
const isDashboardRole = isOneOf<DashboardRole>(DashboardRole.options);

export function SessionProvider({ me, children }: { me: MeResponse; children: ReactNode }) {
  const { principal, account, organizations, entitlements, plan } = me;
  const [searchParams, setSearchParams] = useSearchParams();

  const orgIds = useMemo(() => new Set(organizations.map((o) => o.id)), [organizations]);
  const scope = principalOrgScope(principal);
  const canSelectAll = scope === "all" || organizations.length > 1;
  const multiChoice = organizations.length > 1 || (canSelectAll && organizations.length > 0);
  const storageKeyOrg = `org.${principal.tenantId}.${principal.id}`;

  /** undefined = invalid; null = all organizations; string = an org id the principal can see. */
  const parseOrg = useCallback(
    (value: string | null | undefined): string | null | undefined => {
      if (value === null || value === undefined) return undefined;
      if (value === ALL_ORGS_PARAM) return canSelectAll ? null : undefined;
      return orgIds.has(value) ? value : undefined;
    },
    [canSelectAll, orgIds],
  );

  const fallbackOrg = canSelectAll ? null : (organizations[0]?.id ?? null);

  const [selected, setSelected] = useState<string | null>(() => {
    const fromUrl = parseOrg(searchParams.get(ORG_PARAM));
    if (fromUrl !== undefined) return fromUrl;
    const stored = readStorage<string>(storageKeyOrg, (v): v is string => typeof v === "string");
    const fromStorage = parseOrg(stored);
    return fromStorage !== undefined ? fromStorage : fallbackOrg;
  });

  // Organizations can be created/removed while signed in; never keep an invalid selection.
  const organizationId = selected === null ? (canSelectAll ? null : fallbackOrg) : orgIds.has(selected) ? selected : fallbackOrg;

  const encode = (id: string | null) => id ?? ALL_ORGS_PARAM;
  const urlOrg = searchParams.get(ORG_PARAM);

  // URL ⇄ state sync. A valid ?org= (deep link) wins; otherwise the URL is corrected to the
  // current selection so links are shareable.
  useEffect(() => {
    if (!multiChoice) return;
    const parsed = parseOrg(urlOrg);
    if (parsed !== undefined) {
      if (parsed !== organizationId) {
        setSelected(parsed);
        writeStorage(storageKeyOrg, encode(parsed));
      }
      return;
    }
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set(ORG_PARAM, encode(organizationId));
        return next;
      },
      { replace: true },
    );
  }, [urlOrg, organizationId, multiChoice, parseOrg]);

  const setOrganizationId = useCallback(
    (id: string | null) => {
      const valid = parseOrg(encode(id));
      if (valid === undefined) return;
      setSelected(valid);
      writeStorage(storageKeyOrg, encode(valid));
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set(ORG_PARAM, encode(valid));
        return next;
      });
    },
    [parseOrg, setSearchParams, storageKeyOrg],
  );

  const storageKeyRole = `dashboardRole.${principal.tenantId}.${principal.id}`;
  const [dashboardRole, setDashboardRoleState] = useState<DashboardRole>(
    () => readStorage(storageKeyRole, isDashboardRole) ?? defaultDashboardRole(principal.bindings),
  );
  const setDashboardRole = useCallback(
    (role: DashboardRole) => {
      setDashboardRoleState(role);
      writeStorage(storageKeyRole, role);
    },
    [storageKeyRole],
  );

  const value = useMemo<SessionValue>(() => {
    const entitlementMap = new Map(entitlements.map((e) => [e.module, e]));
    const moduleState = (module: ModuleKey): ModuleState => {
      if (module === "command_center") return "active";
      const ent = entitlementMap.get(module);
      if (ent) return ent.state;
      return planIncludes(plan, module) ? "active" : "locked";
    };
    const orgById = new Map(organizations.map((o) => [o.id, o]));
    return {
      me,
      principal,
      account,
      plan,
      organizations,
      entitlements,
      organizationId,
      organization: organizationId ? (orgById.get(organizationId) ?? null) : null,
      setOrganizationId,
      canSelectAll,
      isMssp: account.kind === "mssp",
      can: (permission, orgId) => principalCan(principal, permission, orgId === undefined ? organizationId : orgId),
      canAnywhere: (permission) => principal.bindings.some((b) => principalCan(principal, permission, b.organizationId)),
      moduleState,
      isModuleEnabled: (module) => {
        const state = moduleState(module);
        return state === "active" || state === "trial";
      },
      entitlement: (module) => entitlementMap.get(module) ?? null,
      dashboardRole,
      setDashboardRole,
      organizationName: (id) => (id ? (orgById.get(id)?.name ?? null) : null),
    };
  }, [me, principal, account, plan, organizations, entitlements, organizationId, setOrganizationId, canSelectAll, dashboardRole, setDashboardRole]);

  return (
    <SessionContext.Provider value={value}>
      <OrgScopeContext.Provider value={organizationId}>{children}</OrgScopeContext.Provider>
    </SessionContext.Provider>
  );
}

export function useSession(): SessionValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used inside <SessionProvider>");
  return ctx;
}

/** Same as useSession but returns null outside an authenticated shell (e.g. on /login). */
export function useOptionalSession(): SessionValue | null {
  return useContext(SessionContext);
}
