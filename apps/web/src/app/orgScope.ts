import { createContext, useContext } from "react";

/**
 * The organization the user is currently looking at (`null` = "All organizations", i.e. the
 * tenant-wide / MSSP aggregate view). Data hooks read this so every query is scoped and keyed
 * by organization — switching org refetches everything without leaking the previous view.
 */
export const OrgScopeContext = createContext<string | null>(null);

export function useCurrentOrganizationId(): string | null {
  return useContext(OrgScopeContext);
}
