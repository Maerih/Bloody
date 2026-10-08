import type { Page } from "@bloody/contracts";
import { useCurrentOrganizationId } from "../app/orgScope";

/**
 * Shared building blocks for the react-query hooks (api/hooks.ts and api/moduleHooks.ts).
 *
 * Every tenant-data query key carries the organization scope as its second segment so that
 * switching organization never renders the previous organization's cached data.
 */

export const ALL_SCOPE = "all";

export const orgKey = (orgId: string | null): string => orgId ?? ALL_SCOPE;

/**
 * Like keepPreviousData, but only while the organization scope (second key segment) is
 * unchanged — after an org switch the UI shows loading states, never the previous
 * organization's numbers under the new organization's name.
 */
export function keepPreviousWithinOrg<T>(orgId: string | null) {
  return (previous: T | undefined, previousQuery: { queryKey: readonly unknown[] } | undefined): T | undefined =>
    previousQuery && previousQuery.queryKey[1] === orgKey(orgId) ? previous : undefined;
}

/** `undefined` → the currently selected organization; `null` → all organizations; string → that org. */
export function useScope(explicit: string | null | undefined): string | null {
  const current = useCurrentOrganizationId();
  return explicit === undefined ? current : explicit;
}

export function withoutOrg<T extends { organizationId?: string | null }>(filters: T): Omit<T, "organizationId"> {
  const { organizationId: _ignored, ...rest } = filters;
  return rest;
}

/** Lists may come back as Page<T> or (from simpler endpoints) a bare array. */
export function toPage<T>(raw: Page<T> | T[] | null | undefined): Page<T> {
  if (!raw) return { items: [], nextCursor: null };
  if (Array.isArray(raw)) return { items: raw, nextCursor: null, total: raw.length };
  return { items: raw.items ?? [], nextCursor: raw.nextCursor ?? null, ...(raw.total !== undefined ? { total: raw.total } : {}) };
}

export function toArray<T>(raw: Page<T> | T[] | null | undefined): T[] {
  return toPage(raw).items;
}
