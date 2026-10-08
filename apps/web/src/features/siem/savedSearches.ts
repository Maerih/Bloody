import { useCallback } from "react";
import type { SavedSearch } from "../../api/types";
import { useSession } from "../../app/session";
import { useLocalStorageState } from "../../lib/storage";

function isSavedSearchList(v: unknown): v is SavedSearch[] {
  return (
    Array.isArray(v) &&
    v.every((s) => typeof s === "object" && s !== null && typeof (s as SavedSearch).id === "string" && typeof (s as SavedSearch).name === "string" && typeof (s as SavedSearch).query === "string" && typeof (s as SavedSearch).range === "string")
  );
}

function newId(): string {
  return typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export const MAX_SAVED_SEARCHES = 100;

/**
 * Saved SIEM searches (query + time range), kept per tenant and principal in this browser —
 * the same persistence model as the data tables' saved views.
 */
export function useSavedSearches() {
  const session = useSession();
  const [list, setList] = useLocalStorageState<SavedSearch[]>(`siem.savedSearches.${session.principal.tenantId}.${session.principal.id}`, [], isSavedSearchList);
  const save = useCallback(
    (name: string, query: string, range: string): SavedSearch => {
      const item: SavedSearch = { id: newId(), name: name.trim().slice(0, 120), query, range, createdAt: new Date().toISOString() };
      setList((cur) => [item, ...cur.filter((s) => s.name !== item.name)].slice(0, MAX_SAVED_SEARCHES));
      return item;
    },
    [setList],
  );
  const remove = useCallback((id: string) => setList((cur) => cur.filter((s) => s.id !== id)), [setList]);
  return { searches: list, save, remove };
}
