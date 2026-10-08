import type { IdentityView } from "../../api/types";

export const DORMANT_DAYS_DEFAULT = 90;

/** Days since last activity; null when never active. */
export function daysInactive(identity: Pick<IdentityView, "lastActivityAt">, now: number = Date.now()): number | null {
  if (!identity.lastActivityAt) return null;
  const t = Date.parse(identity.lastActivityAt);
  return Number.isNaN(t) ? null : Math.floor((now - t) / 86_400_000);
}

/** Dormant = no activity for `days` (or never active). Disabled accounts are not dormant risks. */
export function isDormant(identity: IdentityView, days = DORMANT_DAYS_DEFAULT, now: number = Date.now()): boolean {
  if (identity.enabled === false) return false;
  const inactive = daysInactive(identity, now);
  return inactive === null || inactive >= days;
}

export const NON_HUMAN_KINDS: IdentityView["kind"][] = ["service_account", "service_principal", "machine", "api_key"];

export function identityName(i: Pick<IdentityView, "displayName" | "principal">): string {
  return i.displayName ?? i.principal;
}
