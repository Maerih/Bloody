import type { Severity } from "@bloody/contracts";
import type { IdentityView } from "../api/types";
import { isDormant, NON_HUMAN_KINDS } from "../features/identities/identityUtils";

/**
 * ISPM posture computed from the identity inventory: privilege, MFA coverage, dormancy and
 * non-human identity risk, plus recommendations with the exact count each one addresses.
 */
export interface IdentityPosture {
  total: number;
  humans: number;
  nonHuman: number;
  privileged: number;
  privilegedWithoutMfa: number;
  /** MFA coverage of enabled human identities, 0..1 (null when there are none). */
  mfaCoverage: number | null;
  dormant: number;
  dormantPrivileged: number;
  riskyNonHuman: number;
  highRisk: number;
  byProvider: { provider: string; total: number; mfa: number }[];
}

export function computePosture(identities: IdentityView[], dormantDays = 90, now: number = Date.now()): IdentityPosture {
  const enabled = identities.filter((i) => i.enabled !== false);
  const humans = enabled.filter((i) => !NON_HUMAN_KINDS.includes(i.kind) && i.kind !== "group");
  const nonHuman = enabled.filter((i) => NON_HUMAN_KINDS.includes(i.kind));
  const providers = new Map<string, { total: number; mfa: number }>();
  for (const h of humans) {
    const p = providers.get(h.provider) ?? { total: 0, mfa: 0 };
    p.total += 1;
    if (h.mfaEnabled) p.mfa += 1;
    providers.set(h.provider, p);
  }
  return {
    total: identities.length,
    humans: humans.length,
    nonHuman: nonHuman.length,
    privileged: enabled.filter((i) => i.privileged).length,
    privilegedWithoutMfa: humans.filter((i) => i.privileged && !i.mfaEnabled).length,
    mfaCoverage: humans.length === 0 ? null : humans.filter((i) => i.mfaEnabled).length / humans.length,
    dormant: enabled.filter((i) => isDormant(i, dormantDays, now)).length,
    dormantPrivileged: enabled.filter((i) => i.privileged && isDormant(i, dormantDays, now)).length,
    riskyNonHuman: nonHuman.filter((i) => i.privileged || (i.riskScore ?? 0) >= 70).length,
    highRisk: enabled.filter((i) => (i.riskScore ?? 0) >= 70).length,
    byProvider: [...providers.entries()].map(([provider, v]) => ({ provider, ...v })).sort((a, b) => b.total - a.total),
  };
}

export interface IdentityRecommendation {
  key: string;
  title: string;
  why: string;
  count: number;
  impact: Severity;
  href: string;
}

/** Ranked, data-backed recommendations (only those with something to fix). */
export function identityRecommendations(p: IdentityPosture, dormantDays = 90): IdentityRecommendation[] {
  const out: IdentityRecommendation[] = [];
  if (p.privilegedWithoutMfa > 0) out.push({ key: "mfa_privileged", title: `Enforce MFA on ${p.privilegedWithoutMfa} privileged identit${p.privilegedWithoutMfa === 1 ? "y" : "ies"}`, why: "Privileged accounts without MFA are the most common path to domain or tenant takeover.", count: p.privilegedWithoutMfa, impact: "critical", href: "/ispm/mfa?privileged=1" });
  if (p.dormantPrivileged > 0) out.push({ key: "dormant_privileged", title: `Disable or review ${p.dormantPrivileged} dormant privileged account${p.dormantPrivileged === 1 ? "" : "s"}`, why: `No activity for ${dormantDays}+ days while holding privileges — unused standing access.`, count: p.dormantPrivileged, impact: "high", href: "/ispm/dormant?privileged=1" });
  if (p.riskyNonHuman > 0) out.push({ key: "risky_non_human", title: `Reduce privileges of ${p.riskyNonHuman} risky service account${p.riskyNonHuman === 1 ? "" : "s"}`, why: "Privileged or high-risk non-human identities rarely have MFA and their credentials leak into code and scripts.", count: p.riskyNonHuman, impact: "high", href: "/ispm/service-accounts?risky=1" });
  const humansWithoutMfa = p.mfaCoverage === null ? 0 : Math.round(p.humans * (1 - p.mfaCoverage));
  if (humansWithoutMfa > 0) out.push({ key: "mfa_all", title: `Roll out MFA to ${humansWithoutMfa} remaining user${humansWithoutMfa === 1 ? "" : "s"}`, why: `MFA coverage is ${Math.round((p.mfaCoverage ?? 0) * 100)}% of enabled users.`, count: humansWithoutMfa, impact: "medium", href: "/ispm/mfa" });
  const dormantOther = p.dormant - p.dormantPrivileged;
  if (dormantOther > 0) out.push({ key: "dormant", title: `Clean up ${dormantOther} dormant account${dormantOther === 1 ? "" : "s"}`, why: `Accounts unused for ${dormantDays}+ days widen the attack surface.`, count: dormantOther, impact: "low", href: "/ispm/dormant" });
  return out;
}
