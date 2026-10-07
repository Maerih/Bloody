import type { AttackTechnique } from "@bloody/contracts";

/**
 * MITRE ATT&CK® Enterprise tactic vocabulary and a compact technique → primary-tactic lookup
 * used when a detection omits the tactic. Technique/tactic identifiers are facts published by
 * MITRE under the ATT&CK Terms of Use (attribution: © The MITRE Corporation). Only ids and
 * tactic short-names are used; no ATT&CK content is reproduced.
 */
export const ATTACK_TACTICS = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
] as const;
export type AttackTactic = (typeof ATTACK_TACTICS)[number];

/** Tactics that indicate an intrusion has progressed beyond initial foothold. */
export const LATE_STAGE_TACTICS: ReadonlySet<string> = new Set(["privilege-escalation", "credential-access", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]);
/** Tactics that directly damage confidentiality / integrity / availability of data. */
export const IMPACT_TACTICS: ReadonlySet<string> = new Set(["collection", "exfiltration", "impact"]);

const TECHNIQUE_TACTIC: Record<string, AttackTactic> = {
  T1595: "reconnaissance",
  T1190: "initial-access",
  T1133: "initial-access",
  T1566: "initial-access",
  T1199: "initial-access",
  T1078: "defense-evasion",
  T1059: "execution",
  T1204: "execution",
  T1047: "execution",
  T1053: "execution",
  T1569: "execution",
  T1203: "execution",
  T1136: "persistence",
  T1098: "persistence",
  T1543: "persistence",
  T1547: "persistence",
  T1505: "persistence",
  T1068: "privilege-escalation",
  T1548: "privilege-escalation",
  T1055: "privilege-escalation",
  T1611: "privilege-escalation",
  T1027: "defense-evasion",
  T1036: "defense-evasion",
  T1070: "defense-evasion",
  T1112: "defense-evasion",
  T1218: "defense-evasion",
  T1562: "defense-evasion",
  T1003: "credential-access",
  T1110: "credential-access",
  T1555: "credential-access",
  T1552: "credential-access",
  T1558: "credential-access",
  T1621: "credential-access",
  T1087: "discovery",
  T1018: "discovery",
  T1046: "discovery",
  T1069: "discovery",
  T1082: "discovery",
  T1482: "discovery",
  T1021: "lateral-movement",
  T1210: "lateral-movement",
  T1570: "lateral-movement",
  T1005: "collection",
  T1039: "collection",
  T1114: "collection",
  T1560: "collection",
  T1071: "command-and-control",
  T1090: "command-and-control",
  T1095: "command-and-control",
  T1105: "command-and-control",
  T1568: "command-and-control",
  T1572: "command-and-control",
  T1573: "command-and-control",
  T1041: "exfiltration",
  T1048: "exfiltration",
  T1567: "exfiltration",
  T1485: "impact",
  T1486: "impact",
  T1489: "impact",
  T1490: "impact",
  T1491: "impact",
  T1496: "impact",
};

/** Normalize "Credential Access" / "credential_access" / "TA0006"-less names to ATT&CK short-names. */
export function normalizeTactic(tactic: string): string {
  return tactic.trim().toLowerCase().replace(/[\s_]+/g, "-");
}

export function tacticOf(t: AttackTechnique): string | null {
  if (t.tactic) return normalizeTactic(t.tactic);
  const base = t.id.toUpperCase().split(".")[0] ?? "";
  return TECHNIQUE_TACTIC[base] ?? null;
}

export function tacticsOf(techniques: readonly AttackTechnique[]): Set<string> {
  const out = new Set<string>();
  for (const t of techniques) {
    const tac = tacticOf(t);
    if (tac) out.add(tac);
  }
  return out;
}

/** Order tactics along the kill chain (unknown tactics last). */
export function killChainOrder(tactics: Iterable<string>): string[] {
  const rank = (t: string) => {
    const i = (ATTACK_TACTICS as readonly string[]).indexOf(t);
    return i < 0 ? 99 : i;
  };
  return [...new Set(tactics)].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}
