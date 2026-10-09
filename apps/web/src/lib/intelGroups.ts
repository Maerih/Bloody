import { SEVERITY_RANK, type Indicator, type Severity } from "@bloody/contracts";
import type { IntelMatch } from "../api/types";

/**
 * Threat-actor / campaign / malware rollups over indicators, joined with environment matches.
 * Pure: the CTI workspace computes them from the loaded indicator and match pages and says so.
 */
export interface IntelGroup {
  key: string;
  name: string;
  indicators: number;
  /** Indicators of this group observed in the environment. */
  matchedIndicators: number;
  matches: number;
  maxSeverity: Severity;
  maxConfidence: number;
  types: string[];
  sources: string[];
  related: string[];
  lastSeenAt: string;
  lastMatchedAt: string | null;
}

export type IntelGroupBy = "actor" | "campaign";

function keyOf(i: Indicator, by: IntelGroupBy): string | null {
  if (by === "actor") return i.threatActor?.trim() || null;
  return i.campaign?.trim() || i.malware?.trim() || null;
}

function relatedOf(i: Indicator, by: IntelGroupBy): string[] {
  const out = by === "actor" ? [i.campaign, i.malware] : [i.threatActor];
  return out.filter((v): v is string => typeof v === "string" && v.trim().length > 0).map((v) => v.trim());
}

export function groupIndicators(indicators: Indicator[], matches: IntelMatch[], by: IntelGroupBy): IntelGroup[] {
  const matchesByIndicator = new Map<string, IntelMatch[]>();
  for (const m of matches) matchesByIndicator.set(m.indicatorId, [...(matchesByIndicator.get(m.indicatorId) ?? []), m]);
  const groups = new Map<string, { name: string; list: Indicator[] }>();
  for (const i of indicators) {
    const name = keyOf(i, by);
    if (!name) continue;
    const key = name.toLowerCase();
    const g = groups.get(key) ?? { name, list: [] };
    g.list.push(i);
    groups.set(key, g);
  }
  const out: IntelGroup[] = [];
  for (const [key, { name, list }] of groups) {
    const hits = list.flatMap((i) => matchesByIndicator.get(i.id) ?? []);
    out.push({
      key,
      name,
      indicators: list.length,
      matchedIndicators: list.filter((i) => (matchesByIndicator.get(i.id)?.length ?? 0) > 0).length,
      matches: hits.length,
      maxSeverity: list.reduce<Severity>((m, i) => (SEVERITY_RANK[i.severity] > SEVERITY_RANK[m] ? i.severity : m), "info"),
      maxConfidence: Math.max(...list.map((i) => i.confidence)),
      types: [...new Set(list.map((i) => i.type))].sort(),
      sources: [...new Set(list.map((i) => i.source))].sort(),
      related: [...new Set(list.flatMap((i) => relatedOf(i, by)))].sort(),
      lastSeenAt: list.reduce((m, i) => (i.lastSeenAt > m ? i.lastSeenAt : m), list[0]!.lastSeenAt),
      lastMatchedAt: hits.length > 0 ? hits.reduce((m, h) => (h.matchedAt > m ? h.matchedAt : m), hits[0]!.matchedAt) : null,
    });
  }
  // Groups seen in the environment first, then by severity and size.
  return out.sort((a, b) => b.matches - a.matches || SEVERITY_RANK[b.maxSeverity] - SEVERITY_RANK[a.maxSeverity] || b.indicators - a.indicators || a.name.localeCompare(b.name));
}

export function indicatorInGroup(i: Indicator, by: IntelGroupBy, key: string): boolean {
  return keyOf(i, by)?.toLowerCase() === key;
}
