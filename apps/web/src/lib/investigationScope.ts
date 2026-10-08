import type { TimeRange } from "../api/types";
import { formatValue } from "./eventQuery";
import { windowAround } from "./timeRange";

/**
 * Event-search scope of an investigation: the entities of its incident (assets, identities)
 * inside a window around detection. Used by the workspace's process-tree, network and
 * identity-event panels so they read the same event store as SIEM search.
 */
export interface InvestigationScope {
  assetIds: string[];
  hostnames: string[];
  identityIds: string[];
  principals: string[];
  range: TimeRange;
}

function inList(field: string, values: string[]): string | null {
  const unique = [...new Set(values.filter((v) => v.trim() !== ""))].slice(0, 50);
  if (unique.length === 0) return null;
  return unique.length === 1 ? `${field}:${formatValue(unique[0]!)}` : `${field}:(${unique.map(formatValue).join(" OR ")})`;
}

function anyOf(parts: (string | null)[]): string | null {
  const p = parts.filter((x): x is string => Boolean(x));
  if (p.length === 0) return null;
  return p.length === 1 ? p[0]! : `(${p.join(" OR ")})`;
}

export function buildScope(input: {
  detectedAt?: string | null;
  createdAt: string;
  assets: { id: string; hostname?: string | null }[];
  assetIds?: string[];
  identities: { id: string; principal?: string | null }[];
  identityIds?: string[];
  beforeHours?: number;
  afterHours?: number;
}): InvestigationScope {
  const assetIds = [...new Set([...(input.assetIds ?? []), ...input.assets.map((a) => a.id)])];
  const identityIds = [...new Set([...(input.identityIds ?? []), ...input.identities.map((i) => i.id)])];
  return {
    assetIds,
    hostnames: input.assets.map((a) => a.hostname ?? "").filter(Boolean),
    identityIds,
    principals: input.identities.map((i) => i.principal ?? "").filter(Boolean),
    range: windowAround(input.detectedAt ?? input.createdAt, input.beforeHours ?? 48, input.afterHours ?? 48),
  };
}

export function hasHostScope(s: InvestigationScope): boolean {
  return s.assetIds.length > 0 || s.hostnames.length > 0;
}

export function hasIdentityScope(s: InvestigationScope): boolean {
  return s.identityIds.length > 0 || s.principals.length > 0;
}

/** Events on the investigation's hosts. */
export function hostClause(s: InvestigationScope): string | null {
  return anyOf([inList("asset.id", s.assetIds), inList("asset.hostname", s.hostnames)]);
}

/** Events by / about the investigation's identities. */
export function identityClause(s: InvestigationScope): string | null {
  return anyOf([inList("identity.id", s.identityIds), inList("identity.principal", s.principals), inList("user.name", s.principals.map((p) => p.split("@")[0] ?? p))]);
}

export function processQuery(s: InvestigationScope): string | null {
  const host = hostClause(s);
  return host ? `category:process AND ${host}` : null;
}

export function networkQuery(s: InvestigationScope): string | null {
  const host = hostClause(s);
  return host ? `category:(network OR dns OR http OR tls) AND ${host}` : null;
}

export function identityEventsQuery(s: InvestigationScope): string | null {
  const id = identityClause(s);
  return id ? `category:(authentication OR identity) AND ${id}` : null;
}
