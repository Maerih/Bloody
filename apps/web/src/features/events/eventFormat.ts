import type { CanonicalEvent } from "@bloody/contracts";

/** One-line human summary of a canonical event. */
export function eventSummary(e: CanonicalEvent): string {
  if (e.message) return e.message;
  if (e.process?.commandLine) return e.process.commandLine;
  if (e.process?.name) return `${e.process.parent?.name ? `${e.process.parent.name} → ` : ""}${e.process.name}`;
  if (e.network?.dnsQuery) return `DNS ${e.network.dnsQuery}`;
  if (e.network?.httpHost) return `${e.network.httpHost}${e.network.httpUrl ?? ""}`;
  if (e.network?.dstIp) return `${e.network.srcIp ?? "?"}${e.network.srcPort ? `:${e.network.srcPort}` : ""} → ${e.network.dstIp}${e.network.dstPort ? `:${e.network.dstPort}` : ""}`;
  if (e.identity?.principal) return `${e.identity.principal} ${e.outcome ?? e.identity.outcome ?? ""}`.trim();
  if (e.file?.path) return `${e.file.action ?? "file"} ${e.file.path}`;
  if (e.cloudResource?.action) return `${e.cloudResource.provider} ${e.cloudResource.action}`;
  return e.eventType;
}

export function eventHost(e: CanonicalEvent): string | null {
  return e.asset?.hostname ?? e.asset?.ip?.[0] ?? null;
}

export function eventUser(e: CanonicalEvent): string | null {
  return e.identity?.principal ?? e.user?.name ?? e.user?.email ?? e.process?.user ?? null;
}

/** Query-syntax value for pivots (quotes when needed). */
export function pivotQuery(field: string, value: string): string {
  return /^[A-Za-z0-9_.\-/@]+$/.test(value) ? `${field}:${value}` : `${field}:"${value.replace(/(["\\])/g, "\\$1")}"`;
}

export function searchHref(query: string, range?: string): string {
  return `/siem/search?q=${encodeURIComponent(query)}${range ? `&range=${encodeURIComponent(range)}` : ""}`;
}
