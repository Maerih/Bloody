import type { CanonicalEvent } from "@bloody/contracts";

/**
 * Hot search columns derived from a canonical event. Shared by the Postgres `events` insert and the
 * OpenSearch index so both backends answer the same query identically.
 */
export interface EventColumns {
  outcome: string | null;
  userName: string | null;
  srcIp: string | null;
  dstIp: string | null;
  processName: string | null;
  fileSha256: string | null;
  detectionRule: string | null;
  attackIds: string[];
}

export function eventColumns(e: CanonicalEvent): EventColumns {
  return {
    outcome: e.outcome ?? e.identity?.outcome ?? null,
    userName: e.user?.name ? (e.user.domain ? `${e.user.domain}\\${e.user.name}` : e.user.name) : (e.user?.email ?? null),
    srcIp: e.network?.srcIp ?? e.identity?.sourceIp ?? null,
    dstIp: e.network?.dstIp ?? null,
    processName: e.process?.name ?? (e.process?.path ? (e.process.path.split(/[\\/]/).pop() ?? null) : null),
    fileSha256: e.file?.sha256 ?? e.process?.hashSha256 ?? null,
    detectionRule: e.detection?.ruleName ?? e.detection?.ruleId ?? null,
    attackIds: e.attack.map((t) => t.id),
  };
}
