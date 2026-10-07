/**
 * Sigma field name → Bloody Canonical Event (BCE) dotted path.
 *
 * Bloody-authored mapping table (Sigma taxonomy names are an open, documented convention;
 * the mapping itself is ours). BCE has no first-class fields for a few Windows-specific
 * concepts — adapters place those under `labels.*` (documented per entry) so Sigma rules
 * referencing them still compile.
 *
 * Lookup is case-insensitive. Names that already look like BCE paths (contain a dot, or are
 * a BCE top-level field) pass through unchanged.
 */
export const SIGMA_FIELD_MAP: Readonly<Record<string, string>> = {
  // process creation / access
  image: "process.path",
  originalfilename: "process.name",
  processname: "process.name",
  commandline: "process.commandLine",
  processid: "process.pid",
  parentimage: "process.parent.path",
  parentcommandline: "process.parent.commandLine",
  parentprocessid: "process.parent.pid",
  parentprocessname: "process.parent.name",
  hashes: "process.hashSha256",
  sha256: "process.hashSha256",
  user: "user.name",
  subjectusername: "user.name",
  targetusername: "user.name",
  subjectdomainname: "user.domain",
  targetdomainname: "user.domain",
  targetimage: "labels.targetImage", // process_access: accessed process image
  grantedaccess: "labels.grantedAccess", // process_access: access mask
  calltrace: "labels.callTrace",
  integritylevel: "labels.integrityLevel",
  logontype: "labels.logonType",
  eventid: "labels.eventId",
  // file
  targetfilename: "file.path",
  sourcefilename: "labels.sourceFilename", // file_rename: previous name
  imageloaded: "file.path",
  md5: "file.md5",
  // registry (adapters write registry events into labels)
  targetobject: "labels.registryKey",
  details: "labels.registryValue",
  // network
  sourceip: "network.srcIp",
  src_ip: "network.srcIp",
  ipaddress: "identity.sourceIp",
  destinationip: "network.dstIp",
  dst_ip: "network.dstIp",
  sourceport: "network.srcPort",
  destinationport: "network.dstPort",
  dst_port: "network.dstPort",
  destinationhostname: "network.httpHost",
  protocol: "network.protocol",
  initiated: "network.direction",
  queryname: "network.dnsQuery",
  query: "network.dnsQuery",
  "c-uri": "network.httpUrl",
  "cs-uri": "network.httpUrl",
  "cs-host": "network.httpHost",
  "cs-user-agent": "labels.userAgent",
  ja3: "network.ja3",
  // host / generic
  computer: "asset.hostname",
  computername: "asset.hostname",
  hostname: "asset.hostname",
  workstationname: "asset.hostname",
  // detections (IDS passthrough)
  signature: "detection.ruleName",
  "alert.signature": "detection.ruleName",
  signatureid: "detection.ruleId",
};

const BCE_TOP_LEVEL = new Set([
  "schemaVersion",
  "id",
  "tenantId",
  "organizationId",
  "timestamp",
  "source",
  "category",
  "eventType",
  "action",
  "outcome",
  "message",
  "asset",
  "user",
  "identity",
  "process",
  "file",
  "network",
  "cloudResource",
  "indicators",
  "severity",
  "risk",
  "detection",
  "attack",
  "labels",
  "provenance",
]);

export function isBcePath(field: string): boolean {
  if (field.includes(".")) return BCE_TOP_LEVEL.has(field.split(".")[0] ?? "");
  return BCE_TOP_LEVEL.has(field);
}

export type FieldResolution = { path: string; mapped: boolean } | { path: null; mapped: false };

/** Resolve a Sigma or BCE field name. `overrides` (per rule) win over the global table. */
export function resolveField(field: string, overrides: Readonly<Record<string, string>> = {}): FieldResolution {
  const overrideKey = Object.keys(overrides).find((k) => k.toLowerCase() === field.toLowerCase());
  if (overrideKey) return { path: overrides[overrideKey]!, mapped: true };
  if (isBcePath(field)) return { path: field, mapped: false };
  const mapped = SIGMA_FIELD_MAP[field.toLowerCase()];
  if (mapped) return { path: mapped, mapped: true };
  return { path: null, mapped: false };
}

/** Fields searched by Sigma keyword selections (bare strings, no field). */
export const KEYWORD_FIELDS = [
  "message",
  "process.commandLine",
  "process.parent.commandLine",
  "process.path",
  "file.path",
  "network.httpUrl",
  "network.dnsQuery",
  "detection.ruleName",
  "eventType",
] as const;
