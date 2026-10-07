import type { CanonicalEvent, IndicatorType, NodeKind } from "@bloody/contracts";
import { isIp, isPublicIp, normalizeIp } from "../util/ip.js";

/**
 * Entity resolution primitives: canonical natural keys for every entity the engines reason
 * about. The Security Graph, the Detection Engine (match entities) and the Correlator all use
 * these functions so an entity seen by one engine has the same `(kind, key)` in the others.
 *
 * Key conventions (all lower-cased unless noted):
 *   endpoint  short hostname ("ws-042")  | "agent:<id>" | "asset:<uuid>" | "cloud:<instance>" | "ip:<addr>"
 *   user      "<domain>\\<name>" | "<email>" | "<name>" | "sid:<SID>" (SID upper-case)
 *   identity  "<provider>:<principal>"
 *   process   "<endpointKey>|<pid>|<image>"  (pid omitted when unknown)
 *   file      "<endpointKey>|<path>"
 *   hash      hex digest
 *   ip        canonical address (RFC 5952 for v6)
 *   domain    FQDN without trailing dot
 *   url       scheme://host[:port]/path?query (host lower-cased)
 *   indicator "<type>:<normalized value>"
 *   technique ATT&CK id ("T1059.001", upper-case)
 *   vulnerability CVE id (upper-case) or "vuln:<title>"
 */

export interface EntityRef {
  kind: NodeKind;
  key: string;
  label: string;
  /** Role of the entity in the event(s) it was extracted from. */
  role?: "actor" | "target" | "source" | "destination" | "observable" | "artifact";
}

export const ASSET_NODE_KINDS: readonly NodeKind[] = ["endpoint", "server", "cloud_asset", "container", "application", "saas_app", "data_store", "k8s_resource"];
export const IDENTITY_NODE_KINDS: readonly NodeKind[] = ["user", "identity", "service_account", "group", "credential"];
export const OBSERVABLE_NODE_KINDS: readonly NodeKind[] = ["ip", "domain", "url", "hash", "certificate"];

export function isAssetKind(kind: NodeKind): boolean {
  return ASSET_NODE_KINDS.includes(kind);
}
export function isIdentityKind(kind: NodeKind): boolean {
  return IDENTITY_NODE_KINDS.includes(kind);
}

export function normalizeHostname(hostname: string): string | null {
  const h = hostname.trim().toLowerCase().replace(/\.$/, "");
  if (!h) return null;
  if (isIp(h)) return null; // an IP in the hostname field is not a hostname
  const short = h.split(".")[0] ?? h;
  return short || null;
}

export function normalizeDomain(domain: string): string | null {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!d || d.length > 253 || /\s/.test(d)) return null;
  if (isIp(d)) return null;
  return d;
}

export function normalizeUrl(url: string): string | null {
  const u = url.trim();
  if (!u) return null;
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : `http://${u}`);
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

/** Registrable-ish parent domains, most specific first: a.b.evil.com → [b.evil.com, evil.com]. */
export function parentDomains(domain: string): string[] {
  const labels = domain.split(".");
  const out: string[] = [];
  for (let i = 1; i < labels.length - 1; i++) out.push(labels.slice(i).join("."));
  return out;
}

export function hostOfUrl(url: string): string | null {
  try {
    return normalizeDomain(new URL(url).hostname) ?? normalizeIp(new URL(url).hostname.replace(/^\[|\]$/g, ""));
  } catch {
    return null;
  }
}

export function normalizeIndicatorValue(type: IndicatorType, value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  switch (type) {
    case "ip": {
      if (v.includes("/")) return v.toLowerCase(); // CIDR indicator
      return normalizeIp(v);
    }
    case "domain":
      return normalizeDomain(v);
    case "url":
      return normalizeUrl(v);
    case "sha256":
    case "sha1":
    case "md5":
      return /^[0-9a-f]+$/i.test(v) ? v.toLowerCase() : null;
    case "email":
      return v.toLowerCase();
    case "cve":
      return v.toUpperCase();
    case "ja3":
      return v.toLowerCase();
    case "user_agent":
      return v;
  }
}

export function indicatorKey(type: IndicatorType, value: string): string | null {
  const v = normalizeIndicatorValue(type, value);
  return v === null ? null : `${type}:${v}`;
}

/** Node kind an indicator's observable value lives under in the graph, if any. */
export function observableKindForIndicator(type: IndicatorType): NodeKind | null {
  switch (type) {
    case "ip":
      return "ip";
    case "domain":
      return "domain";
    case "url":
      return "url";
    case "sha256":
    case "sha1":
    case "md5":
      return "hash";
    default:
      return null;
  }
}

type EventAssetLike = NonNullable<CanonicalEvent["asset"]>;
type EventUserLike = NonNullable<CanonicalEvent["user"]>;

/** Natural key for the asset in an event (no alias resolution — see SecurityGraph for that). */
export function assetKey(asset: EventAssetLike | undefined): string | null {
  if (!asset) return null;
  const host = asset.hostname ? normalizeHostname(asset.hostname) : null;
  if (host) return host;
  if (asset.agentId) return `agent:${asset.agentId.trim().toLowerCase()}`;
  if (asset.id) return `asset:${asset.id.toLowerCase()}`;
  if (asset.cloudInstanceId) return `cloud:${asset.cloudInstanceId.trim().toLowerCase()}`;
  const ip = asset.ip?.map((a) => normalizeIp(a)).find((a): a is string => a !== null);
  return ip ? `ip:${ip}` : null;
}

export function assetLabel(asset: EventAssetLike | undefined, key: string): string {
  return asset?.hostname?.trim() || key;
}

export function userKey(user: EventUserLike | undefined): string | null {
  if (!user) return null;
  const name = user.name?.trim();
  const domain = user.domain?.trim();
  if (name && name.includes("\\")) return name.toLowerCase();
  if (name && name.includes("@")) return name.toLowerCase();
  if (name && domain) return `${domain.split(".")[0]}\\${name}`.toLowerCase();
  if (user.email) return user.email.trim().toLowerCase();
  if (name) return name.toLowerCase();
  if (user.sid) return `sid:${user.sid.trim().toUpperCase()}`;
  return null;
}

export function userLabel(user: EventUserLike | undefined, key: string): string {
  if (!user) return key;
  if (user.domain && user.name && !user.name.includes("\\")) return `${user.domain}\\${user.name}`;
  return user.name ?? user.email ?? key;
}

export function identityKey(event: Pick<CanonicalEvent, "identity" | "source">): string | null {
  const principal = event.identity?.principal?.trim();
  if (!principal) return null;
  const provider = (event.identity?.provider ?? event.source.product).trim().toLowerCase() || "unknown";
  return `${provider}:${principal.toLowerCase()}`;
}

export function processKey(endpointKey: string, proc: { pid?: number | undefined; path?: string | undefined; name?: string | undefined; hashSha256?: string | undefined }): string | null {
  const image = (proc.path ?? proc.name)?.trim().toLowerCase();
  if (proc.pid !== undefined && image) return `${endpointKey}|${proc.pid}|${image}`;
  if (image) return `${endpointKey}|${image}`;
  if (proc.pid !== undefined) return `${endpointKey}|${proc.pid}`;
  if (proc.hashSha256) return `${endpointKey}|${proc.hashSha256.toLowerCase()}`;
  return null;
}

export function fileKey(endpointKey: string | null, path: string): string {
  const p = path.trim().toLowerCase();
  return endpointKey ? `${endpointKey}|${p}` : p;
}

/** Well-known built-in principals that carry no correlation value. */
export const NOISE_PRINCIPALS = new Set([
  "system",
  "nt authority\\system",
  "local service",
  "nt authority\\local service",
  "network service",
  "nt authority\\network service",
  "anonymous logon",
  "nt authority\\anonymous logon",
  "-",
  "root",
  "nobody",
]);

/**
 * Extract the entities of a single canonical event, in a deterministic order, de-duplicated.
 * Used by detection matches and correlation (graph ingestion builds the same keys).
 */
export function extractEntities(event: CanonicalEvent): EntityRef[] {
  const out = new Map<string, EntityRef>();
  const add = (ref: EntityRef | null) => {
    if (!ref) return;
    const id = `${ref.kind}:${ref.key}`;
    if (!out.has(id)) out.set(id, ref);
  };

  const ak = assetKey(event.asset);
  if (ak) add({ kind: event.cloudResource && event.asset?.cloudInstanceId ? "cloud_asset" : "endpoint", key: ak, label: assetLabel(event.asset, ak), role: "target" });

  const uk = userKey(event.user);
  if (uk) add({ kind: "user", key: uk, label: userLabel(event.user, uk), role: "actor" });
  const ik = identityKey(event);
  if (ik) add({ kind: "identity", key: ik, label: event.identity?.principal ?? ik, role: "actor" });
  if (event.process?.user) {
    const pk = userKey({ name: event.process.user });
    if (pk) add({ kind: "user", key: pk, label: event.process.user, role: "actor" });
  }

  if (ak && event.process) {
    const pk = processKey(ak, event.process);
    if (pk) add({ kind: "process", key: pk, label: event.process.name ?? event.process.path ?? pk, role: "actor" });
  }
  const hashes = [event.process?.hashSha256, event.file?.sha256, event.file?.md5].filter((h): h is string => !!h && /^[0-9a-f]+$/i.test(h));
  for (const h of hashes) add({ kind: "hash", key: h.toLowerCase(), label: h.toLowerCase(), role: "artifact" });
  if (event.file?.path) add({ kind: "file", key: fileKey(ak, event.file.path), label: event.file.path, role: "artifact" });

  const net = event.network;
  const srcIp = net?.srcIp ? normalizeIp(net.srcIp) : event.identity?.sourceIp ? normalizeIp(event.identity.sourceIp) : null;
  const dstIp = net?.dstIp ? normalizeIp(net.dstIp) : null;
  if (srcIp) add({ kind: "ip", key: srcIp, label: srcIp, role: "source" });
  if (dstIp) add({ kind: "ip", key: dstIp, label: dstIp, role: "destination" });
  for (const d of [net?.dnsQuery, net?.httpHost, net?.tlsSni]) {
    const dn = d ? normalizeDomain(d) : null;
    if (dn) add({ kind: "domain", key: dn, label: dn, role: "destination" });
  }
  if (net?.httpUrl) {
    const u = normalizeUrl(net.httpUrl);
    if (u) add({ kind: "url", key: u, label: u, role: "destination" });
  }

  for (const ind of event.indicators ?? []) {
    const k = indicatorKey(ind.type, ind.value);
    if (k) add({ kind: "indicator", key: k, label: ind.value, role: "observable" });
  }
  for (const t of event.attack ?? []) add({ kind: "technique", key: t.id.toUpperCase(), label: t.name ? `${t.id} ${t.name}` : t.id, role: "observable" });
  return [...out.values()];
}

/** True when an entity is useful for joining detections into one incident. */
export function isCorrelatableEntity(ref: EntityRef): boolean {
  if (ref.kind === "user" || ref.kind === "identity") {
    const bare = ref.key.includes(":") && ref.kind === "identity" ? ref.key.slice(ref.key.indexOf(":") + 1) : ref.key;
    return !NOISE_PRINCIPALS.has(bare);
  }
  if (ref.kind === "ip") return isPublicIp(ref.key);
  return true;
}
