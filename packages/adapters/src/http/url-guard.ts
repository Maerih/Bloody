import { classifyIp, type IpClass } from "../net/ip.js";

/**
 * SSRF guard for engine base URLs and webhook targets.
 *
 * Engine endpoints are tenant-supplied configuration in a multi-tenant SaaS, so a URL such as
 * `http://169.254.169.254/latest/meta-data/` or `http://kubernetes.default.svc/` must never
 * be fetched from the control plane. The policy is deny-by-default:
 *
 *  - only `https:` (plain `http:` only with `allowHttp`, e.g. a lab or an mTLS sidecar);
 *  - no credentials embedded in the URL (secrets live in the credential store);
 *  - link-local, cloud metadata, multicast, broadcast, unspecified, reserved and
 *    documentation addresses are ALWAYS refused, as are metadata host names;
 *  - loopback only with `allowLoopback`; RFC 1918 / ULA / CGNAT and internal DNS suffixes
 *    (`.internal`, `.svc`, `.cluster.local`, `.local`, single-label names) only with
 *    `allowPrivateNetworks` — set for on-prem relays / customer-site collectors, never for
 *    SaaS-hosted integrations;
 *  - host names are additionally checked after DNS resolution ({@link assertResolvedSafe}).
 *    DNS rebinding between this check and the connection remains possible, so production
 *    deployments must also enforce an egress network policy; redirects are never followed.
 */
export interface UrlPolicy {
  allowHttp?: boolean;
  allowPrivateNetworks?: boolean;
  allowLoopback?: boolean;
  /** When non-empty the host must equal one of these or end with ".<entry>" for "*.<entry>". */
  allowedHosts?: readonly string[];
  deniedHosts?: readonly string[];
  allowedPorts?: readonly number[];
}

export type UnsafeUrlReason =
  | "invalid_url"
  | "scheme_not_allowed"
  | "credentials_in_url"
  | "host_not_allowed"
  | "metadata_host"
  | "loopback"
  | "private_network"
  | "blocked_address_class"
  | "port_not_allowed"
  | "dns_resolution_failed";

export class UnsafeUrlError extends Error {
  readonly code = "unsafe_url";
  constructor(
    readonly reason: UnsafeUrlReason,
    message: string,
  ) {
    super(message);
    this.name = "UnsafeUrlError";
  }
}

const METADATA_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data",
  "instance-data.ec2.internal",
  "metadata.azure.com",
  "metadata.tencentyun.com",
]);
const INTERNAL_SUFFIXES = [".internal", ".svc", ".cluster.local", ".local", ".localdomain", ".lan", ".home.arpa", ".intranet", ".corp"];
const ALWAYS_BLOCKED: ReadonlySet<IpClass> = new Set(["link_local", "metadata", "multicast", "broadcast", "unspecified", "reserved", "documentation"]);

function hostMatches(host: string, pattern: string): boolean {
  const p = pattern.toLowerCase();
  if (p.startsWith("*.")) return host.endsWith(p.slice(1)) && host.length > p.length - 1;
  return host === p;
}

/** Check one resolved/literal address against the policy. */
export function checkAddress(ip: string, policy: UrlPolicy): void {
  const cls = classifyIp(ip);
  if (!cls) throw new UnsafeUrlError("invalid_url", `not an IP address: ${ip}`);
  if (cls === "metadata") throw new UnsafeUrlError("metadata_host", "cloud metadata endpoints are never reachable from integrations");
  if (ALWAYS_BLOCKED.has(cls)) throw new UnsafeUrlError("blocked_address_class", `address class "${cls}" is not reachable from integrations`);
  if (cls === "loopback" && !policy.allowLoopback) throw new UnsafeUrlError("loopback", "loopback addresses require allowLoopback");
  if ((cls === "private" || cls === "shared") && !policy.allowPrivateNetworks) {
    throw new UnsafeUrlError("private_network", "private network addresses require allowPrivateNetworks (on-prem relay)");
  }
}

/** Synchronous structural validation. Returns the parsed URL. */
export function validateEngineUrl(input: string, policy: UrlPolicy = {}): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UnsafeUrlError("invalid_url", "invalid URL");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && policy.allowHttp)) {
    throw new UnsafeUrlError("scheme_not_allowed", `scheme ${url.protocol} not allowed (https required)`);
  }
  if (url.username || url.password) throw new UnsafeUrlError("credentials_in_url", "credentials must not be embedded in URLs");
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  const bare = host.startsWith("[") ? host.slice(1, -1) : host;
  if (host === "") throw new UnsafeUrlError("invalid_url", "URL has no host");
  if (policy.deniedHosts?.some((p) => hostMatches(host, p))) throw new UnsafeUrlError("host_not_allowed", `host ${host} is denied`);
  if (policy.allowedHosts && policy.allowedHosts.length > 0 && !policy.allowedHosts.some((p) => hostMatches(host, p))) {
    throw new UnsafeUrlError("host_not_allowed", `host ${host} is not in the allow-list`);
  }
  if (policy.allowedPorts && policy.allowedPorts.length > 0) {
    const p = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
    if (!policy.allowedPorts.includes(p)) throw new UnsafeUrlError("port_not_allowed", `port ${p} not allowed`);
  }
  if (classifyIp(bare)) {
    checkAddress(bare, policy);
    return url;
  }
  if (METADATA_HOSTS.has(host)) throw new UnsafeUrlError("metadata_host", "cloud metadata endpoints are never reachable from integrations");
  if (host === "localhost" || host.endsWith(".localhost")) {
    if (!policy.allowLoopback) throw new UnsafeUrlError("loopback", "localhost requires allowLoopback");
    return url;
  }
  const internalName = !host.includes(".") || INTERNAL_SUFFIXES.some((s) => host.endsWith(s));
  if (internalName && !policy.allowPrivateNetworks) {
    throw new UnsafeUrlError("private_network", `internal host name ${host} requires allowPrivateNetworks`);
  }
  return url;
}

export type HostResolver = (hostname: string) => Promise<string[]>;

/** Resolve the URL's host and check every address (defeats DNS names pointing inside). */
export async function assertResolvedSafe(url: URL, policy: UrlPolicy, resolve: HostResolver): Promise<string[]> {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (classifyIp(host)) {
    checkAddress(host, policy);
    return [host];
  }
  let addresses: string[];
  try {
    addresses = await resolve(host);
  } catch (err) {
    throw new UnsafeUrlError("dns_resolution_failed", `could not resolve ${host}: ${(err as Error).message}`);
  }
  if (addresses.length === 0) throw new UnsafeUrlError("dns_resolution_failed", `${host} resolved to no addresses`);
  for (const a of addresses) checkAddress(a, policy);
  return addresses;
}

/** Default resolver backed by the OS resolver (all A/AAAA records). */
export const systemResolver: HostResolver = async (hostname) => {
  const { lookup } = await import("node:dns/promises");
  const res = await lookup(hostname, { all: true, verbatim: true });
  return res.map((r) => r.address);
};

const SENSITIVE_QUERY = /(token|key|secret|pass(word)?|auth|sig(nature)?|session|credential|code)/i;

/** URL safe to log/audit: no userinfo, sensitive query values masked. */
export function redactUrl(input: string | URL): string {
  try {
    const u = new URL(input.toString());
    u.username = "";
    u.password = "";
    for (const k of [...u.searchParams.keys()]) if (SENSITIVE_QUERY.test(k)) u.searchParams.set(k, "***");
    return u.toString();
  } catch {
    return "[invalid-url]";
  }
}
