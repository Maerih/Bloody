import { lookup } from "node:dns/promises";
import { SsrfBlockedError, type SsrfReason } from "../errors.js";
import { classifyIp, type IpRangeClass } from "./ip.js";

/**
 * SSRF guard for user-configured URLs (AI endpoints). Rules:
 *  - only http/https, no credentials embedded in the URL;
 *  - cloud metadata endpoints (169.254.169.254, fd00:ec2::254, metadata.google.internal, …)
 *    and every link-local / unspecified / multicast / reserved address are ALWAYS blocked;
 *  - loopback, RFC 1918, CGNAT, IPv6 ULA and internal hostnames (localhost, *.internal,
 *    single-label service names…) are allowed only when the tenant enabled
 *    `allowPrivate` (self-hosted / local models);
 *  - cloud providers additionally require https.
 *
 * `assertSafeEndpoint` validates the literal URL synchronously. `assertSafeEndpointResolved`
 * additionally resolves the hostname and validates every returned address (defeats DNS names
 * pointing at internal ranges). Callers must also disable redirects on the HTTP client.
 */

export const CLOUD_METADATA_HOSTNAMES = [
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data",
  "instance-data.ec2.internal",
  "metadata.azure.internal",
  "metadata.tencentyun.com",
  "metadata.packet.net",
] as const;

const INTERNAL_SUFFIXES = [".internal", ".local", ".localdomain", ".lan", ".home", ".home.arpa", ".intranet", ".corp", ".private"];

export type HostClass = IpRangeClass | "private_hostname" | "public_hostname";

export interface EndpointSafetyOptions {
  /** Tenant setting: permit loopback/private ranges (self-hosted models). Default false. */
  allowPrivate: boolean;
  /** Require TLS (always true for cloud providers). */
  requireHttps?: boolean;
}

export type EndpointCheck =
  | { ok: true; url: URL; hostClass: HostClass }
  | { ok: false; reason: SsrfReason; message: string };

function normalizeHost(hostname: string): string {
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  while (h.endsWith(".")) h = h.slice(0, -1);
  return h;
}

export function classifyHost(hostname: string): HostClass {
  const host = normalizeHost(hostname);
  const ipClass = classifyIp(host);
  if (ipClass) return ipClass;
  if ((CLOUD_METADATA_HOSTNAMES as readonly string[]).includes(host)) return "metadata";
  if (host === "localhost" || host.endsWith(".localhost")) return "loopback";
  if (!host.includes(".")) return "private_hostname";
  if (INTERNAL_SUFFIXES.some((s) => host.endsWith(s))) return "private_hostname";
  return "public_hostname";
}

function verdict(hostClass: HostClass, allowPrivate: boolean): { reason: SsrfReason; message: string } | null {
  switch (hostClass) {
    case "public":
    case "public_hostname":
      return null;
    case "metadata":
      return { reason: "metadata_endpoint", message: "Cloud metadata endpoints are never allowed" };
    case "link_local":
      return { reason: "link_local", message: "Link-local addresses are not allowed" };
    case "unspecified":
    case "multicast":
    case "broadcast":
    case "reserved":
      return { reason: "reserved_address", message: `Address range '${hostClass}' is not allowed` };
    case "loopback":
      return allowPrivate ? null : { reason: "loopback", message: "Loopback endpoints require the tenant 'allow private endpoints' setting" };
    case "private":
    case "cgnat":
    case "unique_local":
      return allowPrivate ? null : { reason: "private_address", message: "Private-network endpoints require the tenant 'allow private endpoints' setting" };
    case "private_hostname":
      return allowPrivate ? null : { reason: "private_hostname", message: "Internal hostnames require the tenant 'allow private endpoints' setting" };
  }
}

export function checkEndpoint(input: string | URL, options: EndpointSafetyOptions): EndpointCheck {
  let url: URL;
  try {
    url = typeof input === "string" ? new URL(input) : new URL(input.toString());
  } catch {
    return { ok: false, reason: "invalid_url", message: "Endpoint is not a valid absolute URL" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: "unsupported_scheme", message: `Scheme '${url.protocol}' is not allowed` };
  }
  if (url.username || url.password) {
    return { ok: false, reason: "credentials_in_url", message: "Credentials must not be embedded in the endpoint URL" };
  }
  if (!url.hostname) return { ok: false, reason: "invalid_url", message: "Endpoint has no host" };
  const hostClass = classifyHost(url.hostname);
  const blocked = verdict(hostClass, options.allowPrivate);
  if (blocked) return { ok: false, ...blocked };
  if (options.requireHttps && url.protocol !== "https:") {
    return { ok: false, reason: "https_required", message: "Cloud AI endpoints must use https" };
  }
  return { ok: true, url, hostClass };
}

/** Throws {@link SsrfBlockedError} when the endpoint is not allowed. Returns the parsed URL. */
export function assertSafeEndpoint(input: string | URL, options: EndpointSafetyOptions): URL {
  const res = checkEndpoint(input, options);
  if (!res.ok) throw new SsrfBlockedError(res.reason, res.message);
  return res.url;
}

export type HostResolver = (hostname: string) => Promise<string[]>;

export const systemHostResolver: HostResolver = async (hostname) => {
  const records = await lookup(hostname, { all: true, verbatim: true });
  return records.map((r) => r.address);
};

/**
 * Validate the URL and every address its hostname resolves to. Note: a resolver result is a
 * point-in-time answer; pair with short-lived connections (no redirects) for defence in depth.
 */
export async function assertSafeEndpointResolved(
  input: string | URL,
  options: EndpointSafetyOptions,
  resolver: HostResolver = systemHostResolver,
): Promise<URL> {
  const url = assertSafeEndpoint(input, options);
  const host = normalizeHost(url.hostname);
  if (classifyIp(host)) return url;
  let addresses: string[];
  try {
    addresses = await resolver(host);
  } catch {
    throw new SsrfBlockedError("unresolvable", `Endpoint host '${host}' could not be resolved`);
  }
  if (addresses.length === 0) throw new SsrfBlockedError("unresolvable", `Endpoint host '${host}' has no addresses`);
  for (const address of addresses) {
    const cls = classifyIp(address);
    if (!cls) throw new SsrfBlockedError("unresolvable", `Resolver returned a non-IP answer for '${host}'`);
    const blocked = verdict(cls, options.allowPrivate);
    if (blocked) throw new SsrfBlockedError(blocked.reason, `${blocked.message} (host '${host}' resolves to a ${cls} address)`);
  }
  return url;
}
