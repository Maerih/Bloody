import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";
import { SsrfBlockedError } from "../util/errors.js";

/**
 * SSRF guard for user-supplied destinations (webhooks, Slack/Teams URLs, syslog hosts).
 *
 * Always blocked: unspecified, link-local (incl. cloud metadata 169.254.169.254 and
 * fd00:ec2::254), multicast, broadcast, reserved/benchmark/documentation ranges and metadata
 * host names. Blocked unless explicitly allowed: loopback and private networks (RFC 1918,
 * CGNAT, ULA) — syslog collectors usually live on private networks, webhooks never should.
 *
 * Checks run twice: statically on the URL (literal IPs never hit DNS) and on every DNS answer
 * at connect time through {@link createGuardedLookup}, which defeats DNS-rebinding.
 */
export interface SsrfPolicy {
  allowPrivateNetworks?: boolean;
  allowLoopback?: boolean;
  /** Permit plain http:// (default false — https only). */
  allowHttp?: boolean;
  /** If set, the hostname must equal or end with one of these suffixes (e.g. "hooks.slack.com"). */
  allowedHostSuffixes?: readonly string[];
}

interface Cidr {
  bytes: number[];
  prefix: number;
  label: string;
  kind: "always" | "private" | "loopback";
}

function v4(addr: string): number[] | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  return bytes.every((b) => Number.isInteger(b) && b >= 0 && b <= 255) ? bytes : null;
}

function v6(addr: string): number[] | null {
  let a = addr.toLowerCase();
  const zone = a.indexOf("%");
  if (zone !== -1) a = a.slice(0, zone);
  let tail: number[] = [];
  const lastColon = a.lastIndexOf(":");
  if (a.includes(".") && lastColon !== -1) {
    const four = v4(a.slice(lastColon + 1));
    if (!four) return null;
    tail = four;
    a = `${a.slice(0, lastColon)}:0:0`;
  }
  const halves = a.split("::");
  if (halves.length > 2) return null;
  const parseGroups = (s: string): number[] | null => {
    if (s === "") return [];
    const groups = s.split(":");
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parseGroups(halves[0] ?? "");
  const rest = halves.length === 2 ? parseGroups(halves[1] ?? "") : [];
  if (!head || !rest) return null;
  const missing = 8 - head.length - rest.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...head, ...new Array<number>(halves.length === 2 ? missing : 0).fill(0), ...rest];
  const bytes: number[] = [];
  for (const g of groups) bytes.push(g >> 8, g & 0xff);
  if (tail.length === 4) bytes.splice(12, 4, ...tail);
  return bytes.length === 16 ? bytes : null;
}

function cidr(text: string, label: string, kind: Cidr["kind"]): Cidr {
  const [addr, len] = text.split("/");
  const bytes = (addr!.includes(":") ? v6(addr!) : v4(addr!))!;
  return { bytes, prefix: Number(len), label, kind };
}

const V4_RANGES: Cidr[] = [
  cidr("0.0.0.0/8", "unspecified/this-network", "always"),
  cidr("169.254.0.0/16", "link-local / cloud metadata", "always"),
  cidr("192.0.0.0/24", "IETF protocol assignments", "always"),
  cidr("192.0.2.0/24", "documentation (TEST-NET-1)", "always"),
  cidr("198.18.0.0/15", "benchmarking", "always"),
  cidr("198.51.100.0/24", "documentation (TEST-NET-2)", "always"),
  cidr("203.0.113.0/24", "documentation (TEST-NET-3)", "always"),
  cidr("224.0.0.0/4", "multicast", "always"),
  cidr("240.0.0.0/4", "reserved / broadcast", "always"),
  cidr("127.0.0.0/8", "loopback", "loopback"),
  cidr("10.0.0.0/8", "private (RFC 1918)", "private"),
  cidr("172.16.0.0/12", "private (RFC 1918)", "private"),
  cidr("192.168.0.0/16", "private (RFC 1918)", "private"),
  cidr("100.64.0.0/10", "carrier-grade NAT", "private"),
  cidr("192.88.99.0/24", "6to4 relay anycast", "always"),
];

const V6_RANGES: Cidr[] = [
  cidr("::/128", "unspecified", "always"),
  cidr("fd00:ec2::254/128", "AWS metadata (IPv6)", "always"),
  cidr("fe80::/10", "link-local", "always"),
  cidr("ff00::/8", "multicast", "always"),
  cidr("2001:db8::/32", "documentation", "always"),
  cidr("100::/64", "discard-only", "always"),
  cidr("::1/128", "loopback", "loopback"),
  cidr("fc00::/7", "unique local (private)", "private"),
];

function inCidr(bytes: number[], c: Cidr): boolean {
  if (bytes.length !== c.bytes.length) return false;
  let bits = c.prefix;
  for (let i = 0; i < bytes.length && bits > 0; i++) {
    const take = Math.min(8, bits);
    const mask = (0xff << (8 - take)) & 0xff;
    if ((bytes[i]! & mask) !== (c.bytes[i]! & mask)) return false;
    bits -= take;
  }
  return true;
}

export interface AddressVerdict {
  blocked: boolean;
  reason?: string;
}

/** Classify a literal IPv4/IPv6 address against the policy. Unparseable input is blocked. */
export function checkAddress(address: string, policy: SsrfPolicy = {}): AddressVerdict {
  const family = isIP(address.replace(/^\[|\]$/g, "").split("%")[0] ?? "");
  const raw = address.replace(/^\[|\]$/g, "");
  if (family === 4) return verdict(v4(raw), V4_RANGES, policy, raw);
  if (family === 6) {
    const bytes = v6(raw);
    if (!bytes) return { blocked: true, reason: `unparseable address ${raw}` };
    // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::/96) embed IPv4.
    const isMapped = bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
    const isCompat = bytes.slice(0, 12).every((b) => b === 0) && !(bytes[12] === 0 && bytes[13] === 0 && bytes[14] === 0 && (bytes[15] ?? 0) <= 1);
    const isNat64 = bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && bytes.slice(4, 12).every((b) => b === 0);
    if (isMapped || isCompat || isNat64) {
      const embedded = bytes.slice(12).join(".");
      const inner = verdict(v4(embedded), V4_RANGES, policy, embedded);
      return inner.blocked ? { blocked: true, reason: `${inner.reason} (embedded in ${raw})` } : inner;
    }
    return verdict(bytes, V6_RANGES, policy, raw);
  }
  return { blocked: true, reason: `"${address}" is not an IP address` };
}

function verdict(bytes: number[] | null, ranges: Cidr[], policy: SsrfPolicy, raw: string): AddressVerdict {
  if (!bytes) return { blocked: true, reason: `unparseable address ${raw}` };
  for (const r of ranges) {
    if (!inCidr(bytes, r)) continue;
    if (r.kind === "always") return { blocked: true, reason: `${raw} is in a forbidden range (${r.label})` };
    if (r.kind === "loopback" && !policy.allowLoopback) return { blocked: true, reason: `${raw} is a loopback address` };
    if (r.kind === "private" && !policy.allowPrivateNetworks) return { blocked: true, reason: `${raw} is in a private range (${r.label})` };
    return { blocked: false };
  }
  return { blocked: false };
}

const BLOCKED_HOSTNAMES = new Set(["localhost", "metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal", "kubernetes.default", "kubernetes.default.svc"]);

/** Static hostname checks (no DNS). */
export function checkHostname(hostname: string, policy: SsrfPolicy = {}): AddressVerdict {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host.length === 0) return { blocked: true, reason: "empty host" };
  if (isIP(host.replace(/^\[|\]$/g, ""))) return checkAddress(host, policy);
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith(".localhost")) {
    if (!(policy.allowLoopback && (host === "localhost" || host.endsWith(".localhost")))) return { blocked: true, reason: `host "${host}" is not allowed` };
  }
  if (!policy.allowPrivateNetworks && (host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".svc") || host.endsWith(".cluster.local") || !host.includes("."))) {
    return { blocked: true, reason: `host "${host}" looks like an internal name` };
  }
  if (policy.allowedHostSuffixes && policy.allowedHostSuffixes.length > 0) {
    const ok = policy.allowedHostSuffixes.some((s) => {
      const suffix = s.toLowerCase().replace(/^\./, "");
      return host === suffix || host.endsWith(`.${suffix}`);
    });
    if (!ok) return { blocked: true, reason: `host "${host}" is not an allowed destination (${policy.allowedHostSuffixes.join(", ")})` };
  }
  return { blocked: false };
}

/** Validate a destination URL statically. Throws {@link SsrfBlockedError}. */
export function assertSafeUrl(rawUrl: string, policy: SsrfPolicy = {}): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfBlockedError("invalid URL");
  }
  if (url.protocol !== "https:" && !(policy.allowHttp && url.protocol === "http:")) {
    throw new SsrfBlockedError(`scheme ${url.protocol} is not allowed${policy.allowHttp ? "" : " (https only)"}`);
  }
  if (url.username || url.password) throw new SsrfBlockedError("credentials in URLs are not allowed");
  const v = checkHostname(url.hostname, policy);
  if (v.blocked) throw new SsrfBlockedError(v.reason ?? "destination blocked", { host: url.hostname });
  return url;
}

export type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | { address: string; family: number }[], family?: number) => void;
export type LookupFunction = (hostname: string, options: { all?: boolean; family?: number } | number, callback: LookupCallback) => void;

/**
 * `lookup` for http/https/net/tls/dgram that refuses forbidden answers at connect time.
 * Every resolved address must pass; one bad answer blocks the whole lookup.
 */
export function createGuardedLookup(policy: SsrfPolicy = {}, baseLookup: LookupFunction = dnsLookup as unknown as LookupFunction): LookupFunction {
  return (hostname, options, callback) => {
    const opts = typeof options === "number" ? { family: options } : options ?? {};
    baseLookup(hostname, { ...opts, all: true }, (err, addresses) => {
      if (err) {
        callback(err, opts.all ? [] : "", undefined);
        return;
      }
      const list = Array.isArray(addresses) ? addresses : [{ address: addresses, family: isIP(addresses) }];
      if (list.length === 0) {
        callback(Object.assign(new Error(`no addresses for ${hostname}`), { code: "ENOTFOUND" }), opts.all ? [] : "", undefined);
        return;
      }
      for (const a of list) {
        const v = checkAddress(a.address, policy);
        if (v.blocked) {
          callback(new SsrfBlockedError(`${hostname} resolved to a blocked address: ${v.reason}`, { host: hostname }) as unknown as NodeJS.ErrnoException, opts.all ? [] : "", undefined);
          return;
        }
      }
      if (opts.all) callback(null, list);
      else callback(null, list[0]!.address, list[0]!.family);
    });
  };
}
