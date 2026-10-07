/**
 * IP address parsing and classification (IPv4 + IPv6), written for two jobs:
 *
 *  1. Normalization — deciding traffic direction (inbound / outbound / lateral) and which
 *     addresses are worth emitting as threat-intel indicators (never RFC 1918 space).
 *  2. SSRF defence — refusing to let a tenant-supplied engine URL reach loopback,
 *     link-local, cloud metadata or (unless explicitly allowed) private networks.
 *
 * Parsing is strict: dotted-quad IPv4 only (no octal/hex/short forms — the WHATWG URL parser
 * already canonicalizes those inside URLs before they reach us), RFC 4291 IPv6 text forms
 * including `::` compression, embedded IPv4 tails and zone ids.
 */

export type IpClass =
  | "public"
  | "private"
  | "shared"
  | "loopback"
  | "link_local"
  | "metadata"
  | "multicast"
  | "broadcast"
  | "unspecified"
  | "documentation"
  | "reserved";

export function parseIPv4(input: string): [number, number, number, number] | undefined {
  const parts = input.split(".");
  if (parts.length !== 4) return undefined;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return undefined;
    if (p.length > 1 && p.startsWith("0")) return undefined; // ambiguous octal form
    const n = Number(p);
    if (n > 255) return undefined;
    out.push(n);
  }
  return out as [number, number, number, number];
}

/** Eight 16-bit groups, or undefined when not a valid IPv6 literal. Accepts brackets and zone ids. */
export function parseIPv6(input: string): number[] | undefined {
  let s = input.trim();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(":")) return undefined;

  // Rewrite an embedded dotted IPv4 tail ("::ffff:1.2.3.4") as two hex groups.
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseIPv4(tail);
    if (!v4) return undefined;
    s = `${s.slice(0, lastColon + 1)}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }

  const halves = s.split("::");
  if (halves.length > 2) return undefined;
  const parseGroups = (part: string): number[] | undefined => {
    if (part === "") return [];
    const out: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return undefined;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  };
  const head = parseGroups(halves[0] ?? "");
  const rest = halves.length === 2 ? parseGroups(halves[1] ?? "") : [];
  if (!head || !rest) return undefined;
  if (halves.length === 1) return head.length === 8 ? head : undefined;
  const fill = 8 - head.length - rest.length;
  if (fill < 1) return undefined;
  return [...head, ...new Array<number>(fill).fill(0), ...rest];
}

export function isIPv4(input: string): boolean {
  return parseIPv4(input) !== undefined;
}

export function isIPv6(input: string): boolean {
  return parseIPv6(input) !== undefined;
}

export function isIp(input: string): boolean {
  return isIPv4(input) || isIPv6(input);
}

function v4ToInt(o: readonly number[]): number {
  return (((o[0] ?? 0) << 24) >>> 0) + ((o[1] ?? 0) << 16) + ((o[2] ?? 0) << 8) + (o[3] ?? 0);
}

function inV4(ip: number, base: string, prefix: number): boolean {
  const b = parseIPv4(base);
  if (!b) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((ip & mask) >>> 0) === ((v4ToInt(b) & mask) >>> 0);
}

/** Cloud / container metadata endpoints. Always blocked for outbound engine calls. */
const METADATA_V4 = new Set(["169.254.169.254", "169.254.170.2", "169.254.169.253", "100.100.100.200", "192.0.0.192"]);

const V4_TABLE: Array<[string, number, IpClass]> = [
  ["0.0.0.0", 8, "reserved"],
  ["10.0.0.0", 8, "private"],
  ["100.64.0.0", 10, "shared"],
  ["127.0.0.0", 8, "loopback"],
  ["169.254.0.0", 16, "link_local"],
  ["172.16.0.0", 12, "private"],
  ["192.0.0.0", 24, "reserved"],
  ["192.0.2.0", 24, "documentation"],
  ["192.88.99.0", 24, "reserved"],
  ["192.168.0.0", 16, "private"],
  ["198.18.0.0", 15, "reserved"],
  ["198.51.100.0", 24, "documentation"],
  ["203.0.113.0", 24, "documentation"],
  ["224.0.0.0", 4, "multicast"],
  ["240.0.0.0", 4, "reserved"],
];

function classifyV4(o: readonly number[]): IpClass {
  const text = o.join(".");
  if (METADATA_V4.has(text)) return "metadata";
  if (text === "0.0.0.0") return "unspecified";
  if (text === "255.255.255.255") return "broadcast";
  const n = v4ToInt(o);
  for (const [base, prefix, cls] of V4_TABLE) if (inV4(n, base, prefix)) return cls;
  return "public";
}

function classifyV6(g: readonly number[]): IpClass {
  const at = (i: number): number => g[i] ?? 0;
  if (g.every((x) => x === 0)) return "unspecified";
  if (g.slice(0, 7).every((x) => x === 0) && at(7) === 1) return "loopback";
  // fd00:ec2::254 — AWS IMDS over IPv6
  if (at(0) === 0xfd00 && at(1) === 0x0ec2 && g.slice(2, 7).every((x) => x === 0) && at(7) === 0x254) return "metadata";
  const embedded = (hi: number, lo: number): IpClass => classifyV4([hi >> 8, hi & 0xff, lo >> 8, lo & 0xff]);
  // ::ffff:a.b.c.d (IPv4-mapped) and ::a.b.c.d (deprecated IPv4-compatible)
  if (g.slice(0, 5).every((x) => x === 0) && (at(5) === 0xffff || at(5) === 0)) return embedded(at(6), at(7));
  // 64:ff9b::/96 NAT64
  if (at(0) === 0x64 && at(1) === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return embedded(at(6), at(7));
  // 2002::/16 6to4 carries an IPv4 in groups 1-2
  if (at(0) === 0x2002) return embedded(at(1), at(2));
  if ((at(0) & 0xffc0) === 0xfe80) return "link_local";
  if ((at(0) & 0xffc0) === 0xfec0) return "private"; // deprecated site-local
  if ((at(0) & 0xfe00) === 0xfc00) return "private"; // ULA fc00::/7
  if ((at(0) & 0xff00) === 0xff00) return "multicast";
  if (at(0) === 0x2001 && at(1) === 0x0db8) return "documentation";
  if (at(0) === 0x0100 && at(1) === 0 && at(2) === 0 && at(3) === 0) return "reserved"; // discard-only
  if (at(0) === 0x2001 && at(1) === 0) return "reserved"; // Teredo tunnelling
  if ((at(0) & 0xe000) === 0x2000) return "public"; // global unicast 2000::/3
  return "reserved";
}

/** Classify an IP literal; undefined when the input is not an IP address. */
export function classifyIp(input: string): IpClass | undefined {
  const s = input.trim();
  const v4 = parseIPv4(s);
  if (v4) return classifyV4(v4);
  const v6 = parseIPv6(s);
  if (v6) return classifyV6(v6);
  return undefined;
}

/** Addresses inside an organization's own network space. */
export function isInternalIp(ip: string): boolean {
  const c = classifyIp(ip);
  return c === "private" || c === "shared" || c === "loopback" || c === "link_local" || c === "metadata";
}

/**
 * Addresses outside the organization: real public space plus RFC 5737 / RFC 3849
 * documentation ranges (which analysts and test data use as "the internet").
 */
export function isExternalIp(ip: string): boolean {
  const c = classifyIp(ip);
  return c === "public" || c === "documentation";
}

/** Traffic direction from the organization's point of view. */
export function inferDirection(src: string | undefined, dst: string | undefined): "inbound" | "outbound" | "lateral" | "unknown" {
  if (!src || !dst) return "unknown";
  const si = isInternalIp(src);
  const di = isInternalIp(dst);
  const se = isExternalIp(src);
  const de = isExternalIp(dst);
  if (si && di) return "lateral";
  if (si && de) return "outbound";
  if (se && di) return "inbound";
  return "unknown";
}

/** Split "1.2.3.4:443" / "[2001:db8::1]:443" / "host:443" into host and port. */
export function splitHostPort(input: string): { host: string; port?: number } {
  const s = input.trim();
  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
  if (bracket) return bracket[2] ? { host: bracket[1] ?? "", port: Number(bracket[2]) } : { host: bracket[1] ?? "" };
  if (isIPv6(s)) return { host: s };
  const idx = s.lastIndexOf(":");
  if (idx > 0 && /^\d+$/.test(s.slice(idx + 1))) {
    const p = Number(s.slice(idx + 1));
    if (p <= 65535) return { host: s.slice(0, idx), port: p };
  }
  return { host: s };
}
