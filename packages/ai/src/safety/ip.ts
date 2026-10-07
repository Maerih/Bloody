/**
 * IP address parsing and range classification used by the SSRF guard. Written from the
 * IANA special-purpose registries (RFC 6890 and successors); no third-party code.
 */

export type IpRangeClass =
  | "public"
  | "loopback"
  | "private"
  | "cgnat"
  | "link_local"
  | "unique_local"
  | "metadata"
  | "unspecified"
  | "multicast"
  | "broadcast"
  | "reserved";

/** Cloud instance-metadata / credential endpoints. Always blocked, whatever the tenant setting. */
export const CLOUD_METADATA_IPV4 = [
  "169.254.169.254", // AWS / Azure / GCP / OCI / DigitalOcean IMDS
  "169.254.170.2", // AWS ECS task credentials
  "169.254.169.253", // AWS VPC DNS (link-local, never a model endpoint)
  "169.254.169.123", // AWS time sync
  "100.100.100.200", // Alibaba Cloud metadata
  "192.0.0.192", // Oracle Cloud metadata (legacy)
] as const;

export const CLOUD_METADATA_IPV6 = ["fd00:ec2::254"] as const;

export function parseIPv4(input: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(input);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const part = m[i]!;
    if (part.length > 1 && part.startsWith("0")) return null; // reject ambiguous octal-looking octets
    const octet = Number(part);
    if (octet > 255) return null;
    n = n * 256 + octet;
  }
  return n >>> 0;
}

export function formatIPv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/** Parse an IPv6 address (optionally bracketed, with zone id / embedded IPv4) into 8 hextets. */
export function parseIPv6(input: string): number[] | null {
  let s = input.trim();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(":")) return null;

  let tailV4: number[] = [];
  const lastColon = s.lastIndexOf(":");
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const v4 = parseIPv4(maybeV4);
    if (v4 === null) return null;
    tailV4 = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    s = s.slice(0, lastColon + 1) + "0:0"; // placeholder hextets, replaced below
  }

  const doubleColon = s.indexOf("::");
  if (doubleColon !== s.lastIndexOf("::")) return null;
  let head: string[];
  let tail: string[];
  if (doubleColon >= 0) {
    head = s.slice(0, doubleColon) ? s.slice(0, doubleColon).split(":") : [];
    tail = s.slice(doubleColon + 2) ? s.slice(doubleColon + 2).split(":") : [];
  } else {
    head = s.split(":");
    tail = [];
  }
  const parts = [...head, ...tail];
  if (parts.some((p) => !/^[0-9a-fA-F]{1,4}$/.test(p))) return null;
  const missing = 8 - parts.length;
  if (doubleColon >= 0 ? missing < 1 : missing !== 0) return null;
  const groups = [
    ...head.map((h) => parseInt(h, 16)),
    ...new Array<number>(doubleColon >= 0 ? missing : 0).fill(0),
    ...tail.map((t) => parseInt(t, 16)),
  ];
  if (groups.length !== 8) return null;
  if (tailV4.length === 2) {
    groups[6] = tailV4[0]!;
    groups[7] = tailV4[1]!;
  }
  return groups;
}

function inRange(n: number, base: string, prefix: number): boolean {
  const b = parseIPv4(base)!;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (n & mask) >>> 0 === (b & mask) >>> 0;
}

const METADATA_V4 = new Set<number>(CLOUD_METADATA_IPV4.map((ip) => parseIPv4(ip)!));

export function classifyIPv4(n: number): IpRangeClass {
  if (METADATA_V4.has(n)) return "metadata";
  if (n === 0xffffffff) return "broadcast";
  if (inRange(n, "0.0.0.0", 8)) return "unspecified";
  if (inRange(n, "127.0.0.0", 8)) return "loopback";
  if (inRange(n, "10.0.0.0", 8) || inRange(n, "172.16.0.0", 12) || inRange(n, "192.168.0.0", 16)) return "private";
  if (inRange(n, "100.64.0.0", 10)) return "cgnat";
  if (inRange(n, "169.254.0.0", 16)) return "link_local";
  if (inRange(n, "224.0.0.0", 4)) return "multicast";
  if (
    inRange(n, "192.0.0.0", 24) || // IETF protocol assignments
    inRange(n, "192.0.2.0", 24) || // TEST-NET-1
    inRange(n, "198.51.100.0", 24) || // TEST-NET-2
    inRange(n, "203.0.113.0", 24) || // TEST-NET-3
    inRange(n, "192.88.99.0", 24) || // 6to4 relay anycast
    inRange(n, "198.18.0.0", 15) || // benchmarking
    inRange(n, "240.0.0.0", 4) // future use
  ) {
    return "reserved";
  }
  return "public";
}

const METADATA_V6 = CLOUD_METADATA_IPV6.map((ip) => parseIPv6(ip)!);

export function classifyIPv6(g: readonly number[]): IpRangeClass {
  if (g.length !== 8) return "reserved";
  const at = (i: number): number => g[i] ?? 0;
  if (METADATA_V6.some((m) => m.every((v, i) => v === at(i)))) return "metadata";
  const zeroUpTo = (k: number): boolean => g.slice(0, k).every((v) => v === 0);
  if (g.every((v) => v === 0)) return "unspecified";
  if (zeroUpTo(7) && at(7) === 1) return "loopback";
  const embedded = (hi: number, lo: number): IpRangeClass => classifyIPv4(((hi << 16) >>> 0) + lo);
  // IPv4-mapped ::ffff:a.b.c.d and deprecated IPv4-compatible ::a.b.c.d
  if (zeroUpTo(5) && at(5) === 0xffff) return embedded(at(6), at(7));
  if (zeroUpTo(6)) return embedded(at(6), at(7));
  // NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
  if (at(0) === 0x64 && at(1) === 0xff9b && at(2) === 0 && at(3) === 0 && at(4) === 0 && at(5) === 0) return embedded(at(6), at(7));
  if (at(0) === 0x64 && at(1) === 0xff9b && at(2) === 1) return "private";
  // 6to4 2002:AABB:CCDD::/48 embeds an IPv4 address
  if (at(0) === 0x2002) {
    const cls = embedded(at(1), at(2));
    return cls === "public" ? "public" : cls;
  }
  // Teredo 2001:0000::/32 — client IPv4 is the bitwise NOT of the last 32 bits
  if (at(0) === 0x2001 && at(1) === 0) {
    const cls = embedded(~at(6) & 0xffff, ~at(7) & 0xffff);
    return cls === "public" ? "reserved" : cls;
  }
  if ((at(0) & 0xffc0) === 0xfe80) return "link_local";
  if ((at(0) & 0xffc0) === 0xfec0) return "private"; // deprecated site-local
  if ((at(0) & 0xfe00) === 0xfc00) return "unique_local";
  if ((at(0) & 0xff00) === 0xff00) return "multicast";
  if (at(0) === 0x2001 && at(1) === 0x0db8) return "reserved"; // documentation
  if (at(0) === 0x0100 && at(1) === 0 && at(2) === 0 && at(3) === 0) return "reserved"; // discard-only
  if ((at(0) & 0xe000) === 0x2000) return "public"; // 2000::/3 global unicast
  return "reserved";
}

/** Classify an IP literal; returns null when `addr` is not an IP address. */
export function classifyIp(addr: string): IpRangeClass | null {
  const v4 = parseIPv4(addr);
  if (v4 !== null) return classifyIPv4(v4);
  const v6 = parseIPv6(addr);
  if (v6 !== null) return classifyIPv6(v6);
  return null;
}
