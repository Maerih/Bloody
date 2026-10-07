/**
 * IPv4/IPv6 parsing, CIDR containment and address classification. Implemented from the
 * RFCs (791, 4291, 5952, 1918, 6598, 4193) — no third-party code.
 */

export type ParsedIp = { version: 4; value: bigint } | { version: 6; value: bigint };

export function parseIPv4(input: string): number | null {
  const parts = input.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null; // reject ambiguous octal-looking octets
    const n = Number(part);
    if (n > 255) return null;
    out = out * 256 + n;
  }
  return out;
}

export function parseIPv6(input: string): bigint | null {
  let s = input.trim().toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (s.length === 0 || !/^[0-9a-f:.]+$/.test(s)) return null;

  // Embedded IPv4 tail (e.g. ::ffff:10.0.0.1)
  let tailV4: number | null = null;
  const lastColon = s.lastIndexOf(":");
  if (s.includes(".")) {
    tailV4 = parseIPv4(s.slice(lastColon + 1));
    if (tailV4 === null) return null;
    s = `${s.slice(0, lastColon + 1)}${((tailV4 >>> 16) & 0xffff).toString(16)}:${(tailV4 & 0xffff).toString(16)}`;
  }

  const doubleColon = s.indexOf("::");
  if (doubleColon !== s.lastIndexOf("::")) return null;
  let groups: string[];
  if (doubleColon >= 0) {
    const head = s.slice(0, doubleColon) === "" ? [] : s.slice(0, doubleColon).split(":");
    const tail = s.slice(doubleColon + 2) === "" ? [] : s.slice(doubleColon + 2).split(":");
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
  } else {
    groups = s.split(":");
  }
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    value = (value << 16n) | BigInt(parseInt(g, 16));
  }
  return value;
}

export function parseIp(input: string): ParsedIp | null {
  const s = input.trim();
  const v4 = parseIPv4(s);
  if (v4 !== null) return { version: 4, value: BigInt(v4) };
  const v6 = parseIPv6(s);
  if (v6 === null) return null;
  // Normalise IPv4-mapped IPv6 (::ffff:a.b.c.d) to IPv4 so both spellings resolve to one entity.
  if (v6 >> 32n === 0xffffn) return { version: 4, value: v6 & 0xffffffffn };
  return { version: 6, value: v6 };
}

export function isIp(input: string): boolean {
  return parseIp(input) !== null;
}

/** Canonical text form: dotted quad for v4, RFC 5952 compressed lowercase for v6. */
export function normalizeIp(input: string): string | null {
  const ip = parseIp(input);
  if (!ip) return null;
  if (ip.version === 4) {
    const n = Number(ip.value);
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((ip.value >> BigInt(i * 16)) & 0xffffn));
  // longest run of zeros (length ≥ 2) is compressed
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(":");
  const head = hex.slice(0, bestStart).join(":");
  const tail = hex.slice(bestStart + bestLen).join(":");
  return `${head}::${tail}`;
}

export interface Cidr {
  version: 4 | 6;
  network: bigint;
  prefix: number;
}

export function parseCidr(input: string): Cidr | null {
  const [addr, prefixText, extra] = input.trim().split("/");
  if (extra !== undefined || addr === undefined) return null;
  const ip = parseIp(addr);
  if (!ip) return null;
  const bits = ip.version === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? bits : /^\d{1,3}$/.test(prefixText) ? Number(prefixText) : NaN;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  const mask = prefixMask(bits, prefix);
  return { version: ip.version, network: ip.value & mask, prefix };
}

function prefixMask(bits: number, prefix: number): bigint {
  if (prefix === 0) return 0n;
  const all = (1n << BigInt(bits)) - 1n;
  return all ^ ((1n << BigInt(bits - prefix)) - 1n);
}

export function cidrContains(cidr: Cidr | string, ip: string): boolean {
  const c = typeof cidr === "string" ? parseCidr(cidr) : cidr;
  const addr = parseIp(ip);
  if (!c || !addr || c.version !== addr.version) return false;
  const bits = c.version === 4 ? 32 : 128;
  return (addr.value & prefixMask(bits, c.prefix)) === c.network;
}

const NON_PUBLIC_RANGES = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "::/128",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8",
].map((c) => parseCidr(c) as Cidr);

/** True for private, loopback, link-local, CGNAT, multicast and reserved space. */
export function isNonPublicIp(ip: string): boolean {
  return NON_PUBLIC_RANGES.some((c) => cidrContains(c, ip));
}

export function isPublicIp(ip: string): boolean {
  return isIp(ip) && !isNonPublicIp(ip);
}
