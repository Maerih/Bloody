import { IsolationMode } from "@bloody/contracts";
import { isIPv4, isIPv6 } from "../net/ip.js";
import { ResponseGuardError, type ResponseExecutionRequest } from "./types.js";

/**
 * Endpoint isolation policy (proprietary). Both modes ALWAYS keep the management path open — the
 * Bloody platform plus the engine manager that delivers commands (Wazuh manager, Velociraptor
 * server) — so an isolated endpoint can be released from the platform at any time.
 *
 *   lan  — drop traffic to/from local networks (RFC1918, CGNAT, link-local, IPv6 ULA/link-local)
 *          to stop lateral movement; the internet stays reachable.
 *   full — drop everything except the management path, DHCP and the listed DNS resolvers.
 *
 * The endpoint scripts (infra/agent/active-response/bloody-isolate{,.ps1}) implement exactly this.
 */
export const LOCAL_NETWORKS_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"] as const;
export const LOCAL_NETWORKS_V6 = ["fc00::/7", "fe80::/10"] as const;

export interface IsolationPolicy {
  mode: IsolationMode;
  /** Management addresses that stay reachable (IPs or CIDRs). Never empty. */
  allow: string[];
  /** DNS resolvers kept reachable in full mode (LAN mode keeps public DNS anyway). */
  dns: string[];
}

const MAX_ENTRIES = 32;

/** Strict IP / CIDR validation — no hostnames reach endpoint firewalls. */
export function isIpOrCidr(value: string): boolean {
  const [addr, bits, extra] = value.split("/");
  if (extra !== undefined || !addr) return false;
  const v4 = isIPv4(addr);
  const v6 = !v4 && isIPv6(addr);
  if (!v4 && !v6) return false;
  if (bits === undefined) return true;
  if (!/^\d{1,3}$/.test(bits)) return false;
  const n = Number(bits);
  return v4 ? n >= 8 && n <= 32 : n >= 16 && n <= 128;
}

function list(value: unknown, field: string): string[] {
  const raw = Array.isArray(value) ? value : typeof value === "string" ? value.split(",") : [];
  const out = [...new Set(raw.map((v) => String(v).trim()).filter(Boolean))];
  if (out.length > MAX_ENTRIES) throw new ResponseGuardError("invalid_parameters", `${field} accepts at most ${MAX_ENTRIES} entries`);
  for (const v of out) if (!isIpOrCidr(v)) throw new ResponseGuardError("invalid_parameters", `${field}: "${v}" is not an IP address or CIDR`);
  return out;
}

/**
 * Build the policy for an isolate request. `managementAllow` comes from the integration (the engine
 * manager + Bloody platform addresses); requests may add more but can never remove them.
 */
export function buildIsolationPolicy(req: Pick<ResponseExecutionRequest, "parameters">, managementAllow: readonly string[]): IsolationPolicy {
  const parsed = IsolationMode.safeParse(req.parameters["mode"] ?? "full");
  if (!parsed.success) throw new ResponseGuardError("invalid_parameters", 'parameters.mode must be "lan" or "full"');
  const base = list(managementAllow, "management allow-list");
  const allow = [...new Set([...base, ...list(req.parameters["allow"], "parameters.allow")])];
  if (allow.length === 0) {
    throw new ResponseGuardError("invalid_parameters", "isolation needs the platform/manager addresses (integration isolationAllow) so the endpoint can be released later");
  }
  return { mode: parsed.data, allow, dns: list(req.parameters["dns"], "parameters.dns") };
}

/** Arguments for the endpoint script: `isolate <mode> allow=<csv> [dns=<csv>]` / `release`. */
export function isolationScriptArgs(policy: IsolationPolicy | "release"): string[] {
  if (policy === "release") return ["release"];
  // block4/block6 carry the precomputed block ranges for Windows (Linux nftables ignores them).
  const block = isolationBlockRanges(policy);
  return [
    "isolate",
    policy.mode,
    `allow=${policy.allow.join(",")}`,
    ...(policy.dns.length ? [`dns=${policy.dns.join(",")}`] : []),
    `block4=${block.v4.join(",")}`,
    ...(block.v6.length ? [`block6=${block.v6.join(",")}`] : []),
  ];
}

// ─── Block-range computation (Windows Firewall: block rules always beat allow rules, so the
// exceptions must be carved out of the blocked ranges themselves) ─────────────────────────────

type Range = [bigint, bigint];

function v4ToBig(ip: string): bigint {
  return ip.split(".").reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n);
}
function bigToV4(n: bigint): string {
  return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join(".");
}
function v6ToBig(ip: string): bigint {
  const [head, tail] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : [];
  const groups = tail !== undefined ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || "0", 16)), 0n);
}
function bigToV6(n: bigint): string {
  const groups = Array.from({ length: 8 }, (_, i) => ((n >> BigInt((7 - i) * 16)) & 0xffffn).toString(16));
  return groups.join(":"); // uncompressed form: unambiguous for Windows Firewall
}
function cidrRange(cidr: string): { v6: boolean; range: Range } {
  const [addr, bitsRaw] = cidr.split("/");
  const v6 = addr!.includes(":");
  const width = v6 ? 128n : 32n;
  const bits = BigInt(bitsRaw ?? (v6 ? 128 : 32));
  const base = v6 ? v6ToBig(addr!) : v4ToBig(addr!);
  const hostBits = width - bits;
  const start = (base >> hostBits) << hostBits;
  return { v6, range: [start, start + (1n << hostBits) - 1n] };
}
function subtract(ranges: Range[], holes: Range[]): Range[] {
  let out = ranges.map((r) => [...r] as Range);
  for (const [hs, he] of holes) {
    const next: Range[] = [];
    for (const [s, e] of out) {
      if (he < s || hs > e) next.push([s, e]);
      else {
        if (hs > s) next.push([s, hs - 1n]);
        if (he < e) next.push([he + 1n, e]);
      }
    }
    out = next;
  }
  return out;
}

const ALWAYS_EXEMPT = ["127.0.0.0/8", "0.0.0.0/32", "255.255.255.255/32", "::1/128"];

/**
 * Address ranges an endpoint must BLOCK for a policy: the scope (local networks for "lan", every
 * address for "full") minus the management/DNS addresses, loopback and DHCP broadcast. Returned as
 * Windows-Firewall-style ranges ("a-b" or single addresses).
 */
export function isolationBlockRanges(policy: IsolationPolicy): { v4: string[]; v6: string[] } {
  const scope4 = policy.mode === "full" ? ["0.0.0.0/0"] : [...LOCAL_NETWORKS_V4];
  const scope6 = policy.mode === "full" ? ["::/0"] : [...LOCAL_NETWORKS_V6];
  const holes = [...policy.allow, ...policy.dns, ...ALWAYS_EXEMPT].map(cidrRange);
  const fmt = (v6: boolean) => ([s, e]: Range) => {
    const f = v6 ? bigToV6 : bigToV4;
    return s === e ? f(s) : `${f(s)}-${f(e)}`;
  };
  const v4 = subtract(scope4.map((c) => cidrRange(c).range), holes.filter((h) => !h.v6).map((h) => h.range)).map(fmt(false));
  const v6 = subtract(scope6.map((c) => cidrRange(c).range), holes.filter((h) => h.v6).map((h) => h.range)).map(fmt(true));
  return { v4, v6 };
}
