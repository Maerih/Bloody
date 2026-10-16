/**
 * External Exposure (ESPM, proprietary). The SCIAT Agent reveals the public address each office or
 * home network reaches the internet from; once an administrator confirms an address belongs to the
 * organization (and has recorded an authorization to test it), SCIAT checks it from the internet for
 * services that should never be exposed: remote desktop, file sharing, databases, admin consoles.
 */

export type ExposureSeverity = "critical" | "high" | "medium";

export interface ExposurePort {
  port: number;
  service: string;
  severity: ExposureSeverity;
  /** Why it matters, in plain language. */
  risk: string;
  /** What to do about it. */
  fix: string;
}

const VPN = "Close the port on the firewall; reach it through a VPN or zero-trust gateway with MFA instead.";
const DB = "Never expose a database to the internet: close the port and allow only the application servers that need it.";

export const EXPOSURE_PORTS: ExposurePort[] = [
  { port: 3389, service: "Remote Desktop (RDP)", severity: "critical", risk: "The most common way ransomware crews break in: password spraying and RDP exploits.", fix: VPN },
  { port: 445, service: "SMB file sharing", severity: "critical", risk: "Windows file sharing on the internet allows worm-style exploitation (EternalBlue, WannaCry) and credential theft.", fix: "Block TCP 445 at the edge; share files through a VPN or a cloud file service." },
  { port: 139, service: "NetBIOS session", severity: "high", risk: "Legacy Windows sharing that leaks host and user information.", fix: "Block TCP 139 at the edge." },
  { port: 135, service: "Microsoft RPC", severity: "high", risk: "Windows RPC exposes management interfaces used for lateral movement and exploits.", fix: "Block TCP 135 at the edge." },
  { port: 23, service: "Telnet", severity: "critical", risk: "Unencrypted remote login: passwords cross the internet in clear text and default credentials are scanned constantly.", fix: "Disable Telnet and use SSH (with keys) through a VPN." },
  { port: 21, service: "FTP", severity: "high", risk: "Unencrypted file transfer; credentials are sent in clear text and anonymous access is often left on.", fix: "Replace with SFTP or a managed file-transfer service, and close TCP 21." },
  { port: 5900, service: "VNC remote control", severity: "critical", risk: "Remote control of a desktop, frequently with weak or no password.", fix: VPN },
  { port: 5985, service: "WinRM (HTTP)", severity: "high", risk: "Windows remote management lets anyone with a password run commands on the server.", fix: VPN },
  { port: 5986, service: "WinRM (HTTPS)", severity: "high", risk: "Windows remote management lets anyone with a password run commands on the server.", fix: VPN },
  { port: 22, service: "SSH", severity: "medium", risk: "Remote shell access attracts constant password guessing.", fix: "Allow key-based login only, restrict source addresses, or move behind a VPN." },
  { port: 389, service: "LDAP", severity: "high", risk: "Directory service exposed: account and group enumeration, and a path to domain controllers.", fix: "Close TCP 389; directory services must stay inside the network." },
  { port: 636, service: "LDAPS", severity: "medium", risk: "Directory service exposed to the internet.", fix: "Close TCP 636 unless a cloud service genuinely needs it, then restrict by source address." },
  { port: 88, service: "Kerberos", severity: "high", risk: "A domain controller is reachable from the internet.", fix: "Close TCP 88; domain controllers must never be internet-facing." },
  { port: 1433, service: "Microsoft SQL Server", severity: "high", risk: "Databases on the internet are brute-forced and exploited for data theft and ransomware.", fix: DB },
  { port: 3306, service: "MySQL / MariaDB", severity: "high", risk: "Databases on the internet are brute-forced and exploited for data theft and ransomware.", fix: DB },
  { port: 5432, service: "PostgreSQL", severity: "high", risk: "Databases on the internet are brute-forced and exploited for data theft and ransomware.", fix: DB },
  { port: 1521, service: "Oracle database", severity: "high", risk: "Databases on the internet are brute-forced and exploited for data theft and ransomware.", fix: DB },
  { port: 27017, service: "MongoDB", severity: "critical", risk: "Often deployed without authentication; exposed instances are wiped and held for ransom within hours.", fix: DB },
  { port: 6379, service: "Redis", severity: "critical", risk: "Usually unauthenticated; attackers use it to write files and take over the server.", fix: DB },
  { port: 9200, service: "Elasticsearch", severity: "critical", risk: "Often unauthenticated; a frequent source of large data leaks.", fix: DB },
  { port: 11211, service: "Memcached", severity: "high", risk: "Unauthenticated cache that leaks data and is abused for DDoS amplification.", fix: DB },
  { port: 2375, service: "Docker API (unencrypted)", severity: "critical", risk: "Anyone can start containers on the host and take it over.", fix: "Close TCP 2375; manage Docker locally or over TLS with client certificates through a VPN." },
  { port: 10000, service: "Webmin", severity: "high", risk: "Server administration console with a history of remotely exploitable flaws.", fix: VPN },
  { port: 8291, service: "MikroTik Winbox", severity: "high", risk: "Router management exposed; exploited at scale to build botnets.", fix: "Disable Winbox on the WAN interface and manage the router from inside the network." },
  { port: 161, service: "SNMP (TCP)", severity: "medium", risk: "Network-device management that leaks configuration, often with default community strings.", fix: "Disable SNMP on the internet-facing interface." },
];

export function exposurePort(port: number): ExposurePort | undefined {
  return EXPOSURE_PORTS.find((p) => p.port === port);
}

export const SEVERITY_ORDER: Record<ExposureSeverity, number> = { critical: 0, high: 1, medium: 2 };

function v4(ip: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n <= 255) ? parts : null;
}

/**
 * Only globally routable unicast addresses may be checked: never private, loopback, link-local,
 * carrier-grade NAT, multicast, documentation or otherwise reserved ranges.
 */
export function isPublicAddress(ip: string): boolean {
  const kind = v4(ip) ? 4 : /^[0-9a-fA-F:.]+$/.test(ip) && ip.includes(":") && ip.split("::").length <= 2 ? 6 : 0;
  if (kind === 4) {
    const p = v4(ip);
    if (!p) return false;
    const [a, b, c] = p as [number, number, number, number];
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // carrier-grade NAT
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
    if (a === 192 && b === 88 && c === 99) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && c === 100) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  if (kind === 6) {
    const lower = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return isPublicAddress(mapped[1]!);
    // Global unicast is 2000::/3; exclude documentation (2001:db8::/32), 6to4 relay and Teredo/ORCHID blocks.
    const first = parseInt(lower.split(":")[0] || "0", 16);
    if (Number.isNaN(first) || first < 0x2000 || first > 0x3fff) return false;
    if (lower.startsWith("2001:db8:") || lower.startsWith("2001:0db8:")) return false;
    if (/^2001:0{0,3}:/.test(lower) || /^2001:0{0,2}1[0-9a-f]:/.test(lower) || lower.startsWith("2002:")) return false;
    return true;
  }
  return false;
}

/** IPv4-mapped IPv6 (how Node reports IPv4 clients on dual-stack sockets) back to plain IPv4. */
export function normalizeAddress(ip: string): string {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return (m ? m[1]! : ip).toLowerCase();
}

export type ExposureTargetStatus = "discovered" | "confirmed" | "ignored";

export interface ExposureTarget {
  id: string;
  ip: string;
  source: "agent" | "manual";
  status: ExposureTargetStatus;
  note: string | null;
  hostnames: string[];
  firstSeenAt: string;
  lastSeenAt: string | null;
  lastScannedAt: string | null;
  openPorts: number;
}

export interface ExposureFinding {
  ip: string;
  port: number;
  service: string;
  severity: ExposureSeverity;
  risk: string;
  fix: string;
  hostnames: string[];
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface ExposureAuthorization {
  reference: string;
  authorizedBy: string | null;
  authorizedAt: string;
  expiresAt: string;
  valid: boolean;
}

export interface ExposureScan {
  id: string;
  status: "running" | "finished" | "failed";
  trigger: "manual" | "schedule";
  startedAt: string;
  finishedAt: string | null;
  addresses: number;
  openPorts: number;
  error: string | null;
}
