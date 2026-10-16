import { z } from "zod";

/**
 * Patch Compliance (VM, proprietary). The SCIAT Agent reports what its operating system says is
 * waiting to be installed (Windows Update, apt, dnf/yum, zypper, macOS Software Update), whether a
 * restart is pending, and when updates were last installed and looked for. The platform adds the
 * operating system's vendor support status and how long security updates have been outstanding,
 * and grades every computer against the patch SLA.
 */

const text = (max: number) => z.string().trim().max(max);
const opt = (max: number) => text(max).nullish().transform((v) => (v ? v : null));

export const PATCH_SEVERITIES = ["critical", "important", "moderate", "low", "unspecified"] as const;
export type PatchSeverity = (typeof PATCH_SEVERITIES)[number];

export const PendingUpdate = z.object({
  title: text(400).min(1),
  /** Windows KB number, or the package name on Linux. */
  id: opt(200),
  /** Version that will be installed (Linux / macOS). */
  version: opt(200),
  security: z.boolean().default(false),
  severity: z
    .string()
    .trim()
    .toLowerCase()
    .nullish()
    .transform((v): PatchSeverity => ((PATCH_SEVERITIES as readonly string[]).includes(v ?? "") ? (v as PatchSeverity) : "unspecified")),
});
export type PendingUpdate = z.output<typeof PendingUpdate>;

export const HostPatchStatus = z.object({
  source: z.enum(["windows_update", "apt", "dnf", "yum", "zypper", "softwareupdate"]),
  pending: z.array(PendingUpdate).max(1000).default([]),
  rebootRequired: z.boolean().nullish().transform((v) => v ?? null),
  /** When updates were last installed, ISO-8601 (null when the OS does not say). */
  lastInstalledAt: opt(40),
  /** When the OS last looked for updates (an old date means the list may be stale). */
  lastCheckedAt: opt(40),
  /** The OS could not list updates (no network, broken package manager…). */
  error: opt(500),
});
export type HostPatchStatus = z.output<typeof HostPatchStatus>;

// ---- Operating-system lifecycle -------------------------------------------------------------

export type OsSupportStatus = "supported" | "ending_soon" | "ended" | "unknown";
export interface OsSupport {
  product: string;
  /** Last day of security updates (YYYY-MM-DD), null when unknown or not announced. */
  endsOn: string | null;
  status: OsSupportStatus;
  note: string | null;
}

/** Security updates end within this many days → ending_soon. */
export const OS_ENDING_SOON_DAYS = 120;

const WIN11_BUILDS: Array<[number, string, string, string]> = [
  // build, version, Home/Pro end, Enterprise/Education end
  [22000, "21H2", "2023-10-10", "2024-10-08"],
  [22621, "22H2", "2024-10-08", "2025-10-14"],
  [22631, "23H2", "2025-11-11", "2026-11-10"],
  [26100, "24H2", "2026-10-13", "2027-10-12"],
  [26200, "25H2", "2027-10-12", "2028-10-10"],
];
const WIN_SERVER: Array<[RegExp, string, string]> = [
  [/server 2025/, "Windows Server 2025", "2034-10-10"],
  [/server 2022/, "Windows Server 2022", "2031-10-14"],
  [/server 2019/, "Windows Server 2019", "2029-01-09"],
  [/server 2016/, "Windows Server 2016", "2027-01-12"],
  [/server 2012/, "Windows Server 2012 / 2012 R2", "2023-10-10"],
  [/server 2008/, "Windows Server 2008 / 2008 R2", "2020-01-14"],
];
const UBUNTU: Record<string, string> = {
  "16.04": "2021-04-30",
  "18.04": "2023-05-31",
  "20.04": "2025-05-29",
  "22.04": "2027-06-01",
  "24.04": "2029-05-31",
  "24.10": "2025-07-10",
  "25.04": "2026-01-15",
  "25.10": "2026-07-09",
  "26.04": "2031-05-31",
};
// Debian: until the end of Debian LTS.
const DEBIAN: Record<string, string> = { "9": "2022-06-30", "10": "2024-06-30", "11": "2026-08-31", "12": "2028-06-30", "13": "2030-06-30" };
const RHEL_LIKE: Record<string, string> = { "6": "2020-11-30", "7": "2024-06-30", "8": "2029-05-31", "9": "2032-05-31", "10": "2035-05-31" };
// macOS: Apple patches the current release and the two before it. macOS 27 shipped in September 2026.
const MACOS_SUPPORTED_FROM = 15;

function verdict(product: string, endsOn: string | null, now: Date, note: string | null = null): OsSupport {
  if (!endsOn) return { product, endsOn: null, status: "supported", note };
  const days = (Date.parse(`${endsOn}T23:59:59Z`) - now.getTime()) / 86_400_000;
  return { product, endsOn, status: days < 0 ? "ended" : days <= OS_ENDING_SOON_DAYS ? "ending_soon" : "supported", note };
}

/** Vendor support status of an operating system, from the name the agent reports. */
export function osSupport(os: string | null | undefined, now: Date = new Date()): OsSupport {
  const s = (os ?? "").toLowerCase();
  if (!s) return { product: "Unknown", endsOn: null, status: "unknown", note: null };
  if (s.includes("windows")) {
    for (const [re, product, end] of WIN_SERVER) if (re.test(s)) return verdict(product, end, now);
    const build = Number(/10\.0\.(\d{5})/.exec(s)?.[1] ?? 0);
    const enterprise = /enterprise|education/.test(s);
    if (/windows 11/.test(s) || build >= 22000) {
      const known = [...WIN11_BUILDS].reverse().find(([b]) => build >= b);
      if (!known) return { product: "Windows 11", endsOn: null, status: "unknown", note: null };
      const [b, version, homePro, ent] = known;
      // A later feature update than this table lists (e.g. 26H2): supported, date not known here.
      if (b === WIN11_BUILDS.at(-1)![0] && build >= b + 100) return verdict(`Windows 11 (build ${build})`, null, now, "A newer release than SCIAT's lifecycle table");
      return verdict(`Windows 11 ${version}${enterprise ? " Enterprise / Education" : ""}`, enterprise ? ent : homePro, now, "Install the latest feature update to stay supported");
    }
    if (/windows 10/.test(s) || build >= 10240) {
      if (/ltsc 2021|ltsc.*19044/.test(s) || (/ltsc/.test(s) && build === 19044)) return verdict("Windows 10 Enterprise LTSC 2021", /iot/.test(s) ? "2032-01-13" : "2027-01-12", now);
      if (/ltsc/.test(s) && build === 17763) return verdict("Windows 10 Enterprise LTSC 2019", "2029-01-09", now);
      if (/ltsb/.test(s) && build === 14393) return verdict("Windows 10 Enterprise LTSB 2016", "2026-10-13", now);
      return verdict("Windows 10", "2025-10-14", now, "Only computers enrolled in Extended Security Updates (ESU) still get fixes");
    }
    if (/windows (7|8|vista|xp)/.test(s)) return verdict(`Windows ${/windows (7|8\.1|8|vista|xp)/.exec(s)![1]}`, "2023-01-10", now);
    return { product: os!.trim(), endsOn: null, status: "unknown", note: null };
  }
  let m = /ubuntu (\d+\.\d+)/.exec(s);
  if (m) {
    const end = UBUNTU[m[1]!];
    return end ? verdict(`Ubuntu ${m[1]}`, end, now) : { product: `Ubuntu ${m[1]}`, endsOn: null, status: "unknown", note: null };
  }
  m = /debian gnu\/linux (\d+)/.exec(s);
  if (m) return DEBIAN[m[1]!] ? verdict(`Debian ${m[1]}`, DEBIAN[m[1]!]!, now, "Includes Debian LTS") : { product: `Debian ${m[1]}`, endsOn: null, status: "unknown", note: null };
  m = /(red hat enterprise linux|rocky linux|almalinux|oracle linux|centos linux)[^\d]*(\d+)/.exec(s);
  if (m) {
    const name = m[1]!.replace(/\b\w/g, (c) => c.toUpperCase()).replace("Almalinux", "AlmaLinux").replace("Centos", "CentOS");
    const end = m[1] === "centos linux" ? ({ "7": "2024-06-30", "8": "2021-12-31" } as Record<string, string>)[m[2]!] : RHEL_LIKE[m[2]!];
    return end ? verdict(`${name} ${m[2]}`, end, now) : { product: `${name} ${m[2]}`, endsOn: null, status: "unknown", note: null };
  }
  m = /centos stream (\d+)/.exec(s);
  if (m) return verdict(`CentOS Stream ${m[1]}`, ({ "8": "2024-05-31", "9": "2027-05-31", "10": "2030-01-01" } as Record<string, string>)[m[1]!] ?? null, now);
  m = /macos (\d+)/.exec(s);
  if (m) {
    const major = Number(m[1]);
    return major >= MACOS_SUPPORTED_FROM
      ? verdict(`macOS ${major}`, null, now, "Apple supports the current macOS and the two before it")
      : { product: `macOS ${major}`, endsOn: null, status: "ended", note: "Apple no longer releases security updates for this version" };
  }
  return { product: os!.trim(), endsOn: null, status: "unknown", note: null };
}

// ---- Grading -------------------------------------------------------------------------------

/** Security updates outstanding longer than this breach the patch SLA. */
export const PATCH_SLA_DAYS = 30;
/** An update list older than this is stale (the computer has not looked for updates). */
export const PATCH_STALE_CHECK_DAYS = 14;

export type PatchState = "current" | "behind" | "breached" | "unknown";

export interface PatchGrade {
  state: PatchState;
  reasons: string[];
}

/** Grade one computer: breached (SLA missed or OS unsupported), behind, current or unknown. */
export function gradePatching(input: { status: HostPatchStatus | null; os: OsSupport; securityPendingSince: string | null; now: Date }): PatchGrade {
  const { status, os, now } = input;
  const reasons: string[] = [];
  let state: PatchState = "current";
  const worse = (s: PatchState) => {
    const rank: Record<PatchState, number> = { current: 0, unknown: 1, behind: 2, breached: 3 };
    if (rank[s] > rank[state]) state = s;
  };
  if (os.status === "ended") {
    worse("breached");
    reasons.push(`${os.product} no longer gets security updates${os.endsOn ? ` (since ${os.endsOn})` : ""}`);
  } else if (os.status === "ending_soon") {
    reasons.push(`${os.product} stops getting security updates on ${os.endsOn}`);
  }
  if (!status) {
    worse("unknown");
    reasons.push("The agent has not reported update status yet");
    return { state, reasons };
  }
  if (status.error) {
    worse("unknown");
    reasons.push(`Could not list updates: ${status.error}`);
  }
  const security = status.pending.filter((p) => p.security);
  const critical = security.filter((p) => p.severity === "critical");
  if (security.length) {
    const days = input.securityPendingSince ? Math.floor((now.getTime() - Date.parse(input.securityPendingSince)) / 86_400_000) : 0;
    if (days >= PATCH_SLA_DAYS) {
      worse("breached");
      reasons.push(`${security.length} security update${security.length === 1 ? "" : "s"} outstanding for ${days} days (SLA ${PATCH_SLA_DAYS})`);
    } else {
      worse("behind");
      reasons.push(`${security.length} security update${security.length === 1 ? "" : "s"} waiting${critical.length ? `, ${critical.length} critical` : ""}`);
    }
  }
  if (status.rebootRequired) {
    worse("behind");
    reasons.push("Restart needed to finish installing updates");
  }
  if (status.lastCheckedAt) {
    const age = (now.getTime() - Date.parse(status.lastCheckedAt)) / 86_400_000;
    if (age > PATCH_STALE_CHECK_DAYS) {
      worse("behind");
      reasons.push(`Has not looked for updates in ${Math.floor(age)} days`);
    }
  }
  const other = status.pending.length - security.length;
  if (other > 0 && !security.length) reasons.push(`${other} non-security update${other === 1 ? "" : "s"} available`);
  return { state, reasons };
}

/** GET /patching/overview: one row per computer. */
export interface PatchEndpoint {
  agentId: string;
  hostname: string;
  os: string | null;
  osSupport: OsSupport;
  source: HostPatchStatus["source"] | null;
  pendingCount: number;
  securityCount: number;
  criticalCount: number;
  rebootRequired: boolean | null;
  lastInstalledAt: string | null;
  lastCheckedAt: string | null;
  securityPendingSince: string | null;
  reportedAt: string | null;
  grade: PatchGrade;
  pending: PendingUpdate[];
}

export interface MissingUpdate {
  title: string;
  id: string | null;
  security: boolean;
  severity: PatchSeverity;
  endpoints: number;
}
