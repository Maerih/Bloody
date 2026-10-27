import { z } from "zod";

/**
 * Persistent Footholds (EDR, proprietary). Attackers who get onto a computer make sure they come
 * back after a reboot: a Run key, a scheduled task, a service, a launch daemon, a cron job, an SSH
 * key. The SCIAT Agent reports every autostart entry it finds; the platform remembers what each
 * computer started with (its baseline), points out entries that appear later, and grades each
 * entry on traits attackers rely on (temp folders, encoded PowerShell, download-and-run, unsigned
 * programs, look-alike system names). Analysts mark entries as expected or malicious, per
 * organization, so the same software on a hundred computers is reviewed once.
 */

export const AUTORUN_KINDS = [
  "run_key",
  "startup_folder",
  "scheduled_task",
  "service",
  "wmi_subscription",
  "winlogon",
  "ifeo",
  "launch_agent",
  "launch_daemon",
  "cron",
  "systemd",
  "init_script",
  "shell_profile",
  "preload",
  "ssh_key",
] as const;
export type AutorunKind = (typeof AUTORUN_KINDS)[number];

export const AUTORUN_KIND_LABELS: Record<AutorunKind, string> = {
  run_key: "Run key",
  startup_folder: "Startup folder",
  scheduled_task: "Scheduled task",
  service: "Service",
  wmi_subscription: "WMI subscription",
  winlogon: "Winlogon",
  ifeo: "Debugger hijack (IFEO)",
  launch_agent: "Launch agent",
  launch_daemon: "Launch daemon",
  cron: "Cron job",
  systemd: "systemd unit",
  init_script: "Init script",
  shell_profile: "Shell profile",
  preload: "Library preload",
  ssh_key: "SSH authorized key",
};

const text = (max: number) => z.string().trim().max(max);
const opt = (max: number) => text(max).nullish().transform((v) => (v ? v : null));

export const HostAutorun = z.object({
  kind: z.enum(AUTORUN_KINDS),
  /** Where it is registered: registry key, file, task path, unit file… */
  location: text(500).min(1),
  name: text(300).min(1),
  /** What it runs (command line, program path or, for an SSH key, "type comment …tail"). */
  command: opt(2000),
  /** Account it belongs to or runs as. */
  user: opt(200),
  /** Windows Authenticode: signed by a trusted publisher (null when not checked). */
  signed: z.boolean().nullish().transform((v) => v ?? null),
  signer: opt(300),
});
export type HostAutorun = z.output<typeof HostAutorun>;

/**
 * Stable identity of an entry across computers and reports: kind, location, name and command,
 * case-insensitive, with per-user parts of paths (C:\Users\amina, /home/amina) folded so the same
 * software installed for different people groups together. 16 hex characters (cyrb53, not a
 * security hash — it only groups rows).
 */
export function footholdFingerprint(a: Pick<HostAutorun, "kind" | "location" | "name" | "command">): string {
  const fold = (s: string | null) =>
    (s ?? "")
      .toLowerCase()
      .replace(/([a-z]:\\users\\)[^\\]+/g, "$1*")
      .replace(/(\/(?:home|users))\/[^/\s]+/g, "$1/*")
      .replace(/\b(hkey_users|hku)\\s-1-5-21-[\d-]+/g, "hku\\*")
      .replace(/\s+/g, " ")
      .trim();
  const input = [a.kind, fold(a.location), fold(a.name), fold(a.command)].join("\u0000");
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h2 = Math.imul(h2 ^ c, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h2 >>> 0).toString(16).padStart(8, "0") + (h1 >>> 0).toString(16).padStart(8, "0");
}

export type FootholdLevel = "high" | "medium" | "low";
export interface FootholdAssessment {
  score: number;
  level: FootholdLevel;
  reasons: Array<{ points: number; text: string }>;
}

interface Trait {
  points: number;
  text: string;
  test: (cmd: string, a: HostAutorun) => boolean;
}

const SYSTEM_NAMES = ["svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "smss.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe"];

const TRAITS: Trait[] = [
  {
    points: 45,
    text: "Encoded or obfuscated PowerShell",
    test: (c) => /powershell|pwsh/.test(c) && /(\s-e(nc(odedcommand)?)?\s|frombase64string|\biex\b|invoke-expression)/.test(c),
  },
  {
    points: 20,
    text: "PowerShell with a hidden window",
    test: (c) => /powershell|pwsh/.test(c) && /\s-w(indowstyle)?\s+(hidden|1)\b/.test(c),
  },
  {
    points: 40,
    text: "Downloads and runs code from the internet",
    test: (c) =>
      /(downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer|net\.webclient)/.test(c) ||
      /(curl|wget)[^|;&]*\|\s*(ba|z|da)?sh\b/.test(c) ||
      /(certutil(\.exe)?\s+.*-urlcache|bitsadmin(\.exe)?\s+.*\/transfer)/.test(c) ||
      /(mshta(\.exe)?\s+["']?(https?:|javascript:|vbscript:))/.test(c) ||
      /regsvr32(\.exe)?\s+.*\/i:\s*https?:/.test(c),
  },
  {
    points: 20,
    text: "Contacts a bare IP address",
    test: (c) => /(https?|ftp):\/\/\d{1,3}(\.\d{1,3}){3}\b|\/dev\/(tcp|udp)\/\d{1,3}(\.\d{1,3}){3}\//.test(c),
  },
  {
    points: 60,
    text: "Opens a remote shell",
    test: (c) => /(\/dev\/tcp\/|\bnc(at)?\s+(-\w+\s+)*-e\b|\bsocat\b.*exec:|bash\s+-i\s+>&|python[\d.]*\s+-c\s+.*socket)/.test(c),
  },
  {
    points: 35,
    text: "Runs from a temporary or user-writable folder",
    test: (c) => /(\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\downloads\\|\\\$recycle\.bin\\|(^|[\s"'])\/(tmp|var\/tmp|dev\/shm)\/|\/downloads\/)/.test(c),
  },
  {
    points: 15,
    text: "Runs from AppData or ProgramData",
    test: (c) => /\\appdata\\(roaming|local)\\(?!microsoft\\(teams|onedrive|edge)|programs\\)|\\programdata\\(?!microsoft\\)/.test(c) && !/\\appdata\\local\\temp\\/.test(c),
  },
  {
    points: 25,
    text: "Script host or living-off-the-land binary",
    test: (c) => /\b(wscript|cscript|mshta|regsvr32|rundll32|msbuild|installutil|cmstp|odbcconf)(\.exe)?\b/.test(c) && !/\\windows\\system32\\rundll32\.exe\s+[^,]*\\windows\\/.test(c),
  },
  {
    points: 15,
    text: "Starts a script file (.vbs, .js, .hta, .bat, .ps1…)",
    test: (c) => /\.(vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1|scr)\b(?!\w)/.test(c),
  },
  {
    points: 30,
    text: "Double file extension",
    test: (c) => /\.(pdf|docx?|xlsx?|jpg|png|txt|zip)\.(exe|scr|com|bat|js|vbs)\b/.test(c),
  },
  {
    points: 40,
    text: "Look-alike of a Windows system program outside System32",
    // A bare "explorer.exe" (Winlogon Shell) is the normal value; a path outside Windows is not.
    test: (c) => SYSTEM_NAMES.some((n) => c.includes(`\\${n}`) || c.includes(`/${n}`)) && !/\\windows\\(system32|syswow64)\\/.test(c) && !/[a-z]:\\windows\\explorer\.exe/.test(c),
  },
  {
    points: 20,
    text: "Program is not signed by a trusted publisher",
    test: (_c, a) => a.signed === false,
  },
  {
    points: 15,
    text: "Hidden file or folder",
    test: (c, a) => /(^|\/)\.[a-z0-9_-]+\/[^\s]*/.test(c) && !/\/\.(local|config|cargo|nvm|pyenv|rbenv|sdkman)\//.test(c) && a.kind !== "ssh_key",
  },
  {
    points: 30,
    text: "Hijacks program start-up (debugger or library preload)",
    test: (_c, a) => a.kind === "ifeo" || a.kind === "preload",
  },
  {
    points: 40,
    text: "Backdoor on an accessibility tool (opens a shell at the sign-in screen)",
    test: (c, a) => a.kind === "ifeo" && /^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$/i.test(a.name),
  },
  {
    points: 25,
    text: "WMI event subscription (rarely legitimate)",
    test: (_c, a) => a.kind === "wmi_subscription",
  },
  {
    points: 15,
    text: "Grants remote sign-in with an SSH key",
    test: (_c, a) => a.kind === "ssh_key",
  },
  {
    points: 20,
    text: "Grants remote sign-in to root",
    test: (_c, a) => a.kind === "ssh_key" && /^root$/i.test(a.user ?? ""),
  },
];

/** Grade one autostart entry; ≥60 high, ≥30 medium. */
export function assessFoothold(a: HostAutorun): FootholdAssessment {
  const cmd = ` ${(a.command ?? a.name).toLowerCase()} `;
  const reasons = TRAITS.filter((t) => t.test(cmd, a)).map(({ points, text }) => ({ points, text }));
  const score = Math.min(100, reasons.reduce((s, r) => s + r.points, 0));
  return { score, level: score >= 60 ? "high" : score >= 30 ? "medium" : "low", reasons: reasons.sort((x, y) => y.points - x.points) };
}

export const FOOTHOLD_VERDICTS = ["expected", "malicious"] as const;
export type FootholdVerdict = (typeof FOOTHOLD_VERDICTS)[number];

/** PUT /footholds/verdicts */
export const FootholdVerdictInput = z
  .object({
    organizationId: z.guid(),
    fingerprints: z.array(z.string().regex(/^[0-9a-f]{16}$/)).min(1).max(200),
    /** null clears the verdict. */
    verdict: z.enum(FOOTHOLD_VERDICTS).nullable(),
    note: text(500).optional(),
  })
  .strict();
export type FootholdVerdictInput = z.infer<typeof FootholdVerdictInput>;

/** One entry as GET /footholds/overview lists it: the same entry on every computer, grouped. */
export interface Foothold {
  fingerprint: string;
  kind: AutorunKind;
  location: string;
  name: string;
  command: string | null;
  signer: string | null;
  signed: boolean | null;
  assessment: FootholdAssessment;
  verdict: { verdict: FootholdVerdict; note: string | null; by: string | null; at: string } | null;
  /** Appeared after the computer's first report on at least one computer. */
  isNew: boolean;
  firstSeen: string;
  endpointCount: number;
  endpoints: Array<{ agentId: string; hostname: string; user: string | null; firstSeen: string; lastSeen: string; baseline: boolean }>;
}
