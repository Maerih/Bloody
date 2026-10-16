import { z } from "zod";

/**
 * Attack Reduction (ESPM, proprietary). The SCIAT Agent reports a handful of hardening facts with
 * its host inventory (is SMBv1 on, is LLMNR off, does LSASS run protected, is the disk encrypted,
 * ...). SCIAT grades them against the settings attackers rely on, explains each gap with the ATT&CK
 * technique it enables, and gives the fix. Organizations can accept a gap with a written reason.
 */

/** Facts as the agent reports them: short keys, scalar values. Unknown keys are kept but ignored. */
export const HardeningFacts = z
  .record(z.string().regex(/^[a-z0-9_]{1,40}$/), z.union([z.string().max(2000), z.number(), z.boolean(), z.null()]))
  .refine((v) => Object.keys(v).length <= 100, "At most 100 hardening facts");
export type HardeningFacts = z.infer<typeof HardeningFacts>;

export type HardeningPlatform = "windows" | "macos" | "linux";
export type HardeningSeverity = "high" | "medium" | "low";
export type HardeningCategory = "credentials" | "network" | "exploitation" | "encryption" | "patching" | "logging" | "access";
export type HardeningStatus = "pass" | "fail" | "unknown" | "na";

export interface HardeningContext {
  facts: Record<string, unknown>;
  users: Array<{ name: string; admin: boolean; enabled: boolean }>;
  firewall: { enabled: boolean } | null;
}

export interface HardeningResult {
  status: HardeningStatus;
  detail?: string;
}

export interface HardeningCheck {
  key: string;
  title: string;
  platforms: HardeningPlatform[];
  category: HardeningCategory;
  severity: HardeningSeverity;
  /** MITRE ATT&CK technique the gap enables. */
  attack: string;
  why: string;
  fix: string;
  /** Command(s) that apply the fix on one computer (test first; prefer GPO / Intune / MDM at scale). */
  script?: string;
  evaluate(ctx: HardeningContext): HardeningResult;
}

export const SEVERITY_WEIGHT: Record<HardeningSeverity, number> = { high: 3, medium: 2, low: 1 };

const has = (f: Record<string, unknown>, k: string) => f[k] !== undefined && f[k] !== null && f[k] !== "";
const bool = (f: Record<string, unknown>, k: string): boolean | undefined => {
  const v = f[k];
  if (typeof v === "boolean") return v;
  if (v === 1 || v === "1" || v === "true" || v === "True" || v === "on" || v === "yes") return true;
  if (v === 0 || v === "0" || v === "false" || v === "False" || v === "off" || v === "no") return false;
  return undefined;
};
const num = (f: Record<string, unknown>, k: string): number | undefined => {
  const v = typeof f[k] === "string" ? Number(f[k]) : f[k];
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
};
const unknown: HardeningResult = { status: "unknown", detail: "Not reported by this agent yet" };
/** pass when the fact equals `good`. */
const isTrue = (k: string, good: boolean, failDetail: string) => (ctx: HardeningContext): HardeningResult => {
  const v = bool(ctx.facts, k);
  if (v === undefined) return unknown;
  return v === good ? { status: "pass" } : { status: "fail", detail: failDetail };
};

/** Microsoft Defender attack surface reduction rules (action 1 = block, 2 = audit, 6 = warn). */
export const ASR_STANDARD: Record<string, string> = {
  "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block abuse of exploited vulnerable signed drivers",
  "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from LSASS",
  "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block persistence through WMI event subscription",
};
export const ASR_RECOMMENDED: Record<string, string> = {
  "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block Office applications from creating child processes",
  "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office applications from creating executable content",
  "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office applications from injecting code into other processes",
  "26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication apps from creating child processes",
  "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
  "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block execution of potentially obfuscated scripts",
  "d3e037e1-3eb8-44c8-a917-57927947596d": "Block JavaScript or VBScript from launching downloaded executables",
  "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email client and webmail",
  "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted and unsigned processes that run from USB",
  "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader from creating child processes",
  "c1db55ab-c21a-4637-bb3f-a12568109d35": "Use advanced protection against ransomware",
};

/** "guid=action,guid=action" (as the agent reports it) to a map of lower-case GUID → action. */
export function parseAsr(raw: unknown): Map<string, number> {
  const out = new Map<string, number>();
  if (typeof raw !== "string") return out;
  for (const part of raw.split(/[,;\s]+/)) {
    const [id, action] = part.split("=");
    if (id && action !== undefined && /^[0-9a-f-]{36}$/i.test(id)) out.set(id.toLowerCase(), Number(action));
  }
  return out;
}
const asrScript = (rules: Record<string, string>) =>
  Object.keys(rules)
    .map((id) => `Add-MpPreference -AttackSurfaceReductionRules_Ids ${id} -AttackSurfaceReductionRules_Actions Enabled`)
    .join("\n");

export const HARDENING_CHECKS: HardeningCheck[] = [
  // ---- every platform ----------------------------------------------------------------------
  {
    key: "firewall",
    title: "Host firewall is on",
    platforms: ["windows", "macos", "linux"],
    category: "network",
    severity: "high",
    attack: "T1021 Remote Services",
    why: "Without the host firewall every listening service on the computer is reachable by anything on the same network, which is how attackers move from one compromised machine to the next.",
    fix: "Turn the firewall on for every network profile (Windows: Domain, Private, Public).",
    script: "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
    evaluate: (ctx) => (ctx.firewall ? (ctx.firewall.enabled ? { status: "pass" } : { status: "fail", detail: "Firewall is off" }) : unknown),
  },
  {
    key: "local_admins",
    title: "Few local administrator accounts",
    platforms: ["windows", "macos", "linux"],
    category: "access",
    severity: "medium",
    attack: "T1078.003 Valid Accounts: Local Accounts",
    why: "Every extra local administrator is another password that unlocks the whole computer. Day-to-day accounts with admin rights let any malware the user runs take full control.",
    fix: "Keep at most two enabled local administrators (a managed break-glass account, e.g. LAPS, and IT). Give users standard accounts.",
    evaluate: (ctx) => {
      if (!ctx.users.length) return unknown;
      const admins = ctx.users.filter((u) => u.admin && u.enabled).map((u) => u.name);
      return admins.length <= 2 ? { status: "pass", detail: admins.join(", ") || undefined } : { status: "fail", detail: `${admins.length} enabled administrators: ${admins.join(", ")}` };
    },
  },

  // ---- Windows -----------------------------------------------------------------------------
  {
    key: "win_smb1",
    title: "SMBv1 is disabled",
    platforms: ["windows"],
    category: "exploitation",
    severity: "high",
    attack: "T1210 Exploitation of Remote Services",
    why: "SMBv1 is the 30-year-old file-sharing protocol behind WannaCry and NotPetya (EternalBlue). Nothing modern needs it.",
    fix: "Disable the SMBv1 server and remove the SMBv1 feature.",
    script: "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
    evaluate: isTrue("smb1_enabled", false, "SMBv1 is enabled"),
  },
  {
    key: "win_llmnr",
    title: "LLMNR is turned off",
    platforms: ["windows"],
    category: "credentials",
    severity: "high",
    attack: "T1557.001 LLMNR/NBT-NS Poisoning",
    why: "When a name lookup fails, Windows asks the whole local network via LLMNR. Tools like Responder answer and capture password hashes, one of the most common first steps in an internal attack.",
    fix: "Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled.",
    script: "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null\nSet-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -Type DWord",
    evaluate: isTrue("llmnr_disabled", true, "LLMNR is on (Windows default)"),
  },
  {
    key: "win_netbios",
    title: "NetBIOS over TCP/IP is off",
    platforms: ["windows"],
    category: "credentials",
    severity: "medium",
    attack: "T1557.001 LLMNR/NBT-NS Poisoning",
    why: "NetBIOS name service is the second protocol Responder-style tools poison to steal password hashes.",
    fix: "Disable NetBIOS over TCP/IP on every adapter (or set DHCP option 001 to disable it network-wide).",
    script: "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 }",
    evaluate: (ctx) => {
      const n = num(ctx.facts, "netbios_enabled_adapters");
      if (n === undefined) return unknown;
      return n === 0 ? { status: "pass" } : { status: "fail", detail: `Enabled on ${n} network adapter${n === 1 ? "" : "s"}` };
    },
  },
  {
    key: "win_wdigest",
    title: "WDigest does not keep clear-text passwords",
    platforms: ["windows"],
    category: "credentials",
    severity: "high",
    attack: "T1003.001 OS Credential Dumping: LSASS Memory",
    why: "With WDigest UseLogonCredential = 1, Windows keeps users' passwords in memory in clear text, ready for Mimikatz. Attackers switch it on deliberately.",
    fix: "Set UseLogonCredential to 0 (or remove it) and watch for it being changed back.",
    script: "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0 -Type DWord",
    evaluate: (ctx) => {
      if (!("wdigest_use_logon_credential" in ctx.facts)) return unknown;
      return num(ctx.facts, "wdigest_use_logon_credential") === 1 ? { status: "fail", detail: "UseLogonCredential = 1: passwords are kept in clear text" } : { status: "pass" };
    },
  },
  {
    key: "win_lsa_ppl",
    title: "LSA protection (RunAsPPL) is on",
    platforms: ["windows"],
    category: "credentials",
    severity: "high",
    attack: "T1003.001 OS Credential Dumping: LSASS Memory",
    why: "LSA protection runs LSASS as a protected process so credential-dumping tools cannot read its memory.",
    fix: "Enable LSA protection (RunAsPPL = 1, or 2 on Windows 11 22H2+). Reboot required; test third-party authentication plug-ins first.",
    script: "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord",
    evaluate: (ctx) => {
      const v = num(ctx.facts, "lsa_run_as_ppl");
      if (v === undefined) return unknown;
      return v >= 1 ? { status: "pass" } : { status: "fail", detail: "LSASS is not protected" };
    },
  },
  {
    key: "win_credential_guard",
    title: "Credential Guard is running",
    platforms: ["windows"],
    category: "credentials",
    severity: "medium",
    attack: "T1003 OS Credential Dumping",
    why: "Credential Guard isolates NTLM hashes and Kerberos tickets with virtualization so pass-the-hash and ticket theft from memory stop working.",
    fix: "Enable Virtualization-based Security with Credential Guard (Intune endpoint security or Group Policy > Device Guard). Needs supported hardware.",
    evaluate: isTrue("credential_guard_running", true, "Credential Guard is not running"),
  },
  {
    key: "win_rdp_nla",
    title: "Remote Desktop requires Network Level Authentication",
    platforms: ["windows"],
    category: "access",
    severity: "high",
    attack: "T1021.001 Remote Services: Remote Desktop Protocol",
    why: "Without NLA, anyone who can reach the computer gets a Windows logon screen before authenticating, exposing it to pre-authentication exploits (BlueKeep) and password guessing.",
    fix: "Require NLA for Remote Desktop, or turn Remote Desktop off where it is not needed.",
    script: "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord",
    evaluate: (ctx) => {
      const on = bool(ctx.facts, "rdp_enabled");
      if (on === undefined) return unknown;
      if (!on) return { status: "pass", detail: "Remote Desktop is off" };
      const nla = bool(ctx.facts, "rdp_nla");
      if (nla === undefined) return unknown;
      return nla ? { status: "pass", detail: "Remote Desktop on, NLA required" } : { status: "fail", detail: "Remote Desktop is on without NLA" };
    },
  },
  {
    key: "win_powershell_v2",
    title: "PowerShell 2.0 is removed",
    platforms: ["windows"],
    category: "logging",
    severity: "medium",
    attack: "T1059.001 Command and Scripting Interpreter: PowerShell",
    why: "PowerShell 2.0 has no script-block logging or AMSI. Attackers run `powershell -version 2` to slip past antivirus and logging.",
    fix: "Remove the Windows PowerShell 2.0 feature.",
    script: "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
    evaluate: isTrue("powershell_v2_enabled", false, "PowerShell 2.0 engine is installed"),
  },
  {
    key: "win_ps_logging",
    title: "PowerShell script-block logging is on",
    platforms: ["windows"],
    category: "logging",
    severity: "medium",
    attack: "T1059.001 Command and Scripting Interpreter: PowerShell",
    why: "Script-block logging records the PowerShell code that actually ran, even when it was obfuscated, which is essential for investigating an attack.",
    fix: "Group Policy: Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled.",
    script: "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null\nSet-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord",
    evaluate: isTrue("ps_scriptblock_logging", true, "Script-block logging is off"),
  },
  {
    key: "win_uac",
    title: "User Account Control prompts administrators",
    platforms: ["windows"],
    category: "access",
    severity: "high",
    attack: "T1548.002 Abuse Elevation Control Mechanism: Bypass UAC",
    why: "With UAC off, or set to elevate administrators without asking, any program an administrator starts silently gets full control of the computer.",
    fix: "Keep UAC on (EnableLUA = 1) and prompt administrators for consent (ConsentPromptBehaviorAdmin = 2 or 5).",
    script: "$k = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'\nSet-ItemProperty $k -Name EnableLUA -Value 1 -Type DWord\nSet-ItemProperty $k -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord",
    evaluate: (ctx) => {
      const lua = bool(ctx.facts, "uac_enabled");
      if (lua === undefined) return unknown;
      if (!lua) return { status: "fail", detail: "UAC is turned off" };
      const prompt = num(ctx.facts, "uac_admin_prompt");
      return prompt === 0 ? { status: "fail", detail: "Administrators are elevated without a prompt" } : { status: "pass" };
    },
  },
  {
    key: "win_autorun",
    title: "AutoRun is disabled for all drives",
    platforms: ["windows"],
    category: "exploitation",
    severity: "low",
    attack: "T1091 Replication Through Removable Media",
    why: "AutoRun starts programs from inserted USB drives and discs, a classic way malware spreads between computers.",
    fix: "Group Policy: Administrative Templates > Windows Components > AutoPlay Policies > Turn off AutoPlay = All drives.",
    script: "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord",
    evaluate: isTrue("autorun_disabled", true, "AutoRun is not disabled for every drive type"),
  },
  {
    key: "win_bitlocker",
    title: "System drive is encrypted (BitLocker)",
    platforms: ["windows"],
    category: "encryption",
    severity: "high",
    attack: "T1005 Data from Local System (lost or stolen device)",
    why: "A lost or stolen laptop without disk encryption hands over every file and cached credential on it.",
    fix: "Turn on BitLocker for the system drive with a TPM protector and escrow the recovery key (Entra ID / Active Directory).",
    script: "Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -TpmProtector -UsedSpaceOnly",
    evaluate: isTrue("bitlocker_os_protected", true, "System drive is not protected by BitLocker"),
  },
  {
    key: "win_asr_standard",
    title: "Defender ASR standard-protection rules block",
    platforms: ["windows"],
    category: "exploitation",
    severity: "high",
    attack: "T1003.001 / T1546.003 / T1068",
    why: "Microsoft recommends these three attack surface reduction rules in block mode for every Windows computer: they stop LSASS credential theft, WMI persistence and vulnerable-driver abuse with almost no false positives.",
    fix: "Set the three standard-protection ASR rules to Block (Intune: Endpoint security > Attack surface reduction; or Group Policy / PowerShell).",
    script: asrScript(ASR_STANDARD),
    evaluate: (ctx) => {
      if (!has(ctx.facts, "asr_rules") && ctx.facts.asr_rules !== "") return unknown;
      const rules = parseAsr(ctx.facts.asr_rules);
      const missing = Object.entries(ASR_STANDARD).filter(([id]) => rules.get(id) !== 1).map(([, name]) => name);
      return missing.length ? { status: "fail", detail: `Not in block mode: ${missing.join("; ")}` } : { status: "pass" };
    },
  },
  {
    key: "win_asr_recommended",
    title: "Defender ASR rules for Office, scripts and email",
    platforms: ["windows"],
    category: "exploitation",
    severity: "medium",
    attack: "T1204 User Execution / T1059 Command and Scripting Interpreter",
    why: "Most ransomware starts with a document, script or attachment the user opens. These rules stop Office, script hosts and email clients from launching or injecting code.",
    fix: "Run the rules in audit mode for a couple of weeks, add exclusions for line-of-business tools, then switch them to Block.",
    script: asrScript(ASR_RECOMMENDED),
    evaluate: (ctx) => {
      if (!has(ctx.facts, "asr_rules") && ctx.facts.asr_rules !== "") return unknown;
      const rules = parseAsr(ctx.facts.asr_rules);
      const ids = Object.keys(ASR_RECOMMENDED);
      const block = ids.filter((id) => rules.get(id) === 1 || rules.get(id) === 6).length;
      const audit = ids.filter((id) => rules.get(id) === 2).length;
      const detail = `${block} of ${ids.length} blocking${audit ? `, ${audit} in audit` : ""}`;
      return block >= 8 ? { status: "pass", detail } : { status: "fail", detail };
    },
  },
  {
    key: "win_patch_age",
    title: "Windows updates installed in the last 35 days",
    platforms: ["windows"],
    category: "patching",
    severity: "high",
    attack: "T1203 Exploitation for Client Execution",
    why: "Microsoft ships security fixes every month (Patch Tuesday). A computer more than a month behind is open to vulnerabilities attackers already exploit.",
    fix: "Make sure Windows Update (or WSUS / Intune update rings) installs monthly updates and the computer restarts to apply them.",
    evaluate: (ctx) => {
      const d = num(ctx.facts, "last_patch_days");
      if (d === undefined) return unknown;
      return d <= 35 ? { status: "pass", detail: `Last update ${d} day${d === 1 ? "" : "s"} ago` } : { status: "fail", detail: `Last update ${d} days ago` };
    },
  },
  {
    key: "win_smb_signing",
    title: "SMB signing is required",
    platforms: ["windows"],
    category: "credentials",
    severity: "medium",
    attack: "T1557 Adversary-in-the-Middle (NTLM relay)",
    why: "Without required SMB signing, captured authentication can be relayed to this computer to log in as the victim (NTLM relay).",
    fix: "Group Policy: Microsoft network server: Digitally sign communications (always) = Enabled.",
    script: "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
    evaluate: isTrue("smb_signing_required", true, "SMB signing is not required"),
  },
  {
    key: "win_ntlmv1",
    title: "Only NTLMv2 is accepted (no LM / NTLMv1)",
    platforms: ["windows"],
    category: "credentials",
    severity: "medium",
    attack: "T1557 Adversary-in-the-Middle",
    why: "LM and NTLMv1 responses can be cracked in minutes. Level 5 refuses them.",
    fix: "Group Policy: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM (level 5).",
    script: "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord",
    evaluate: (ctx) => {
      if (!("lm_compat_level" in ctx.facts)) return unknown;
      const v = num(ctx.facts, "lm_compat_level") ?? 3;
      return v >= 5 ? { status: "pass" } : { status: "fail", detail: `LmCompatibilityLevel = ${v}` };
    },
  },
  {
    key: "win_guest",
    title: "Guest account is disabled",
    platforms: ["windows"],
    category: "access",
    severity: "medium",
    attack: "T1078.001 Valid Accounts: Default Accounts",
    why: "The built-in Guest account allows access without a password.",
    fix: "Disable the Guest account.",
    script: "Disable-LocalUser -Name Guest",
    evaluate: (ctx) => {
      if (!ctx.users.length) return unknown;
      return ctx.users.some((u) => u.name.toLowerCase() === "guest" && u.enabled) ? { status: "fail", detail: "Guest account is enabled" } : { status: "pass" };
    },
  },

  // ---- macOS -------------------------------------------------------------------------------
  {
    key: "mac_filevault",
    title: "FileVault disk encryption is on",
    platforms: ["macos"],
    category: "encryption",
    severity: "high",
    attack: "T1005 Data from Local System (lost or stolen device)",
    why: "A lost or stolen Mac without FileVault hands over every file on it.",
    fix: "Turn on FileVault and escrow the recovery key in your MDM.",
    script: "sudo fdesetup enable",
    evaluate: isTrue("filevault_on", true, "FileVault is off"),
  },
  {
    key: "mac_gatekeeper",
    title: "Gatekeeper is on",
    platforms: ["macos"],
    category: "exploitation",
    severity: "high",
    attack: "T1553.001 Subvert Trust Controls: Gatekeeper Bypass",
    why: "Gatekeeper refuses unsigned and unnotarized apps, the usual delivery for Mac info-stealers.",
    fix: "Turn Gatekeeper back on.",
    script: "sudo spctl --master-enable",
    evaluate: isTrue("gatekeeper_on", true, "Gatekeeper assessments are disabled"),
  },
  {
    key: "mac_sip",
    title: "System Integrity Protection is on",
    platforms: ["macos"],
    category: "exploitation",
    severity: "high",
    attack: "T1562.001 Impair Defenses",
    why: "SIP stops even root from modifying the operating system, so malware cannot hide in system files or disable protections.",
    fix: "Re-enable SIP from Recovery mode: csrutil enable.",
    evaluate: isTrue("sip_on", true, "System Integrity Protection is disabled"),
  },
  {
    key: "mac_auto_updates",
    title: "Security updates install automatically",
    platforms: ["macos"],
    category: "patching",
    severity: "medium",
    attack: "T1203 Exploitation for Client Execution",
    why: "Rapid Security Responses and XProtect updates fix actively exploited flaws; they only help when installed.",
    fix: "System Settings > General > Software Update > Automatic updates: install Security Responses and system files.",
    script: "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true",
    evaluate: isTrue("auto_security_updates", true, "Automatic security updates are off"),
  },
  {
    key: "mac_remote_login",
    title: "Remote Login (SSH) is off",
    platforms: ["macos"],
    category: "access",
    severity: "medium",
    attack: "T1021.004 Remote Services: SSH",
    why: "Remote Login lets anyone with a password log in to a shell from the network.",
    fix: "Turn off Remote Login unless the Mac is administered over SSH.",
    script: "sudo systemsetup -f -setremotelogin off",
    evaluate: isTrue("ssh_enabled", false, "Remote Login (SSH) is on"),
  },
  {
    key: "mac_guest",
    title: "Guest user is disabled",
    platforms: ["macos"],
    category: "access",
    severity: "low",
    attack: "T1078.001 Valid Accounts: Default Accounts",
    why: "The guest user lets anyone use the Mac without a password.",
    fix: "System Settings > Users & Groups > Guest User: off.",
    script: "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false",
    evaluate: isTrue("guest_enabled", false, "Guest user is enabled"),
  },

  // ---- Linux -------------------------------------------------------------------------------
  {
    key: "linux_ssh_root",
    title: "SSH does not allow root password login",
    platforms: ["linux"],
    category: "access",
    severity: "high",
    attack: "T1110 Brute Force",
    why: "Root over SSH with a password is the account every internet scanner guesses first.",
    fix: "Set PermitRootLogin no (or prohibit-password) in /etc/ssh/sshd_config and reload sshd.",
    script: "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload ssh sshd 2>/dev/null",
    evaluate: (ctx) => {
      const v = ctx.facts.ssh_permit_root_login;
      if (v === "none") return { status: "na", detail: "No SSH server" };
      if (typeof v !== "string") return unknown;
      return v === "yes" ? { status: "fail", detail: "PermitRootLogin yes" } : { status: "pass", detail: `PermitRootLogin ${v}` };
    },
  },
  {
    key: "linux_ssh_password",
    title: "SSH uses keys, not passwords",
    platforms: ["linux"],
    category: "access",
    severity: "medium",
    attack: "T1110 Brute Force",
    why: "Password logins over SSH are brute-forced constantly; keys are not.",
    fix: "Set PasswordAuthentication no in /etc/ssh/sshd_config once every user has a key, then reload sshd.",
    evaluate: (ctx) => {
      const v = ctx.facts.ssh_password_auth;
      if (v === "none") return { status: "na", detail: "No SSH server" };
      if (typeof v !== "string") return unknown;
      return v === "no" ? { status: "pass" } : { status: "fail", detail: "PasswordAuthentication yes" };
    },
  },
  {
    key: "linux_aslr",
    title: "Address space layout randomization is full",
    platforms: ["linux"],
    category: "exploitation",
    severity: "medium",
    attack: "T1203 Exploitation for Client Execution",
    why: "ASLR makes memory-corruption exploits unreliable. Level 2 randomizes the stack, libraries and heap.",
    fix: "Set kernel.randomize_va_space = 2 in /etc/sysctl.d/ and apply it.",
    script: "echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/60-aslr.conf && sudo sysctl --system",
    evaluate: (ctx) => {
      const v = num(ctx.facts, "aslr");
      if (v === undefined) return unknown;
      return v === 2 ? { status: "pass" } : { status: "fail", detail: `randomize_va_space = ${v}` };
    },
  },
  {
    key: "linux_uid0",
    title: "Only root has UID 0",
    platforms: ["linux"],
    category: "access",
    severity: "high",
    attack: "T1136.001 Create Account: Local Account",
    why: "A second account with UID 0 is a full root backdoor, a common persistence trick.",
    fix: "Investigate and remove any account other than root with UID 0.",
    evaluate: (ctx) => {
      const v = ctx.facts.uid0_accounts;
      if (typeof v !== "string") return unknown;
      const extra = v.split(/[,\s]+/).filter((n) => n && n !== "root");
      return extra.length ? { status: "fail", detail: `UID 0 accounts besides root: ${extra.join(", ")}` } : { status: "pass" };
    },
  },
  {
    key: "linux_auto_updates",
    title: "Security updates install automatically",
    platforms: ["linux"],
    category: "patching",
    severity: "medium",
    attack: "T1203 Exploitation for Client Execution",
    why: "Unpatched packages are the most common way Linux servers are compromised.",
    fix: "Enable unattended-upgrades (Debian / Ubuntu) or dnf-automatic (RHEL / Fedora) for security updates.",
    script: "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
    evaluate: isTrue("auto_security_updates", true, "Automatic security updates are not configured"),
  },
];

/**
 * Fixes the SCIAT Agent can apply itself (Response action "harden_endpoint", approval required).
 * Only changes that cannot lock people out or break sign-in: no firewall, SSH, BitLocker, LSA
 * protection, NTLM or ASR changes, which stay manual. The agent runs its own built-in routine for
 * the check; the platform never sends script text to an endpoint.
 */
export const AGENT_FIXABLE: ReadonlySet<string> = new Set([
  "win_smb1",
  "win_llmnr",
  "win_netbios",
  "win_wdigest",
  "win_powershell_v2",
  "win_ps_logging",
  "win_autorun",
  "win_guest",
  "mac_gatekeeper",
  "mac_guest",
  "mac_auto_updates",
  "linux_aslr",
]);

export function agentCanFix(key: string, platform: string): boolean {
  const c = HARDENING_CHECKS.find((x) => x.key === key);
  return !!c && AGENT_FIXABLE.has(key) && c.platforms.includes(platform as HardeningPlatform);
}

export function hardeningCheck(key: string): HardeningCheck | undefined {
  return HARDENING_CHECKS.find((c) => c.key === key);
}

export interface HardeningEvaluation {
  key: string;
  status: HardeningStatus;
  detail: string | null;
}

/** Grade one computer: every check for its platform. */
export function evaluateHardening(platform: string, ctx: HardeningContext): HardeningEvaluation[] {
  return HARDENING_CHECKS.filter((c) => c.platforms.includes(platform as HardeningPlatform)).map((c) => {
    let r: HardeningResult;
    try {
      r = c.evaluate(ctx);
    } catch {
      r = unknown;
    }
    return { key: c.key, status: r.status, detail: r.detail ?? null };
  });
}

/** 0–100: share of severity weight passing among checks that were assessed and not accepted. */
export function hardeningScore(results: HardeningEvaluation[], accepted: ReadonlySet<string> = new Set()): number | null {
  let total = 0;
  let passing = 0;
  for (const r of results) {
    if ((r.status !== "pass" && r.status !== "fail") || accepted.has(r.key)) continue;
    const w = SEVERITY_WEIGHT[hardeningCheck(r.key)!.severity];
    total += w;
    if (r.status === "pass") passing += w;
  }
  return total ? Math.round((passing / total) * 100) : null;
}

/** Catalogue entry without the evaluator (what the API returns). */
export type HardeningCheckInfo = Omit<HardeningCheck, "evaluate">;
export const hardeningCatalog = (): HardeningCheckInfo[] => HARDENING_CHECKS.map(({ evaluate: _evaluate, ...info }) => info);

export interface AttackReductionEndpoint {
  agentId: string;
  /** Asset the agent runs on (target of the "harden_endpoint" response action). */
  assetId: string | null;
  hostname: string;
  platform: string;
  collectedAt: string;
  score: number | null;
  results: HardeningEvaluation[];
}

export interface AttackReductionCheckSummary {
  key: string;
  failing: number;
  passing: number;
  unknown: number;
  exception: { reason: string; createdBy: string | null; createdAt: string } | null;
}
