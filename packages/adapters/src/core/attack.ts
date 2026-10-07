import { AttackTechnique } from "@bloody/contracts";

/**
 * Curated subset of MITRE ATT&CK® Enterprise techniques (id → name, primary tactic) used to
 * name techniques that engines report by id only (Suricata metadata, Falco tags, CoPilot
 * tags, Zeek notices, our own heuristics) and to render human-readable explanations.
 *
 * Attribution: MITRE ATT&CK® is a registered trademark of The MITRE Corporation; technique
 * identifiers and names are reproduced under the ATT&CK Terms of Use. This table is a small,
 * hand-written reference subset, not a copy of the ATT&CK STIX dataset. Unknown ids remain
 * valid — they are kept with no name rather than dropped.
 */
export const ATTACK_TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;
export type AttackTactic = (typeof ATTACK_TACTICS)[number];

export interface AttackTechniqueInfo {
  id: string;
  name: string;
  tactic: AttackTactic;
}

const T = (id: string, name: string, tactic: AttackTactic): AttackTechniqueInfo => ({ id, name, tactic });

export const ATTACK_TECHNIQUES: readonly AttackTechniqueInfo[] = [
  // Reconnaissance / resource development
  T("T1595", "Active Scanning", "Reconnaissance"),
  T("T1595.001", "Scanning IP Blocks", "Reconnaissance"),
  T("T1595.002", "Vulnerability Scanning", "Reconnaissance"),
  T("T1589", "Gather Victim Identity Information", "Reconnaissance"),
  T("T1590", "Gather Victim Network Information", "Reconnaissance"),
  T("T1592", "Gather Victim Host Information", "Reconnaissance"),
  T("T1583", "Acquire Infrastructure", "Resource Development"),
  T("T1588", "Obtain Capabilities", "Resource Development"),
  T("T1608", "Stage Capabilities", "Resource Development"),
  // Initial access
  T("T1078", "Valid Accounts", "Initial Access"),
  T("T1078.001", "Default Accounts", "Initial Access"),
  T("T1078.002", "Domain Accounts", "Initial Access"),
  T("T1078.003", "Local Accounts", "Initial Access"),
  T("T1078.004", "Cloud Accounts", "Initial Access"),
  T("T1133", "External Remote Services", "Initial Access"),
  T("T1189", "Drive-by Compromise", "Initial Access"),
  T("T1190", "Exploit Public-Facing Application", "Initial Access"),
  T("T1195", "Supply Chain Compromise", "Initial Access"),
  T("T1199", "Trusted Relationship", "Initial Access"),
  T("T1200", "Hardware Additions", "Initial Access"),
  T("T1566", "Phishing", "Initial Access"),
  T("T1566.001", "Spearphishing Attachment", "Initial Access"),
  T("T1566.002", "Spearphishing Link", "Initial Access"),
  T("T1091", "Replication Through Removable Media", "Initial Access"),
  // Execution
  T("T1047", "Windows Management Instrumentation", "Execution"),
  T("T1053", "Scheduled Task/Job", "Execution"),
  T("T1053.003", "Cron", "Execution"),
  T("T1053.005", "Scheduled Task", "Execution"),
  T("T1059", "Command and Scripting Interpreter", "Execution"),
  T("T1059.001", "PowerShell", "Execution"),
  T("T1059.003", "Windows Command Shell", "Execution"),
  T("T1059.004", "Unix Shell", "Execution"),
  T("T1059.005", "Visual Basic", "Execution"),
  T("T1059.006", "Python", "Execution"),
  T("T1059.007", "JavaScript", "Execution"),
  T("T1106", "Native API", "Execution"),
  T("T1129", "Shared Modules", "Execution"),
  T("T1203", "Exploitation for Client Execution", "Execution"),
  T("T1204", "User Execution", "Execution"),
  T("T1204.002", "Malicious File", "Execution"),
  T("T1569", "System Services", "Execution"),
  T("T1569.002", "Service Execution", "Execution"),
  T("T1609", "Container Administration Command", "Execution"),
  T("T1610", "Deploy Container", "Execution"),
  T("T1648", "Serverless Execution", "Execution"),
  T("T1651", "Cloud Administration Command", "Execution"),
  // Persistence
  T("T1037", "Boot or Logon Initialization Scripts", "Persistence"),
  T("T1098", "Account Manipulation", "Persistence"),
  T("T1098.001", "Additional Cloud Credentials", "Persistence"),
  T("T1098.003", "Additional Cloud Roles", "Persistence"),
  T("T1098.004", "SSH Authorized Keys", "Persistence"),
  T("T1136", "Create Account", "Persistence"),
  T("T1136.001", "Local Account", "Persistence"),
  T("T1136.002", "Domain Account", "Persistence"),
  T("T1136.003", "Cloud Account", "Persistence"),
  T("T1505", "Server Software Component", "Persistence"),
  T("T1505.003", "Web Shell", "Persistence"),
  T("T1525", "Implant Internal Image", "Persistence"),
  T("T1543", "Create or Modify System Process", "Persistence"),
  T("T1543.002", "Systemd Service", "Persistence"),
  T("T1543.003", "Windows Service", "Persistence"),
  T("T1546", "Event Triggered Execution", "Persistence"),
  T("T1547", "Boot or Logon Autostart Execution", "Persistence"),
  T("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
  T("T1556", "Modify Authentication Process", "Persistence"),
  T("T1556.006", "Multi-Factor Authentication", "Persistence"),
  T("T1574", "Hijack Execution Flow", "Persistence"),
  T("T1574.002", "DLL Side-Loading", "Persistence"),
  // Privilege escalation
  T("T1055", "Process Injection", "Privilege Escalation"),
  T("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
  T("T1134", "Access Token Manipulation", "Privilege Escalation"),
  T("T1484", "Domain or Tenant Policy Modification", "Privilege Escalation"),
  T("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
  T("T1548.002", "Bypass User Account Control", "Privilege Escalation"),
  T("T1548.003", "Sudo and Sudo Caching", "Privilege Escalation"),
  T("T1611", "Escape to Host", "Privilege Escalation"),
  // Defense evasion
  T("T1014", "Rootkit", "Defense Evasion"),
  T("T1027", "Obfuscated Files or Information", "Defense Evasion"),
  T("T1036", "Masquerading", "Defense Evasion"),
  T("T1070", "Indicator Removal", "Defense Evasion"),
  T("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
  T("T1070.002", "Clear Linux or Mac System Logs", "Defense Evasion"),
  T("T1070.004", "File Deletion", "Defense Evasion"),
  T("T1070.006", "Timestomp", "Defense Evasion"),
  T("T1112", "Modify Registry", "Defense Evasion"),
  T("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
  T("T1218", "System Binary Proxy Execution", "Defense Evasion"),
  T("T1218.005", "Mshta", "Defense Evasion"),
  T("T1218.011", "Rundll32", "Defense Evasion"),
  T("T1222", "File and Directory Permissions Modification", "Defense Evasion"),
  T("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
  T("T1550", "Use Alternate Authentication Material", "Defense Evasion"),
  T("T1550.002", "Pass the Hash", "Defense Evasion"),
  T("T1550.003", "Pass the Ticket", "Defense Evasion"),
  T("T1562", "Impair Defenses", "Defense Evasion"),
  T("T1562.001", "Disable or Modify Tools", "Defense Evasion"),
  T("T1562.002", "Disable Windows Event Logging", "Defense Evasion"),
  T("T1562.004", "Disable or Modify System Firewall", "Defense Evasion"),
  T("T1562.008", "Disable or Modify Cloud Logs", "Defense Evasion"),
  T("T1564", "Hide Artifacts", "Defense Evasion"),
  T("T1578", "Modify Cloud Compute Infrastructure", "Defense Evasion"),
  T("T1620", "Reflective Code Loading", "Defense Evasion"),
  // Credential access
  T("T1003", "OS Credential Dumping", "Credential Access"),
  T("T1003.001", "LSASS Memory", "Credential Access"),
  T("T1003.003", "NTDS", "Credential Access"),
  T("T1003.006", "DCSync", "Credential Access"),
  T("T1003.008", "/etc/passwd and /etc/shadow", "Credential Access"),
  T("T1040", "Network Sniffing", "Credential Access"),
  T("T1056", "Input Capture", "Credential Access"),
  T("T1110", "Brute Force", "Credential Access"),
  T("T1110.001", "Password Guessing", "Credential Access"),
  T("T1110.003", "Password Spraying", "Credential Access"),
  T("T1110.004", "Credential Stuffing", "Credential Access"),
  T("T1528", "Steal Application Access Token", "Credential Access"),
  T("T1539", "Steal Web Session Cookie", "Credential Access"),
  T("T1552", "Unsecured Credentials", "Credential Access"),
  T("T1552.001", "Credentials In Files", "Credential Access"),
  T("T1552.005", "Cloud Instance Metadata API", "Credential Access"),
  T("T1555", "Credentials from Password Stores", "Credential Access"),
  T("T1557", "Adversary-in-the-Middle", "Credential Access"),
  T("T1558", "Steal or Forge Kerberos Tickets", "Credential Access"),
  T("T1558.003", "Kerberoasting", "Credential Access"),
  T("T1621", "Multi-Factor Authentication Request Generation", "Credential Access"),
  // Discovery
  T("T1016", "System Network Configuration Discovery", "Discovery"),
  T("T1018", "Remote System Discovery", "Discovery"),
  T("T1033", "System Owner/User Discovery", "Discovery"),
  T("T1046", "Network Service Discovery", "Discovery"),
  T("T1049", "System Network Connections Discovery", "Discovery"),
  T("T1057", "Process Discovery", "Discovery"),
  T("T1069", "Permission Groups Discovery", "Discovery"),
  T("T1082", "System Information Discovery", "Discovery"),
  T("T1083", "File and Directory Discovery", "Discovery"),
  T("T1087", "Account Discovery", "Discovery"),
  T("T1087.002", "Domain Account", "Discovery"),
  T("T1135", "Network Share Discovery", "Discovery"),
  T("T1482", "Domain Trust Discovery", "Discovery"),
  T("T1518", "Software Discovery", "Discovery"),
  T("T1526", "Cloud Service Discovery", "Discovery"),
  T("T1580", "Cloud Infrastructure Discovery", "Discovery"),
  T("T1613", "Container and Resource Discovery", "Discovery"),
  // Lateral movement
  T("T1021", "Remote Services", "Lateral Movement"),
  T("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
  T("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
  T("T1021.004", "SSH", "Lateral Movement"),
  T("T1021.006", "Windows Remote Management", "Lateral Movement"),
  T("T1210", "Exploitation of Remote Services", "Lateral Movement"),
  T("T1534", "Internal Spearphishing", "Lateral Movement"),
  T("T1563", "Remote Service Session Hijacking", "Lateral Movement"),
  T("T1570", "Lateral Tool Transfer", "Lateral Movement"),
  // Collection
  T("T1005", "Data from Local System", "Collection"),
  T("T1039", "Data from Network Shared Drive", "Collection"),
  T("T1113", "Screen Capture", "Collection"),
  T("T1114", "Email Collection", "Collection"),
  T("T1119", "Automated Collection", "Collection"),
  T("T1213", "Data from Information Repositories", "Collection"),
  T("T1530", "Data from Cloud Storage", "Collection"),
  T("T1560", "Archive Collected Data", "Collection"),
  // Command and control
  T("T1001", "Data Obfuscation", "Command and Control"),
  T("T1071", "Application Layer Protocol", "Command and Control"),
  T("T1071.001", "Web Protocols", "Command and Control"),
  T("T1071.004", "DNS", "Command and Control"),
  T("T1090", "Proxy", "Command and Control"),
  T("T1095", "Non-Application Layer Protocol", "Command and Control"),
  T("T1102", "Web Service", "Command and Control"),
  T("T1105", "Ingress Tool Transfer", "Command and Control"),
  T("T1132", "Data Encoding", "Command and Control"),
  T("T1219", "Remote Access Software", "Command and Control"),
  T("T1568", "Dynamic Resolution", "Command and Control"),
  T("T1568.002", "Domain Generation Algorithms", "Command and Control"),
  T("T1572", "Protocol Tunneling", "Command and Control"),
  T("T1573", "Encrypted Channel", "Command and Control"),
  // Exfiltration
  T("T1020", "Automated Exfiltration", "Exfiltration"),
  T("T1030", "Data Transfer Size Limits", "Exfiltration"),
  T("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
  T("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
  T("T1537", "Transfer Data to Cloud Account", "Exfiltration"),
  T("T1567", "Exfiltration Over Web Service", "Exfiltration"),
  T("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration"),
  // Impact
  T("T1485", "Data Destruction", "Impact"),
  T("T1486", "Data Encrypted for Impact", "Impact"),
  T("T1489", "Service Stop", "Impact"),
  T("T1490", "Inhibit System Recovery", "Impact"),
  T("T1491", "Defacement", "Impact"),
  T("T1496", "Resource Hijacking", "Impact"),
  T("T1498", "Network Denial of Service", "Impact"),
  T("T1499", "Endpoint Denial of Service", "Impact"),
  T("T1529", "System Shutdown/Reboot", "Impact"),
  T("T1531", "Account Access Removal", "Impact"),
  T("T1565", "Data Manipulation", "Impact"),
];

const BY_ID = new Map(ATTACK_TECHNIQUES.map((t) => [t.id, t]));

const TECHNIQUE_ID_RE = /^T\d{4}(\.\d{3})?$/;
const TECHNIQUE_IN_TEXT_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;

export function lookupTechnique(id: string): AttackTechniqueInfo | undefined {
  return BY_ID.get(id.trim().toUpperCase());
}

export function isTechniqueId(id: string): boolean {
  return TECHNIQUE_ID_RE.test(id.trim().toUpperCase());
}

/** Canonical tactic display name from any vendor spelling ("credential-access", "mitre_credential_access", "TA0006"…). */
export function normalizeTactic(input: string | undefined): AttackTactic | undefined {
  if (!input) return undefined;
  const ids: Record<string, AttackTactic> = {
    TA0043: "Reconnaissance",
    TA0042: "Resource Development",
    TA0001: "Initial Access",
    TA0002: "Execution",
    TA0003: "Persistence",
    TA0004: "Privilege Escalation",
    TA0005: "Defense Evasion",
    TA0006: "Credential Access",
    TA0007: "Discovery",
    TA0008: "Lateral Movement",
    TA0009: "Collection",
    TA0011: "Command and Control",
    TA0010: "Exfiltration",
    TA0040: "Impact",
  };
  const up = input.trim().toUpperCase();
  if (ids[up]) return ids[up];
  const key = input
    .trim()
    .toLowerCase()
    .replace(/^mitre[_\s-]*/, "")
    .replace(/[_\s-]+/g, " ")
    .replace(/\band\b/g, "and");
  for (const t of ATTACK_TACTICS) if (t.toLowerCase() === key) return t;
  if (key === "command control" || key === "c2") return "Command and Control";
  return undefined;
}

/**
 * Build a validated technique reference. Name/tactic supplied by the engine win; the
 * curated table fills gaps. Returns undefined for anything that is not a technique id.
 */
export function technique(id: string, name?: string, tactic?: string): AttackTechnique | undefined {
  const norm = id.trim().toUpperCase();
  if (!TECHNIQUE_ID_RE.test(norm)) return undefined;
  const known = BY_ID.get(norm);
  const out: AttackTechnique = { id: norm };
  const n = name?.trim() || known?.name;
  if (n) out.name = n;
  const tac = normalizeTactic(tactic) ?? (tactic?.trim() || known?.tactic);
  if (tac) out.tactic = tac;
  const parsed = AttackTechnique.safeParse(out);
  return parsed.success ? parsed.data : undefined;
}

/** Every technique id mentioned in free text or tag lists ("T1059", "attack.t1059.001"). */
export function techniquesInText(...inputs: Array<string | readonly string[] | undefined>): AttackTechnique[] {
  const out: AttackTechnique[] = [];
  const seen = new Set<string>();
  for (const input of inputs) {
    if (!input) continue;
    const texts = typeof input === "string" ? [input] : input;
    for (const text of texts) {
      for (const m of text.matchAll(TECHNIQUE_IN_TEXT_RE)) {
        const t = technique(m[0]);
        if (t && !seen.has(t.id)) {
          seen.add(t.id);
          out.push(t);
        }
      }
    }
  }
  return out;
}

/** De-duplicate techniques by id, keeping the most descriptive entry. */
export function mergeTechniques(...lists: AttackTechnique[][]): AttackTechnique[] {
  const byId = new Map<string, AttackTechnique>();
  for (const list of lists) {
    for (const t of list) {
      const prev = byId.get(t.id);
      if (!prev) {
        byId.set(t.id, t);
        continue;
      }
      const merged: AttackTechnique = { id: t.id };
      const name = prev.name ?? t.name;
      const tactic = prev.tactic ?? t.tactic;
      if (name) merged.name = name;
      if (tactic) merged.tactic = tactic;
      byId.set(t.id, merged);
    }
  }
  return [...byId.values()];
}
