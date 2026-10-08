import type { Alert } from "@bloody/contracts";

/**
 * Explainable alert categorization for module lenses (ITDR detections, NDR beaconing, email
 * impersonation…). A category matches on MITRE ATT&CK technique ids first, then on rule / title
 * keywords; the matched reason is returned so the UI can say *why* an alert is in a bucket.
 */

export interface AlertCategory {
  key: string;
  label: string;
  description: string;
  techniques: string[];
  keywords: RegExp;
}

export interface CategoryMatch {
  category: AlertCategory;
  reason: string;
}

export function matchCategory(alert: Pick<Alert, "attack" | "title" | "ruleId" | "source">, categories: AlertCategory[]): CategoryMatch | null {
  for (const c of categories) {
    const tech = alert.attack.find((t) => c.techniques.some((x) => t.id === x || t.id.startsWith(`${x}.`)));
    if (tech) return { category: c, reason: `ATT&CK ${tech.id}${tech.name ? ` ${tech.name}` : ""}` };
  }
  const text = `${alert.title} ${alert.ruleId ?? ""}`;
  for (const c of categories) {
    const m = c.keywords.exec(text);
    if (m) return { category: c, reason: `Rule/title mentions “${m[0]}”` };
  }
  return null;
}

export const IDENTITY_DETECTIONS: AlertCategory[] = [
  { key: "impossible_travel", label: "Impossible travel", description: "Sign-ins from locations too far apart for the elapsed time.", techniques: [], keywords: /impossible[\s_-]?travel|geo[\s_-]?velocity|atypical[\s_-]?travel/i },
  { key: "mfa_manipulation", label: "MFA manipulation", description: "MFA fatigue / push bombing, MFA method changes or bypass.", techniques: ["T1621", "T1556.006"], keywords: /mfa|multi[\s_-]?factor|push[\s_-]?(bomb|fatigue)/i },
  { key: "password_spray", label: "Password spray", description: "Few passwords tried against many accounts.", techniques: ["T1110.003"], keywords: /password[\s_-]?spray|spraying/i },
  { key: "brute_force", label: "Brute force", description: "Repeated failed authentications against one account.", techniques: ["T1110.001", "T1110"], keywords: /brute[\s_-]?force|failed[\s_-]?log(i|o)ns?/i },
  { key: "token_theft", label: "Token & session theft", description: "Stolen session cookies, refresh tokens or pass-the-token.", techniques: ["T1528", "T1550.001", "T1539", "T1550.004"], keywords: /token|session[\s_-]?(hijack|replay|theft)|cookie/i },
  { key: "privilege_escalation", label: "Privilege escalation", description: "New admin role assignments or account manipulation.", techniques: ["T1098", "T1078.004", "T1484"], keywords: /privilege|admin[\s_-]?role|role[\s_-]?assign|escalat/i },
  { key: "credential_access", label: "Credential dumping & Kerberos abuse", description: "LSASS access, DCSync, Kerberoasting, golden tickets.", techniques: ["T1003", "T1558"], keywords: /lsass|dcsync|kerberoast|golden[\s_-]?ticket|as-?rep/i },
  { key: "oauth_abuse", label: "Suspicious OAuth consent", description: "Illicit consent grants and malicious OAuth apps.", techniques: ["T1550"], keywords: /oauth|consent/i },
  { key: "dormant_account", label: "Dormant account activity", description: "Sign-ins by accounts with no recent activity.", techniques: [], keywords: /dormant|stale[\s_-]?account|inactive[\s_-]?account/i },
  { key: "valid_accounts", label: "Suspicious sign-in", description: "Anomalous use of valid accounts.", techniques: ["T1078"], keywords: /sign[\s_-]?in|login|logon|authentication/i },
];

export const NETWORK_DETECTIONS: AlertCategory[] = [
  { key: "beaconing", label: "Beaconing & C2", description: "Periodic callbacks to command-and-control infrastructure.", techniques: ["T1071", "T1573", "T1095", "T1571", "T1102"], keywords: /beacon|c2|command[\s_-]?and[\s_-]?control|cobalt/i },
  { key: "dns_abuse", label: "DNS abuse", description: "Tunnelling, DGA and fast-flux domains.", techniques: ["T1071.004", "T1568"], keywords: /dns|dga|tunnel/i },
  { key: "exfiltration", label: "Exfiltration", description: "Unusual outbound volume or destinations.", techniques: ["T1041", "T1048", "T1567", "T1020"], keywords: /exfil|data[\s_-]?transfer|upload/i },
  { key: "lateral_movement", label: "Lateral movement", description: "Remote services, SMB/RDP/WinRM between internal hosts.", techniques: ["T1021", "T1570", "T1210"], keywords: /lateral|smb|rdp|winrm|psexec/i },
  { key: "scanning", label: "Scanning & discovery", description: "Port scans and network discovery.", techniques: ["T1046", "T1595"], keywords: /scan|sweep|discovery/i },
  { key: "ids_signature", label: "IDS signature", description: "Signature matches from the network IDS.", techniques: [], keywords: /et |suricata|signature|ids/i },
];

export const EMAIL_DETECTIONS: AlertCategory[] = [
  { key: "impersonation", label: "Impersonation / BEC", description: "Display-name spoofing, look-alike domains, business email compromise.", techniques: [], keywords: /imperson|spoof|look[\s_-]?alike|bec\b|business[\s_-]?email/i },
  { key: "phishing_link", label: "Phishing link", description: "Credential-harvesting or malicious URLs.", techniques: ["T1566.002"], keywords: /phish|credential[\s_-]?harvest|malicious[\s_-]?url/i },
  { key: "malicious_attachment", label: "Malicious attachment", description: "Weaponized documents and archives.", techniques: ["T1566.001"], keywords: /attachment|macro|maldoc/i },
  { key: "phishing", label: "Phishing", description: "Other phishing techniques.", techniques: ["T1566"], keywords: /e-?mail|mail/i },
];

export const PERSISTENCE_TECHNIQUES = ["T1547", "T1053", "T1543", "T1546", "T1136", "T1098", "T1505", "T1574", "T1037", "T1197", "T1137"];

/** True when the alert maps to one of the techniques (sub-techniques included) or to `tactic`. */
export function hasTechnique(alert: Pick<Alert, "attack">, prefixes: string[], tactic?: string): boolean {
  return alert.attack.some((t) => prefixes.some((p) => t.id === p || t.id.startsWith(`${p}.`)) || (tactic !== undefined && t.tactic?.toLowerCase().replace(/[\s_]/g, "-") === tactic));
}

/** Count alerts per category (+ "other"), keeping the categories' declared order. */
export function categorize<T extends Pick<Alert, "attack" | "title" | "ruleId" | "source">>(alerts: T[], categories: AlertCategory[]): { category: AlertCategory; alerts: T[] }[] {
  const buckets = new Map<string, T[]>(categories.map((c) => [c.key, []]));
  for (const a of alerts) {
    const m = matchCategory(a, categories);
    if (m) buckets.get(m.category.key)!.push(a);
  }
  return categories.map((c) => ({ category: c, alerts: buckets.get(c.key)! }));
}
