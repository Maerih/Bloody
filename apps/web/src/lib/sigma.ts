import type { Severity } from "@bloody/contracts";

/**
 * Lightweight, dependency-free structural checks for Sigma YAML in the rule editor. The
 * server's Sigma compiler is the authority (it compiles and tests the rule); this only catches
 * the obvious mistakes while typing and reads a few top-level values for the form.
 */

export interface SigmaLint {
  errors: string[];
  warnings: string[];
}

const TOP_KEY = /^([A-Za-z_][A-Za-z0-9_-]*)\s*:(.*)$/;

function topLevel(source: string): Map<string, { line: number; value: string }> {
  const out = new Map<string, { line: number; value: string }>();
  source.split(/\r?\n/).forEach((raw, i) => {
    if (/^\s/.test(raw) || raw.trimStart().startsWith("#")) return;
    const m = TOP_KEY.exec(raw);
    if (m && !out.has(m[1]!)) out.set(m[1]!, { line: i + 1, value: m[2]!.trim() });
  });
  return out;
}

function unquote(v: string): string {
  const t = v.replace(/\s+#.*$/, "").trim();
  return (t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"')) ? t.slice(1, -1) : t;
}

export function lintSigma(source: string): SigmaLint {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!source.trim()) return { errors: ["The rule is empty"], warnings };
  const lines = source.split(/\r?\n/);
  lines.forEach((l, i) => {
    if (/^[ ]*\t/.test(l)) errors.push(`Line ${i + 1}: YAML does not allow tab indentation`);
  });
  const keys = topLevel(source);
  for (const k of ["title", "logsource", "detection"]) if (!keys.has(k)) errors.push(`Missing top-level "${k}"`);
  const det = keys.get("detection");
  if (det) {
    // `condition:` must appear indented under detection.
    const after = lines.slice(det.line);
    const block: string[] = [];
    for (const l of after) {
      if (l.trim() === "" || /^\s/.test(l)) block.push(l);
      else break;
    }
    if (!block.some((l) => /^\s+condition\s*:/.test(l))) errors.push('"detection" needs a "condition"');
    const selections = block.filter((l) => /^\s{1,4}[A-Za-z_][\w-]*\s*:/.test(l) && !/^\s+condition\s*:/.test(l)).length;
    if (selections === 0) errors.push('"detection" needs at least one selection');
  }
  if (keys.has("logsource") && !/^\s+(category|product|service)\s*:/m.test(source)) warnings.push('"logsource" should name a category, product or service');
  const level = keys.get("level");
  if (level && !["informational", "low", "medium", "high", "critical"].includes(unquote(level.value).toLowerCase())) warnings.push(`Unknown level "${unquote(level.value)}"`);
  if (!keys.has("level")) warnings.push('No "level" — the rule severity from the form is used');
  return { errors, warnings };
}

export function sigmaTitle(source: string): string | null {
  const t = topLevel(source).get("title");
  return t ? unquote(t.value) || null : null;
}

export function sigmaLevel(source: string): Severity | null {
  const l = topLevel(source).get("level");
  if (!l) return null;
  const v = unquote(l.value).toLowerCase();
  return v === "informational" ? "info" : v === "low" || v === "medium" || v === "high" || v === "critical" ? v : null;
}

/** ATT&CK technique ids from `tags: [attack.t1059.001, …]`. */
export function sigmaTechniques(source: string): string[] {
  const out = new Set<string>();
  for (const m of source.matchAll(/attack\.(t\d{4}(?:\.\d{3})?)/gi)) out.add(m[1]!.toUpperCase());
  return [...out];
}

/** Starting point for a new rule (Sigma field names are mapped to the canonical event schema). */
export const SIGMA_TEMPLATE = `title: Suspicious encoded PowerShell command
status: experimental
description: PowerShell started with an encoded command line, common in malware loaders.
author: Your SOC
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith: '\\powershell.exe'
  selection_flags:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection_image and selection_flags
falsepositives:
  - Administrative scripts that legitimately encode commands
level: high
tags:
  - attack.execution
  - attack.t1059.001
`;
