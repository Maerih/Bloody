import { maxSeverity, SEVERITY_RANK, type Severity } from "@bloody/contracts";

/** CVSS v2/v3/v4 base score → severity band (FIRST qualitative scale). */
export function severityFromCvss(score: number | undefined): Severity | undefined {
  if (score === undefined || !Number.isFinite(score) || score < 0 || score > 10) return undefined;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

const WORDS: Record<string, Severity> = {
  critical: "critical",
  crit: "critical",
  "very-high": "critical",
  "very high": "critical",
  veryhigh: "critical",
  emergency: "critical",
  severe: "critical",
  high: "high",
  major: "high",
  important: "high",
  error: "high",
  medium: "medium",
  moderate: "medium",
  med: "medium",
  warning: "medium",
  warn: "medium",
  low: "low",
  minor: "low",
  notice: "low",
  info: "info",
  informational: "info",
  information: "info",
  none: "info",
  log: "info",
  debug: "info",
  unknown: "info",
  negligible: "info",
};

/** Vendor severity words ("Major", "MEDIUM", "Very-High", "Informational") → severity. */
export function severityFromWord(word: string | undefined): Severity | undefined {
  if (!word) return undefined;
  return WORDS[word.trim().toLowerCase()];
}

/** Raise `sev` to at least `floor`. */
export function atLeast(sev: Severity, floor: Severity | undefined): Severity {
  return floor ? maxSeverity(sev, floor) : sev;
}

export function severityRank(sev: Severity): number {
  return SEVERITY_RANK[sev];
}

/** Keys removed from raw payloads before they are embedded as event provenance. */
export const DEFAULT_SENSITIVE_KEYS: ReadonlySet<string> = new Set([
  "password",
  "passwd",
  "pass",
  "pwd",
  "secret",
  "client_secret",
  "token",
  "access_token",
  "refresh_token",
  "id_token",
  "api_key",
  "apikey",
  "authorization",
  "cookie",
  "set-cookie",
  "private_key",
  "privatekey",
  "credentials",
  "session_token",
]);
