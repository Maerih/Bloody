import { z } from "zod";
import { IsoDateTime, Uuid } from "./common.js";

/**
 * App Control (ESPM, proprietary). Each organization has a policy mode and rules; the SCIAT Agent
 * applies them to the programs running on the endpoint.
 *
 *   off      nothing is checked
 *   audit    programs matching a block rule are reported, not stopped
 *   enforce  programs matching a block rule are stopped and reported
 *
 * An allow rule always beats a block rule (exceptions such as "block AnyDesk, except the copy our
 * helpdesk ships"). Rules of the whole account (organizationId null) apply to every organization.
 * Core operating-system processes and the agent itself can never be blocked.
 */

export const AppControlMode = z.enum(["off", "audit", "enforce"]);
export type AppControlMode = z.infer<typeof AppControlMode>;
export const AppRuleAction = z.enum(["allow", "block"]);
export type AppRuleAction = z.infer<typeof AppRuleAction>;
/** name: program file name (anydesk.exe); path: full path; sha256: file hash; publisher: code-signing subject (Windows). */
export const AppMatchKind = z.enum(["name", "path", "sha256", "publisher"]);
export type AppMatchKind = z.infer<typeof AppMatchKind>;
export const AppPlatform = z.enum(["any", "windows", "linux", "macos"]);
export type AppPlatform = z.infer<typeof AppPlatform>;

/** Never blockable: stopping these breaks the endpoint or the agent itself (lower-case file names). */
export const PROTECTED_PROGRAMS: readonly string[] = [
  // Windows
  "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
  "explorer.exe", "dwm.exe", "fontdrvhost.exe", "conhost.exe", "powershell.exe", "sciatagent.exe", "msmpeng.exe", "registry",
  // Linux / macOS
  "init", "systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "dbus-daemon", "sshd", "login", "agetty", "sudo",
  "bash", "sh", "dash", "curl", "nft", "launchd", "kernel_task", "loginwindow", "sciat-agent",
];

const SHA256_RE = /^[0-9a-f]{64}$/;

/** Rule values: one line, no quotes (the agents parse them as plain text); `*` is a wildcard. */
export const AppRuleValue = z
  .string()
  .trim()
  .min(1)
  .max(500)
  .refine((v) => !/["\r\n\t]/.test(v), "must be a single line without quotes");

export const AppControlRuleInput = z
  .object({
    organizationId: Uuid.nullable(),
    action: AppRuleAction,
    kind: AppMatchKind,
    value: AppRuleValue,
    platform: AppPlatform.default("any"),
    note: z.string().trim().max(300).optional(),
  })
  .strict()
  .superRefine((r, ctx) => {
    if (r.kind === "sha256" && !SHA256_RE.test(r.value.toLowerCase())) ctx.addIssue({ code: "custom", path: ["value"], message: "must be a SHA-256 hash (64 hex characters)" });
    if (r.kind === "name" && /[\\/]/.test(r.value)) ctx.addIssue({ code: "custom", path: ["value"], message: "a program name has no folder; use a path rule instead" });
    if (r.action === "block" && blocksProtected(r.kind, r.value)) ctx.addIssue({ code: "custom", path: ["value"], message: "this would stop a core system process or the SCIAT Agent itself" });
  });
export type AppControlRuleInput = z.input<typeof AppControlRuleInput>;

export const AppControlRule = z.object({
  id: Uuid,
  organizationId: Uuid.nullable(),
  action: AppRuleAction,
  kind: AppMatchKind,
  value: z.string(),
  platform: AppPlatform,
  note: z.string().nullable(),
  createdBy: z.string().nullable(),
  createdAt: IsoDateTime,
});
export type AppControlRule = z.infer<typeof AppControlRule>;

/** What an agent sees: the organization's mode and every rule that applies to it. */
export interface AppControlPolicy {
  etag: string;
  mode: AppControlMode;
  rules: Array<Pick<AppControlRule, "id" | "action" | "kind" | "value" | "platform">>;
}

export interface ProgramFacts {
  name: string;
  path?: string | null;
  sha256?: string | null;
  publisher?: string | null;
}

const baseName = (p: string) => p.split(/[\\/]/).pop() ?? p;

/** Case-insensitive match where `*` stands for any characters. */
export function wildcardMatch(pattern: string, value: string): boolean {
  const re = new RegExp(`^${pattern.toLowerCase().split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "s");
  return re.test(value.toLowerCase());
}

export function ruleMatches(rule: Pick<AppControlRule, "kind" | "value">, p: ProgramFacts): boolean {
  switch (rule.kind) {
    case "name":
      return wildcardMatch(rule.value, p.name) || (p.path ? wildcardMatch(rule.value, baseName(p.path)) : false);
    case "path":
      return p.path ? wildcardMatch(rule.value, p.path) : false;
    case "sha256":
      return p.sha256 ? rule.value.toLowerCase() === p.sha256.toLowerCase() : false;
    case "publisher":
      return p.publisher ? wildcardMatch(rule.value, p.publisher) : false;
  }
}

export function isProtectedProgram(p: ProgramFacts): boolean {
  const names = [p.name, p.path ? baseName(p.path) : ""].map((n) => n.toLowerCase());
  return names.some((n) => n && PROTECTED_PROGRAMS.includes(n));
}

/** A block rule that would hit a protected program by name or path. */
export function blocksProtected(kind: AppMatchKind, value: string): boolean {
  if (kind !== "name" && kind !== "path") return false;
  const v = kind === "path" ? baseName(value) : value;
  return PROTECTED_PROGRAMS.some((n) => wildcardMatch(v, n));
}

/** The policy decision for one program (what the agents implement). */
export function decideProgram(policy: Pick<AppControlPolicy, "mode" | "rules">, platform: Exclude<AppPlatform, "any">, p: ProgramFacts): { verdict: "allowed" | "blocked" | "audited" | "none"; ruleId: string | null } {
  if (policy.mode === "off" || isProtectedProgram(p)) return { verdict: "none", ruleId: null };
  const applicable = policy.rules.filter((r) => r.platform === "any" || r.platform === platform);
  const allow = applicable.find((r) => r.action === "allow" && ruleMatches(r, p));
  if (allow) return { verdict: "allowed", ruleId: allow.id };
  const block = applicable.find((r) => r.action === "block" && ruleMatches(r, p));
  if (!block) return { verdict: "none", ruleId: null };
  return { verdict: policy.mode === "enforce" ? "blocked" : "audited", ruleId: block.id };
}

export const AppControlEvent = z.object({
  id: Uuid,
  organizationId: Uuid,
  agentId: Uuid,
  hostname: z.string(),
  name: z.string(),
  path: z.string().nullable(),
  sha256: z.string().nullable(),
  publisher: z.string().nullable(),
  ruleId: Uuid.nullable(),
  verdict: z.enum(["blocked", "audited"]),
  occurredAt: IsoDateTime,
});
export type AppControlEvent = z.infer<typeof AppControlEvent>;

/** One program as seen across the organization's endpoints. */
export interface AppInventoryItem {
  name: string;
  path: string;
  sha256: string | null;
  publisher: string | null;
  endpoints: number;
  lastSeenAt: string;
  verdict: "allowed" | "blocked" | "audited" | "none";
}
