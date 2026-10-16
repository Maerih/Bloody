import { z } from "zod";
import { HardeningFacts } from "./attack-reduction.js";
import { IsoDateTime, Uuid } from "./common.js";
import { HostAutorun } from "./footholds.js";
import { HostPatchStatus } from "./patching.js";

/**
 * Host inventory reported by the SCIAT Agent (proprietary): installed software, services, local
 * users, running processes, listening ports, firewall and antivirus products. One snapshot per
 * agent, replaced on every report (about every 30 minutes).
 */

const text = (max: number) => z.string().trim().max(max);
const opt = (max: number) => text(max).nullish().transform((v) => (v ? v : null));

export const HostSoftware = z.object({ name: text(300).min(1), version: opt(100), publisher: opt(200), installedAt: opt(40) });
export type HostSoftware = z.infer<typeof HostSoftware>;

export const HostService = z.object({
  name: text(200).min(1),
  displayName: opt(300),
  /** running, stopped, failed… (as the OS reports it, lower-case). */
  state: text(40).min(1).transform((v) => v.toLowerCase()),
  /** auto, manual, disabled… */
  startMode: opt(40).transform((v) => v?.toLowerCase() ?? null),
  account: opt(200),
});
export type HostService = z.infer<typeof HostService>;

export const HostUser = z.object({
  name: text(200).min(1),
  fullName: opt(300),
  admin: z.boolean().default(false),
  enabled: z.boolean().default(true),
  loggedIn: z.boolean().default(false),
  lastLogon: opt(40),
});
export type HostUser = z.infer<typeof HostUser>;

export const HostProcess = z.object({
  pid: z.number().int().min(0).max(2 ** 32),
  name: text(300).min(1),
  path: opt(1000),
  user: opt(200),
});
export type HostProcess = z.infer<typeof HostProcess>;

export const HostPort = z.object({
  protocol: z.enum(["tcp", "udp"]),
  address: text(100).min(1),
  port: z.number().int().min(0).max(65535),
  process: opt(300),
});
export type HostPort = z.infer<typeof HostPort>;

export const AntivirusProduct = z.object({
  name: text(200).min(1),
  enabled: z.boolean(),
  /** Definitions current (null when the product does not say). */
  upToDate: z.boolean().nullable().default(null),
  realTimeProtection: z.boolean().nullable().default(null),
  /** Windows tamper protection (Microsoft Defender); null when not applicable. */
  tamperProtection: z.boolean().nullable().default(null),
  signatureAgeDays: z.number().int().min(0).max(100_000).nullable().default(null),
});
export type AntivirusProduct = z.infer<typeof AntivirusProduct>;

export const HostFirewall = z.object({ enabled: z.boolean(), detail: opt(300) });
export type HostFirewall = z.infer<typeof HostFirewall>;

/** POST /agent/inventory */
export const HostInventoryReport = z
  .object({
    software: z.array(HostSoftware).max(5000).default([]),
    services: z.array(HostService).max(2000).default([]),
    users: z.array(HostUser).max(1000).default([]),
    processes: z.array(HostProcess).max(2000).default([]),
    ports: z.array(HostPort).max(2000).default([]),
    antivirus: z.array(AntivirusProduct).max(20).default([]),
    firewall: HostFirewall.nullish().transform((v) => v ?? null),
    /** Attack Reduction facts (agent 1.2+). */
    hardening: HardeningFacts.default({}),
    /** Persistent Footholds: autostart entries (agent 1.4+). */
    autoruns: z.array(HostAutorun).max(5000).default([]),
    /** Patch Compliance: pending updates, restart, last install (agent 1.5+). */
    patches: HostPatchStatus.nullish().transform((v) => v ?? null),
  })
  .strict();
export type HostInventoryReport = z.output<typeof HostInventoryReport>;

/** GET /assets/:id/inventory */
export interface HostInventory extends Omit<HostInventoryReport, "autoruns" | "patches"> {
  agentId: string;
  hostname: string;
  platform: string;
  collectedAt: string;
  antivirusStatus: AntivirusStatus;
  antivirusIssues: string[];
}
export const HostInventoryMeta = z.object({ agentId: Uuid, collectedAt: IsoDateTime });

export type AntivirusStatus = "protected" | "unhealthy" | "unmanaged";

/** Signatures older than this count as out of date when the product does not say. */
export const SIGNATURE_MAX_AGE_DAYS = 7;

/** What is wrong with each product: disabled, real-time off, tamper protection off, old signatures. */
export function antivirusIssues(products: readonly AntivirusProduct[]): string[] {
  const issues: string[] = [];
  for (const p of products) {
    if (!p.enabled) issues.push(`${p.name} is turned off`);
    if (p.realTimeProtection === false) issues.push(`${p.name}: real-time protection is off`);
    if (p.tamperProtection === false) issues.push(`${p.name}: tamper protection is off`);
    if (p.upToDate === false) issues.push(`${p.name}: definitions are out of date`);
    else if (p.signatureAgeDays !== null && p.signatureAgeDays > SIGNATURE_MAX_AGE_DAYS) issues.push(`${p.name}: definitions are ${p.signatureAgeDays} days old`);
  }
  return issues;
}

/**
 * Protected when at least one product is on, with real-time protection, current definitions and
 * tamper protection not switched off; unhealthy when products exist but none is; unmanaged when
 * there is no antivirus at all.
 */
export function antivirusStatusOf(products: readonly AntivirusProduct[]): AntivirusStatus {
  if (products.length === 0) return "unmanaged";
  const healthy = products.some(
    (p) =>
      p.enabled &&
      p.realTimeProtection !== false &&
      p.tamperProtection !== false &&
      p.upToDate !== false &&
      (p.signatureAgeDays === null || p.signatureAgeDays <= SIGNATURE_MAX_AGE_DAYS),
  );
  return healthy ? "protected" : "unhealthy";
}
