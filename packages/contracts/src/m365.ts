import { z } from "zod";
import { Uuid } from "./common.js";

/**
 * Microsoft 365 hardening (ITDR / SSPM, proprietary). A customer organization connects its
 * Microsoft 365 tenant through a read-only Entra app registration; Bloody reads the configuration
 * with Microsoft Graph (and public DNS for mail authentication) and grades it against checks
 * mapped to CISA SCuBA and the CIS Microsoft 365 Foundations Benchmark.
 */

export const M365_CHECK_AREAS = ["identity", "email", "apps"] as const;
export type M365CheckArea = (typeof M365_CHECK_AREAS)[number];
export type M365Severity = "critical" | "high" | "medium" | "low";
/**
 * pass / fail / warn: graded. unknown: Bloody could not read the setting (missing Graph
 * permission or licence — the evidence says which). manual: Microsoft exposes the setting only
 * through Exchange PowerShell or the portal, so the check comes with guided steps instead.
 */
export type M365CheckStatus = "pass" | "fail" | "warn" | "unknown" | "manual";

export interface M365CheckDefinition {
  id: string;
  area: M365CheckArea;
  title: string;
  severity: M365Severity;
  /** e.g. "CISA SCuBA MS.AAD.1.1v1", "CIS M365 Foundations: block legacy authentication". */
  references: string[];
  why: string;
  /** Step-by-step remediation with the admin-portal path. */
  howToFix: string[];
  /** Licence the control needs, when not every tenant has it. */
  requires?: string;
}

export interface M365CheckResult extends M365CheckDefinition {
  status: M365CheckStatus;
  summary: string;
  evidence: string[];
}

export interface M365Assessment {
  id: string;
  connectionId: string;
  organizationId: string;
  tenantName: string | null;
  startedAt: string;
  finishedAt: string;
  /** 0–100, severity-weighted share of graded checks that pass (warn counts half). */
  score: number;
  counts: Record<M365CheckStatus, number>;
  results: M365CheckResult[];
}

export interface M365Connection {
  id: string;
  organizationId: string;
  directoryTenantId: string;
  clientId: string;
  displayName: string | null;
  status: "pending" | "connected" | "error";
  lastError: string | null;
  lastAssessedAt: string | null;
  lastScore: number | null;
  createdAt: string;
}

const GUID = z.string().regex(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, "must be a GUID");

export const M365ConnectionInput = z
  .object({
    organizationId: Uuid,
    /** Directory (tenant) ID, or the tenant's primary domain (contoso.onmicrosoft.com). */
    directoryTenantId: z.union([GUID, z.string().regex(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i, "must be a GUID or a domain").max(253)]),
    clientId: GUID,
    clientSecret: z.string().min(8).max(500),
  })
  .strict();
export type M365ConnectionInput = z.infer<typeof M365ConnectionInput>;

/** Microsoft Graph application permissions the connector needs (all read-only). */
export const M365_GRAPH_PERMISSIONS: Array<{ name: string; why: string }> = [
  { name: "Policy.Read.All", why: "Conditional Access, security defaults, authorization and consent policies" },
  { name: "Directory.Read.All", why: "Users, admin roles, domains, app consent grants" },
  { name: "RoleManagement.Read.Directory", why: "Who holds privileged admin roles" },
  { name: "AuditLog.Read.All", why: "MFA registration details per user (needs Entra ID P1)" },
  { name: "Application.Read.All", why: "Which third-party apps were granted access" },
  { name: "MailboxSettings.Read", why: "Inbox rules that forward or delete mail (business email compromise)" },
  { name: "IdentityRiskyUser.Read.All", why: "Users Microsoft flags as risky (needs Entra ID P2)" },
];
