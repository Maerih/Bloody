import { z } from "zod";
import { IsoDateTime, Uuid } from "./common.js";

/**
 * Tenancy hierarchy:
 *   Platform
 *     └─ Account (tenant)  — kind "mssp" | "enterprise"
 *          └─ Organization — the unit every security record is scoped to
 *
 * Every row of customer data carries BOTH tenant_id (account) and organization_id.
 * tenant_id is the hard isolation boundary (enforced by Postgres RLS + API context);
 * organization_id is the delegated-administration boundary inside an account.
 */
export const AccountKind = z.enum(["mssp", "enterprise"]);
export type AccountKind = z.infer<typeof AccountKind>;

export const Account = z.object({
  id: Uuid,
  name: z.string().min(1).max(200),
  slug: z.string().regex(/^[a-z0-9-]{2,63}$/),
  kind: AccountKind,
  dataRegion: z.string().default("eu-west"),
  createdAt: IsoDateTime,
});
export type Account = z.infer<typeof Account>;

export const Organization = z.object({
  id: Uuid,
  tenantId: Uuid,
  name: z.string().min(1).max(200),
  slug: z.string().regex(/^[a-z0-9-]{2,63}$/),
  parentOrganizationId: Uuid.nullable(),
  retentionDays: z.number().int().min(1).max(3650),
  createdAt: IsoDateTime,
});
export type Organization = z.infer<typeof Organization>;

export const CreateOrganizationInput = z.object({
  name: z.string().min(1).max(200),
  slug: z.string().regex(/^[a-z0-9-]{2,63}$/),
  parentOrganizationId: Uuid.nullable().optional(),
  retentionDays: z.number().int().min(1).max(3650).default(90),
});
export type CreateOrganizationInput = z.infer<typeof CreateOrganizationInput>;

export const Team = z.object({
  id: Uuid,
  tenantId: Uuid,
  organizationId: Uuid.nullable(),
  name: z.string().min(1).max(200),
});
export type Team = z.infer<typeof Team>;
