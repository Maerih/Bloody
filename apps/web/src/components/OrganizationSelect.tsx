import type { Permission } from "@bloody/contracts";
import { useSession } from "../app/session";
import { Select } from "./Form";

/**
 * Organization picker for create dialogs. Lists only organizations where the principal holds
 * `permission`; `allowTenantWide` adds a "tenant-wide" option (null) when the principal can act
 * at tenant level (MSSP-wide feeds, global playbooks, default AI providers).
 */
export function OrganizationSelect({
  value,
  onChange,
  permission,
  allowTenantWide = false,
  tenantWideLabel = "All organizations (tenant-wide)",
  id,
  ...aria
}: {
  value: string | null;
  onChange: (id: string | null) => void;
  permission: Permission;
  allowTenantWide?: boolean;
  tenantWideLabel?: string;
  id?: string;
  "aria-invalid"?: boolean;
  "aria-describedby"?: string;
}) {
  const session = useSession();
  const orgs = session.organizations.filter((o) => session.can(permission, o.id));
  const tenantOk = allowTenantWide && session.can(permission, null);
  return (
    <Select id={id} {...aria} value={value ?? ""} onChange={(e) => onChange(e.target.value || null)}>
      {tenantOk ? <option value="">{tenantWideLabel}</option> : value === null ? <option value="">Select an organization…</option> : null}
      {orgs.map((o) => (
        <option key={o.id} value={o.id}>
          {o.name}
        </option>
      ))}
    </Select>
  );
}

/** Default organization for a create dialog: the selected org, else the only/first permitted org. */
export function useDefaultOrganization(permission: Permission, allowTenantWide = false): string | null {
  const session = useSession();
  if (session.organizationId && session.can(permission, session.organizationId)) return session.organizationId;
  if (allowTenantWide && session.can(permission, null)) return null;
  return session.organizations.find((o) => session.can(permission, o.id))?.id ?? null;
}
