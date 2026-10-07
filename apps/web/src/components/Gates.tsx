import type { ModuleKey, Permission } from "@bloody/contracts";
import type { ReactNode } from "react";
import { useSession } from "../app/session";

/**
 * Hide UI the principal is not allowed to use. Purely cosmetic: the API enforces RBAC on every
 * request — these only avoid offering actions that would be refused.
 */
export function PermissionGate({
  permission,
  organizationId,
  anywhere = false,
  fallback = null,
  children,
}: {
  permission: Permission;
  organizationId?: string | null;
  /** Pass when any binding suffices (e.g. showing a nav entry). */
  anywhere?: boolean;
  fallback?: ReactNode;
  children: ReactNode;
}) {
  const session = useSession();
  const allowed = anywhere ? session.canAnywhere(permission) : session.can(permission, organizationId);
  return <>{allowed ? children : fallback}</>;
}

/** Render children only when the tenant is entitled to the module (active or in trial). */
export function ModuleGate({ module, fallback = null, children }: { module: ModuleKey; fallback?: ReactNode; children: ReactNode }) {
  const session = useSession();
  return <>{session.isModuleEnabled(module) ? children : fallback}</>;
}
