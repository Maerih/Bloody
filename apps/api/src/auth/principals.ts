import { RoleKey, type Principal } from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";

/** The principal (with direct and team role bindings) of an active user of the tenant, or null. */
export async function userPrincipal(tx: Queryable, tenantId: string, userId: string): Promise<Principal | null> {
  const u = await tx.query<{ id: string; email: string; status: string }>("SELECT id, email, status FROM users WHERE id = $1", [userId]);
  if (!u.rows[0] || u.rows[0].status !== "active") return null;
  const b = await tx.query<{ role: string; organization_id: string | null }>(
    `SELECT DISTINCT role, organization_id FROM role_bindings
     WHERE (principal_kind = 'user' AND principal_id = $1) OR (principal_kind = 'team' AND principal_id IN (SELECT team_id FROM team_members WHERE user_id = $1))`,
    [userId],
  );
  const bindings = b.rows.flatMap((r) => {
    const role = RoleKey.safeParse(r.role);
    return role.success ? [{ role: role.data, organizationId: r.organization_id }] : [];
  });
  return { kind: "user", id: userId, tenantId, email: u.rows[0].email, bindings };
}
