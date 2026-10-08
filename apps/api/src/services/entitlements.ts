import { MODULES, PlanKey, planIncludes, type Entitlement, type ModuleKey, type ModuleState } from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";

/**
 * Effective module entitlements of a tenant: the account plan grants a base set (PLANS), and
 * tenant-wide rows in `entitlements` (trials, explicit grants, locks) override it. Expired
 * trials are reported as `trial_ended` even before a sweeper rewrites the row.
 */
export interface EntitlementView extends Entitlement {
  uninstallAt: string | null;
  /** Why the module has this state — "plan", "trial", "grant" or "lock". */
  basis: "plan" | "trial" | "grant" | "lock" | "not_in_plan";
}

export interface AccountPlan {
  plan: PlanKey;
  trialEndsAt: string | null;
}

export async function loadAccountPlan(tx: Queryable, tenantId: string): Promise<AccountPlan> {
  const { rows } = await tx.query<{ plan: string; trial_ends_at: string | null }>("SELECT plan, trial_ends_at FROM accounts WHERE id = $1", [tenantId]);
  const parsed = PlanKey.safeParse(rows[0]?.plan);
  return { plan: parsed.success ? parsed.data : "trial", trialEndsAt: rows[0]?.trial_ends_at ?? null };
}

export async function computeEntitlements(tx: Queryable, tenantId: string, now: number): Promise<{ plan: PlanKey; entitlements: EntitlementView[] }> {
  const account = await loadAccountPlan(tx, tenantId);
  const { rows } = await tx.query<{ module: string; state: ModuleState; trial_ends_at: string | null; uninstall_at: string | null }>(
    "SELECT module, state, trial_ends_at, uninstall_at FROM entitlements WHERE organization_id IS NULL",
  );
  const overrides = new Map(rows.map((r) => [r.module, r]));
  const accountTrialOver = account.plan === "trial" && account.trialEndsAt !== null && Date.parse(account.trialEndsAt) <= now;
  const entitlements = MODULES.map((m): EntitlementView => {
    const key = m.key as ModuleKey;
    const row = overrides.get(key);
    if (row) {
      const ended = row.state === "trial" && row.trial_ends_at !== null && Date.parse(row.trial_ends_at) <= now;
      const state: ModuleState = ended ? "trial_ended" : row.state;
      const basis = row.state === "trial" || row.state === "trial_ended" ? "trial" : row.state === "locked" ? "lock" : "grant";
      return { module: key, state, trialEndsAt: row.trial_ends_at, uninstallAt: row.uninstall_at, basis };
    }
    if (planIncludes(account.plan, key)) {
      if (account.plan === "trial") return { module: key, state: accountTrialOver ? "trial_ended" : "trial", trialEndsAt: account.trialEndsAt, uninstallAt: null, basis: "plan" };
      return { module: key, state: "active", trialEndsAt: null, uninstallAt: null, basis: "plan" };
    }
    return { module: key, state: "available", trialEndsAt: null, uninstallAt: null, basis: "not_in_plan" };
  });
  return { plan: account.plan, entitlements };
}
