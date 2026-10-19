import type { FastifyRequest } from "fastify";
import type { AppServices } from "../context.js";
import { HttpError } from "../http/errors.js";
import { requireAuth } from "./rbac.js";

/** How long a second-factor check covers dangerous actions. */
export const STEP_UP_MINUTES = 10;

/**
 * Dangerous actions (emergency response, approvals, role grants, API keys, password resets…)
 * need a recent second factor from people who have MFA set up, so a stolen session alone cannot
 * do them. The web app answers `mfa_step_up_required` by asking for an authenticator code
 * (POST /auth/mfa/verify) and retrying. API keys are governed by their own scope and are not
 * asked; people without MFA cannot be asked and pass (enforce MFA enrolment by policy).
 */
export async function requireRecentMfa(request: FastifyRequest, s: Pick<AppServices, "db">): Promise<void> {
  const auth = requireAuth(request);
  if (auth.principal.kind !== "user" || !auth.sessionId) return;
  const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
    tx.query<{ mfa_enabled: boolean; recent: boolean }>(
      `SELECT u.mfa_enabled, coalesce(se.mfa_verified_at > now() - make_interval(mins => $2), false) AS recent
         FROM sessions se JOIN users u ON u.id = se.user_id WHERE se.id = $1`,
      [auth.sessionId, STEP_UP_MINUTES],
    ),
  );
  const row = rows[0];
  if (!row || !row.mfa_enabled || row.recent) return;
  request.auditState.details = { ...(request.auditState.details ?? {}), stepUp: "required" };
  throw new HttpError(403, "mfa_step_up_required", "Confirm it is you with your authenticator code to continue");
}
