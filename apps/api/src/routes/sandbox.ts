import type { FastifyInstance } from "fastify";
import { writeAudit, actorFromRequest } from "../audit/audit.js";
import { requireAuth } from "../auth/rbac.js";
import { SESSION_COOKIE } from "../auth/types.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import { clearSessionCookies, clientInfo, setSessionCookies } from "./util.js";

/** Holds the visitor's own session while they explore the sandbox (httpOnly; never readable by JS). */
export const RETURN_COOKIE = "bloody_sandbox_return";

/**
 * Demo sandbox: any signed-in user can switch into the read-only demo account and back.
 * Their own session stays valid and is restored by "Return to My Account".
 */
export async function sandboxRoutes(app: FastifyInstance, s: AppServices): Promise<void> {

  const sandboxStatus = async (tenantId: string, sessionId: string | null) => {
    if (!sessionId) return false;
    return s.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT auth_method FROM sessions WHERE id = $1", [sessionId])).rows[0]?.auth_method === "sandbox");
  };

  app.get("/sandbox", async (request) => {
    const auth = requireAuth(request);
    const demo = s.config.sandbox.accountId;
    const inSandbox = await sandboxStatus(auth.tenantId, auth.sessionId);
    let accountName: string | null = null;
    if (demo) accountName = await s.db.withTenant(demo, async (tx) => ((await tx.query<Row>("SELECT name FROM accounts WHERE id = $1", [demo])).rows[0]?.name as string | undefined) ?? null);
    return { available: Boolean(demo && accountName), accountName, inSandbox };
  });

  app.post("/sandbox/enter", { config: { audit: false, rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request, reply) => {
    const auth = requireAuth(request);
    const demo = s.config.sandbox.accountId;
    if (!demo) throw new HttpError(404, "sandbox_unavailable", "The demo sandbox is not set up on this platform");
    if (auth.method !== "session" || !auth.sessionId) throw badRequest("Sign in with your account in the browser to open the demo sandbox");
    if (await sandboxStatus(auth.tenantId, auth.sessionId)) return { ok: true, alreadyInSandbox: true };
    const own = request.cookies[SESSION_COOKIE];
    if (!own) throw badRequest("No browser session to return to");
    const exists = await s.db.withTenant(demo, async (tx) => (await tx.query("SELECT 1 FROM accounts WHERE id = $1", [demo])).rowCount);
    if (!exists) throw new HttpError(404, "sandbox_unavailable", "The demo sandbox account does not exist");
    const result = await s.auth.sandboxSession(demo, clientInfo(request));
    await s.db.withTenant(auth.tenantId, (tx) => writeAudit(tx, actorFromRequest(request), { action: "sandbox.entered", targetKind: "account", targetId: demo, outcome: "success", details: {} }));
    void reply.setCookie(RETURN_COOKIE, own, { httpOnly: true, secure: s.config.http.cookieSecure, sameSite: "lax", path: "/", expires: new Date(result.session.expiresAt) });
    setSessionCookies(s, reply, result.session);
    return { ok: true };
  });

  app.post("/sandbox/exit", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    if (!(await sandboxStatus(auth.tenantId, auth.sessionId))) throw badRequest("You are not in the demo sandbox");
    await s.db.withTenant(auth.tenantId, (tx) => s.auth.revokeSession(tx, auth.sessionId!, "sandbox_exit"));
    const own = request.cookies[RETURN_COOKIE];
    void reply.clearCookie(RETURN_COOKIE, { path: "/", secure: s.config.http.cookieSecure, sameSite: "lax", httpOnly: true });
    const restored = own ? await s.auth.authenticateSessionCookie(own) : null;
    if (!restored?.sessionId) {
      clearSessionCookies(s, reply);
      return { restored: false };
    }
    const expiresAt = await s.db.withTenant(restored.tenantId, async (tx) => (await tx.query<Row>("SELECT expires_at FROM sessions WHERE id = $1", [restored.sessionId])).rows[0]?.expires_at);
    setSessionCookies(s, reply, { sessionId: restored.sessionId, cookieValue: own!, expiresAt: new Date(String(expiresAt)).toISOString() });
    return { restored: true };
  });
}
