import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { recordAudit } from "../audit/audit.js";
import { requirePermission, requirePerson } from "../auth/rbac.js";
import { requireRecentMfa } from "../auth/step-up.js";
import type { AppServices } from "../context.js";
import { parse } from "./util.js";

/** Settings → Email server: the account's outgoing mail (SMTP) server. */
export async function mailServerRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/settings/email-server", async (request) => {
    const auth = requirePermission(request, "settings:write", null);
    return s.db.withTenant(auth.tenantId, (tx) => s.mailServer.view(tx, auth.tenantId));
  });

  app.put("/settings/email-server", { config: { audit: false } }, async (request) => {
    const auth = requirePermission(request, "settings:write", null);
    requirePerson(request);
    await requireRecentMfa(request, s);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await s.mailServer.save(tx, auth.tenantId, request.body, auth.principal.id);
      const view = await s.mailServer.view(tx, auth.tenantId);
      const a = view.account!;
      await recordAudit(tx, request, {
        action: "settings.email_server_changed",
        targetKind: "account",
        targetId: auth.tenantId,
        details: { host: a.host, port: a.port, encryption: a.encryption, username: a.username, fromAddress: a.fromAddress, passwordChanged: (request.body as { password?: unknown } | null)?.password !== undefined },
      });
      return view;
    });
  });

  app.delete("/settings/email-server", { config: { audit: false } }, async (request) => {
    const auth = requirePermission(request, "settings:write", null);
    requirePerson(request);
    await requireRecentMfa(request, s);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      if (await s.mailServer.clear(tx, auth.tenantId)) await recordAudit(tx, request, { action: "settings.email_server_removed", targetKind: "account", targetId: auth.tenantId });
      return s.mailServer.view(tx, auth.tenantId);
    });
  });

  app.post("/settings/email-server/test", { config: { audit: "settings.email_server_tested" } }, async (request) => {
    const auth = requirePermission(request, "settings:write", null);
    const { to } = parse(z.object({ to: z.string().trim().email() }).strict(), request.body);
    request.auditState.targetKind = "account";
    request.auditState.details = { to };
    const res = await s.mailServer.sendTest(auth.tenantId, to);
    return { ok: true, message: `Test message accepted by the mail server for ${to}`, ...res };
  });
}
