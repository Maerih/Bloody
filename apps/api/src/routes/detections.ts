import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { Severity, Uuid, type NodeKind } from "@bloody/contracts";
import { detectionCoverage, type DetectionRule, type EntityRef } from "@bloody/engines";
import { recordAudit } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter, actorId } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest, notFound } from "../http/errors.js";
import { IdParam, csvOf } from "../http/params.js";
import { toAlert, type Row } from "../repo/mappers.js";
import {
  AUTO_SUPPRESS_AFTER,
  AUTO_SUPPRESS_DAYS,
  DetectionInput,
  RULE_KINDS,
  SuppressionInput,
  buildRule,
  insertSuppression,
  toSuppression,
  type DetectionRuleView,
} from "../services/detections.js";
import { QueryBool, loadOne, parse } from "./util.js";

const RuleIdParam = z.object({ id: z.string().regex(/^[a-z0-9][a-z0-9._:-]{2,127}$/i, "invalid rule id") });

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  q: z.string().trim().max(200).optional(),
  kind: csvOf(z.enum(RULE_KINDS)).optional(),
  severity: csvOf(Severity).optional(),
  enabled: QueryBool.optional(),
  builtin: QueryBool.optional(),
  tag: z.string().trim().max(100).optional(),
});

const TestBody = z
  .object({
    /** Test unsaved content instead of the stored version. */
    source: z.string().min(1).max(100_000).optional(),
    definition: z.record(z.unknown()).optional(),
    kind: z.enum(RULE_KINDS).optional(),
    lookbackHours: z.number().int().min(1).max(24 * 30).default(24),
    maxEvents: z.number().int().min(1).max(20_000).default(5_000),
    organizationId: Uuid.optional(),
    events: z.array(z.record(z.unknown())).max(1000).optional(),
  })
  .strict();

const FeedbackBody = z
  .object({
    verdict: z.enum(["true_positive", "false_positive", "benign_positive"]),
    comment: z.string().trim().max(2000).optional(),
    /** Suppress future matches now (otherwise automatic after repeated non-malicious verdicts). */
    suppress: z
      .object({
        scope: z.enum(["entity", "rule"]).default("entity"),
        reason: z.string().trim().min(3).max(2000).optional(),
        expiresInDays: z.number().int().min(1).max(365).default(AUTO_SUPPRESS_DAYS),
      })
      .optional(),
  })
  .strict();

const SuppressionListQuery = z.object({ organizationId: Uuid.optional(), ruleId: z.string().max(128).optional(), active: QueryBool.optional() });

function filterViews(views: DetectionRuleView[], q: z.infer<typeof ListQuery>): DetectionRuleView[] {
  const term = q.q?.toLowerCase();
  return views.filter(
    (v) =>
      (!term || v.id.toLowerCase().includes(term) || v.name.toLowerCase().includes(term) || v.attack.some((t) => t.id.toLowerCase() === term)) &&
      (!q.kind?.length || q.kind.includes(v.kind)) &&
      (!q.severity?.length || q.severity.includes(v.severity)) &&
      (q.enabled === undefined || v.enabled === q.enabled) &&
      (q.builtin === undefined || v.builtin === q.builtin) &&
      (!q.tag || v.tags.includes(q.tag)) &&
      (!q.organizationId || v.organizationId === null || v.organizationId === q.organizationId),
  );
}

/** Write permission for a rule scope: organization rules need it there, tenant-wide rules tenant-wide. */
function requireRuleWrite(request: FastifyRequest, organizationId: string | null): void {
  requirePermission(request, "detection:write", organizationId);
}

export async function detectionRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const siem = { module: "siem" as const };

  app.get("/detections", { config: siem }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "detection:read", q.organizationId);
    const views = await s.db.withTenant(auth.tenantId, (tx) => s.detections.list(tx, orgs));
    const items = filterViews(views, q);
    return { items, nextCursor: null, total: items.length };
  });

  app.get("/detections/coverage", { config: siem }, async (request) => {
    const auth = requireAuth(request);
    const orgs = resolveOrgFilter(request, "detection:read", undefined);
    const views = await s.db.withTenant(auth.tenantId, (tx) => s.detections.list(tx, orgs));
    return detectionCoverage(views.map((v) => ({ ...v.definition, enabled: v.enabled }) as DetectionRule));
  });

  app.get("/detections/stats", { config: siem }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional(), days: z.coerce.number().int().min(1).max(365).default(30) }), request.query);
    const orgs = resolveOrgFilter(request, "detection:read", q.organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const params: unknown[] = [q.days];
      const org = orgs ? `AND organization_id = ANY($2::uuid[])` : "";
      if (orgs) params.push(orgs);
      const alerts = await tx.query<Row>(
        `SELECT rule_id, count(*)::int AS alerts, count(*) FILTER (WHERE status = 'false_positive')::int AS fp_status,
                count(*) FILTER (WHERE status = 'suppressed')::int AS suppressed, count(*) FILTER (WHERE incident_id IS NOT NULL)::int AS promoted
         FROM alerts WHERE rule_id IS NOT NULL AND created_at > now() - make_interval(days => $1) ${org} GROUP BY rule_id`,
        params,
      );
      const feedback = await tx.query<Row>(
        `SELECT rule_id, count(*) FILTER (WHERE verdict = 'true_positive')::int AS tp, count(*) FILTER (WHERE verdict = 'false_positive')::int AS fp,
                count(*) FILTER (WHERE verdict = 'benign_positive')::int AS bp
         FROM detection_feedback WHERE created_at > now() - make_interval(days => $1) ${org} GROUP BY rule_id`,
        params,
      );
      const fb = new Map(feedback.rows.map((r) => [String(r.rule_id), r]));
      const items = alerts.rows.map((r) => {
        const f = fb.get(String(r.rule_id));
        const tp = Number(f?.tp ?? 0);
        const fp = Number(f?.fp ?? 0);
        const precision = tp + fp > 0 ? Math.round((tp / (tp + fp)) * 1000) / 1000 : null;
        const recommendation = precision !== null && precision < 0.3 ? "review" : precision !== null && precision < 0.7 ? "tune" : "healthy";
        return {
          ruleId: String(r.rule_id),
          alerts: Number(r.alerts),
          promoted: Number(r.promoted),
          suppressed: Number(r.suppressed),
          verdicts: { truePositive: tp, falsePositive: fp, benignPositive: Number(f?.bp ?? 0) },
          precision,
          recommendation,
          explanation:
            precision === null
              ? "No analyst verdicts in the window — precision unknown."
              : `${tp} true and ${fp} false positive verdict(s): precision ${Math.round(precision * 100)}%${recommendation === "healthy" ? "" : ` → ${recommendation} the rule`}.`,
        };
      });
      return { days: q.days, items: items.sort((a, b) => b.alerts - a.alerts) };
    });
  });

  app.post("/detections/validate", { config: { ...siem, audit: false } }, async (request) => {
    requireAuth(request);
    const body = parse(DetectionInput, request.body);
    try {
      const { rule, warnings } = buildRule(body, { id: body.id ?? "custom.validation-only", version: 1 });
      return { valid: true, errors: [], warnings, rule };
    } catch (err) {
      if (err instanceof HttpError && err.code === "invalid_rule") return { valid: false, ...(err.details as { errors: string[]; warnings: string[] }), rule: null };
      throw err;
    }
  });

  app.post("/detections/test", { config: { ...siem, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const body = parse(TestBody, request.body);
    const orgs = resolveOrgFilter(request, "event:read", body.organizationId);
    const input = DetectionInput.parse({ ...(body.definition ? { definition: body.definition } : {}), ...(body.source ? { source: body.source } : {}), ...(body.kind ? { kind: body.kind } : {}) });
    const { rule } = buildRule(input, { id: "custom.draft-test", version: 1 });
    return s.detections.test(auth.tenantId, orgs, rule, { lookbackHours: body.lookbackHours, maxEvents: body.maxEvents, ...(body.events ? { samples: body.events } : {}) });
  });

  app.post("/detections", { config: { ...siem, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(DetectionInput, request.body);
    const organizationId = body.organizationId ?? null;
    requireRuleWrite(request, organizationId);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (organizationId) await loadOne(tx, "organizations", organizationId, "Organization");
      const res = await s.detections.create(tx, auth.tenantId, body, actorId(auth));
      await recordAudit(tx, request, { action: "detection.created", organizationId, targetKind: "detection_rule", targetId: res.view.id, details: { kind: res.view.kind, severity: res.view.severity, version: 1 } });
      return res;
    });
    return reply.status(201).send({ ...created.view, warnings: created.warnings });
  });

  app.get("/detections/suppressions", { config: siem }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(SuppressionListQuery, request.query);
    const orgs = resolveOrgFilter(request, "detection:read", q.organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const params: unknown[] = [];
      const where = [orgs ? `(organization_id IS NULL OR organization_id = ANY($${params.push(orgs)}::uuid[]))` : "TRUE"];
      if (q.ruleId) where.push(`rule_id = $${params.push(q.ruleId)}`);
      if (q.active === true) where.push("revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())");
      if (q.active === false) where.push("(revoked_at IS NOT NULL OR expires_at <= now())");
      const { rows } = await tx.query<Row>(`SELECT * FROM detection_suppressions WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT 1000`, params);
      return { items: rows.map((r) => toSuppression(r, s.now())), nextCursor: null };
    });
  });

  app.post("/detections/suppressions", { config: { ...siem, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(SuppressionInput, request.body);
    requireRuleWrite(request, body.organizationId);
    const expiresAt = body.expiresAt ?? (body.expiresInDays ? new Date(s.now() + body.expiresInDays * 86_400_000).toISOString() : null);
    if (expiresAt && Date.parse(expiresAt) <= s.now()) throw badRequest("expiresAt must be in the future");
    const row = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.organizationId) await loadOne(tx, "organizations", body.organizationId, "Organization");
      const r = await insertSuppression(tx, auth.tenantId, { organizationId: body.organizationId, ruleId: body.ruleId, entity: body.entity ?? null, reason: body.reason, expiresAt, source: "analyst", alertId: null, createdBy: actorId(auth) });
      await recordAudit(tx, request, { action: "detection.suppression_created", organizationId: body.organizationId, targetKind: "detection_suppression", targetId: String(r.id), details: { ruleId: body.ruleId, entity: body.entity ?? null, expiresAt } });
      return r;
    });
    return reply.status(201).send(toSuppression(row, s.now()));
  });

  app.delete("/detections/suppressions/:id", { config: { ...siem, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "detection_suppressions", id, "Suppression");
      requireRuleWrite(request, (row.organization_id as string | null) ?? null);
      if (row.revoked_at) throw new HttpError(409, "already_revoked", "The suppression is already revoked");
      await tx.query("UPDATE detection_suppressions SET revoked_at = now(), revoked_by = $2 WHERE id = $1", [id, actorId(auth)]);
      await recordAudit(tx, request, { action: "detection.suppression_revoked", organizationId: (row.organization_id as string | null) ?? null, targetKind: "detection_suppression", targetId: id, details: { ruleId: row.rule_id } });
    });
    return reply.status(204).send();
  });

  app.get("/detections/:id", { config: siem }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(RuleIdParam, request.params);
    const orgs = resolveOrgFilter(request, "detection:read", undefined);
    const found = await s.db.withTenant(auth.tenantId, (tx) => s.detections.get(tx, id, orgs));
    if (!found) throw notFound("Detection rule");
    return found.view;
  });

  app.patch("/detections/:id", { config: { ...siem, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(RuleIdParam, request.params);
    const body = parse(DetectionInput, request.body);
    const orgs = resolveOrgFilter(request, "detection:read", undefined);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const cur = await s.detections.get(tx, id, orgs);
      if (!cur) throw notFound("Detection rule");
      requireRuleWrite(request, cur.view.organizationId);
      const res = await s.detections.update(tx, auth.tenantId, id, body, actorId(auth), orgs);
      if (res.changed) {
        await recordAudit(tx, request, {
          action: cur.view.version !== res.view.version ? "detection.updated" : "detection.enabled_changed",
          organizationId: cur.view.organizationId,
          targetKind: "detection_rule",
          targetId: id,
          details: { fromVersion: cur.view.version, toVersion: res.view.version, enabled: res.view.enabled, comment: body.comment ?? null },
        });
      }
      return { ...res.view, changed: res.changed, warnings: res.warnings };
    });
  });

  for (const action of ["enable", "disable"] as const) {
    app.post(`/detections/:id/${action}`, { config: { ...siem, audit: false } }, async (request) => {
      const auth = requireAuth(request);
      const { id } = parse(RuleIdParam, request.params);
      const orgs = resolveOrgFilter(request, "detection:read", undefined);
      return s.db.withTenant(auth.tenantId, async (tx) => {
        const cur = await s.detections.get(tx, id, orgs);
        if (!cur) throw notFound("Detection rule");
        requireRuleWrite(request, cur.view.organizationId);
        const res = await s.detections.setEnabled(tx, auth.tenantId, id, action === "enable", actorId(auth), orgs);
        if (res.changed) await recordAudit(tx, request, { action: `detection.${action}d`, organizationId: cur.view.organizationId, targetKind: "detection_rule", targetId: id, details: { builtin: cur.view.builtin } });
        else request.auditState.recorded = true;
        return res.view;
      });
    });
  }

  app.delete("/detections/:id", { config: { ...siem, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(RuleIdParam, request.params);
    const orgs = resolveOrgFilter(request, "detection:read", undefined);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const cur = await s.detections.get(tx, id, orgs);
      if (!cur) throw notFound("Detection rule");
      requireRuleWrite(request, cur.view.organizationId);
      const res = await s.detections.remove(tx, id, orgs);
      await recordAudit(tx, request, { action: res.builtinReverted ? "detection.override_removed" : "detection.deleted", organizationId: cur.view.organizationId, targetKind: "detection_rule", targetId: id, details: { version: cur.view.version } });
    });
    return reply.status(204).send();
  });

  app.get("/detections/:id/versions", { config: siem }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(RuleIdParam, request.params);
    const orgs = resolveOrgFilter(request, "detection:read", undefined);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      if (!(await s.detections.get(tx, id, orgs))) throw notFound("Detection rule");
      return { items: await s.detections.versions(tx, id), nextCursor: null };
    });
  });

  app.post("/detections/:id/rollback", { config: { ...siem, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(RuleIdParam, request.params);
    const { version } = parse(z.object({ version: z.number().int().min(1) }).strict(), request.body);
    const orgs = resolveOrgFilter(request, "detection:read", undefined);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const cur = await s.detections.get(tx, id, orgs);
      if (!cur) throw notFound("Detection rule");
      requireRuleWrite(request, cur.view.organizationId);
      const view = await s.detections.rollback(tx, auth.tenantId, id, version, actorId(auth), orgs);
      await recordAudit(tx, request, { action: "detection.rolled_back", organizationId: cur.view.organizationId, targetKind: "detection_rule", targetId: id, details: { toContentOf: version, newVersion: view.version } });
      return view;
    });
  });

  app.post("/detections/:id/test", { config: { ...siem, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(RuleIdParam, request.params);
    const body = parse(TestBody, request.body ?? {});
    const orgs = resolveOrgFilter(request, "event:read", body.organizationId);
    const found = await s.db.withTenant(auth.tenantId, (tx) => s.detections.get(tx, id, resolveOrgFilter(request, "detection:read", undefined)));
    if (!found) throw notFound("Detection rule");
    let rule = found.view.definition;
    if (body.source || body.definition) {
      const input = DetectionInput.parse({ ...(body.definition ? { definition: body.definition } : {}), ...(body.source ? { source: body.source } : {}), kind: body.kind ?? found.view.kind });
      rule = buildRule(input, { id, version: found.view.version, definition: found.view.definition as unknown as Record<string, unknown> }).rule;
    }
    return s.detections.test(auth.tenantId, orgs, rule, { lookbackHours: body.lookbackHours, maxEvents: body.maxEvents, ...(body.events ? { samples: body.events } : {}) });
  });

  // ─── Analyst verdicts on alerts (false-positive marking → suppression) ──────
  app.post("/alerts/:id/feedback", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(FeedbackBody, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const alert = toAlert(await loadOne(tx, "alerts", id, "Alert"));
      assertRecordAccess(request, "alert:read", alert.organizationId, "Alert");
      requirePermission(request, "incident:write", alert.organizationId);
      if (!alert.ruleId) throw badRequest("This alert was not produced by a detection rule");
      const entity = (alert.entities[0] as EntityRef | undefined) ?? null;
      const analyst = actorId(auth);
      const fb = await tx.query<Row>(
        `INSERT INTO detection_feedback (tenant_id, organization_id, rule_id, alert_id, verdict, analyst, entity_kind, entity_key, comment)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
        [auth.tenantId, alert.organizationId, alert.ruleId, id, body.verdict, analyst, entity?.kind ?? null, entity?.key ?? null, body.comment ?? null],
      );
      const nextStatus = body.verdict === "false_positive" ? "false_positive" : alert.status === "new" ? "triaged" : alert.status;
      const updated = (await tx.query<Row>("UPDATE alerts SET status = $2 WHERE id = $1 RETURNING *", [id, nextStatus])).rows[0]!;

      let suppression: Row | null = null;
      let automatic = false;
      if (body.suppress) {
        if (body.suppress.scope === "entity" && !entity) throw badRequest("The alert has no entity to scope a suppression to; use scope \"rule\"");
        requirePermission(request, "detection:write", alert.organizationId);
        suppression = await insertSuppression(tx, auth.tenantId, {
          organizationId: alert.organizationId,
          ruleId: alert.ruleId,
          entity: body.suppress.scope === "entity" && entity ? { kind: entity.kind, key: entity.key } : null,
          reason: body.suppress.reason ?? `Marked ${body.verdict.replace("_", " ")} by ${auth.principal.email ?? analyst}${body.comment ? `: ${body.comment}` : ""}`,
          expiresAt: new Date(s.now() + body.suppress.expiresInDays * 86_400_000).toISOString(),
          source: "analyst",
          alertId: id,
          createdBy: analyst,
        });
      } else if (body.verdict !== "true_positive" && entity) {
        // Auto-suppress after repeated non-malicious verdicts for the same rule + entity.
        const { rows } = await tx.query<{ n: number; active: number }>(
          `SELECT (SELECT count(*)::int FROM detection_feedback WHERE organization_id = $1 AND rule_id = $2 AND entity_kind = $3 AND entity_key = $4 AND verdict <> 'true_positive') AS n,
                  (SELECT count(*)::int FROM detection_suppressions WHERE (organization_id = $1 OR organization_id IS NULL) AND rule_id IN ($2, '*')
                     AND (entity_key IS NULL OR (entity_kind = $3 AND entity_key = $4)) AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())) AS active`,
          [alert.organizationId, alert.ruleId, entity.kind, entity.key],
        );
        if ((rows[0]?.n ?? 0) >= AUTO_SUPPRESS_AFTER && (rows[0]?.active ?? 0) === 0) {
          automatic = true;
          suppression = await insertSuppression(tx, auth.tenantId, {
            organizationId: alert.organizationId,
            ruleId: alert.ruleId,
            entity: { kind: entity.kind as NodeKind, key: entity.key },
            reason: `Auto-suppressed after ${rows[0]!.n} non-malicious verdicts for ${entity.label ?? entity.key} (last by ${auth.principal.email ?? analyst})`,
            expiresAt: new Date(s.now() + AUTO_SUPPRESS_DAYS * 86_400_000).toISOString(),
            source: "feedback",
            alertId: id,
            createdBy: "system:feedback",
          });
        }
      }
      await recordAudit(tx, request, {
        action: "alert.feedback",
        organizationId: alert.organizationId,
        targetKind: "alert",
        targetId: id,
        details: { verdict: body.verdict, ruleId: alert.ruleId, statusFrom: alert.status, statusTo: nextStatus, suppressionId: suppression ? String(suppression.id) : null, automatic },
      });
      return {
        alert: toAlert(updated),
        feedback: { id: String(fb.rows[0]!.id), verdict: body.verdict, ruleId: alert.ruleId, entity: entity ? { kind: entity.kind, key: entity.key } : null },
        suppression: suppression ? { ...toSuppression(suppression, s.now()), automatic } : null,
      };
    });
  });
}
