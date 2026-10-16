import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { AwarenessAssignmentInput, AwarenessLearnerInput, LESSONS, PASS_MARK, PHISH_TEMPLATES, PhishCampaignInput, QuizSubmission, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { parse } from "./util.js";

const sat = { module: "awareness" as const };
const TokenParam = z.object({ token: z.string().min(10).max(200) });
const learnerLimit = { max: 60, timeWindow: "1 minute" };

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/** Security Awareness Training: learners, assignments and the learner's personal-link pages. */
export async function awarenessRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/awareness/lessons", { config: sat }, async (request) => {
    requireAuth(request);
    return { passMark: PASS_MARK, items: LESSONS.map(({ key, title, minutes, summary, quiz }) => ({ key, title, minutes, summary, questions: quiz.length })) };
  });

  app.get("/awareness/overview", { config: sat }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "org:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      const learners = await s.awareness.learners(tx, organizationId);
      const summary = await s.awareness.summary(tx, organizationId);
      return {
        organizationId,
        canEmail: s.awareness.canEmail,
        summary: {
          ...summary,
          highRisk: learners.filter((l) => l.risk.level === "high").length,
          averageRisk: learners.length ? Math.round(learners.reduce((n, l) => n + l.risk.score, 0) / learners.length) : null,
        },
        learners,
        assignments: await s.awareness.assignments(tx, organizationId),
      };
    });
  });

  app.post("/awareness/learners", { config: { ...sat, audit: false } }, async (request, reply) => {
    const body = parse(AwarenessLearnerInput, request.body);
    const auth = requirePermission(request, "org:write", body.organizationId);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, body.organizationId);
      await s.awareness.addLearner(tx, auth.tenantId, body);
      await recordAudit(tx, request, { action: "awareness.learner_added", organizationId: body.organizationId, targetKind: "learner", targetId: body.email });
    });
    return reply.code(201).send({ ok: true });
  });

  app.post("/awareness/learners/import", { config: { ...sat, audit: false } }, async (request) => {
    const { organizationId } = parse(z.object({ organizationId: Uuid }).strict(), request.body);
    const auth = requirePermission(request, "org:write", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      const added = await s.awareness.importDirectory(tx, auth.tenantId, organizationId);
      await recordAudit(tx, request, { action: "awareness.learners_imported", organizationId, targetKind: "organization", targetId: organizationId, details: { added } });
      return { added };
    });
  });

  app.delete("/awareness/learners/:id", { config: { ...sat, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const auth = requireAuth(request);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const org = await s.awareness.learnerOrg(tx, id);
      requirePermission(request, "org:write", org);
      await s.awareness.removeLearner(tx, id);
      await recordAudit(tx, request, { action: "awareness.learner_removed", organizationId: org, targetKind: "learner", targetId: id });
      return { ok: true };
    });
  });

  app.post("/awareness/assignments", { config: { ...sat, audit: false } }, async (request, reply) => {
    const body = parse(AwarenessAssignmentInput, request.body);
    const auth = requirePermission(request, "org:write", body.organizationId);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, body.organizationId);
      const r = await s.awareness.createAssignment(tx, auth.tenantId, body, actorId(auth));
      await recordAudit(tx, request, { action: "awareness.assignment_created", organizationId: body.organizationId, targetKind: "assignment", targetId: r.id, details: { title: body.title, lessons: body.lessons, learners: r.links.length } });
      return r;
    });
    return reply.code(201).send(created);
  });

  app.post("/awareness/assignments/:id/invite", { config: { ...sat, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const auth = requireAuth(request);
    const org = await s.db.withTenant(auth.tenantId, (tx) => s.awareness.assignmentOrg(tx, id));
    requirePermission(request, "org:write", org);
    const result = await s.awareness.invite(auth.tenantId, id);
    await s.db.withTenant(auth.tenantId, (tx) => recordAudit(tx, request, { action: "awareness.invitations_sent", organizationId: org, targetKind: "assignment", targetId: id, details: result }));
    return result;
  });

  app.patch("/awareness/assignments/:id", { config: { ...sat, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const { reminders } = parse(z.object({ reminders: z.boolean() }).strict(), request.body);
    const auth = requireAuth(request);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const org = await s.awareness.assignmentOrg(tx, id);
      requirePermission(request, "org:write", org);
      await s.awareness.setReminders(tx, id, reminders);
      await recordAudit(tx, request, { action: "awareness.reminders_changed", organizationId: org, targetKind: "assignment", targetId: id, details: { reminders } });
      return { reminders };
    });
  });

  // A new personal link for one learner (to copy into a chat or email by hand). The old one stops working.
  app.post("/awareness/enrolments/:id/link", { config: { ...sat, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const auth = requireAuth(request);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const org = await s.awareness.enrolmentOrg(tx, id);
      requirePermission(request, "org:write", org);
      const url = await s.awareness.newLink(tx, auth.tenantId, id);
      await recordAudit(tx, request, { action: "awareness.link_created", organizationId: org, targetKind: "enrolment", targetId: id });
      return { url };
    });
  });

  // ---- Phishing simulations ----
  app.get("/awareness/phishing/templates", { config: sat }, async (request) => {
    requireAuth(request);
    return { items: PHISH_TEMPLATES };
  });

  app.get("/awareness/phishing/campaigns", { config: sat }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "org:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      return { organizationId, canEmail: s.awareness.canEmail, campaigns: await s.phishing.campaigns(tx, organizationId) };
    });
  });

  // Launching sends real emails to the organization's people: org:write, a recorded authorization
  // and an explicit attestation are required, and the launch is audited.
  app.post("/awareness/phishing/campaigns", { config: { ...sat, audit: false } }, async (request, reply) => {
    const body = parse(PhishCampaignInput, request.body);
    const auth = requirePermission(request, "org:write", body.organizationId);
    const result = await s.phishing.launch(auth.tenantId, body, actorId(auth));
    await s.db.withTenant(auth.tenantId, (tx) =>
      recordAudit(tx, request, {
        action: "awareness.phishing_launched",
        organizationId: body.organizationId,
        targetKind: "phishing_campaign",
        targetId: result.id,
        details: { name: body.name, template: body.template, reference: body.reference, attested: true, recipients: result.recipients, sent: result.sent, failed: result.failed },
      }),
    );
    return reply.code(201).send(result);
  });

  // ---- Learner pages (public: the personal link is the credential) ----
  // Simulation reveal: POST from SCIAT's page (not the email link itself), so link scanners that
  // only fetch URLs do not count as clicks.
  app.post("/caught/:token", { config: { public: true, audit: false, rateLimit: learnerLimit } }, async (request) => {
    const { token } = parse(TokenParam, request.params);
    return s.phishing.reveal(token);
  });

  app.get("/learn/:token", { config: { public: true, audit: false, rateLimit: learnerLimit } }, async (request) => {
    const { token } = parse(TokenParam, request.params);
    return s.awareness.learnerView(token);
  });

  app.post("/learn/:token/lessons/:lesson/quiz", { config: { public: true, audit: false, rateLimit: learnerLimit } }, async (request) => {
    const { token, lesson } = parse(TokenParam.extend({ lesson: z.string().regex(/^[a-z0-9_]{1,40}$/) }), request.params);
    const { answers } = parse(QuizSubmission, request.body);
    return s.awareness.submitQuiz(token, lesson, answers);
  });
}
