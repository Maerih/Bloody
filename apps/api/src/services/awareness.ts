import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createSmtpTransport } from "@bloody/automation";
import {
  gradeQuiz,
  lessonByKey,
  lessonForLearner,
  type AwarenessAssignment,
  type AwarenessAssignmentInput,
  type AwarenessLearner,
  type AwarenessLearnerInput,
  type LessonForLearner,
  type QuizResult,
} from "@bloody/contracts";
import type { SmtpConfig } from "../config.js";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { EmailTransport } from "./notifications.js";

const iso = (v: unknown) => (v ? new Date(String(v)).toISOString() : null);
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
// Personal link token: l_ + tenant id + enrolment id (16 bytes each) + 24-byte secret, base64url (78 chars).
const b64 = (uuid: string) => Buffer.from(uuid.replace(/-/g, ""), "hex").toString("base64url");
const uuidOf = (b: string) => {
  const h = Buffer.from(b, "base64url").toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};
const TOKEN = /^l_([A-Za-z0-9_-]{22})([A-Za-z0-9_-]{22})([A-Za-z0-9_-]{32})$/;

/** Personal-link tokens ("<prefix>_" + tenant id + row id + secret): only a hash of the secret is stored. */
export function makeLinkToken(prefix: "l" | "p", tenantId: string, rowId: string): { token: string; hash: string } {
  const secret = randomBytes(24).toString("base64url");
  return { token: `${prefix}_${b64(tenantId)}${b64(rowId)}${secret}`, hash: sha256(secret) };
}
export function parseLinkToken(prefix: "l" | "p", token: string): { tenantId: string; rowId: string; hash: string } | null {
  const m = new RegExp(`^${prefix}_([A-Za-z0-9_-]{22})([A-Za-z0-9_-]{22})([A-Za-z0-9_-]{32})$`).exec(token);
  return m ? { tenantId: uuidOf(m[1]!), rowId: uuidOf(m[2]!), hash: sha256(m[3]!) } : null;
}
export function sameHash(a: string, b: string): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
const EMAILISH = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export interface LearnerView {
  learner: { name: string };
  organization: { name: string };
  assignment: { title: string; dueAt: string | null; completedAt: string | null };
  lessons: Array<LessonForLearner & { progress: { bestScore: number; passed: boolean; attempts: number } | null }>;
}

/** Sends training invitations through the platform SMTP relay (null when none is configured). */
export class AwarenessMailer {
  private transport: EmailTransport | null;
  constructor(
    private readonly smtp: SmtpConfig | null,
    override: EmailTransport | null,
  ) {
    this.transport =
      override ??
      (smtp ? createSmtpTransport({ host: smtp.host, port: smtp.port, secure: smtp.secure, ...(smtp.user ? { user: smtp.user } : {}), ...(smtp.password ? { password: smtp.password } : {}), fromAddress: smtp.from, pool: true }) : null);
  }
  get configured(): boolean {
    return this.transport !== null;
  }
  /** Always from the platform's own address (never spoofed); simulations only change the display name. */
  async send(to: { name: string; email: string }, subject: string, text: string, html: string, opts: { fromName?: string; headers?: Record<string, string> } = {}): Promise<void> {
    if (!this.transport) throw new HttpError(409, "smtp_not_configured", "No SMTP relay is configured (SMTP_HOST): copy the learners' personal links instead");
    await this.transport.sendMail({
      from: { address: this.smtp?.from ?? "training@sciat.local", name: opts.fromName ?? this.smtp?.fromName ?? "SCIAT Security Awareness" },
      to: { address: to.email, name: to.name },
      subject,
      text,
      html,
      headers: opts.headers ?? { "Auto-Submitted": "auto-generated" },
    });
  }
}

/**
 * Security Awareness Training: learners per organization, lesson assignments, personal learner
 * links (only a hash of the secret is stored; a new link replaces the previous one) and quiz results.
 */
export class AwarenessService {
  constructor(private readonly deps: { db: Database; mailer: AwarenessMailer; publicUrl: string; now: () => number }) {}

  get canEmail(): boolean {
    return this.deps.mailer.configured;
  }

  get mailer(): AwarenessMailer {
    return this.deps.mailer;
  }

  get publicUrl(): string {
    return this.deps.publicUrl.replace(/\/+$/, "");
  }

  private linkFor(tenantId: string, enrolmentId: string): { token: string; hash: string; url: string } {
    const secret = randomBytes(24).toString("base64url");
    const token = `l_${b64(tenantId)}${b64(enrolmentId)}${secret}`;
    return { token, hash: sha256(secret), url: `${this.deps.publicUrl.replace(/\/+$/, "")}/learn/${token}` };
  }

  // ─── Learners ──────────────────────────────────────────────────────────────

  async learners(tx: Queryable, organizationId: string): Promise<AwarenessLearner[]> {
    const { rows } = await tx.query<Row>(
      `SELECT l.*,
              (SELECT count(*)::int FROM sat_enrolments e WHERE e.learner_id = l.id) AS assigned,
              (SELECT count(*)::int FROM sat_enrolments e WHERE e.learner_id = l.id AND e.completed_at IS NOT NULL) AS completed,
              (SELECT round(avg(p.best_score))::int FROM sat_progress p JOIN sat_enrolments e ON e.id = p.enrolment_id WHERE e.learner_id = l.id) AS avg_score
         FROM sat_learners l WHERE l.organization_id = $1 AND l.active ORDER BY l.name`,
      [organizationId],
    );
    return rows.map((r) => ({
      id: String(r.id),
      name: String(r.name),
      email: String(r.email),
      source: r.source as AwarenessLearner["source"],
      createdAt: iso(r.created_at)!,
      assigned: Number(r.assigned),
      completed: Number(r.completed),
      averageScore: r.avg_score === null ? null : Number(r.avg_score),
    }));
  }

  async addLearner(tx: Queryable, tenantId: string, input: AwarenessLearnerInput): Promise<void> {
    const { rows } = await tx.query<Row>(
      `INSERT INTO sat_learners (tenant_id, organization_id, name, email) VALUES ($1, $2, $3, $4)
       ON CONFLICT (organization_id, email) DO UPDATE SET active = true, name = EXCLUDED.name WHERE NOT sat_learners.active
       RETURNING id`,
      [tenantId, input.organizationId, input.name, input.email],
    );
    if (!rows[0]) throw new HttpError(409, "duplicate_learner", `${input.email} is already a learner in this organization`);
  }

  /** Every enabled user identity of the organization whose principal is an email address. */
  async importDirectory(tx: Queryable, tenantId: string, organizationId: string): Promise<number> {
    const { rows } = await tx.query<Row>("SELECT id, principal, display_name FROM identities WHERE organization_id = $1 AND kind = 'user' AND enabled", [organizationId]);
    let added = 0;
    for (const r of rows) {
      const email = String(r.principal).trim().toLowerCase();
      if (!EMAILISH.test(email) || email.length > 320) continue;
      const res = await tx.query(
        `INSERT INTO sat_learners (tenant_id, organization_id, name, email, source, identity_id) VALUES ($1, $2, $3, $4, 'directory', $5)
         ON CONFLICT (organization_id, email) DO NOTHING`,
        [tenantId, organizationId, String(r.display_name ?? email.split("@")[0]), email, r.id],
      );
      added += res.rowCount ?? 0;
    }
    return added;
  }

  async learnerOrg(tx: Queryable, id: string): Promise<string> {
    const { rows } = await tx.query<Row>("SELECT organization_id FROM sat_learners WHERE id = $1 AND active", [id]);
    if (!rows[0]) throw notFound("Learner");
    return String(rows[0].organization_id);
  }

  /** Learners leave the active list; their past results stay in the reports. */
  async removeLearner(tx: Queryable, id: string): Promise<void> {
    await tx.query("UPDATE sat_learners SET active = false WHERE id = $1", [id]);
  }

  // ─── Assignments ───────────────────────────────────────────────────────────

  async assignments(tx: Queryable, organizationId: string): Promise<AwarenessAssignment[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM sat_assignments WHERE organization_id = $1 ORDER BY created_at DESC", [organizationId]);
    const { rows: en } = await tx.query<Row>(
      `SELECT e.*, l.name, l.email,
              (SELECT count(*)::int FROM sat_progress p WHERE p.enrolment_id = e.id AND p.passed) AS passed,
              (SELECT round(avg(p.best_score))::int FROM sat_progress p WHERE p.enrolment_id = e.id) AS avg_score
         FROM sat_enrolments e JOIN sat_learners l ON l.id = e.learner_id
        WHERE e.organization_id = $1 ORDER BY l.name`,
      [organizationId],
    );
    return rows.map((a) => ({
      id: String(a.id),
      title: String(a.title),
      lessons: a.lessons as string[],
      dueAt: iso(a.due_at),
      createdAt: iso(a.created_at)!,
      enrolments: en
        .filter((e) => e.assignment_id === a.id)
        .map((e) => ({
          id: String(e.id),
          learnerId: String(e.learner_id),
          learnerName: String(e.name),
          learnerEmail: String(e.email),
          invitedAt: iso(e.invited_at),
          completedAt: iso(e.completed_at),
          lessonsPassed: Number(e.passed),
          averageScore: e.avg_score === null ? null : Number(e.avg_score),
        })),
    }));
  }

  /** Create an assignment and a personal link per learner (returned once: only hashes are stored). */
  async createAssignment(tx: Queryable, tenantId: string, input: AwarenessAssignmentInput, actor: string): Promise<{ id: string; links: Array<{ enrolmentId: string; name: string; email: string; url: string }> }> {
    const learners = (
      await tx.query<Row>(
        `SELECT id, name, email FROM sat_learners WHERE organization_id = $1 AND active ${input.learnerIds ? "AND id = ANY($2)" : ""} ORDER BY name`,
        input.learnerIds ? [input.organizationId, input.learnerIds] : [input.organizationId],
      )
    ).rows;
    if (!learners.length) throw new HttpError(400, "no_learners", "Add learners to the organization (or import them from the directory) first");
    const { rows } = await tx.query<Row>(
      "INSERT INTO sat_assignments (tenant_id, organization_id, title, lessons, due_at, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
      [tenantId, input.organizationId, input.title, [...new Set(input.lessons)], input.dueAt ?? null, actor],
    );
    const assignmentId = String(rows[0]!.id);
    const links = [];
    for (const l of learners) {
      const id = String((await tx.query<Row>("SELECT gen_random_uuid() AS id")).rows[0]!.id);
      const link = this.linkFor(tenantId, id);
      await tx.query(
        "INSERT INTO sat_enrolments (id, tenant_id, organization_id, assignment_id, learner_id, token_hash) VALUES ($1, $2, $3, $4, $5, $6)",
        [id, tenantId, input.organizationId, assignmentId, l.id, link.hash],
      );
      links.push({ enrolmentId: id, name: String(l.name), email: String(l.email), url: link.url });
    }
    return { id: assignmentId, links };
  }

  async assignmentOrg(tx: Queryable, id: string): Promise<string> {
    const { rows } = await tx.query<Row>("SELECT organization_id FROM sat_assignments WHERE id = $1", [id]);
    if (!rows[0]) throw notFound("Assignment");
    return String(rows[0].organization_id);
  }

  async enrolmentOrg(tx: Queryable, id: string): Promise<string> {
    const { rows } = await tx.query<Row>("SELECT organization_id FROM sat_enrolments WHERE id = $1", [id]);
    if (!rows[0]) throw notFound("Enrolment");
    return String(rows[0].organization_id);
  }

  /**
   * Phishing follow-up: make sure the learner is in the campaign's training assignment (created on
   * first use). Idempotent; the learner opens it with the same personal link as the simulation.
   */
  async ensureFollowUp(tx: Queryable, tenantId: string, organizationId: string, campaign: { id: string; name: string; lesson: string; assignmentId: string | null }, learnerId: string): Promise<void> {
    let assignmentId = campaign.assignmentId;
    if (!assignmentId) {
      const { rows } = await tx.query<Row>(
        "INSERT INTO sat_assignments (tenant_id, organization_id, title, lessons, due_at, created_by) VALUES ($1, $2, $3, $4, now() + interval '14 days', 'phishing-simulation') RETURNING id",
        [tenantId, organizationId, `Follow-up: ${campaign.name}`.slice(0, 200), [campaign.lesson]],
      );
      assignmentId = String(rows[0]!.id);
      await tx.query("UPDATE sat_phish_campaigns SET follow_up_assignment_id = $2 WHERE id = $1", [campaign.id, assignmentId]);
    }
    // The enrolment's own link starts unusable (random hash); an administrator can issue one later.
    await tx.query(
      "INSERT INTO sat_enrolments (tenant_id, organization_id, assignment_id, learner_id, token_hash) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (assignment_id, learner_id) DO NOTHING",
      [tenantId, organizationId, assignmentId, learnerId, sha256(randomBytes(24).toString("base64url"))],
    );
  }

  /** A fresh personal link for one learner; the previous link stops working. */
  async newLink(tx: Queryable, tenantId: string, enrolmentId: string): Promise<string> {
    const link = this.linkFor(tenantId, enrolmentId);
    await tx.query("UPDATE sat_enrolments SET token_hash = $2 WHERE id = $1", [enrolmentId, link.hash]);
    return link.url;
  }

  /** Email every learner who has not finished a fresh personal link. */
  async invite(tenantId: string, assignmentId: string): Promise<{ sent: number; failed: number }> {
    if (!this.deps.mailer.configured) throw new HttpError(409, "smtp_not_configured", "No SMTP relay is configured (SMTP_HOST): copy the learners' personal links instead");
    const todo = await this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        `SELECT e.id, l.name, l.email, a.title, a.lessons, a.due_at, o.name AS org
           FROM sat_enrolments e JOIN sat_learners l ON l.id = e.learner_id JOIN sat_assignments a ON a.id = e.assignment_id JOIN organizations o ON o.id = e.organization_id
          WHERE e.assignment_id = $1 AND e.completed_at IS NULL AND l.active`,
        [assignmentId],
      );
      const out: Array<Row & { url: string }> = [];
      for (const r of rows) out.push({ ...r, url: await this.newLink(tx, tenantId, String(r.id)) });
      return out;
    });
    let sent = 0;
    let failed = 0;
    for (const r of todo) {
      const lessons = (r.lessons as string[]).map((k) => lessonByKey(k)!);
      const minutes = lessons.reduce((n, l) => n + l.minutes, 0);
      const due = r.due_at ? ` by ${new Date(String(r.due_at)).toDateString()}` : "";
      const subject = `Security awareness training: ${String(r.title)}`;
      const text = `Hello ${String(r.name)},\n\n${String(r.org)} has asked you to complete a short security awareness training${due} (about ${minutes} minutes, ${lessons.length} lesson${lessons.length === 1 ? "" : "s"}):\n\n${lessons.map((l) => `- ${l.title}`).join("\n")}\n\nOpen your personal link (no password needed):\n${r.url}\n\nThis link is personal: please do not forward it.\n`;
      const html = `<p>Hello ${esc(String(r.name))},</p><p>${esc(String(r.org))} has asked you to complete a short security awareness training${esc(due)} (about ${minutes} minutes):</p><ul>${lessons.map((l) => `<li>${esc(l.title)}</li>`).join("")}</ul><p><a href="${esc(r.url)}">Start the training</a></p><p style="color:#666">This link is personal: please do not forward it.</p>`;
      try {
        await this.deps.mailer.send({ name: String(r.name), email: String(r.email) }, subject, text, html);
        sent++;
        await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE sat_enrolments SET invited_at = now(), invite_error = NULL WHERE id = $1", [r.id]));
      } catch (err) {
        failed++;
        const message = err instanceof Error ? err.message : String(err);
        await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE sat_enrolments SET invite_error = $2 WHERE id = $1", [r.id, message.slice(0, 500)]));
      }
    }
    return { sent, failed };
  }

  /** Organization summary for the dashboard tiles. */
  async summary(tx: Queryable, organizationId: string) {
    const { rows } = await tx.query<Row>(
      `SELECT (SELECT count(*)::int FROM sat_learners WHERE organization_id = $1 AND active) AS learners,
              (SELECT count(*)::int FROM sat_enrolments WHERE organization_id = $1) AS enrolments,
              (SELECT count(*)::int FROM sat_enrolments WHERE organization_id = $1 AND completed_at IS NOT NULL) AS completed,
              (SELECT count(*)::int FROM sat_enrolments e JOIN sat_assignments a ON a.id = e.assignment_id
                 WHERE e.organization_id = $1 AND e.completed_at IS NULL AND a.due_at < now()) AS overdue,
              (SELECT round(avg(p.best_score))::int FROM sat_progress p JOIN sat_enrolments e ON e.id = p.enrolment_id WHERE e.organization_id = $1) AS avg_score`,
      [organizationId],
    );
    const r = rows[0]!;
    const enrolments = Number(r.enrolments);
    return {
      learners: Number(r.learners),
      enrolments,
      completed: Number(r.completed),
      completionRate: enrolments ? Math.round((Number(r.completed) / enrolments) * 100) : null,
      overdue: Number(r.overdue),
      averageScore: r.avg_score === null ? null : Number(r.avg_score),
    };
  }

  // ─── Learner (public, by personal link) ───────────────────────────────────

  /**
   * The enrolment a personal link opens: a training link ("l_") directly, or a phishing-simulation
   * link ("p_") opens the follow-up training of the person who clicked it.
   */
  private async withEnrolment<T>(token: string, fn: (tx: Queryable, e: Row) => Promise<T>): Promise<T> {
    const phish = parseLinkToken("p", token);
    if (phish) {
      return this.deps.db.withTenant(phish.tenantId, async (tx) => {
        const { rows } = await tx.query<Row>(
          `SELECT t.token_hash, e.id AS enrolment_id FROM sat_phish_targets t JOIN sat_phish_campaigns c ON c.id = t.campaign_id
             JOIN sat_enrolments e ON e.assignment_id = c.follow_up_assignment_id AND e.learner_id = t.learner_id
            WHERE t.id = $1`,
          [phish.rowId],
        );
        if (!rows[0] || !sameHash(String(rows[0].token_hash), phish.hash)) throw notFound("Training link");
        return this.enrolment(tx, String(rows[0].enrolment_id), null, fn);
      });
    }
    const m = TOKEN.exec(token);
    if (!m) throw notFound("Training link");
    const tenantId = uuidOf(m[1]!);
    const enrolmentId = uuidOf(m[2]!);
    return this.deps.db.withTenant(tenantId, (tx) => this.enrolment(tx, enrolmentId, sha256(m[3]!), fn));
  }

  /** Load an enrolment; `expectedHash` null = the caller already authenticated the link. */
  private async enrolment<T>(tx: Queryable, enrolmentId: string, expectedHash: string | null, fn: (tx: Queryable, e: Row) => Promise<T>): Promise<T> {
    const { rows } = await tx.query<Row>(
      `SELECT e.*, l.name AS learner_name, l.active, a.title, a.lessons, a.due_at, o.name AS org_name
         FROM sat_enrolments e JOIN sat_learners l ON l.id = e.learner_id JOIN sat_assignments a ON a.id = e.assignment_id JOIN organizations o ON o.id = e.organization_id
        WHERE e.id = $1`,
      [enrolmentId],
    );
    const e = rows[0];
    if (!e || !e.active || (expectedHash !== null && !sameHash(String(e.token_hash), expectedHash))) throw notFound("Training link");
    return fn(tx, e);
  }

  private async progress(tx: Queryable, enrolmentId: string) {
    const { rows } = await tx.query<Row>("SELECT lesson_key, best_score, passed, attempts FROM sat_progress WHERE enrolment_id = $1", [enrolmentId]);
    return new Map(rows.map((r) => [String(r.lesson_key), { bestScore: Number(r.best_score), passed: Boolean(r.passed), attempts: Number(r.attempts) }]));
  }

  async learnerView(token: string): Promise<LearnerView> {
    return this.withEnrolment(token, async (tx, e) => {
      if (!e.started_at) await tx.query("UPDATE sat_enrolments SET started_at = now() WHERE id = $1", [e.id]);
      const progress = await this.progress(tx, String(e.id));
      return {
        learner: { name: String(e.learner_name) },
        organization: { name: String(e.org_name) },
        assignment: { title: String(e.title), dueAt: iso(e.due_at), completedAt: iso(e.completed_at) },
        lessons: (e.lessons as string[]).flatMap((k) => {
          const l = lessonByKey(k);
          return l ? [{ ...lessonForLearner(l), progress: progress.get(k) ?? null }] : [];
        }),
      };
    });
  }

  /** Grade a quiz attempt; the best score is kept, and the enrolment completes when every lesson is passed. */
  async submitQuiz(token: string, lessonKey: string, answers: Record<string, number>): Promise<QuizResult & { completed: boolean }> {
    return this.withEnrolment(token, async (tx, e) => {
      if (!(e.lessons as string[]).includes(lessonKey)) throw notFound("Lesson");
      const result = gradeQuiz(lessonByKey(lessonKey)!, answers);
      await tx.query(
        `INSERT INTO sat_progress (enrolment_id, tenant_id, lesson_key, best_score, passed) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (enrolment_id, lesson_key) DO UPDATE SET best_score = greatest(sat_progress.best_score, EXCLUDED.best_score),
           passed = sat_progress.passed OR EXCLUDED.passed, attempts = sat_progress.attempts + 1, updated_at = now()`,
        [e.id, e.tenant_id, lessonKey, result.score, result.passed],
      );
      const progress = await this.progress(tx, String(e.id));
      const completed = (e.lessons as string[]).every((k) => progress.get(k)?.passed);
      if (completed && !e.completed_at) await tx.query("UPDATE sat_enrolments SET completed_at = now() WHERE id = $1", [e.id]);
      return { ...result, completed };
    });
  }
}
