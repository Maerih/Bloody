import { lessonByKey, phishTemplate, renderPhish, type PhishCampaign, type PhishCampaignInput } from "@bloody/contracts";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import { makeLinkToken, parseLinkToken, sameHash, type AwarenessService } from "./awareness.js";
import { MailServerUnavailableError } from "./mail-server.js";

const iso = (v: unknown) => (v ? new Date(String(v)).toISOString() : null);
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export interface PhishReveal {
  organization: { name: string };
  learner: { name: string };
  email: { fromName: string; subject: string };
  redFlags: string[];
  lesson: { title: string; minutes: number } | null;
  /** Personal link to the follow-up lesson (campaigns with automatic training). */
  trainingUrl: string | null;
}

/**
 * Phishing simulations: an authorized campaign sends one template to an organization's learners,
 * each with a personal tracking link that opens SCIAT's "this was a simulation" page. Clicks are
 * recorded, and people who click can be enrolled in the matching lesson straight away.
 */
export class PhishingService {
  constructor(private readonly deps: { db: Database; awareness: AwarenessService }) {}

  async campaigns(tx: Queryable, organizationId: string): Promise<PhishCampaign[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM sat_phish_campaigns WHERE organization_id = $1 ORDER BY launched_at DESC", [organizationId]);
    const { rows: targets } = await tx.query<Row>(
      `SELECT t.*, l.name, l.email FROM sat_phish_targets t JOIN sat_learners l ON l.id = t.learner_id WHERE t.organization_id = $1 ORDER BY l.name`,
      [organizationId],
    );
    return rows.map((c) => ({
      id: String(c.id),
      name: String(c.name),
      template: String(c.template),
      autoAssign: Boolean(c.auto_assign),
      reference: String(c.reference),
      launchedAt: iso(c.launched_at)!,
      launchedBy: (c.launched_by as string | null) ?? null,
      targets: targets
        .filter((t) => t.campaign_id === c.id)
        .map((t) => ({ id: String(t.id), learnerName: String(t.name), learnerEmail: String(t.email), sentAt: iso(t.sent_at), sendError: (t.send_error as string | null) ?? null, clickedAt: iso(t.clicked_at) })),
    }));
  }

  /** Create the campaign and send it now. Needs a configured SMTP relay. */
  async launch(tenantId: string, input: PhishCampaignInput, actor: string): Promise<{ id: string; recipients: number; sent: number; failed: number }> {
    const { mailer } = this.deps.awareness;
    if (!(await mailer.configured(tenantId))) throw new MailServerUnavailableError("Phishing simulations need a mail server (Settings → Email server)");
    const template = phishTemplate(input.template)!;
    const created = await this.deps.db.withTenant(tenantId, async (tx) => {
      const org = await tx.query<Row>("SELECT name FROM organizations WHERE id = $1", [input.organizationId]);
      if (!org.rows[0]) throw notFound("Organization");
      const learners = (
        await tx.query<Row>(
          `SELECT id, name, email FROM sat_learners WHERE organization_id = $1 AND active ${input.learnerIds ? "AND id = ANY($2)" : ""} ORDER BY name`,
          input.learnerIds ? [input.organizationId, input.learnerIds] : [input.organizationId],
        )
      ).rows;
      if (!learners.length) throw new HttpError(400, "no_learners", "Add learners to the organization first");
      const { rows } = await tx.query<Row>(
        "INSERT INTO sat_phish_campaigns (tenant_id, organization_id, name, template, auto_assign, reference, launched_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        [tenantId, input.organizationId, input.name, input.template, input.autoAssign, input.reference, actor],
      );
      const campaignId = String(rows[0]!.id);
      const out: Array<{ id: string; name: string; email: string; url: string }> = [];
      for (const l of learners) {
        const id = String((await tx.query<Row>("SELECT gen_random_uuid() AS id")).rows[0]!.id);
        const link = makeLinkToken("p", tenantId, id);
        await tx.query("INSERT INTO sat_phish_targets (id, tenant_id, organization_id, campaign_id, learner_id, token_hash) VALUES ($1, $2, $3, $4, $5, $6)", [id, tenantId, input.organizationId, campaignId, l.id, link.hash]);
        out.push({ id, name: String(l.name), email: String(l.email), url: `${this.deps.awareness.publicUrl}/caught/${link.token}` });
      }
      return { campaignId, org: String(org.rows[0].name), targets: out };
    });

    let sent = 0;
    let failed = 0;
    for (const t of created.targets) {
      const mail = renderPhish(template, { name: t.name, org: created.org, link: t.url });
      const html = esc(mail.text)
        .split("\n\n")
        .map((p) => `<p>${p.replace(/\n/g, "<br>").replace(esc(t.url), `<a href="${esc(t.url)}">${esc(t.url)}</a>`)}</p>`)
        .join("");
      try {
        await mailer.send(tenantId, { name: t.name, email: t.email }, mail.subject, mail.text, html, {
          fromName: template.fromName,
          // Lets mail gateways recognise (and allowlist) authorized simulations.
          headers: { "X-SCIAT-Simulation": `phishing; campaign=${created.campaignId}` },
        });
        sent++;
        await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE sat_phish_targets SET sent_at = now(), send_error = NULL WHERE id = $1", [t.id]));
      } catch (err) {
        failed++;
        const message = err instanceof Error ? err.message : String(err);
        await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE sat_phish_targets SET send_error = $2 WHERE id = $1", [t.id, message.slice(0, 500)]));
      }
    }
    return { id: created.campaignId, recipients: created.targets.length, sent, failed };
  }

  /** The person opened the simulation link: record the click and show what they should have noticed. */
  async reveal(token: string): Promise<PhishReveal> {
    const parsed = parseLinkToken("p", token);
    if (!parsed) throw notFound("Link");
    return this.deps.db.withTenant(parsed.tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        `SELECT t.*, c.name AS campaign_name, c.template, c.auto_assign, c.follow_up_assignment_id, l.name AS learner_name, o.name AS org_name
           FROM sat_phish_targets t JOIN sat_phish_campaigns c ON c.id = t.campaign_id JOIN sat_learners l ON l.id = t.learner_id JOIN organizations o ON o.id = t.organization_id
          WHERE t.id = $1`,
        [parsed.rowId],
      );
      const t = rows[0];
      if (!t || !sameHash(String(t.token_hash), parsed.hash)) throw notFound("Link");
      await tx.query("UPDATE sat_phish_targets SET clicked_at = coalesce(clicked_at, now()), click_count = click_count + 1 WHERE id = $1", [t.id]);
      const template = phishTemplate(String(t.template))!;
      const lesson = lessonByKey(template.lesson) ?? null;
      let trainingUrl: string | null = null;
      if (t.auto_assign && lesson) {
        // Lock the campaign so simultaneous first clicks share one follow-up assignment.
        const { rows: c } = await tx.query<Row>("SELECT follow_up_assignment_id FROM sat_phish_campaigns WHERE id = $1 FOR UPDATE", [t.campaign_id]);
        await this.deps.awareness.ensureFollowUp(
          tx,
          parsed.tenantId,
          String(t.organization_id),
          { id: String(t.campaign_id), name: String(t.campaign_name), lesson: lesson.key, assignmentId: (c[0]?.follow_up_assignment_id as string | null) ?? null },
          String(t.learner_id),
        );
        // Same personal link as the simulation: repeated visits never invalidate it.
        trainingUrl = `${this.deps.awareness.publicUrl}/learn/${token}`;
      }
      return {
        organization: { name: String(t.org_name) },
        learner: { name: String(t.learner_name) },
        email: { fromName: template.fromName, subject: renderPhish(template, { name: String(t.learner_name), org: String(t.org_name), link: "" }).subject },
        redFlags: template.redFlags,
        lesson: lesson ? { title: lesson.title, minutes: lesson.minutes } : null,
        trainingUrl,
      };
    });
  }

  async campaignOrg(tx: Queryable, id: string): Promise<string> {
    const { rows } = await tx.query<Row>("SELECT organization_id FROM sat_phish_campaigns WHERE id = $1", [id]);
    if (!rows[0]) throw notFound("Campaign");
    return String(rows[0].organization_id);
  }
}
