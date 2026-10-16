import { formatNumber, formatPercent } from "../format.js";
import { kpi, percent, sumBy } from "../metrics.js";
import type { Recommendation } from "../model.js";
import { changePhrase, narrative, plural, table } from "./blocks.js";
import type { BuildContext, BuilderResult } from "./context.js";

/** Security awareness: training completion, phishing-simulation results and the people who need help. */
export async function buildSecurityAwareness(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, topN } = ctx;
  const [cur, before] = await Promise.all([ds.awareness(q), ds.awareness(prev)]);
  const learners = sumBy(cur, (o) => o.learners);
  const assignments = sumBy(cur, (o) => o.assignments);
  const completed = sumBy(cur, (o) => o.completed);
  const overdue = sumBy(cur, (o) => o.overdue);
  const sent = sumBy(cur, (o) => o.phishSent);
  const clicked = sumBy(cur, (o) => o.phishClicked);
  const highRisk = sumBy(cur, (o) => o.highRisk);
  const prevSent = sumBy(before, (o) => o.phishSent);
  const prevClicked = sumBy(before, (o) => o.phishClicked);
  const completion = percent(completed, assignments);
  const prevCompletion = percent(sumBy(before, (o) => o.completed), sumBy(before, (o) => o.assignments));
  const clickRate = percent(clicked, sent);
  const prevClickRate = percent(prevClicked, prevSent);
  const scores = cur.filter((o) => o.averageScore !== null);
  const avgScore = scores.length ? Math.round(sumBy(scores, (o) => o.averageScore! * Math.max(1, o.learners)) / sumBy(scores, (o) => Math.max(1, o.learners))) : null;

  const kpis = [
    kpi({ key: "completion", label: "Training completion", value: completion, unit: "percent", previous: prevCompletion, betterWhen: "higher", thresholds: { good: 90, warn: 70 }, explanation: `${formatNumber(completed)} of ${formatNumber(assignments)} training assignments completed.` }),
    kpi({ key: "click_rate", label: "Phishing click rate", value: sent ? clickRate : null, unit: "percent", previous: prevSent ? prevClickRate : null, betterWhen: "lower", thresholds: { good: 5, warn: 15 }, explanation: `${formatNumber(clicked)} of ${formatNumber(sent)} simulation emails were clicked in the period.` }),
    kpi({ key: "high_risk", label: "High-risk people", value: highRisk, unit: "count", betterWhen: "lower", thresholds: { good: 0, warn: Math.max(1, Math.round(learners * 0.1)) }, explanation: "People whose human risk score is 60 or more." }),
    kpi({ key: "overdue", label: "Overdue training", value: overdue, unit: "count", betterWhen: "lower", explanation: "Assignments past their due date and not yet completed." }),
    kpi({ key: "quiz", label: "Average quiz score", value: avgScore, unit: "percent", betterWhen: "higher", thresholds: { good: 85, warn: 75 }, explanation: "Best quiz score per lesson, averaged over everyone who took one." }),
  ];

  const recommendations: Recommendation[] = [];
  if (learners === 0) recommendations.push({ priority: "high", title: "Start security awareness training", rationale: "No one is enrolled yet. Most attacks start with a person being tricked; import staff from the directory and assign the core lessons.", owner: "customer" });
  if (sent === 0 && learners > 0) recommendations.push({ priority: "medium", title: "Run a phishing simulation", rationale: "No simulation was sent this period. A quarterly simulation shows who needs help and keeps people alert.", owner: "mssp" });
  if (sent > 0 && clickRate !== null && clickRate > 15) recommendations.push({ priority: "high", title: "Reduce the phishing click rate", rationale: `${formatPercent(clickRate)} of simulation emails were clicked. Make sure everyone who clicked completes the follow-up lesson, and repeat the simulation next month.`, owner: "customer" });
  if (overdue > 0) recommendations.push({ priority: "medium", title: "Chase overdue training", rationale: `${plural(overdue, "assignment is", "assignments are")} overdue. A reminder from a manager is the most effective nudge.`, owner: "customer" });
  if (highRisk > 0) recommendations.push({ priority: "high", title: "Coach high-risk people", rationale: `${plural(highRisk, "person has", "people have")} a high human-risk score. Short one-to-one coaching and stricter email filtering for them reduce the risk most.`, owner: "customer" });

  const campaigns = cur.flatMap((o) => o.campaigns.map((c) => ({ ...c, org: ctx.orgName(o.organizationId), rate: c.sent ? Math.round((c.clicked / c.sent) * 100) : null })));
  const atRisk = cur
    .flatMap((o) => o.atRisk.map((p) => ({ ...p, org: ctx.orgName(o.organizationId) })))
    .sort((a, b) => b.score - a.score)
    .slice(0, topN);
  const multiOrg = cur.length > 1;

  return {
    title: "Security awareness report",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · ${ctx.period.label}` : `${ctx.organizations.length} organizations · ${ctx.period.label}`,
    summary: {
      headline:
        learners === 0
          ? "No one is enrolled in security awareness training yet."
          : `${formatNumber(learners)} people enrolled; ${completion === null ? "no training assigned yet" : `${formatPercent(completion)} of training completed`}${sent ? `; ${formatPercent(clickRate)} clicked a phishing simulation` : ""}.`,
      highlights: [
        !sent
          ? "No phishing simulation was sent in this period."
          : prevSent
            ? `Phishing click rate ${changePhrase(clickRate, prevClickRate, { up: "rose", down: "fell" })} versus the previous period.`
            : `${formatPercent(clickRate)} of simulation emails were clicked; there was no simulation in the previous period to compare with.`,
        `${plural(highRisk, "person is", "people are")} at high human risk.`,
        overdue ? `${plural(overdue, "training assignment is", "training assignments are")} overdue.` : "No training is overdue.",
      ],
      kpis,
    },
    recommendations,
    terms: ["Training completion", "Click rate", "Human risk", "Trend vs previous period"],
    sections: [
      {
        id: "overview",
        title: "Overview",
        blocks: [
          { kind: "kpis", items: kpis },
          narrative([
            "People are the most targeted part of any organization: most breaches start with a convincing email, message or call. This report shows how well staff are trained, how they responded to safe phishing simulations, and who needs more help.",
            completion !== null && completion < 70 ? "Training completion is low; incomplete training leaves people unprepared for the attacks they are most likely to meet." : null,
          ]),
          { kind: "recommendations", items: recommendations, emptyMessage: "Awareness is on track; keep the regular training and simulation cadence." },
        ],
      },
      {
        id: "phishing",
        title: "Phishing simulations",
        description: "Safe test emails sent in the period and how many people clicked.",
        blocks: [
          table(
            "phishing-campaigns",
            "Simulations",
            [
              ...(multiOrg ? [{ key: "org", label: "Organization" }] : []),
              { key: "name", label: "Simulation" },
              { key: "sentAt", label: "Sent", format: "date" as const },
              { key: "sent", label: "Delivered", format: "number" as const, align: "right" as const },
              { key: "clicked", label: "Clicked", format: "number" as const, align: "right" as const },
              { key: "rate", label: "Click rate", format: "percent" as const, align: "right" as const },
            ],
            campaigns.map((c) => ({ org: c.org, name: c.name, sentAt: c.sentAt, sent: c.sent, clicked: c.clicked, rate: c.rate })),
            { emptyMessage: "No phishing simulation was sent in this period." },
          ),
        ],
      },
      {
        id: "people",
        title: "People who need attention",
        description: "Highest human-risk scores (medium and high). Each score is explained in the platform.",
        blocks: [
          table(
            "awareness-at-risk",
            "People to coach",
            [
              ...(multiOrg ? [{ key: "org", label: "Organization" }] : []),
              { key: "name", label: "Person" },
              { key: "score", label: "Human risk", format: "score" as const, align: "right" as const },
              { key: "level", label: "Level" },
              { key: "reason", label: "Main reason" },
            ],
            atRisk.map((p) => ({ org: p.org, name: p.name, score: p.score, level: p.level, reason: p.mainReason })),
            { emptyMessage: "No one has a medium or high human-risk score." },
          ),
        ],
      },
    ],
  };
}
