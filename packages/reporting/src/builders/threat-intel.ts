import { defang, formatNumber } from "../format.js";
import { bucketDaily, inWindow, kpi, timeBuckets, topTechniques } from "../metrics.js";
import { chart, changePhrase, hbar, lineChart, narrative, table, topNamed } from "./blocks.js";
import type { BuildContext, BuilderResult } from "./context.js";

/** Threat intelligence — feeds, matches in the environment, actors, malware and techniques. */
export async function buildThreatIntel(ctx: BuildContext): Promise<BuilderResult> {
  const { ds, q, prev, from, to, topN } = ctx;
  const [intel, prevIntel, incidents, alerts] = await Promise.all([ds.intelStats(q, topN), ds.intelStats(prev, topN), ds.incidents(q), ds.alertStats(q)]);
  const detected = incidents.filter((i) => inWindow(i.detectedAt, from, to));
  const buckets = timeBuckets(from, to);
  const techniques = topTechniques(detected, alerts.topTechniques, topN);
  const topActor = topNamed(intel.topActors, 1)[0];
  const kpis = [
    kpi({ key: "indicators", label: "Active indicators", value: intel.indicatorsTotal, unit: "count", previous: prevIntel.indicatorsTotal, betterWhen: "neutral", explanation: "Unexpired indicators available for matching at period end." }),
    kpi({ key: "new", label: "New indicators", value: intel.indicatorsNew, unit: "count", previous: prevIntel.indicatorsNew, betterWhen: "neutral", explanation: "Indicators first seen in the period, across all feeds." }),
    kpi({ key: "matches", label: "Matches in environment", value: intel.matchesTotal, unit: "count", previous: prevIntel.matchesTotal, betterWhen: "lower", explanation: "Telemetry observations matching a known indicator." }),
    kpi({ key: "sources", label: "Intel sources", value: intel.bySource.length, unit: "count", betterWhen: "neutral", explanation: "Feeds and platforms contributing indicators (e.g. MISP, OpenCTI, internal)." }),
  ];
  return {
    title: "Threat intelligence report",
    subtitle: ctx.scopeName ? `${ctx.scopeName} · ${ctx.period.label}` : `${ctx.organizations.length} organizations · ${ctx.period.label}`,
    summary: {
      headline: `${formatNumber(intel.matchesTotal)} indicator matches in the environment from ${formatNumber(intel.indicatorsTotal, { compact: true })} active indicators${topActor ? `; most active actor: ${topActor.name}` : ""}.`,
      highlights: [
        `Matches ${changePhrase(intel.matchesTotal, prevIntel.matchesTotal)} versus the previous period.`,
        `${formatNumber(intel.indicatorsNew)} new indicators ingested.`,
        techniques[0] ? `Most observed technique in incidents and alerts: ${techniques[0].id}${techniques[0].name ? ` ${techniques[0].name}` : ""}.` : "No ATT&CK techniques observed.",
      ],
      kpis,
    },
    recommendations: [],
    terms: ["Trend vs previous period"],
    sections: [
      {
        id: "overview",
        title: "Intelligence overview",
        blocks: [
          { kind: "kpis", items: kpis },
          chart(lineChart("matches", "Indicator matches", buckets.labels, [{ key: "matches", name: "Matches", values: bucketDaily(intel.matchesDaily, buckets) }], "count", { subtitle: `per ${buckets.granularity}` })),
          chart(hbar("by-type", "Indicators by type", topNamed(intel.byType, 10), { seriesName: "Indicators" })),
          chart(hbar("by-source", "Indicators by source", topNamed(intel.bySource, 10), { seriesName: "Indicators" })),
          narrative(["Indicator values are defanged (e.g. hxxps://example[.]com) so they cannot be opened accidentally from this report."], { tone: "note" }),
        ],
      },
      {
        id: "matches",
        title: "Indicators observed in the environment",
        blocks: [
          table(
            "top-matched",
            "Most matched indicators",
            [
              { key: "type", label: "Type", format: "code" },
              { key: "value", label: "Indicator", format: "code", width: 3 },
              { key: "severity", label: "Severity", format: "severity" },
              { key: "confidence", label: "Confidence", format: "percent", align: "right" },
              { key: "matches", label: "Matches", format: "number", align: "right" },
              { key: "actor", label: "Attribution", width: 1.4 },
              { key: "source", label: "Source" },
              { key: "lastSeenAt", label: "Last seen", format: "date" },
            ],
            intel.topMatched.slice(0, topN).map((m) => ({ type: m.type, value: defang(m.value), severity: m.severity, confidence: m.confidence, matches: m.matches, actor: m.threatActor ?? "unattributed", source: m.source, lastSeenAt: m.lastSeenAt })),
            { emptyMessage: "No indicators matched telemetry in this period." },
          ),
        ],
      },
      {
        id: "adversaries",
        title: "Adversaries, malware and campaigns",
        blocks: [
          table("actors", "Threat actors", [{ key: "name", label: "Actor", width: 3 }, { key: "count", label: "Matches", format: "number", align: "right" }], topNamed(intel.topActors, topN).map((a) => ({ name: a.name, count: a.count })), { emptyMessage: "No attributed activity." }),
          table("malware", "Malware families", [{ key: "name", label: "Malware", width: 3 }, { key: "count", label: "Matches", format: "number", align: "right" }], topNamed(intel.topMalware, topN).map((a) => ({ name: a.name, count: a.count })), { emptyMessage: "No malware families matched." }),
          table("campaigns", "Campaigns", [{ key: "name", label: "Campaign", width: 3 }, { key: "count", label: "Matches", format: "number", align: "right" }], topNamed(intel.topCampaigns, topN).map((a) => ({ name: a.name, count: a.count })), { emptyMessage: "No campaigns matched." }),
          chart(hbar("techniques", "Top ATT&CK techniques observed", techniques.map((x) => ({ name: x.name ? `${x.id} ${x.name}` : x.id, count: x.count })), { seriesName: "Observations" })),
        ],
      },
    ],
  };
}
