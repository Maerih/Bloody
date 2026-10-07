import { describe, expect, it } from "vitest";
import { brandInk, contrastRatio, decodeLogo, onColor, resolveReportBranding } from "./branding.js";
import type { EscalationFact, IncidentFact } from "./datasource.js";
import { defang, formatCurrency, formatDuration, formatPercent, formatPeriod, formatValue, slugify } from "./format.js";
import { bucketBySeverity, bucketDaily, coefficientOfVariation, computeDelta, distribution, incidentTimings, kpi, timeBuckets, topTechniques } from "./metrics.js";
import { DEFAULT_SLA_TARGETS, evaluateEscalations, evaluateIncidentSla, mergeSlaTargets } from "./sla.js";

const ORG = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
function inc(p: Partial<IncidentFact>): IncidentFact {
  return { id: "x", organizationId: ORG, number: 1, title: "t", severity: "high", status: "new", riskScore: 50, detectedAt: "2026-09-10T00:00:00.000Z", firstActivityAt: null, acknowledgedAt: null, containedAt: null, closedAt: null, assigneeId: null, assigneeName: null, attack: [], alertCount: 1, assetCount: 1, identityCount: 0, ...p };
}

describe("metrics", () => {
  it("computes distributions with median and p90", () => {
    expect(distribution([10, 20, 30, 40])).toEqual({ n: 4, mean: 25, median: 25, p90: 37 });
    expect(distribution([])).toEqual({ n: 0, mean: null, median: null, p90: null });
  });

  it("computes deltas with direction and sentiment", () => {
    expect(computeDelta(120, 100, "higher")).toEqual({ previous: 100, absolute: 20, percent: 20, direction: "up", sentiment: "good" });
    expect(computeDelta(120, 100, "lower")).toMatchObject({ direction: "up", sentiment: "bad" });
    expect(computeDelta(100, 100, "lower")).toMatchObject({ direction: "flat", sentiment: "neutral" });
    expect(computeDelta(5, 0, "lower")).toMatchObject({ percent: null, direction: "up", sentiment: "bad" });
    expect(computeDelta(null, 3, "lower")).toBeNull();
    expect(kpi({ key: "k", label: "K", value: 96, unit: "percent", betterWhen: "higher", thresholds: { good: 95, warn: 85 }, explanation: "x" }).status).toBe("good");
    expect(kpi({ key: "k", label: "K", value: 7, unit: "count", betterWhen: "lower", thresholds: { good: 0, warn: 5 }, explanation: "x" }).status).toBe("bad");
  });

  it("derives MTTD / MTTA / MTTC / MTTR from incident timestamps", () => {
    const from = new Date("2026-09-01T00:00:00Z");
    const to = new Date("2026-10-01T00:00:00Z");
    const t = incidentTimings(
      [
        inc({ firstActivityAt: "2026-09-09T23:00:00.000Z", acknowledgedAt: "2026-09-10T00:10:00.000Z", containedAt: "2026-09-10T01:00:00.000Z", closedAt: "2026-09-10T02:00:00.000Z" }),
        inc({ detectedAt: "2026-08-30T00:00:00.000Z", closedAt: "2026-09-02T00:00:00.000Z" }),
      ],
      from,
      to,
    );
    expect(t.mttd.mean).toBe(60);
    expect(t.mtta.mean).toBe(10);
    expect(t.mttc.mean).toBe(60);
    expect(t.mttr.n).toBe(2); // closed in window, including the incident detected before it
    expect(t.mttr.mean).toBe((120 + 4320) / 2);
  });

  it("buckets time series by day, week or month", () => {
    const daily = timeBuckets(new Date("2026-09-01T00:00:00Z"), new Date("2026-09-08T00:00:00Z"));
    expect(daily.granularity).toBe("day");
    expect(daily.labels[0]).toBe("01 Sep");
    expect(bucketDaily([{ date: "2026-09-02", count: 3 }, { date: "2026-09-02", count: 2 }, { date: "2026-10-02", count: 9 }], daily)[1]).toBe(5);
    const weekly = timeBuckets(new Date("2026-06-01T00:00:00Z"), new Date("2026-09-01T00:00:00Z"));
    expect(weekly.granularity).toBe("week");
    expect(weekly.labels[0]).toBe("Wk 01 Jun");
    expect(timeBuckets(new Date("2025-10-01T00:00:00Z"), new Date("2026-10-01T00:00:00Z")).labels).toHaveLength(12);
    const sev = bucketBySeverity([inc({ severity: "critical", detectedAt: "2026-09-03T05:00:00Z" })], (i) => i.detectedAt, daily);
    expect(sev.critical[2]).toBe(1);
  });

  it("ranks ATT&CK techniques and measures workload balance", () => {
    const top = topTechniques([inc({ attack: [{ id: "T1486", name: "Data Encrypted for Impact" }] }), inc({ attack: [{ id: "T1486" }] })], [{ id: "T1059", count: 1 }], 5);
    expect(top[0]).toMatchObject({ id: "T1486", count: 2, name: "Data Encrypted for Impact" });
    expect(coefficientOfVariation([5, 5, 5])).toBe(0);
    expect(coefficientOfVariation([1])).toBeNull();
  });
});

describe("SLA evaluation", () => {
  const asOf = new Date("2026-09-10T03:00:00.000Z");
  const targets = (): typeof DEFAULT_SLA_TARGETS => DEFAULT_SLA_TARGETS;

  it("counts not-yet-due objectives as pending and overdue open incidents as breaches", () => {
    const s = evaluateIncidentSla(
      [
        inc({ id: "a", severity: "critical", acknowledgedAt: "2026-09-10T00:05:00.000Z", closedAt: "2026-09-10T02:00:00.000Z", status: "closed" }),
        inc({ id: "b", severity: "high" }), // 180 min unacknowledged > 60 → breach; resolve 180 < 1440 → pending
        inc({ id: "c", severity: "medium", acknowledgedAt: "2026-09-10T00:30:00.000Z", status: "false_positive", closedAt: "2026-09-10T00:40:00.000Z" }),
      ],
      targets,
      asOf,
    );
    expect(s.acknowledge).toEqual({ met: 2, breached: 1, pending: 0, attainmentPct: (2 / 3) * 100 });
    expect(s.resolve).toEqual({ met: 2, breached: 0, pending: 1, attainmentPct: 100 });
    expect(s.incidents.find((r) => r.incident.id === "b")!.reasons).toEqual(["not acknowledged after 3h 0m (target 1h 0m)"]);
    expect(s.bySeverity.critical.resolve.attainmentPct).toBe(100);
    expect(evaluateIncidentSla([], targets, asOf).overall.attainmentPct).toBeNull();
    expect(mergeSlaTargets(DEFAULT_SLA_TARGETS, { acknowledgeMinutes: { critical: 5, high: 30, medium: 120, low: 600, info: 1000 } }).resolveMinutes.critical).toBe(240);
  });

  it("evaluates escalations on time / late / overdue", () => {
    const e = (p: Partial<EscalationFact>): EscalationFact => ({ id: "e", organizationId: ORG, incidentId: null, title: "t", severity: "high", status: "open", createdAt: "2026-09-01T00:00:00Z", dueAt: "2026-09-02T00:00:00Z", acknowledgedAt: null, resolvedAt: null, ...p });
    const s = evaluateEscalations([e({ resolvedAt: "2026-09-01T12:00:00Z" }), e({ resolvedAt: "2026-09-03T00:00:00Z" }), e({}), e({ dueAt: "2026-09-30T00:00:00Z" })], new Date("2026-09-10T00:00:00Z"));
    expect(s).toMatchObject({ onTime: 1, late: 1, overdueOpen: 1, openWithinDue: 1 });
    expect(s.onTimePct).toBeCloseTo(100 / 3, 5);
  });
});

describe("formatting and branding", () => {
  it("formats durations, percentages, currency and periods", () => {
    expect(formatDuration(45)).toBe("45m");
    expect(formatDuration(200)).toBe("3h 20m");
    expect(formatDuration(3000)).toBe("2d 2h");
    expect(formatDuration(null)).toBe("—");
    expect(formatPercent(66.666)).toBe("66.7%");
    expect(formatPercent(100)).toBe("100%");
    expect(formatCurrency(14000, "USD")).toBe("$14,000");
    expect(formatValue(58_700, "count", { compact: true })).toBe("58.7K");
    expect(formatPeriod(new Date("2026-09-01T00:00:00Z"), new Date("2026-10-01T00:00:00Z"))).toMatch(/^1 – 30 Sept? 2026$/);
    expect(formatPeriod(new Date("2025-12-15T00:00:00Z"), new Date("2026-01-15T00:00:00Z"))).toBe("15 Dec 2025 – 14 Jan 2026");
    expect(defang("http://bad.example/x")).toBe("hxxp://bad[.]example/x");
    expect(slugify("Acme Corp — EU")).toBe("acme-corp-eu");
  });

  it("validates branding and derives accessible colours", () => {
    expect(resolveReportBranding({ name: "Acme", primaryColor: "#0055AA" }).issues).toEqual([]);
    expect(resolveReportBranding({ primaryColor: "red" }).issues[0]).toMatch(/primaryColor/);
    expect(onColor("#FFE000")).not.toBe("#FFFFFF");
    expect(onColor("#0055AA")).toBe("#FFFFFF");
    expect(contrastRatio(brandInk("#FFB3B3"), "#FFFFFF")).toBeGreaterThanOrEqual(4.5);
    expect(decodeLogo("data:image/png;base64,AAAA")).toBeNull(); // not a real PNG
  });
});
