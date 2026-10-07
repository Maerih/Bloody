import { describe, expect, it } from "vitest";
import { CronParseError, cronMatches, describeCron, firesBetween, isDue, isValidCron, nextRun, nextRuns, parseCron, validateCron } from "./cron.js";

const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);

describe("cron parser", () => {
  it("parses fields, names, steps, ranges and macros", () => {
    const s = parseCron("*/15 9-17 * JAN,jul MON-FRI");
    expect(s.minutes).toEqual([0, 15, 30, 45]);
    expect(s.hours).toEqual([9, 10, 11, 12, 13, 14, 15, 16, 17]);
    expect(s.months).toEqual([1, 7]);
    expect(s.daysOfWeek).toEqual([1, 2, 3, 4, 5]);
    expect(s.domRestricted).toBe(false);
    expect(s.dowRestricted).toBe(true);
    expect(parseCron("0 0 * * 7").daysOfWeek).toEqual([0]);
    expect(parseCron("5/20 * * * *").minutes).toEqual([5, 25, 45]);
    expect(parseCron("@daily").minutes).toEqual([0]);
    expect(parseCron("@weekly").daysOfWeek).toEqual([0]);
  });

  it("rejects malformed expressions with clear errors", () => {
    expect(() => parseCron("* * * *")).toThrow(CronParseError);
    expect(() => parseCron("60 * * * *")).toThrow(/out of range/);
    expect(() => parseCron("*/0 * * * *")).toThrow(/invalid step/);
    expect(() => parseCron("0 0 * * FRI-MON")).toThrow(/ascending/);
    expect(() => parseCron("@reboot")).toThrow(/unsupported macro/);
    expect(() => parseCron("a b c d e")).toThrow(CronParseError);
    expect(isValidCron("0 6 1 * *")).toBe(true);
    expect(validateCron("bad")).toMatchObject({ ok: false });
  });
});

describe("next run calculation", () => {
  const after = new Date("2026-10-07T12:07:30Z"); // a Wednesday

  it("handles minute steps, daily and weekly schedules", () => {
    expect(iso(nextRun("*/15 * * * *", after))).toBe("2026-10-07T12:15:00.000Z");
    expect(iso(nextRun("0 8 * * *", after))).toBe("2026-10-08T08:00:00.000Z");
    expect(iso(nextRun("30 6 * * MON", after))).toBe("2026-10-12T06:30:00.000Z");
    expect(iso(nextRun("0 0 1 * *", after))).toBe("2026-11-01T00:00:00.000Z");
    expect(iso(nextRun("0 12 * * *", new Date("2026-10-07T12:00:00Z")))).toBe("2026-10-08T12:00:00.000Z");
  });

  it("is strictly after the reference time", () => {
    expect(iso(nextRun("* * * * *", new Date("2026-10-07T12:00:00.000Z")))).toBe("2026-10-07T12:01:00.000Z");
  });

  it("ORs day-of-month and day-of-week when both are restricted", () => {
    // 13th of the month OR Friday → Fri 9 Oct comes before Tue 13 Oct.
    expect(iso(nextRun("0 0 13 * FRI", after))).toBe("2026-10-09T00:00:00.000Z");
    // */2 in day-of-month counts as unrestricted → only weekday applies.
    expect(iso(nextRun("0 0 */2 * FRI", after))).toBe("2026-10-09T00:00:00.000Z");
  });

  it("handles leap days and impossible dates", () => {
    expect(iso(nextRun("0 0 29 2 *", after))).toBe("2028-02-29T00:00:00.000Z");
    expect(nextRun("0 0 30 2 *", after)).toBeNull();
    expect(nextRun("0 0 31 4 *", after)).toBeNull();
  });

  it("evaluates wall-clock time in an IANA time zone across DST", () => {
    // New York: EDT (UTC-4) until 1 Nov 2026, then EST (UTC-5).
    expect(iso(nextRun("0 9 * * *", new Date("2026-10-30T00:00:00Z"), { timeZone: "America/New_York" }))).toBe("2026-10-30T13:00:00.000Z");
    expect(iso(nextRun("0 9 * * *", new Date("2026-11-01T12:00:00Z"), { timeZone: "America/New_York" }))).toBe("2026-11-01T14:00:00.000Z");
    // 02:30 does not exist on the spring-forward day (8 Mar 2026) → next valid 02:30 is 9 Mar.
    expect(iso(nextRun("30 2 * * *", new Date("2026-03-08T00:00:00Z"), { timeZone: "America/New_York" }))).toBe("2026-03-09T06:30:00.000Z");
    // Ambiguous 01:30 on fall-back day fires once.
    const runs = firesBetween("30 1 * * *", new Date("2026-11-01T00:00:00Z"), new Date("2026-11-02T00:00:00Z"), { timeZone: "America/New_York" });
    expect(runs).toHaveLength(1);
    expect(() => nextRun("0 9 * * *", after, { timeZone: "Mars/Olympus" })).toThrow(/unknown time zone/);
  });

  it("lists upcoming runs and matches instants", () => {
    expect(nextRuns("0 */6 * * *", after, 3).map(iso)).toEqual(["2026-10-07T18:00:00.000Z", "2026-10-08T00:00:00.000Z", "2026-10-08T06:00:00.000Z"]);
    expect(cronMatches("*/5 * * * *", new Date("2026-10-07T12:10:42Z"))).toBe(true);
    expect(cronMatches("*/5 * * * *", new Date("2026-10-07T12:11:00Z"))).toBe(false);
  });
});

describe("due checks for schedules", () => {
  it("is due once per slot and coalesces missed runs", () => {
    const now = new Date("2026-10-07T08:00:20Z");
    const due = isDue({ cron: "0 8 * * *", now, lastRunAt: "2026-10-06T08:00:05Z" });
    expect(due.due).toBe(true);
    expect(iso(due.scheduledFor)).toBe("2026-10-07T08:00:00.000Z");
    expect(due.missedRuns).toBe(1);
    expect(iso(due.nextRunAt)).toBe("2026-10-08T08:00:00.000Z");

    expect(isDue({ cron: "0 8 * * *", now, lastRunAt: now }).due).toBe(false);

    const afterOutage = isDue({ cron: "0 8 * * *", now, lastRunAt: "2026-10-03T08:00:00Z" });
    expect(afterOutage.missedRuns).toBe(4);
    expect(iso(afterOutage.scheduledFor)).toBe("2026-10-07T08:00:00.000Z");
  });

  it("does not fire a brand-new schedule for an old slot", () => {
    expect(isDue({ cron: "0 8 * * *", now: new Date("2026-10-07T09:30:00Z"), lastRunAt: null }).due).toBe(false);
    expect(isDue({ cron: "0 8 * * *", now: new Date("2026-10-07T08:00:30Z"), lastRunAt: null }).due).toBe(true);
  });
});

describe("describeCron", () => {
  it("produces human-readable descriptions", () => {
    expect(describeCron("* * * * *")).toBe("Every minute");
    expect(describeCron("*/15 * * * *")).toBe("Every 15 minutes");
    expect(describeCron("0 * * * *")).toBe("Every hour");
    expect(describeCron("0 8 * * *")).toBe("Every day at 08:00");
    expect(describeCron("30 6 * * 1-5")).toBe("On weekdays at 06:30");
    expect(describeCron("0 7 1 * *")).toBe("On the 1st of the month at 07:00");
    expect(describeCron("0 9 * * MON")).toBe("On Mondays at 09:00");
    expect(describeCron("0 0 1 1 *")).toBe("On the 1st of the month at 00:00 in January");
  });
});
