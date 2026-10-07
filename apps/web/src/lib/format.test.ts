import { describe, expect, it } from "vitest";
import {
  daysUntil,
  describeCron,
  formatCurrency,
  formatDuration,
  formatInteger,
  formatNumber,
  formatPercent,
  formatRelativeTime,
  humanize,
  plural,
  slugify,
} from "./format";
import { csvCell, toCsv } from "./download";

describe("formatNumber", () => {
  it("formats the Command Center K/M style", () => {
    expect(formatNumber(58_700)).toBe("58.7K");
    expect(formatNumber(1_000)).toBe("1K");
    expect(formatNumber(1_250_000)).toBe("1.3M");
    expect(formatNumber(2_000_000_000)).toBe("2B");
    expect(formatNumber(999)).toBe("999");
    expect(formatNumber(0)).toBe("0");
  });

  it("promotes to the next unit instead of printing 1000K", () => {
    expect(formatNumber(999_950)).toBe("1M");
    expect(formatNumber(999_949)).toBe("999.9K");
  });

  it("handles negatives, decimals and missing values", () => {
    expect(formatNumber(-1_500)).toBe("-1.5K");
    expect(formatNumber(12.34)).toBe("12.3");
    expect(formatNumber(null)).toBe("—");
    expect(formatNumber(undefined)).toBe("—");
    expect(formatNumber(Number.NaN)).toBe("—");
  });

  it("supports custom precision", () => {
    expect(formatNumber(58_765, 2)).toBe("58.77K");
  });
});

describe("other formatters", () => {
  it("formatInteger uses thousands separators", () => {
    expect(formatInteger(128_421)).toBe("128,421");
    expect(formatInteger(null)).toBe("—");
  });

  it("formatPercent refuses a zero denominator", () => {
    expect(formatPercent(9, 10)).toBe("90%");
    expect(formatPercent(1, 3, 1)).toBe("33.3%");
    expect(formatPercent(0, 0)).toBe("—");
  });

  it("formatDuration renders MTTD/MTTR minutes", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(0.4)).toBe("<1m");
    expect(formatDuration(45)).toBe("45m");
    expect(formatDuration(84)).toBe("1h 24m");
    expect(formatDuration(120)).toBe("2h");
    expect(formatDuration(1440 + 180)).toBe("1d 3h");
  });

  it("formatRelativeTime is relative to an injected clock", () => {
    const now = Date.parse("2026-10-07T12:00:00Z");
    expect(formatRelativeTime("2026-10-07T11:59:50Z", now)).toBe("just now");
    expect(formatRelativeTime("2026-10-07T11:55:00Z", now)).toBe("5m ago");
    expect(formatRelativeTime("2026-10-07T09:00:00Z", now)).toBe("3h ago");
    expect(formatRelativeTime("2026-10-05T12:00:00Z", now)).toBe("2d ago");
    expect(formatRelativeTime("2026-10-07T16:00:00Z", now)).toBe("in 4h");
    expect(formatRelativeTime("not a date", now)).toBe("—");
  });

  it("daysUntil counts whole days", () => {
    const now = Date.parse("2026-10-07T00:00:00Z");
    expect(daysUntil("2026-11-01T00:00:00Z", now)).toBe(25);
  });

  it("formatCurrency compacts large values", () => {
    expect(formatCurrency(12_400)).toBe("$12,400");
    expect(formatCurrency(1_240_000)).toBe("$1.2M");
    expect(formatCurrency(null)).toBe("—");
  });

  it("slugify produces valid organization slugs", () => {
    expect(slugify("Dorisec Africa & Co.")).toBe("dorisec-africa-co");
    expect(slugify("  Équipe Sécurité ")).toBe("equipe-securite");
    expect(/^[a-z0-9-]{2,63}$/.test(slugify("A".repeat(100)))).toBe(true);
  });

  it("describeCron explains common schedules", () => {
    expect(describeCron("0 7 * * *")).toBe("Daily at 07:00 UTC");
    expect(describeCron("30 6 * * 1")).toBe("Weekly on Monday at 06:30 UTC");
    expect(describeCron("0 8 1 * *")).toBe("Monthly on day 1 at 08:00 UTC");
    expect(describeCron("0 7 * * 1-5")).toBe("Weekdays at 07:00 UTC");
    expect(describeCron("*/5 * * * *")).toBe("*/5 * * * *");
  });

  it("humanize and plural", () => {
    expect(humanize("false_positive")).toBe("False positive");
    expect(plural(1, "agent")).toBe("1 agent");
    expect(plural(2, "agent")).toBe("2 agents");
  });
});

describe("CSV export", () => {
  it("neutralises spreadsheet formula injection and quotes", () => {
    expect(csvCell("=HYPERLINK(\"x\")")).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvCell("+1")).toBe("'+1");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell(null)).toBe("");
    expect(toCsv(["h1", "h2"], [[1, "x"]])).toBe("h1,h2\r\n1,x");
  });
});
