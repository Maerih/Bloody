import { describe, expect, it } from "vitest";
import { DEFAULT_PRICE_BOOK, formatMoney, quote } from "./billing.js";

describe("billing quotes", () => {
  it("pay as you go bills the units actually protected at list price", () => {
    const q = quote({ product: "edr", model: "payg", units: 7 });
    expect(q).toMatchObject({ unitPrice: 500, billedUnits: 7, minimum: 0, monthlyTotal: 3500, invoiceTotal: 3500, discounts: [] });
    expect(formatMoney(q.monthlyTotal, q.currency)).toBe("$35.00");
  });

  it("commit models bill at least the minimum, with the model discount", () => {
    const q = quote({ product: "edr", model: "annual", units: 10 });
    expect(q.billedUnits).toBe(50); // default annual minimum
    expect(q.unitPrice).toBe(400); // 20% off $5.00
    expect(q.monthlyTotal).toBe(20_000);
    expect(q.termMonths).toBe(12);
  });

  it("stacks volume tiers and the annual-upfront discount, explaining each", () => {
    const q = quote({ product: "edr", model: "annual", units: 1200, interval: "annual_upfront" });
    expect(q.discounts.map((d) => d.label)).toEqual(["Annual discount", "Volume 1000+ units", "Paid annually upfront"]);
    expect(q.unitPrice).toBe(Math.round(500 * 0.8 * 0.9 * 0.95)); // 342
    expect(q.invoiceTotal).toBe(q.unitPrice * 1200 * 12);
  });

  it("only annual terms can be paid upfront; MSSP partners get wholesale", () => {
    expect(quote({ product: "itdr", model: "payg", units: 3, interval: "annual_upfront" }).interval).toBe("monthly");
    const partner = quote({ product: "edr", model: "mssp_partner", units: 400 });
    expect(partner.unitPrice).toBe(Math.round(500 * 0.55 * 0.95));
    expect(partner.billedUnits).toBe(400);
  });

  it("uses the operator's price book", () => {
    const q = quote({ product: "siem", model: "payg", units: 2 }, { ...DEFAULT_PRICE_BOOK, currency: "EUR", listPrice: { edr: 600, itdr: 350, siem: 450 } });
    expect(q).toMatchObject({ currency: "EUR", unitPrice: 450, monthlyTotal: 900 });
  });
});
