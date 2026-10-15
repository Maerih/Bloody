import { BILLING_MODELS, BILLING_PRODUCTS, DEFAULT_PRICE_BOOK, PAYMENT_PROVIDERS } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { BillingOverview } from "../../api/types";
import { mockApi, renderWithSession } from "../../test/utils";
import { CommercialBilling } from "./CommercialBilling";

const NOW = "2026-10-01T00:00:00.000Z";
function overview(over: Partial<BillingOverview> = {}): BillingOverview {
  return {
    contact: { name: "SCIAT Account Team", email: "billing@sciat.africa" },
    currency: "USD",
    priceBook: DEFAULT_PRICE_BOOK,
    models: [...BILLING_MODELS] as BillingOverview["models"],
    products: [...BILLING_PRODUCTS],
    providers: PAYMENT_PROVIDERS.filter((p) => p.key === "stripe" || p.key === "nowpayments" || p.key === "bank_transfer").map((p) => ({ ...p, canSaveCard: p.key === "stripe" })),
    bankDetails: "SCIAT AFRICA LTD\nSWIFT TESTKENA",
    profile: { companyName: "Kilimanjaro Bank", billingEmail: "ap@kb.example", taxId: "", billingAddress: { line1: "0100", line2: "", city: "Nairobi", region: "", postalCode: "00100", country: "KE" }, shippingAddress: { line1: "", line2: "", city: "", region: "", postalCode: "", country: "" } },
    units: { edr: 12, itdr: 4, siem: 2 },
    subscriptions: [{ id: "00000000-0000-4000-8000-000000000a01", product: "edr", model: "payg", interval: "monthly", status: "active", minimum: 0, unitPrice: 500, currency: "USD", startsAt: NOW, endsAt: null, autoRenew: true, currentUnits: 12 }],
    paymentMethods: [{ id: "00000000-0000-4000-8000-000000000b01", kind: "card", provider: "stripe", label: "visa •••• 6865", brand: "visa", last4: "6865", expMonth: 6, expYear: 2031, isDefault: true, status: "active", createdAt: NOW }],
    invoices: [{ id: "00000000-0000-4000-8000-000000000c01", number: "INV-202609-0001", periodStart: "2026-09-01T00:00:00.000Z", periodEnd: NOW, currency: "USD", lines: [{ product: "edr", model: "payg", description: "Managed EDR — Pay as you go: 12 endpoints", quantity: 12, unitPrice: 500, amount: 6000 }], total: 6000, status: "open", dueAt: "2026-10-15T00:00:00.000Z", paidAt: null, paidVia: null, createdAt: NOW, paymentUrl: null }],
    ...over,
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("Commercial billing", () => {
  it("shows the account team, subscription, card on file and invoices", async () => {
    mockApi({ "/billing/overview": overview() });
    renderWithSession(<CommercialBilling />);
    expect(await screen.findByText("SCIAT Account Team")).toBeInTheDocument();
    expect(screen.getByText("visa •••• 6865")).toBeInTheDocument();
    expect(screen.getByText("expires 06/2031")).toBeInTheDocument();
    expect(screen.getByText("INV-202609-0001")).toBeInTheDocument();
    expect(screen.getByText(/never sees or stores card numbers/)).toBeInTheDocument();
  });

  it("quotes a plan live with each discount and subscribes", async () => {
    const { calls } = mockApi({ "/billing/overview": overview(), "POST /billing/subscriptions": { subscription: {} } });
    renderWithSession(<CommercialBilling />);
    fireEvent.click(await screen.findByRole("radio", { name: /^Annual/ }));
    const q = screen.getByTestId("quote");
    expect(within(q).getByText("Annual discount")).toBeInTheDocument();
    expect(within(q).getByText("50 endpoints × $4.00")).toBeInTheDocument(); // 12 protected, 50 committed minimum
    expect(within(q).getByText("$200.00 / month")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Billing interval"), { target: { value: "annual_upfront" } });
    expect(within(q).getByText("Paid annually upfront")).toBeInTheDocument();
    fireEvent.click(within(q).getByRole("button", { name: "Switch to this plan" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ product: "edr", model: "annual", minimum: 50, interval: "annual_upfront" });
  });

  it("pays an invoice on the provider's hosted page, or shows wire instructions", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const { calls } = mockApi({ "/billing/overview": overview(), "POST /billing/invoices/00000000-0000-4000-8000-000000000c01/checkout": { url: "https://checkout.stripe.test/c/cs_1" } });
    renderWithSession(<CommercialBilling />);
    fireEvent.click(await screen.findByRole("button", { name: "Pay" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Show instructions" }));
    expect(within(dialog).getByTestId("wire-instructions")).toHaveTextContent("SWIFT TESTKENA");
    fireEvent.click(within(dialog).getByRole("button", { name: "Pay with Stripe" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://checkout.stripe.test/c/cs_1"));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ provider: "stripe" });
  });

  it("offers card (hosted), crypto and bank transfer when adding a payment method", async () => {
    const { calls } = mockApi({ "/billing/overview": overview({ paymentMethods: [] }), "POST /billing/payment-methods": { id: "x" } });
    renderWithSession(<CommercialBilling />);
    fireEvent.click(await screen.findByRole("button", { name: "Add" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "Add card" })).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Use crypto" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ kind: "crypto", provider: "nowpayments" });
  });
});
