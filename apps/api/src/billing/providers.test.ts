import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { btcPayProvider, nowPaymentsProvider, orderRef, paddleProvider, parseOrderRef, sortKeysDeep, stripeProvider, WebhookSignatureError, type CheckoutInput } from "./providers.js";

const TENANT = "11111111-1111-4111-8111-111111111111";
const INVOICE = "22222222-2222-4222-8222-222222222222";
const NOW = Date.parse("2026-10-16T08:00:00Z");
const input: CheckoutInput = {
  tenantId: TENANT,
  invoiceId: INVOICE,
  invoiceNumber: "INV-202610-0001",
  amount: 12_345,
  currency: "USD",
  description: "Managed EDR — October 2026",
  customerEmail: "billing@client.example",
  successUrl: "https://soc.example/settings/billing?paid=1",
  cancelUrl: "https://soc.example/settings/billing",
  webhookUrl: "https://soc.example/api/v1/billing/webhooks/nowpayments",
};

function fakeFetch(responses: Array<{ match: RegExp; body: unknown; status?: number }>) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fn = vi.fn(async (url: string | URL | Request, init: RequestInit = {}) => {
    const u = String(url);
    calls.push({ url: u, init });
    const r = responses.find((x) => x.match.test(u));
    if (!r) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return { fn, calls };
}

describe("order reference", () => {
  it("round-trips tenant and invoice ids and rejects anything else", () => {
    expect(parseOrderRef(orderRef(TENANT, INVOICE))).toEqual({ tenantId: TENANT, invoiceId: INVOICE });
    expect(parseOrderRef("x:y")).toBeNull();
    expect(parseOrderRef(42)).toBeNull();
  });
});

describe("Stripe", () => {
  const cfg = { secretKey: "sk_test_123", webhookSecret: "whsec_abc" };
  it("creates a hosted checkout with our order reference and the exact amount", async () => {
    const { fn, calls } = fakeFetch([{ match: /checkout\/sessions$/, body: { id: "cs_1", url: "https://checkout.stripe.com/c/cs_1" } }]);
    const r = await stripeProvider(cfg, fn).checkout(input);
    expect(r).toEqual({ url: "https://checkout.stripe.com/c/cs_1", providerRef: "cs_1" });
    const form = new URLSearchParams(String(calls[0]!.init.body));
    expect(form.get("line_items[0][price_data][unit_amount]")).toBe("12345");
    expect(form.get("metadata[order_ref]")).toBe(orderRef(TENANT, INVOICE));
    expect((calls[0]!.init.headers as Record<string, string>).authorization).toBe("Bearer sk_test_123");
  });

  it("accepts a correctly signed completion and reports card display fields only", async () => {
    const body = JSON.stringify({ id: "evt_1", type: "checkout.session.completed", data: { object: { id: "cs_1", payment_status: "paid", payment_intent: "pi_1", metadata: { order_ref: orderRef(TENANT, INVOICE) } } } });
    const t = Math.floor(NOW / 1000);
    const sig = `t=${t},v1=${createHmac("sha256", cfg.webhookSecret).update(`${t}.${body}`).digest("hex")}`;
    const { fn } = fakeFetch([{ match: /payment_intents\/pi_1/, body: { payment_method: { id: "pm_9", card: { brand: "visa", last4: "6865", exp_month: 6, exp_year: 2031 } } } }]);
    const evt = await stripeProvider(cfg, fn).parseWebhook(body, { "stripe-signature": sig }, NOW);
    expect(evt).toMatchObject({ kind: "invoice.paid", tenantId: TENANT, invoiceId: INVOICE, method: { kind: "card", brand: "visa", last4: "6865", expMonth: 6, expYear: 2031, providerRef: "pm_9" } });
    await expect(stripeProvider(cfg, fn).parseWebhook(body.replace("paid", "unpaid"), { "stripe-signature": sig }, NOW)).rejects.toBeInstanceOf(WebhookSignatureError);
    await expect(stripeProvider(cfg, fn).parseWebhook(body, { "stripe-signature": sig }, NOW + 3_600_000)).rejects.toThrow(/stale/);
  });
});

describe("Stripe card setup (no payment)", () => {
  const cfg = { secretKey: "sk_test_123", webhookSecret: "whsec_abc" };
  it("creates a customer once, opens a hosted setup page and reports the saved card", async () => {
    const { fn, calls } = fakeFetch([
      { match: /\/v1\/customers$/, body: { id: "cus_1" } },
      { match: /checkout\/sessions$/, body: { id: "cs_setup", url: "https://checkout.stripe.com/c/cs_setup" } },
      { match: /setup_intents\/seti_1/, body: { payment_method: { id: "pm_7", card: { brand: "visa", last4: "4242", exp_month: 12, exp_year: 2030 } } } },
    ]);
    const p = stripeProvider(cfg, fn);
    expect(await p.setupCard!({ tenantId: TENANT, customerEmail: "a@b.example", customerRef: null, successUrl: "https://x/ok", cancelUrl: "https://x/no" })).toEqual({ url: "https://checkout.stripe.com/c/cs_setup", customerRef: "cus_1" });
    expect(new URLSearchParams(String(calls[1]!.init.body)).get("mode")).toBe("setup");
    await p.setupCard!({ tenantId: TENANT, customerEmail: null, customerRef: "cus_1", successUrl: "https://x/ok", cancelUrl: "https://x/no" });
    expect(calls.filter((c) => c.url.endsWith("/v1/customers"))).toHaveLength(1);

    const body = JSON.stringify({ id: "evt_s", type: "checkout.session.completed", data: { object: { id: "cs_setup", mode: "setup", customer: "cus_1", setup_intent: "seti_1", metadata: { tenant_ref: TENANT } } } });
    const t = Math.floor(NOW / 1000);
    const sig = `t=${t},v1=${createHmac("sha256", cfg.webhookSecret).update(`${t}.${body}`).digest("hex")}`;
    expect(await p.parseWebhook(body, { "stripe-signature": sig }, NOW)).toMatchObject({ kind: "method.added", tenantId: TENANT, providerRef: "cus_1", method: { last4: "4242", providerRef: "pm_7" } });
  });
});

describe("Paddle", () => {
  const cfg = { apiKey: "pdl_key", webhookSecret: "pdl_whsec", sandbox: true };
  it("creates a transaction with a non-catalog price and returns its checkout link", async () => {
    const { fn, calls } = fakeFetch([{ match: /sandbox-api\.paddle\.com\/transactions$/, body: { data: { id: "txn_1", checkout: { url: "https://pay.example/txn_1" } } } }]);
    expect(await paddleProvider(cfg, fn).checkout(input)).toEqual({ url: "https://pay.example/txn_1", providerRef: "txn_1" });
    const sent = JSON.parse(String(calls[0]!.init.body));
    expect(sent.items[0].price.unit_price).toEqual({ amount: "12345", currency_code: "USD" });
    expect(sent.custom_data.order_ref).toBe(orderRef(TENANT, INVOICE));
  });

  it("verifies the h1 signature and records the card brand and last 4", async () => {
    const body = JSON.stringify({ event_id: "evt_p1", event_type: "transaction.completed", data: { id: "txn_1", customer_id: "ctm_1", custom_data: { order_ref: orderRef(TENANT, INVOICE) }, payments: [{ method_details: { type: "card", card: { type: "mastercard", last4: "4444", expiry_month: 1, expiry_year: 2030 } } }] } });
    const ts = Math.floor(NOW / 1000);
    const sig = `ts=${ts};h1=${createHmac("sha256", cfg.webhookSecret).update(`${ts}:${body}`).digest("hex")}`;
    const evt = await paddleProvider(cfg).parseWebhook(body, { "paddle-signature": sig }, NOW);
    expect(evt).toMatchObject({ kind: "invoice.paid", invoiceId: INVOICE, method: { kind: "card", brand: "mastercard", last4: "4444" } });
    await expect(paddleProvider(cfg).parseWebhook(body, { "paddle-signature": `ts=${ts};h1=00` }, NOW)).rejects.toBeInstanceOf(WebhookSignatureError);
  });
});

describe("NOWPayments", () => {
  const cfg = { apiKey: "np_key", ipnSecret: "np_secret", sandbox: false };
  it("creates a crypto invoice priced in the invoice currency", async () => {
    const { fn, calls } = fakeFetch([{ match: /api\.nowpayments\.io\/v1\/invoice$/, body: { id: 5077, invoice_url: "https://nowpayments.io/payment/?iid=5077" } }]);
    expect(await nowPaymentsProvider(cfg, fn).checkout(input)).toEqual({ url: "https://nowpayments.io/payment/?iid=5077", providerRef: "5077" });
    expect(JSON.parse(String(calls[0]!.init.body))).toMatchObject({ price_amount: 123.45, price_currency: "usd", order_id: orderRef(TENANT, INVOICE) });
  });

  it("verifies the HMAC-SHA512 over the sorted body; only 'finished' pays the invoice", async () => {
    const payload = { payment_status: "finished", payment_id: 99, order_id: orderRef(TENANT, INVOICE), pay_currency: "usdttrc20", invoice_id: 5077, actually_paid: 123.45 };
    const body = JSON.stringify(payload);
    const sig = createHmac("sha512", cfg.ipnSecret).update(JSON.stringify(sortKeysDeep(payload))).digest("hex");
    const evt = await nowPaymentsProvider(cfg).parseWebhook(body, { "x-nowpayments-sig": sig }, NOW);
    expect(evt).toMatchObject({ kind: "invoice.paid", eventId: "99:finished", tenantId: TENANT, invoiceId: INVOICE, method: { kind: "crypto", brand: "usdttrc20" } });
    const waiting = { ...payload, payment_status: "confirming" };
    const sig2 = createHmac("sha512", cfg.ipnSecret).update(JSON.stringify(sortKeysDeep(waiting))).digest("hex");
    expect((await nowPaymentsProvider(cfg).parseWebhook(JSON.stringify(waiting), { "x-nowpayments-sig": sig2 }, NOW)).kind).toBe("invoice.pending");
    await expect(nowPaymentsProvider(cfg).parseWebhook(body, { "x-nowpayments-sig": sig2 }, NOW)).rejects.toBeInstanceOf(WebhookSignatureError);
  });
});

describe("BTCPay Server", () => {
  const cfg = { url: "https://pay.sciat.example/", storeId: "store1", apiKey: "btc_key", webhookSecret: "btc_secret" };
  it("creates an invoice on the store and verifies settled webhooks", async () => {
    const { fn, calls } = fakeFetch([{ match: /\/api\/v1\/stores\/store1\/invoices$/, body: { id: "inv_b1", checkoutLink: "https://pay.sciat.example/i/inv_b1" } }]);
    expect(await btcPayProvider(cfg, fn).checkout(input)).toEqual({ url: "https://pay.sciat.example/i/inv_b1", providerRef: "inv_b1" });
    expect(JSON.parse(String(calls[0]!.init.body))).toMatchObject({ amount: "123.45", currency: "USD" });
    const body = JSON.stringify({ deliveryId: "d1", type: "InvoiceSettled", invoiceId: "inv_b1", metadata: { orderId: orderRef(TENANT, INVOICE) } });
    const sig = `sha256=${createHmac("sha256", cfg.webhookSecret).update(body).digest("hex")}`;
    expect(await btcPayProvider(cfg).parseWebhook(body, { "btcpay-sig": sig }, NOW)).toMatchObject({ kind: "invoice.paid", invoiceId: INVOICE, providerRef: "inv_b1" });
    await expect(btcPayProvider(cfg).parseWebhook(body, {}, NOW)).rejects.toBeInstanceOf(WebhookSignatureError);
  });
});
