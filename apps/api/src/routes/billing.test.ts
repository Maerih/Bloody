import { createHmac } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { monthPeriod } from "../billing/service.js";
import { api, call, createTenant, createTestApp, createUser, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

const WHSEC = "whsec_test_secret";
/** Fake Stripe API: hosted checkout sessions + the payment intent behind a completed session. */
const stripeCalls: Array<{ url: string; body: string }> = [];
const fakeStripe = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  stripeCalls.push({ url, body: String(init?.body ?? "") });
  const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });
  if (url.endsWith("/v1/checkout/sessions")) return json({ id: `cs_${stripeCalls.length}`, url: `https://checkout.stripe.test/c/cs_${stripeCalls.length}` });
  if (url.includes("/v1/payment_intents/pi_1")) return json({ payment_method: { id: "pm_1", card: { brand: "visa", last4: "6865", exp_month: 6, exp_year: 2031 } } });
  return new Response("not found", { status: 404 });
}) as typeof fetch;

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let other: ReturnType<typeof api>;

beforeAll(async () => {
  t = await createTestApp({
    env: { STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: WHSEC, BLOODY_BILLING_BANK_DETAILS: "SCIAT AFRICA\\nIBAN KE00 TEST", BLOODY_BILLING_CONTACT: "Account Team <billing@sciat.africa>" },
    deps: { fetch: fakeStripe, hostResolver: false },
  });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, a.email)).token });
  const o = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = api(t.app, { token: (await login(t.app, o.admin.email)).token });
  // Three protected endpoints to meter.
  for (const host of ["ws-01", "ws-02", "srv-01"]) {
    expect((await admin.post("/agents", { organizationId: tenant.orgIds[0], hostname: host, platform: "linux", version: "1.0", engine: "sciat", status: "protected" })).status).toBeLessThan(300);
  }
});
afterAll(async () => {
  await t?.close();
});

function stripeWebhook(body: object) {
  const raw = JSON.stringify(body);
  const ts = Math.floor(Date.now() / 1000);
  const sig = `t=${ts},v1=${createHmac("sha256", WHSEC).update(`${ts}.${raw}`).digest("hex")}`;
  return t.app.inject({ method: "POST", url: "/api/v1/billing/webhooks/stripe", headers: { "content-type": "application/json", "stripe-signature": sig }, payload: raw });
}

describe("billing", () => {
  let invoice: Json;

  it("shows models, prices, configured gateways and live unit counts", async () => {
    const res = await admin.get("/billing/overview");
    expect(res.status).toBe(200);
    expect(res.body.contact).toEqual({ name: "Account Team", email: "billing@sciat.africa" });
    expect(res.body.models.map((m: Json) => m.key)).toEqual(["payg", "monthly_commit", "annual", "mssp_partner"]);
    expect(res.body.providers.map((p: Json) => p.key).sort()).toEqual(["bank_transfer", "stripe"]);
    expect(res.body.bankDetails).toBe("SCIAT AFRICA\nIBAN KE00 TEST");
    expect(res.body.units.edr).toBe(3);
    const q = await admin.get("/billing/quote?product=edr&model=annual");
    expect(q.body).toMatchObject({ billedUnits: 50, unitPrice: 400, monthlyTotal: 20_000 });
  });

  it("subscribes, changes model and refuses commitments below the minimum", async () => {
    const payg = await admin.post("/billing/subscriptions", { product: "edr", model: "payg" });
    expect(payg.status).toBe(201);
    expect(payg.body.subscription).toMatchObject({ model: "payg", unitPrice: 500, currentUnits: 3, status: "active" });
    expect((await admin.post("/billing/subscriptions", { product: "edr", model: "annual", minimum: 10 })).status).toBe(400);
    const annual = await admin.post("/billing/subscriptions", { product: "edr", model: "monthly_commit", minimum: 30 });
    expect(annual.status).toBe(201);
    const live = (await admin.get("/billing/overview")).body.subscriptions;
    expect(live).toHaveLength(1);
    expect(live[0]).toMatchObject({ model: "monthly_commit", minimum: 30, unitPrice: 450 });
    expect((await analyst.post("/billing/subscriptions", { product: "edr", model: "payg" })).status).toBe(403);
    expect((await analyst.get("/billing/overview")).status).toBe(403);
  });

  it("invoices each period once: quantity = max(units, committed minimum)", async () => {
    const period = monthPeriod(Date.now());
    const first = await t.db.withTenant(tenant.tenantId, (tx) => t.services.billing.generateInvoice(tx, tenant.tenantId, period));
    expect(first).toMatchObject({ status: "open", total: 30 * 450, currency: "USD" });
    expect(first!.lines[0]).toMatchObject({ product: "edr", quantity: 30, unitPrice: 450 });
    const again = await t.db.withTenant(tenant.tenantId, (tx) => t.services.billing.generateInvoice(tx, tenant.tenantId, period));
    expect(again!.id).toBe(first!.id);
    invoice = (await admin.get("/billing/overview")).body.invoices[0];
    expect(invoice.number).toMatch(/^INV-\d{6}-0001$/);
    expect((await other.get("/billing/overview")).body.invoices).toHaveLength(0);
  });

  it("sends the invoice to a hosted checkout and a signed webhook marks it paid, once", async () => {
    const co = await admin.post(`/billing/invoices/${invoice.id}/checkout`, { provider: "stripe" });
    expect(co.status).toBe(200);
    expect(co.body.url).toMatch(/^https:\/\/checkout\.stripe\.test\//);
    const form = new URLSearchParams(stripeCalls.at(-1)!.body);
    expect(form.get("line_items[0][price_data][unit_amount]")).toBe(String(30 * 450));
    expect((await admin.post(`/billing/invoices/${invoice.id}/checkout`, { provider: "paddle" })).status).toBe(400);

    const event = { id: "evt_paid_1", type: "checkout.session.completed", data: { object: { id: "cs_9", payment_status: "paid", payment_intent: "pi_1", metadata: { order_ref: `${tenant.tenantId}:${invoice.id}` } } } };
    const forged = await t.app.inject({ method: "POST", url: "/api/v1/billing/webhooks/stripe", headers: { "content-type": "application/json", "stripe-signature": "t=1,v1=00" }, payload: JSON.stringify(event) });
    expect(forged.statusCode).toBe(400);
    expect((await stripeWebhook(event)).statusCode).toBe(200);
    expect((await stripeWebhook(event)).statusCode).toBe(200); // redelivery: no-op

    const after = (await admin.get("/billing/overview")).body;
    expect(after.invoices[0]).toMatchObject({ status: "paid", paidVia: "stripe" });
    expect(after.paymentMethods).toHaveLength(1);
    expect(after.paymentMethods[0]).toMatchObject({ kind: "card", brand: "visa", last4: "6865", expMonth: 6, expYear: 2031, isDefault: true });
    expect(JSON.stringify(after.paymentMethods)).not.toMatch(/pm_1/); // provider token stays server-side
    expect((await admin.post(`/billing/invoices/${invoice.id}/checkout`, { provider: "stripe" })).status).toBe(409);
    const events = await t.db.withTenant(tenant.tenantId, async (tx) => (await tx.query("SELECT count(*)::int AS n FROM payment_events")).rows[0]);
    expect(events).toEqual({ n: 1 });
  });

  it("records crypto / bank-transfer preferences only for configured gateways", async () => {
    expect((await admin.post("/billing/payment-methods", { kind: "bank_transfer", provider: "bank_transfer" })).status).toBe(201);
    expect((await admin.post("/billing/payment-methods", { kind: "crypto", provider: "nowpayments" })).status).toBe(400);
    expect((await admin.post("/billing/payment-methods", { kind: "crypto", provider: "stripe" })).status).toBe(400);
    const methods = (await admin.get("/billing/overview")).body.paymentMethods as Json[];
    const wire = methods.find((m) => m.kind === "bank_transfer")!;
    expect((await admin.post(`/billing/payment-methods/${wire.id}/default`, {})).status).toBe(200);
    const now = (await admin.get("/billing/overview")).body.paymentMethods as Json[];
    expect(now.filter((m) => m.isDefault).map((m) => m.kind)).toEqual(["bank_transfer"]);
  });

  it("keeps the billing profile per account", async () => {
    const profile = { companyName: "Kilimanjaro Bank", billingEmail: "ap@kb.example", taxId: "P051234567X", billingAddress: { line1: "0100", city: "Nairobi", postalCode: "00100", country: "KE" }, shippingAddress: {} };
    const token = (await login(t.app, tenant.admin.email)).token;
    expect((await call(t.app, "PUT", "/billing/profile", { auth: { token }, body: profile })).status).toBe(200);
    expect((await admin.get("/billing/overview")).body.profile).toMatchObject({ companyName: "Kilimanjaro Bank", billingAddress: { city: "Nairobi", country: "KE" } });
    expect((await other.get("/billing/overview")).body.profile.companyName).toBe("");
    const bad = await call(t.app, "PUT", "/billing/profile", { auth: { token }, body: { ...profile, billingEmail: "not-an-email" } });
    expect(bad.status).toBe(400);
  });
});
