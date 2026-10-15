import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { BILLING_MODELS, BILLING_PRODUCTS, BillingInterval, BillingModel, BillingProduct, BillingProfile, PAYMENT_PROVIDERS, PaymentProviderKey } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { requireAuth, requirePermission } from "../auth/rbac.js";
import { WebhookSignatureError } from "../billing/providers.js";
import type { AppServices } from "../context.js";
import { badRequest, notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { parse } from "./util.js";

const SubscribeBody = z
  .object({ product: BillingProduct, model: BillingModel, interval: BillingInterval.optional(), minimum: z.number().int().min(0).max(1_000_000).optional() })
  .strict();
const QuoteQuery = z.object({
  product: BillingProduct,
  model: BillingModel,
  interval: BillingInterval.optional(),
  minimum: z.coerce.number().int().min(0).max(1_000_000).optional(),
  units: z.coerce.number().int().min(0).max(10_000_000).optional(),
});
const PatchSubscription = z.object({ autoRenew: z.boolean().optional(), cancel: z.literal(true).optional() }).strict();
const CheckoutBody = z.object({ provider: PaymentProviderKey }).strict();
const PreferenceBody = z.object({ kind: z.enum(["crypto", "bank_transfer"]), provider: PaymentProviderKey }).strict();

/**
 * Billing: plans & pricing models, live quotes, subscriptions, payment methods (provider tokens
 * only), invoices, hosted checkout and verified provider webhooks.
 */
export async function billingRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const b = s.billing;

  app.get("/billing/overview", async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:read", null);
    return s.db.withTenant(auth.tenantId, async (tx) => ({
      contact: s.config.billing.contact,
      currency: b.priceBook.currency,
      priceBook: b.priceBook,
      models: BILLING_MODELS,
      products: BILLING_PRODUCTS,
      providers: PAYMENT_PROVIDERS.filter((p) => s.paymentProviders.has(p.key)).map((p) => ({ ...p, canSaveCard: Boolean(s.paymentProviders.get(p.key)?.setupCard) })),
      bankDetails: s.config.billing.bankDetails,
      profile: await b.getProfile(tx).then(({ stripeCustomer: _hidden, ...p }) => p),
      units: await b.currentUnits(tx),
      subscriptions: await b.subscriptions(tx),
      paymentMethods: await b.paymentMethods(tx),
      invoices: await b.invoices(tx),
    }));
  });

  app.get("/billing/quote", async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:read", null);
    const q = parse(QuoteQuery, request.query);
    return s.db.withTenant(auth.tenantId, (tx) => b.quoteFor(tx, q));
  });

  app.put("/billing/profile", { config: { audit: "billing.profile_updated" } }, async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:write", null);
    const body = parse(BillingProfile, request.body);
    return s.db.withTenant(auth.tenantId, (tx) => b.saveProfile(tx, auth.tenantId, body));
  });

  app.post("/billing/subscriptions", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:write", null);
    const body = parse(SubscribeBody, request.body);
    const res = await s.db.withTenant(auth.tenantId, async (tx) => {
      const r = await b.subscribe(tx, auth.tenantId, body, auth.principal.id);
      await recordAudit(tx, request, { action: "billing.subscribed", targetKind: "subscription", targetId: r.subscription.id, details: { ...body, unitPrice: r.quote.unitPrice, currency: r.quote.currency } });
      return r;
    });
    return reply.status(201).send(res);
  });

  app.patch("/billing/subscriptions/:id", { config: { audit: "billing.subscription_updated" } }, async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:write", null);
    const { id } = parse(IdParam, request.params);
    const body = parse(PatchSubscription, request.body);
    return s.db.withTenant(auth.tenantId, (tx) => b.update(tx, id, body));
  });

  app.post("/billing/invoices/:id/checkout", { config: { audit: "billing.checkout" } }, async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:write", null);
    const { id } = parse(IdParam, request.params);
    const body = parse(CheckoutBody, request.body);
    const profile = await s.db.withTenant(auth.tenantId, (tx) => b.getProfile(tx));
    return b.checkout(auth.tenantId, id, body.provider, profile.billingEmail || null);
  });

  // Save a card at the provider's hosted page (card numbers never reach Bloody).
  app.post("/billing/payment-methods/card", { config: { audit: "billing.card_setup" } }, async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:write", null);
    const body = parse(CheckoutBody, request.body);
    return b.setupCard(auth.tenantId, body.provider);
  });

  // Crypto or bank transfer as the preferred way to pay (nothing secret to store).
  app.post("/billing/payment-methods", { config: { audit: "billing.method_added" } }, async (request, reply) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:write", null);
    const body = parse(PreferenceBody, request.body);
    const def = PAYMENT_PROVIDERS.find((p) => p.key === body.provider)!;
    if (!(def.kinds as readonly string[]).includes(body.kind)) throw badRequest(`${def.label} does not take ${body.kind.replace("_", " ")} payments`);
    if (!s.paymentProviders.has(body.provider)) throw badRequest(`${def.label} is not configured on this platform`);
    const label = body.kind === "bank_transfer" ? "Bank transfer (wire)" : `Crypto via ${def.label}`;
    const method = await s.db.withTenant(auth.tenantId, (tx) =>
      b.addMethod(tx, auth.tenantId, { kind: body.kind, provider: body.provider, label, brand: null, last4: null, expMonth: null, expYear: null, providerRef: null }),
    );
    return reply.status(201).send(method);
  });

  app.post("/billing/payment-methods/:id/default", { config: { audit: "billing.method_default" } }, async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:write", null);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, (tx) => b.setDefaultMethod(tx, id));
    return { ok: true };
  });

  app.delete("/billing/payment-methods/:id", { config: { audit: "billing.method_removed" } }, async (request, reply) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:write", null);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, (tx) => b.removeMethod(tx, id));
    return reply.status(204).send();
  });

  // Provider webhooks: public, but only accepted with a valid signature (raw body needed).
  await app.register(async (hooks) => {
    hooks.removeAllContentTypeParsers();
    hooks.addContentTypeParser("*", { parseAs: "string", bodyLimit: 256 * 1024 }, (_req, body, done) => done(null, body));
    hooks.post("/billing/webhooks/:provider", { config: { public: true, audit: false } }, async (request, reply) => {
      const { provider: key } = parse(z.object({ provider: PaymentProviderKey }), request.params);
      const provider = s.paymentProviders.get(key);
      if (!provider) throw notFound("Payment provider");
      const raw = typeof request.body === "string" ? request.body : "";
      try {
        const evt = await provider.parseWebhook(raw, request.headers, s.now());
        const changed = await b.applyEvent(evt, JSON.parse(raw));
        request.log.info({ provider: key, kind: evt.kind, event: evt.eventId, changed }, "payment webhook");
        return reply.send({ received: true });
      } catch (err) {
        if (err instanceof WebhookSignatureError) return reply.status(400).send({ error: { code: "invalid_signature", message: "Invalid webhook signature" } });
        throw err;
      }
    });
  });
}
