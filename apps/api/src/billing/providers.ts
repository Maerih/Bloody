import { createHmac, timingSafeEqual } from "node:crypto";
import type { Currency, PaymentMethodKind, PaymentProviderKey } from "@bloody/contracts";

/**
 * Payment-provider adapters (proprietary). The operator (SCIAT AFRICA) configures gateways in
 * .env; customers pay invoices on the provider's hosted page, so card data never touches Bloody
 * (PCI DSS scope stays with the provider). Webhooks are accepted only with a valid signature and
 * carry the account + invoice ids we put in the provider's metadata, so no cross-tenant lookup is
 * ever needed.
 */

export interface CheckoutInput {
  tenantId: string;
  invoiceId: string;
  invoiceNumber: string;
  /** Amount in minor units (cents). */
  amount: number;
  currency: Currency;
  description: string;
  customerEmail: string | null;
  successUrl: string;
  cancelUrl: string;
  webhookUrl: string;
}

export interface CheckoutResult {
  url: string;
  providerRef: string;
}

export interface PaymentEvent {
  provider: PaymentProviderKey;
  /** Provider event id, for exactly-once processing. */
  eventId: string;
  kind: "invoice.paid" | "invoice.pending" | "method.added" | "ignored";
  tenantId: string | null;
  invoiceId: string | null;
  providerRef: string | null;
  /** Payment method reported by the provider (stored as a token + display fields only). */
  method?: { kind: PaymentMethodKind; label: string; brand: string | null; last4: string | null; expMonth: number | null; expYear: number | null; providerRef: string | null };
}

export class WebhookSignatureError extends Error {}

export interface CardSetupInput {
  tenantId: string;
  customerEmail: string | null;
  /** Existing customer at the provider (stored on the billing profile). */
  customerRef: string | null;
  successUrl: string;
  cancelUrl: string;
}

export interface PaymentProvider {
  key: PaymentProviderKey;
  checkout(input: CheckoutInput): Promise<CheckoutResult>;
  /** Hosted page to save a card without paying (card entry happens at the provider). */
  setupCard?(input: CardSetupInput): Promise<{ url: string; customerRef: string }>;
  /** Verify the signature and translate the payload. Throws WebhookSignatureError when invalid. */
  parseWebhook(rawBody: string, headers: Record<string, string | string[] | undefined>, now: number): Promise<PaymentEvent>;
}

export interface ProviderConfig {
  publicUrl: string;
  bankDetails: string | null;
  stripe: { secretKey: string; webhookSecret: string } | null;
  paddle: { apiKey: string; webhookSecret: string; sandbox: boolean } | null;
  nowpayments: { apiKey: string; ipnSecret: string; sandbox: boolean } | null;
  btcpay: { url: string; storeId: string; apiKey: string; webhookSecret: string } | null;
}

type Fetch = typeof fetch;
const header = (h: Record<string, string | string[] | undefined>, name: string) => {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
};
const safeEqualHex = (a: string, b: string) => {
  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");
  return x.length > 0 && x.length === y.length && timingSafeEqual(x, y);
};
const decimal = (cents: number) => (cents / 100).toFixed(2);
/** Metadata reference we send to every provider and read back from its webhooks. */
export const orderRef = (tenantId: string, invoiceId: string) => `${tenantId}:${invoiceId}`;
export function parseOrderRef(ref: unknown): { tenantId: string; invoiceId: string } | null {
  if (typeof ref !== "string") return null;
  const m = /^([0-9a-f-]{36}):([0-9a-f-]{36})$/i.exec(ref);
  return m ? { tenantId: m[1]!.toLowerCase(), invoiceId: m[2]!.toLowerCase() } : null;
}

async function call<T>(fetchImpl: Fetch, url: string, init: RequestInit, what: string): Promise<T> {
  const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(15_000) });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!res.ok) {
    const msg = typeof body === "object" && body !== null ? JSON.stringify(body).slice(0, 300) : String(body).slice(0, 300);
    throw new Error(`${what} failed (HTTP ${res.status}): ${msg}`);
  }
  return body as T;
}

// ─── Bank transfer ──────────────────────────────────────────────────────────

export function bankTransferProvider(cfg: ProviderConfig): PaymentProvider {
  return {
    key: "bank_transfer",
    async checkout(input) {
      // The "checkout" is the invoice's wire-instructions page; the operator confirms receipt
      // (pnpm admin mark-paid) because banks do not call webhooks.
      return { url: `${cfg.publicUrl}/settings/billing?invoice=${input.invoiceId}&pay=bank_transfer`, providerRef: `wire:${input.invoiceNumber}` };
    },
    async parseWebhook() {
      throw new WebhookSignatureError("bank transfers have no webhook");
    },
  };
}

// ─── Stripe (Checkout Sessions) ─────────────────────────────────────────────

export function stripeProvider(cfg: NonNullable<ProviderConfig["stripe"]>, fetchImpl: Fetch = fetch): PaymentProvider {
  const auth = { authorization: `Bearer ${cfg.secretKey}`, "content-type": "application/x-www-form-urlencoded" };
  return {
    key: "stripe",
    async checkout(input) {
      const form = new URLSearchParams({
        mode: "payment",
        success_url: input.successUrl,
        cancel_url: input.cancelUrl,
        client_reference_id: orderRef(input.tenantId, input.invoiceId),
        "metadata[order_ref]": orderRef(input.tenantId, input.invoiceId),
        "payment_intent_data[metadata][order_ref]": orderRef(input.tenantId, input.invoiceId),
        // Keep the card on file (as a Stripe token) for the next invoices.
        "payment_intent_data[setup_future_usage]": "off_session",
        customer_creation: "always",
        "line_items[0][quantity]": "1",
        "line_items[0][price_data][currency]": input.currency.toLowerCase(),
        "line_items[0][price_data][unit_amount]": String(input.amount),
        "line_items[0][price_data][product_data][name]": `${input.invoiceNumber} — ${input.description}`.slice(0, 250),
      });
      if (input.customerEmail) form.set("customer_email", input.customerEmail);
      const s = await call<{ id: string; url: string }>(fetchImpl, "https://api.stripe.com/v1/checkout/sessions", { method: "POST", headers: auth, body: form }, "Stripe checkout");
      return { url: s.url, providerRef: s.id };
    },
    async setupCard(input) {
      let customer = input.customerRef;
      if (!customer) {
        const form = new URLSearchParams({ "metadata[tenant_ref]": input.tenantId });
        if (input.customerEmail) form.set("email", input.customerEmail);
        customer = (await call<{ id: string }>(fetchImpl, "https://api.stripe.com/v1/customers", { method: "POST", headers: auth, body: form }, "Stripe customer")).id;
      }
      const form = new URLSearchParams({
        mode: "setup",
        customer,
        "payment_method_types[0]": "card",
        success_url: input.successUrl,
        cancel_url: input.cancelUrl,
        "metadata[tenant_ref]": input.tenantId,
        "setup_intent_data[metadata][tenant_ref]": input.tenantId,
      });
      const s = await call<{ id: string; url: string }>(fetchImpl, "https://api.stripe.com/v1/checkout/sessions", { method: "POST", headers: auth, body: form }, "Stripe card setup");
      return { url: s.url, customerRef: customer };
    },
    async parseWebhook(rawBody, headers, now) {
      const sig = header(headers, "stripe-signature") ?? "";
      const parts = Object.fromEntries(sig.split(",").map((p) => p.split("=") as [string, string]));
      const ts = Number(parts.t);
      const expected = createHmac("sha256", cfg.webhookSecret).update(`${parts.t}.${rawBody}`).digest("hex");
      if (!parts.v1 || !safeEqualHex(parts.v1, expected)) throw new WebhookSignatureError("invalid Stripe signature");
      if (!Number.isFinite(ts) || Math.abs(now / 1000 - ts) > 300) throw new WebhookSignatureError("stale Stripe webhook");
      const evt = JSON.parse(rawBody) as { id: string; type: string; data: { object: Record<string, unknown> } };
      if (evt.type !== "checkout.session.completed") return { provider: "stripe", eventId: evt.id, kind: "ignored", tenantId: null, invoiceId: null, providerRef: null };
      const obj = evt.data.object;
      if (obj.mode === "setup") {
        // Card saved without a payment: report its display fields; the token stays at Stripe.
        const tenantRef = (obj.metadata as Record<string, unknown> | undefined)?.tenant_ref;
        const si = typeof obj.setup_intent === "string"
          ? await call<{ payment_method?: { id: string; card?: { brand: string; last4: string; exp_month: number; exp_year: number } } }>(
              fetchImpl,
              `https://api.stripe.com/v1/setup_intents/${encodeURIComponent(obj.setup_intent)}?expand[]=payment_method`,
              { headers: { authorization: `Bearer ${cfg.secretKey}` } },
              "Stripe setup intent",
            )
          : null;
        const card = si?.payment_method?.card;
        return {
          provider: "stripe",
          eventId: evt.id,
          kind: card && typeof tenantRef === "string" && /^[0-9a-f-]{36}$/i.test(tenantRef) ? "method.added" : "ignored",
          tenantId: typeof tenantRef === "string" ? tenantRef.toLowerCase() : null,
          invoiceId: null,
          providerRef: String(obj.customer ?? ""),
          ...(card ? { method: { kind: "card" as const, label: `${card.brand} •••• ${card.last4}`, brand: card.brand, last4: card.last4, expMonth: card.exp_month, expYear: card.exp_year, providerRef: si?.payment_method?.id ?? null } } : {}),
        };
      }
      const ref = parseOrderRef((obj.metadata as Record<string, unknown> | undefined)?.order_ref ?? obj.client_reference_id);
      let method: PaymentEvent["method"];
      if (typeof obj.payment_intent === "string") {
        // Card display fields (brand, last 4, expiry) — the token stays at Stripe.
        const pi = await call<{ payment_method?: { id: string; card?: { brand: string; last4: string; exp_month: number; exp_year: number } } }>(
          fetchImpl,
          `https://api.stripe.com/v1/payment_intents/${encodeURIComponent(obj.payment_intent)}?expand[]=payment_method`,
          { headers: { authorization: `Bearer ${cfg.secretKey}` } },
          "Stripe payment intent",
        ).catch(() => null);
        const card = pi?.payment_method?.card;
        if (card) method = { kind: "card", label: `${card.brand} •••• ${card.last4}`, brand: card.brand, last4: card.last4, expMonth: card.exp_month, expYear: card.exp_year, providerRef: pi?.payment_method?.id ?? null };
      }
      return {
        provider: "stripe",
        eventId: evt.id,
        kind: obj.payment_status === "paid" ? "invoice.paid" : "invoice.pending",
        tenantId: ref?.tenantId ?? null,
        invoiceId: ref?.invoiceId ?? null,
        providerRef: String(obj.id),
        ...(method ? { method } : {}),
      };
    },
  };
}

// ─── Paddle Billing (merchant of record) ────────────────────────────────────

export function paddleProvider(cfg: NonNullable<ProviderConfig["paddle"]>, fetchImpl: Fetch = fetch): PaymentProvider {
  const base = cfg.sandbox ? "https://sandbox-api.paddle.com" : "https://api.paddle.com";
  return {
    key: "paddle",
    async checkout(input) {
      const body = {
        items: [
          {
            quantity: 1,
            price: {
              description: input.invoiceNumber,
              name: input.description.slice(0, 150),
              unit_price: { amount: String(input.amount), currency_code: input.currency },
              product: { name: input.description.slice(0, 150), tax_category: "saas" },
            },
          },
        ],
        collection_mode: "automatic",
        custom_data: { order_ref: orderRef(input.tenantId, input.invoiceId) },
        checkout: { url: input.successUrl },
      };
      const res = await call<{ data: { id: string; checkout?: { url?: string } } }>(
        fetchImpl,
        `${base}/transactions`,
        { method: "POST", headers: { authorization: `Bearer ${cfg.apiKey}`, "content-type": "application/json" }, body: JSON.stringify(body) },
        "Paddle transaction",
      );
      if (!res.data.checkout?.url) throw new Error("Paddle returned no checkout URL (set a default payment link in Paddle → Checkout settings)");
      return { url: res.data.checkout.url, providerRef: res.data.id };
    },
    async parseWebhook(rawBody, headers, now) {
      const sig = header(headers, "paddle-signature") ?? "";
      const parts = Object.fromEntries(sig.split(";").map((p) => p.split("=") as [string, string]));
      const expected = createHmac("sha256", cfg.webhookSecret).update(`${parts.ts}:${rawBody}`).digest("hex");
      if (!parts.h1 || !safeEqualHex(parts.h1, expected)) throw new WebhookSignatureError("invalid Paddle signature");
      if (Math.abs(now / 1000 - Number(parts.ts)) > 300) throw new WebhookSignatureError("stale Paddle webhook");
      const evt = JSON.parse(rawBody) as { event_id: string; event_type: string; data: Record<string, unknown> };
      const ref = parseOrderRef((evt.data.custom_data as Record<string, unknown> | undefined)?.order_ref);
      if (evt.event_type !== "transaction.completed" && evt.event_type !== "transaction.paid") {
        return { provider: "paddle", eventId: evt.event_id, kind: "ignored", tenantId: ref?.tenantId ?? null, invoiceId: ref?.invoiceId ?? null, providerRef: String(evt.data.id ?? "") };
      }
      const payment = (evt.data.payments as Array<Record<string, unknown>> | undefined)?.[0];
      const details = payment?.method_details as { type?: string; card?: { type?: string; last4?: string; expiry_month?: number; expiry_year?: number } } | undefined;
      let method: PaymentEvent["method"];
      if (details?.type === "card" && details.card) {
        method = { kind: "card", label: `${details.card.type ?? "card"} •••• ${details.card.last4 ?? ""}`, brand: details.card.type ?? null, last4: details.card.last4 ?? null, expMonth: details.card.expiry_month ?? null, expYear: details.card.expiry_year ?? null, providerRef: String(evt.data.customer_id ?? "") || null };
      } else if (details?.type === "paypal") {
        method = { kind: "paypal", label: "PayPal", brand: "paypal", last4: null, expMonth: null, expYear: null, providerRef: String(evt.data.customer_id ?? "") || null };
      }
      return { provider: "paddle", eventId: evt.event_id, kind: "invoice.paid", tenantId: ref?.tenantId ?? null, invoiceId: ref?.invoiceId ?? null, providerRef: String(evt.data.id), ...(method ? { method } : {}) };
    },
  };
}

// ─── NOWPayments (crypto, incl. USDT) ───────────────────────────────────────

/** NOWPayments signs the JSON body with keys sorted recursively. */
export function sortKeysDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sortKeysDeep((v as Record<string, unknown>)[k])]));
  return v;
}

export function nowPaymentsProvider(cfg: NonNullable<ProviderConfig["nowpayments"]>, fetchImpl: Fetch = fetch): PaymentProvider {
  const base = cfg.sandbox ? "https://api-sandbox.nowpayments.io/v1" : "https://api.nowpayments.io/v1";
  return {
    key: "nowpayments",
    async checkout(input) {
      const res = await call<{ id: string | number; invoice_url: string }>(
        fetchImpl,
        `${base}/invoice`,
        {
          method: "POST",
          headers: { "x-api-key": cfg.apiKey, "content-type": "application/json" },
          body: JSON.stringify({
            price_amount: Number(decimal(input.amount)),
            price_currency: input.currency.toLowerCase(),
            order_id: orderRef(input.tenantId, input.invoiceId),
            order_description: `${input.invoiceNumber} — ${input.description}`.slice(0, 200),
            ipn_callback_url: input.webhookUrl,
            success_url: input.successUrl,
            cancel_url: input.cancelUrl,
          }),
        },
        "NOWPayments invoice",
      );
      return { url: res.invoice_url, providerRef: String(res.id) };
    },
    async parseWebhook(rawBody, headers) {
      const sig = header(headers, "x-nowpayments-sig") ?? "";
      const body = JSON.parse(rawBody) as Record<string, unknown>;
      const expected = createHmac("sha512", cfg.ipnSecret).update(JSON.stringify(sortKeysDeep(body))).digest("hex");
      if (!safeEqualHex(sig, expected)) throw new WebhookSignatureError("invalid NOWPayments signature");
      const ref = parseOrderRef(body.order_id);
      const status = String(body.payment_status ?? "");
      return {
        provider: "nowpayments",
        eventId: `${String(body.payment_id)}:${status}`,
        // "finished" = funds received and confirmed; earlier states are informational.
        kind: status === "finished" ? "invoice.paid" : "invoice.pending",
        tenantId: ref?.tenantId ?? null,
        invoiceId: ref?.invoiceId ?? null,
        providerRef: String(body.invoice_id ?? body.payment_id ?? ""),
        method: { kind: "crypto", label: `Crypto (${String(body.pay_currency ?? "").toUpperCase() || "NOWPayments"})`, brand: String(body.pay_currency ?? "") || null, last4: null, expMonth: null, expYear: null, providerRef: null },
      };
    },
  };
}

// ─── BTCPay Server (self-hosted crypto) ─────────────────────────────────────

export function btcPayProvider(cfg: NonNullable<ProviderConfig["btcpay"]>, fetchImpl: Fetch = fetch): PaymentProvider {
  const base = cfg.url.replace(/\/+$/, "");
  return {
    key: "btcpay",
    async checkout(input) {
      const res = await call<{ id: string; checkoutLink: string }>(
        fetchImpl,
        `${base}/api/v1/stores/${encodeURIComponent(cfg.storeId)}/invoices`,
        {
          method: "POST",
          headers: { authorization: `token ${cfg.apiKey}`, "content-type": "application/json" },
          body: JSON.stringify({
            amount: decimal(input.amount),
            currency: input.currency,
            metadata: { orderId: orderRef(input.tenantId, input.invoiceId), itemDesc: `${input.invoiceNumber} — ${input.description}` },
            checkout: { redirectURL: input.successUrl },
          }),
        },
        "BTCPay invoice",
      );
      return { url: res.checkoutLink, providerRef: res.id };
    },
    async parseWebhook(rawBody, headers) {
      const sig = (header(headers, "btcpay-sig") ?? "").replace(/^sha256=/, "");
      const expected = createHmac("sha256", cfg.webhookSecret).update(rawBody).digest("hex");
      if (!safeEqualHex(sig, expected)) throw new WebhookSignatureError("invalid BTCPay signature");
      const evt = JSON.parse(rawBody) as { deliveryId: string; type: string; invoiceId: string; metadata?: Record<string, unknown> };
      const ref = parseOrderRef(evt.metadata?.orderId);
      return {
        provider: "btcpay",
        eventId: evt.deliveryId,
        kind: evt.type === "InvoiceSettled" ? "invoice.paid" : evt.type === "InvoiceProcessing" ? "invoice.pending" : "ignored",
        tenantId: ref?.tenantId ?? null,
        invoiceId: ref?.invoiceId ?? null,
        providerRef: evt.invoiceId,
        method: { kind: "crypto", label: "Crypto (BTCPay)", brand: "btcpay", last4: null, expMonth: null, expYear: null, providerRef: null },
      };
    },
  };
}

/** Providers the operator has configured (bank transfer is available when bank details are set). */
export function configuredProviders(cfg: ProviderConfig, fetchImpl: Fetch = fetch): Map<PaymentProviderKey, PaymentProvider> {
  const out = new Map<PaymentProviderKey, PaymentProvider>();
  if (cfg.paddle) out.set("paddle", paddleProvider(cfg.paddle, fetchImpl));
  if (cfg.stripe) out.set("stripe", stripeProvider(cfg.stripe, fetchImpl));
  if (cfg.nowpayments) out.set("nowpayments", nowPaymentsProvider(cfg.nowpayments, fetchImpl));
  if (cfg.btcpay) out.set("btcpay", btcPayProvider(cfg.btcpay, fetchImpl));
  if (cfg.bankDetails) out.set("bank_transfer", bankTransferProvider(cfg));
  return out;
}
