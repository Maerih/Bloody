import {
  BILLING_MODELS,
  BILLING_PRODUCTS,
  BillingProfile,
  quote,
  type BillingInterval,
  type BillingModel,
  type BillingProduct,
  type Invoice,
  type PaymentMethod,
  type PaymentProviderKey,
  type PriceBook,
  type Quote,
  type Subscription,
} from "@bloody/contracts";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, badRequest, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { PaymentEvent, PaymentProvider } from "./providers.js";

/**
 * Billing (proprietary): subscriptions per product and pricing model, live unit counts, invoices
 * (one per account and period — regenerating is a no-op), hosted checkout at the configured
 * providers and exactly-once processing of their verified webhooks.
 */

export interface BillingDeps {
  db: Database;
  priceBook: PriceBook;
  providers: Map<PaymentProviderKey, PaymentProvider>;
  publicUrl: string;
  invoiceDueDays: number;
  now: () => number;
}

const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);

function toSubscription(r: Row, currentUnits: number): Subscription {
  return {
    id: String(r.id),
    product: r.product as BillingProduct,
    model: r.model as BillingModel,
    interval: r.interval as BillingInterval,
    status: r.status as Subscription["status"],
    minimum: Number(r.minimum),
    unitPrice: Number(r.unit_price),
    currency: r.currency as Subscription["currency"],
    startsAt: iso(r.starts_at)!,
    endsAt: iso(r.ends_at),
    autoRenew: Boolean(r.auto_renew),
    currentUnits,
  };
}

function toPaymentMethod(r: Row): PaymentMethod {
  return {
    id: String(r.id),
    kind: r.kind as PaymentMethod["kind"],
    provider: r.provider as PaymentMethod["provider"],
    label: String(r.label),
    brand: (r.brand as string | null) ?? null,
    last4: (r.last4 as string | null) ?? null,
    expMonth: r.exp_month === null || r.exp_month === undefined ? null : Number(r.exp_month),
    expYear: r.exp_year === null || r.exp_year === undefined ? null : Number(r.exp_year),
    isDefault: Boolean(r.is_default),
    status: r.status as PaymentMethod["status"],
    createdAt: iso(r.created_at)!,
  };
}

export function toInvoice(r: Row): Invoice & { paymentUrl: string | null } {
  return {
    id: String(r.id),
    number: String(r.number),
    periodStart: iso(r.period_start)!,
    periodEnd: iso(r.period_end)!,
    currency: r.currency as Invoice["currency"],
    lines: (r.lines as Invoice["lines"]) ?? [],
    total: Number(r.total),
    status: r.status as Invoice["status"],
    dueAt: iso(r.due_at)!,
    paidAt: iso(r.paid_at),
    paidVia: (r.paid_via as Invoice["paidVia"]) ?? null,
    createdAt: iso(r.created_at)!,
    paymentUrl: (r.payment_url as string | null) ?? null,
  };
}

/** Calendar month [start, end) in UTC containing `at`. */
export function monthPeriod(at: number): { start: Date; end: Date } {
  const d = new Date(at);
  return { start: new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)), end: new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1)) };
}

export class BillingService {
  constructor(private readonly deps: BillingDeps) {}

  get priceBook(): PriceBook {
    return this.deps.priceBook;
  }

  /** Units protected right now, per product (the metering behind PAYG and overage). */
  async currentUnits(tx: Queryable): Promise<Record<BillingProduct, number>> {
    const { rows } = await tx.query<{ edr: string; itdr: string; siem: string }>(
      `SELECT (SELECT count(*) FROM agents WHERE status <> 'pending') AS edr,
              (SELECT count(*) FROM identities WHERE kind IN ('user', 'service_account', 'service_principal')) AS itdr,
              (SELECT count(*) FROM integrations WHERE enabled) AS siem`,
    );
    const r = rows[0]!;
    return { edr: Number(r.edr), itdr: Number(r.itdr), siem: Number(r.siem) };
  }

  async getProfile(tx: Queryable): Promise<BillingProfile & { stripeCustomer?: string }> {
    const { rows } = await tx.query<Row>("SELECT profile FROM billing_profiles");
    const raw = (rows[0]?.profile as Record<string, unknown> | undefined) ?? {};
    return { ...BillingProfile.parse(raw), ...(typeof raw.stripeCustomer === "string" ? { stripeCustomer: raw.stripeCustomer } : {}) };
  }

  async saveProfile(tx: Queryable, tenantId: string, profile: BillingProfile): Promise<BillingProfile> {
    // Keep provider references (e.g. the Stripe customer) that are not part of the editable profile.
    const existing = await this.getProfile(tx);
    const merged = { ...profile, ...(existing.stripeCustomer ? { stripeCustomer: existing.stripeCustomer } : {}) };
    await tx.query(
      `INSERT INTO billing_profiles (tenant_id, profile) VALUES ($1, $2::jsonb)
       ON CONFLICT (tenant_id) DO UPDATE SET profile = EXCLUDED.profile`,
      [tenantId, JSON.stringify(merged)],
    );
    return profile;
  }

  async subscriptions(tx: Queryable): Promise<Subscription[]> {
    const units = await this.currentUnits(tx);
    const { rows } = await tx.query<Row>("SELECT * FROM billing_subscriptions WHERE status <> 'canceled' ORDER BY product");
    return rows.map((r) => toSubscription(r, units[r.product as BillingProduct] ?? 0));
  }

  async quoteFor(tx: Queryable, input: { product: BillingProduct; model: BillingModel; minimum?: number; interval?: BillingInterval; units?: number }): Promise<Quote> {
    const units = input.units ?? (await this.currentUnits(tx))[input.product];
    return quote({ ...input, units }, this.deps.priceBook);
  }

  /** Start or change the subscription for a product (the previous one ends now). */
  async subscribe(
    tx: Queryable,
    tenantId: string,
    input: { product: BillingProduct; model: BillingModel; interval?: BillingInterval; minimum?: number },
    by: string,
  ): Promise<{ subscription: Subscription; quote: Quote }> {
    const model = BILLING_MODELS.find((m) => m.key === input.model)!;
    if (input.minimum !== undefined && input.model !== "payg" && input.minimum < model.defaultMinimum) {
      throw badRequest(`${model.label} needs at least ${model.defaultMinimum} committed units`);
    }
    const q = await this.quoteFor(tx, input);
    const now = new Date(this.deps.now());
    await tx.query("UPDATE billing_subscriptions SET status = 'canceled', ends_at = $2 WHERE product = $1 AND status <> 'canceled'", [input.product, now.toISOString()]);
    const ends = model.termMonths > 0 && input.model !== "monthly_commit" ? new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + model.termMonths, now.getUTCDate())) : null;
    const { rows } = await tx.query<Row>(
      `INSERT INTO billing_subscriptions (tenant_id, product, model, interval, minimum, unit_price, currency, starts_at, ends_at, quote, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11) RETURNING *`,
      [tenantId, input.product, input.model, q.interval, q.minimum, q.unitPrice, q.currency, now.toISOString(), ends?.toISOString() ?? null, JSON.stringify(q), by],
    );
    const units = await this.currentUnits(tx);
    return { subscription: toSubscription(rows[0]!, units[input.product]), quote: q };
  }

  async update(tx: Queryable, id: string, patch: { autoRenew?: boolean; cancel?: boolean }): Promise<Subscription> {
    const { rows } = await tx.query<Row>("SELECT * FROM billing_subscriptions WHERE id = $1 AND status <> 'canceled'", [id]);
    if (!rows[0]) throw notFound("Subscription");
    if (patch.cancel) {
      // Commit models run to the end of their term; PAYG stops now.
      const endNow = rows[0].model === "payg" || !rows[0].ends_at;
      await tx.query("UPDATE billing_subscriptions SET auto_renew = false, status = CASE WHEN $2 THEN 'canceled' ELSE status END, ends_at = CASE WHEN $2 THEN now() ELSE ends_at END WHERE id = $1", [id, endNow]);
    } else if (patch.autoRenew !== undefined) {
      await tx.query("UPDATE billing_subscriptions SET auto_renew = $2 WHERE id = $1", [id, patch.autoRenew]);
    }
    const { rows: after } = await tx.query<Row>("SELECT * FROM billing_subscriptions WHERE id = $1", [id]);
    const units = await this.currentUnits(tx);
    return toSubscription(after[0]!, units[after[0]!.product as BillingProduct]);
  }

  // ─── Invoices ─────────────────────────────────────────────────────────────

  /**
   * Invoice one period for an account: one line per live subscription, quantity = max(units
   * protected, committed minimum). Idempotent per (account, period). Annual-upfront terms are
   * invoiced for 12 months in their first period and not again until renewal.
   */
  async generateInvoice(tx: Queryable, tenantId: string, period: { start: Date; end: Date }): Promise<(Invoice & { paymentUrl: string | null }) | null> {
    const existing = await tx.query<Row>("SELECT * FROM invoices WHERE period_start = $1 AND period_end = $2", [period.start.toISOString(), period.end.toISOString()]);
    if (existing.rows[0]) return toInvoice(existing.rows[0]);
    const subs = await tx.query<Row>(
      "SELECT * FROM billing_subscriptions WHERE status <> 'canceled' AND starts_at < $2 AND (ends_at IS NULL OR ends_at > $1) ORDER BY product",
      [period.start.toISOString(), period.end.toISOString()],
    );
    if (subs.rows.length === 0) return null;
    const units = await this.currentUnits(tx);
    const lines: Invoice["lines"] = [];
    let currency: Invoice["currency"] = this.deps.priceBook.currency;
    for (const s of subs.rows) {
      const product = s.product as BillingProduct;
      const upfront = s.interval === "annual_upfront";
      const startedThisPeriod = new Date(String(s.starts_at)) >= period.start;
      if (upfront && !startedThisPeriod) continue;
      const qty = Math.max(units[product], Number(s.minimum));
      const months = upfront ? 12 : 1;
      const meta = BILLING_PRODUCTS.find((p) => p.key === product)!;
      const modelLabel = BILLING_MODELS.find((m) => m.key === s.model)!.label;
      currency = s.currency as Invoice["currency"];
      lines.push({
        product,
        model: s.model as BillingModel,
        description: `${meta.label} — ${modelLabel}${upfront ? " (12 months)" : ""}: ${qty} ${meta.unit}${qty === 1 ? "" : "s"}`,
        quantity: qty * months,
        unitPrice: Number(s.unit_price),
        amount: qty * months * Number(s.unit_price),
      });
    }
    if (lines.length === 0) return null;
    const ym = `${period.start.getUTCFullYear()}${String(period.start.getUTCMonth() + 1).padStart(2, "0")}`;
    const seq = await tx.query<{ n: string }>("SELECT count(*) + 1 AS n FROM invoices");
    const number = `INV-${ym}-${String(seq.rows[0]!.n).padStart(4, "0")}`;
    const due = new Date(this.deps.now() + this.deps.invoiceDueDays * 86_400_000);
    const { rows } = await tx.query<Row>(
      `INSERT INTO invoices (tenant_id, number, period_start, period_end, currency, lines, total, due_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
       ON CONFLICT (tenant_id, period_start, period_end) DO NOTHING RETURNING *`,
      [tenantId, number, period.start.toISOString(), period.end.toISOString(), currency, JSON.stringify(lines), lines.reduce((a, l) => a + l.amount, 0), due.toISOString()],
    );
    if (rows[0]) return toInvoice(rows[0]);
    const again = await tx.query<Row>("SELECT * FROM invoices WHERE period_start = $1 AND period_end = $2", [period.start.toISOString(), period.end.toISOString()]);
    return again.rows[0] ? toInvoice(again.rows[0]) : null;
  }

  async invoices(tx: Queryable, limit = 36): Promise<Array<Invoice & { paymentUrl: string | null }>> {
    const { rows } = await tx.query<Row>("SELECT * FROM invoices ORDER BY period_start DESC, created_at DESC LIMIT $1", [limit]);
    return rows.map(toInvoice);
  }

  /** Send an open invoice to a provider's hosted checkout. */
  async checkout(tenantId: string, invoiceId: string, providerKey: PaymentProviderKey, customerEmail: string | null): Promise<{ url: string }> {
    const provider = this.deps.providers.get(providerKey);
    if (!provider) throw badRequest(`${providerKey} is not configured on this platform`);
    const inv = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM invoices WHERE id = $1", [invoiceId])).rows[0]);
    if (!inv) throw notFound("Invoice");
    if (inv.status !== "open") throw new HttpError(409, "invoice_not_open", `Invoice ${String(inv.number)} is ${String(inv.status)}`);
    const back = `${this.deps.publicUrl}/settings/billing`;
    const res = await provider.checkout({
      tenantId,
      invoiceId,
      invoiceNumber: String(inv.number),
      amount: Number(inv.total),
      currency: inv.currency as Invoice["currency"],
      description: ((inv.lines as Invoice["lines"])[0]?.description ?? "Security services").split(":")[0]!,
      customerEmail,
      successUrl: `${back}?paid=${invoiceId}`,
      cancelUrl: back,
      webhookUrl: `${this.deps.publicUrl}/api/v1/billing/webhooks/${providerKey}`,
    });
    await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE invoices SET provider_ref = $2, payment_url = $3 WHERE id = $1", [invoiceId, res.providerRef, res.url]));
    return { url: res.url };
  }

  async setupCard(tenantId: string, providerKey: PaymentProviderKey): Promise<{ url: string }> {
    const provider = this.deps.providers.get(providerKey);
    if (!provider?.setupCard) throw badRequest(`${providerKey} cannot save a card without a payment (cards are saved during the first payment)`);
    const profile = await this.deps.db.withTenant(tenantId, (tx) => this.getProfile(tx));
    const back = `${this.deps.publicUrl}/settings/billing`;
    const res = await provider.setupCard({ tenantId, customerEmail: profile.billingEmail || null, customerRef: profile.stripeCustomer ?? null, successUrl: `${back}?card=added`, cancelUrl: back });
    if (res.customerRef !== profile.stripeCustomer) {
      await this.deps.db.withTenant(tenantId, (tx) =>
        tx.query(
          `INSERT INTO billing_profiles (tenant_id, profile) VALUES ($1, jsonb_build_object('stripeCustomer', $2::text))
           ON CONFLICT (tenant_id) DO UPDATE SET profile = billing_profiles.profile || jsonb_build_object('stripeCustomer', $2::text)`,
          [tenantId, res.customerRef],
        ),
      );
    }
    return { url: res.url };
  }

  // ─── Payment methods ──────────────────────────────────────────────────────

  async paymentMethods(tx: Queryable): Promise<PaymentMethod[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM payment_methods WHERE status <> 'removed' ORDER BY is_default DESC, created_at DESC");
    return rows.map(toPaymentMethod);
  }

  /** Record a method (from a verified provider event, or a crypto / bank-transfer preference). */
  async addMethod(tx: Queryable, tenantId: string, m: NonNullable<PaymentEvent["method"]> & { provider: PaymentProviderKey }): Promise<PaymentMethod> {
    const dup = await tx.query<Row>(
      `SELECT * FROM payment_methods WHERE status = 'active' AND provider = $1 AND kind = $2
         AND coalesce(last4, '') = coalesce($3, '') AND coalesce(exp_year, 0) = coalesce($4, 0) AND coalesce(brand, '') = coalesce($5, '')`,
      [m.provider, m.kind, m.last4, m.expYear, m.brand],
    );
    if (dup.rows[0]) return toPaymentMethod(dup.rows[0]);
    const hasDefault = (await tx.query("SELECT 1 FROM payment_methods WHERE is_default AND status = 'active'")).rowCount ?? 0;
    const { rows } = await tx.query<Row>(
      `INSERT INTO payment_methods (tenant_id, kind, provider, label, brand, last4, exp_month, exp_year, provider_ref, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [tenantId, m.kind, m.provider, m.label.slice(0, 120), m.brand, m.last4, m.expMonth, m.expYear, m.providerRef, hasDefault === 0],
    );
    return toPaymentMethod(rows[0]!);
  }

  async setDefaultMethod(tx: Queryable, id: string): Promise<void> {
    const { rows } = await tx.query<Row>("SELECT id FROM payment_methods WHERE id = $1 AND status = 'active'", [id]);
    if (!rows[0]) throw notFound("Payment method");
    await tx.query("UPDATE payment_methods SET is_default = false WHERE is_default");
    await tx.query("UPDATE payment_methods SET is_default = true WHERE id = $1", [id]);
  }

  async removeMethod(tx: Queryable, id: string): Promise<void> {
    const { rowCount } = await tx.query("UPDATE payment_methods SET status = 'removed', is_default = false WHERE id = $1 AND status <> 'removed'", [id]);
    if (!rowCount) throw notFound("Payment method");
  }

  // ─── Payments ─────────────────────────────────────────────────────────────

  /**
   * Apply a verified provider event exactly once. Returns false for duplicates and events that
   * do not change anything.
   */
  async applyEvent(evt: PaymentEvent, payload: unknown): Promise<boolean> {
    if (!evt.tenantId || evt.kind === "ignored") return false;
    return this.deps.db.withTenant(evt.tenantId, async (tx) => {
      const ins = await tx.query(
        `INSERT INTO payment_events (tenant_id, provider, provider_event_id, kind, payload) VALUES ($1, $2, $3, $4, $5::jsonb)
         ON CONFLICT (provider, provider_event_id) DO NOTHING`,
        [evt.tenantId, evt.provider, evt.eventId, evt.kind, JSON.stringify(payload)],
      );
      if (!ins.rowCount) return false; // redelivery
      if (evt.method && (evt.kind === "invoice.paid" || evt.kind === "method.added")) await this.addMethod(tx, evt.tenantId!, { ...evt.method, provider: evt.provider });
      if (evt.kind !== "invoice.paid" || !evt.invoiceId) return evt.kind === "method.added";
      const { rowCount } = await tx.query(
        "UPDATE invoices SET status = 'paid', paid_at = $2, paid_via = $3, provider_ref = coalesce($4, provider_ref) WHERE id = $1 AND status = 'open'",
        [evt.invoiceId, new Date(this.deps.now()).toISOString(), evt.provider, evt.providerRef],
      );
      if (rowCount) await tx.query("UPDATE billing_subscriptions SET status = 'active' WHERE status = 'past_due'");
      return Boolean(rowCount);
    });
  }

  /** Operator confirmation of a payment the platform cannot see (bank transfer). */
  async markPaid(tx: Queryable, invoiceNumber: string, via: PaymentProviderKey, reference: string | null): Promise<Invoice> {
    const { rows } = await tx.query<Row>(
      "UPDATE invoices SET status = 'paid', paid_at = $2, paid_via = $3, provider_ref = coalesce($4, provider_ref) WHERE number = $1 AND status = 'open' RETURNING *",
      [invoiceNumber, new Date(this.deps.now()).toISOString(), via, reference],
    );
    if (!rows[0]) throw notFound("Open invoice");
    return toInvoice(rows[0]);
  }

  /** Overdue open invoices put their account's subscriptions in past_due (dunning). */
  async markOverdue(tx: Queryable): Promise<number> {
    const { rows } = await tx.query<{ n: string }>("SELECT count(*) AS n FROM invoices WHERE status = 'open' AND due_at < $1", [new Date(this.deps.now()).toISOString()]);
    if (Number(rows[0]!.n) === 0) return 0;
    const { rowCount } = await tx.query("UPDATE billing_subscriptions SET status = 'past_due' WHERE status = 'active'");
    return rowCount ?? 0;
  }
}
