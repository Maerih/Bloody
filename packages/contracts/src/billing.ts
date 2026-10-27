import { z } from "zod";
import { IsoDateTime, Uuid } from "./common.js";

/**
 * Commercial billing (proprietary). SCIAT AFRICA, the platform operator, bills each account.
 *
 * Pricing is per protected unit and month, like the rest of the managed-security market
 * (per endpoint for EDR, per identity for ITDR, per data source for SIEM). Every model starts
 * from the same list price:
 *   payg            pay as you go, billed monthly in arrears for the units actually protected,
 *                   no commitment, no minimum
 *   monthly_commit  committed minimum units per month, cancellable monthly
 *   annual          12-month term, committed minimum, cheapest per unit; billed monthly or upfront
 *   mssp_partner    wholesale rates for MSSPs reselling to their own customers (minimum units)
 * plus volume tiers. Card numbers never reach Bloody: payment methods are tokens held by the
 * payment provider (PCI DSS scope stays with the provider).
 */

export const BILLING_MODELS = [
  { key: "payg", label: "Pay as you go", description: "Monthly, billed for the units you actually protect. No commitment, no minimum.", termMonths: 0, discount: 0, defaultMinimum: 0 },
  { key: "monthly_commit", label: "Monthly commitment", description: "Commit to a minimum number of units; cancel any month.", termMonths: 1, discount: 0.1, defaultMinimum: 25 },
  { key: "annual", label: "Annual", description: "12-month term with a committed minimum — the lowest price per unit.", termMonths: 12, discount: 0.2, defaultMinimum: 50 },
  { key: "mssp_partner", label: "MSSP partner", description: "Wholesale rates for MSSPs serving their own customers.", termMonths: 12, discount: 0.45, defaultMinimum: 100 },
] as const;
export type BillingModel = (typeof BILLING_MODELS)[number]["key"];
export const BillingModel = z.enum(["payg", "monthly_commit", "annual", "mssp_partner"]);

export const BillingInterval = z.enum(["monthly", "annual_upfront"]);
export type BillingInterval = z.infer<typeof BillingInterval>;

/** Billable products (one meter each). */
export const BILLING_PRODUCTS = [
  { key: "edr", label: "Managed EDR", unit: "endpoint", meter: "endpoints" },
  { key: "itdr", label: "Identity threat detection (ITDR)", unit: "identity", meter: "identities" },
  { key: "siem", label: "Managed SIEM", unit: "data source", meter: "dataSources" },
] as const;
export type BillingProduct = (typeof BILLING_PRODUCTS)[number]["key"];
export const BillingProduct = z.enum(["edr", "itdr", "siem"]);

export const Currency = z.enum(["USD", "EUR", "GBP"]);
export type Currency = z.infer<typeof Currency>;

/** Prices in minor units (cents) to avoid floating-point money. */
export const PriceBook = z.object({
  currency: Currency,
  /** List price per unit per month, in cents. */
  listPrice: z.object({ edr: z.number().int().min(0), itdr: z.number().int().min(0), siem: z.number().int().min(0) }),
  /** Volume tiers: from `minUnits` up, an extra discount on top of the model discount. */
  volumeTiers: z.array(z.object({ minUnits: z.number().int().min(1), discount: z.number().min(0).max(0.9) })).max(10),
  /** Extra discount for paying an annual term upfront. */
  annualUpfrontDiscount: z.number().min(0).max(0.5),
});
export type PriceBook = z.infer<typeof PriceBook>;

/** Default price book; the operator overrides it with BLOODY_PRICE_BOOK (JSON). */
export const DEFAULT_PRICE_BOOK: PriceBook = {
  currency: "USD",
  listPrice: { edr: 500, itdr: 300, siem: 300 },
  volumeTiers: [
    { minUnits: 250, discount: 0.05 },
    { minUnits: 1000, discount: 0.1 },
    { minUnits: 5000, discount: 0.15 },
  ],
  annualUpfrontDiscount: 0.05,
};

export interface QuoteInput {
  product: BillingProduct;
  model: BillingModel;
  /** Units expected to be protected (billed quantity for PAYG). */
  units: number;
  /** Committed minimum (commit models); defaults to the model's minimum. */
  minimum?: number;
  interval?: BillingInterval;
}

export interface Quote {
  product: BillingProduct;
  model: BillingModel;
  currency: Currency;
  listUnitPrice: number;
  unitPrice: number;
  /** Units billed each month: max(units, minimum). */
  billedUnits: number;
  minimum: number;
  monthlyTotal: number;
  /** Amount per invoice (monthly, or 12 months for annual upfront). */
  invoiceTotal: number;
  termMonths: number;
  interval: BillingInterval;
  /** Each discount applied, for an explainable price. */
  discounts: Array<{ label: string; rate: number }>;
}

const round = (cents: number) => Math.round(cents);

/** Price a subscription. Pure; used by the API (invoices) and the UI (live quotes) alike. */
export function quote(input: QuoteInput, book: PriceBook = DEFAULT_PRICE_BOOK): Quote {
  const model = BILLING_MODELS.find((m) => m.key === input.model)!;
  const units = Math.max(0, Math.floor(input.units));
  const minimum = input.model === "payg" ? 0 : Math.max(0, Math.floor(input.minimum ?? model.defaultMinimum));
  const interval: BillingInterval = input.model === "annual" || input.model === "mssp_partner" ? (input.interval ?? "monthly") : "monthly";
  const billedUnits = Math.max(units, minimum);
  const discounts: Quote["discounts"] = [];
  if (model.discount > 0) discounts.push({ label: `${model.label} discount`, rate: model.discount });
  const tier = [...book.volumeTiers].sort((a, b) => b.minUnits - a.minUnits).find((t) => billedUnits >= t.minUnits);
  if (tier) discounts.push({ label: `Volume ${tier.minUnits}+ units`, rate: tier.discount });
  if (interval === "annual_upfront" && book.annualUpfrontDiscount > 0) discounts.push({ label: "Paid annually upfront", rate: book.annualUpfrontDiscount });
  const list = book.listPrice[input.product];
  // Discounts compound (each applies to the already-discounted price).
  const unitPrice = round(discounts.reduce((p, d) => p * (1 - d.rate), list));
  const monthlyTotal = unitPrice * billedUnits;
  return {
    product: input.product,
    model: input.model,
    currency: book.currency,
    listUnitPrice: list,
    unitPrice,
    billedUnits,
    minimum,
    monthlyTotal,
    invoiceTotal: interval === "annual_upfront" ? monthlyTotal * 12 : monthlyTotal,
    termMonths: model.termMonths,
    interval,
    discounts,
  };
}

export function formatMoney(cents: number, currency: Currency): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(cents / 100);
}

// ─── Records ────────────────────────────────────────────────────────────────

export const PaymentMethodKind = z.enum(["card", "paypal", "crypto", "bank_transfer"]);
export type PaymentMethodKind = z.infer<typeof PaymentMethodKind>;

/** Gateways Bloody can hand payments to (configured by the operator in .env). */
export const PAYMENT_PROVIDERS = [
  { key: "paddle", label: "Paddle", kinds: ["card", "paypal"], note: "Merchant of record: collects and remits VAT/sales tax worldwide." },
  { key: "stripe", label: "Stripe", kinds: ["card"], note: "Cards worldwide where Stripe accounts are available." },
  { key: "nowpayments", label: "NOWPayments", kinds: ["crypto"], note: "USDT, USDC, BTC, ETH and 100+ coins; optional conversion to fiat." },
  { key: "btcpay", label: "BTCPay Server", kinds: ["crypto"], note: "Self-hosted, no processor fees, non-custodial." },
  { key: "bank_transfer", label: "Bank transfer", kinds: ["bank_transfer"], note: "International wire to the operator's bank account." },
] as const;
export type PaymentProviderKey = (typeof PAYMENT_PROVIDERS)[number]["key"];
export const PaymentProviderKey = z.enum(["paddle", "stripe", "nowpayments", "btcpay", "bank_transfer"]);

export const Address = z.object({
  line1: z.string().trim().max(200).default(""),
  line2: z.string().trim().max(200).default(""),
  city: z.string().trim().max(100).default(""),
  region: z.string().trim().max(100).default(""),
  postalCode: z.string().trim().max(20).default(""),
  country: z.string().trim().max(2).default(""),
});
export type Address = z.infer<typeof Address>;

export const BillingProfile = z.object({
  companyName: z.string().trim().max(200).default(""),
  billingEmail: z.string().trim().email().max(320).or(z.literal("")).default(""),
  taxId: z.string().trim().max(50).default(""),
  billingAddress: Address.prefault({}),
  shippingAddress: Address.prefault({}),
});
export type BillingProfile = z.infer<typeof BillingProfile>;

export const PaymentMethod = z.object({
  id: Uuid,
  kind: PaymentMethodKind,
  provider: PaymentProviderKey,
  label: z.string(),
  brand: z.string().nullable(),
  last4: z.string().nullable(),
  expMonth: z.number().int().nullable(),
  expYear: z.number().int().nullable(),
  isDefault: z.boolean(),
  status: z.enum(["pending", "active", "removed"]),
  createdAt: IsoDateTime,
});
export type PaymentMethod = z.infer<typeof PaymentMethod>;

export const SubscriptionStatus = z.enum(["active", "past_due", "canceled"]);
export const Subscription = z.object({
  id: Uuid,
  product: BillingProduct,
  model: BillingModel,
  interval: BillingInterval,
  status: SubscriptionStatus,
  minimum: z.number().int(),
  unitPrice: z.number().int(),
  currency: Currency,
  startsAt: IsoDateTime,
  endsAt: IsoDateTime.nullable(),
  autoRenew: z.boolean(),
  currentUnits: z.number().int(),
});
export type Subscription = z.infer<typeof Subscription>;

export const InvoiceStatus = z.enum(["open", "paid", "void"]);
export const InvoiceLine = z.object({ product: BillingProduct, model: BillingModel, description: z.string(), quantity: z.number().int(), unitPrice: z.number().int(), amount: z.number().int() });
export const Invoice = z.object({
  id: Uuid,
  number: z.string(),
  periodStart: IsoDateTime,
  periodEnd: IsoDateTime,
  currency: Currency,
  lines: z.array(InvoiceLine),
  total: z.number().int(),
  status: InvoiceStatus,
  dueAt: IsoDateTime,
  paidAt: IsoDateTime.nullable(),
  paidVia: PaymentProviderKey.nullable(),
  createdAt: IsoDateTime,
});
export type Invoice = z.infer<typeof Invoice>;
