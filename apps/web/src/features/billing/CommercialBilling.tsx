import { BILLING_MODELS, formatMoney, quote, type BillingInterval, type BillingModel, type BillingProduct, type BillingProfile, type Invoice, type PaymentProviderKey } from "@bloody/contracts";
import { clsx } from "clsx";
import { Bitcoin, Building2, CreditCard, FileText, Landmark, Mail, Plus, ShieldCheck, Star, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import {
  useAddPaymentPreference,
  useBillingOverview,
  useInvoiceCheckout,
  useRemovePaymentMethod,
  useSaveBillingProfile,
  useSetDefaultPaymentMethod,
  useSetupCard,
  useSubscribe,
  useUpdateSubscription,
} from "../../api/hooks";
import type { BillingOverview } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { CopyButton } from "../../components/CopyButton";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { Field, Input, Select } from "../../components/Form";
import { Dialog } from "../../components/Overlay";
import { SkeletonText } from "../../components/Skeleton";
import { formatDate } from "../../lib/format";

type Overview = BillingOverview;
type InvoiceRow = Overview["invoices"][number];
type SubRow = Overview["subscriptions"][number];

const modelLabel = (m: BillingModel) => BILLING_MODELS.find((x) => x.key === m)?.label ?? m;
const go = (url: string) => window.location.assign(url);

/**
 * Commercial billing: account team, subscriptions per product and pricing model (pay as you go,
 * monthly commitment, annual, MSSP partner) with live quotes, payment methods (provider tokens
 * only: card entry happens on the provider's page), addresses and invoices with hosted checkout.
 */
export function CommercialBilling() {
  const session = useSession();
  const canWrite = session.canAnywhere("billing:write");
  const overview = useBillingOverview();
  if (overview.isPending) return <SkeletonText lines={8} />;
  if (overview.isError) return <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />;
  const o = overview.data;
  return (
    <div className="space-y-3" data-testid="commercial-billing">
      {o.contact ? <AccountTeam contact={o.contact} /> : null}
      <Subscriptions o={o} canWrite={canWrite} />
      <PlanChooser o={o} canWrite={canWrite} />
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <PaymentMethods o={o} canWrite={canWrite} />
        <Addresses o={o} canWrite={canWrite} />
      </div>
      <Invoices o={o} canWrite={canWrite} />
    </div>
  );
}

function AccountTeam({ contact }: { contact: { name: string; email: string } }) {
  return (
    <div className="flex items-center gap-3 rounded border border-line bg-surface p-3 shadow-card">
      <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-primary text-white">
        <Building2 size={18} aria-hidden />
      </span>
      <div className="text-sm">
        <p className="text-2xs font-semibold uppercase tracking-wide text-fg-muted">Account team</p>
        <p className="font-semibold text-heading">{contact.name}</p>
        <p className="text-fg-muted">
          Questions about plans, invoices or payments?{" "}
          <a className="font-medium text-primary underline" href={`mailto:${contact.email}`}>
            {contact.email}
          </a>
          <CopyButton value={contact.email} label="Copy email address" className="ml-1 align-middle" />
        </p>
      </div>
    </div>
  );
}

function Subscriptions({ o, canWrite }: { o: Overview; canWrite: boolean }) {
  const update = useUpdateSubscription();
  const productLabel = (k: BillingProduct) => o.products.find((p) => p.key === k)?.label ?? k;
  const columns: DataTableColumn<SubRow>[] = [
    { id: "product", header: "Product", accessor: (s) => productLabel(s.product), hideable: false },
    { id: "plan", header: "Plan", accessor: (s) => modelLabel(s.model) },
    { id: "status", header: "Status", accessor: (s) => s.status, cell: (s) => <StatusBadge status={s.status} size="xs" /> },
    { id: "starts", header: "Starts", accessor: (s) => new Date(s.startsAt), cell: (s) => formatDate(s.startsAt) },
    { id: "ends", header: "Ends", accessor: (s) => (s.endsAt ? new Date(s.endsAt) : null), cell: (s) => (s.endsAt ? formatDate(s.endsAt) : "N/A") },
    { id: "minimum", header: "Minimum", accessor: (s) => s.minimum },
    { id: "interval", header: "Billing interval", accessor: (s) => (s.interval === "annual_upfront" ? "Annually (upfront)" : "Monthly") },
    { id: "current", header: "Current", accessor: (s) => s.currentUnits },
    { id: "cost", header: "Cost per unit", accessor: (s) => s.unitPrice, cell: (s) => `${formatMoney(s.unitPrice, s.currency)} / mo` },
    {
      id: "renew",
      header: "Auto-renew",
      sortable: false,
      exportable: false,
      cell: (s) => (
        <label className="inline-flex items-center gap-1.5 text-xs">
          <input type="checkbox" checked={s.autoRenew} disabled={!canWrite || update.isPending} onChange={(e) => update.mutate({ id: s.id, autoRenew: e.target.checked })} aria-label={`Auto-renew ${productLabel(s.product)}`} />
          {s.autoRenew ? "On" : "Off"}
        </label>
      ),
    },
  ];
  return (
    <DataTable
      caption="Active subscriptions"
      columns={columns}
      rows={o.subscriptions}
      getRowId={(s) => s.id}
      exportFileName="bloody-subscriptions"
      emptyState={<EmptyState compact icon={CreditCard} title="No subscription yet" description="Choose a plan below. Pay as you go has no commitment." />}
    />
  );
}

function PlanChooser({ o, canWrite }: { o: Overview; canWrite: boolean }) {
  const subscribe = useSubscribe();
  const [product, setProduct] = useState<BillingProduct>("edr");
  const [model, setModel] = useState<BillingModel>("payg");
  const [interval, setInterval] = useState<BillingInterval>("monthly");
  const def = o.models.find((m) => m.key === model)!;
  const [minimum, setMinimum] = useState<string>("");
  const min = model === "payg" ? 0 : Math.max(def.defaultMinimum, Number(minimum) || def.defaultMinimum);
  const units = o.units[product] ?? 0;
  const q = useMemo(() => quote({ product, model, units, minimum: min, interval }, o.priceBook), [product, model, units, min, interval, o.priceBook]);
  const unit = o.products.find((p) => p.key === product)!.unit;
  const current = o.subscriptions.find((s) => s.product === product);
  return (
    <Card title="Choose a plan" info="Prices are per protected unit per month. Commitment plans bill at least the committed minimum; discounts are shown line by line.">
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <Field label="Product">
          {(p) => (
            <Select {...p} value={product} onChange={(e) => setProduct(e.target.value as BillingProduct)}>
              {o.products.map((x) => (
                <option key={x.key} value={x.key}>
                  {x.label} — {o.units[x.key] ?? 0} {x.unit}s now
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-4" role="radiogroup" aria-label="Pricing model">
        {o.models.map((m) => {
          const price = quote({ product, model: m.key, units, minimum: m.defaultMinimum }, o.priceBook).unitPrice;
          const selected = m.key === model;
          return (
            <button
              key={m.key}
              type="button"
              role="radio"
              aria-checked={selected}
              onClick={() => {
                setModel(m.key);
                setMinimum("");
                if (m.key !== "annual" && m.key !== "mssp_partner") setInterval("monthly");
              }}
              className={clsx("rounded border p-3 text-left transition-colors", selected ? "border-primary bg-primary-soft" : "border-line hover:bg-surface-2")}
            >
              <span className="flex items-center justify-between gap-2">
                <span className="font-semibold text-heading">{m.label}</span>
                {current?.model === m.key ? <Badge size="xs" tone="success">Current</Badge> : m.discount > 0 ? <Badge size="xs" tone="info">-{Math.round(m.discount * 100)}%</Badge> : null}
              </span>
              <span className="mt-1 block text-lg font-semibold tabular-nums text-heading">
                {formatMoney(price, o.currency)} <span className="text-xs font-normal text-fg-muted">/ {unit} / month</span>
              </span>
              <span className="mt-1 block text-xs text-fg-muted">{m.description}</span>
              {m.defaultMinimum > 0 ? <span className="mt-1 block text-2xs text-fg-subtle">Minimum {m.defaultMinimum} {unit}s</span> : null}
            </button>
          );
        })}
      </div>
      <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <div className="space-y-2">
          {model !== "payg" ? (
            <Field label={`Committed ${unit}s`} hint={`At least ${def.defaultMinimum}.`}>
              {(p) => <Input {...p} type="number" min={def.defaultMinimum} value={minimum} placeholder={String(def.defaultMinimum)} onChange={(e) => setMinimum(e.target.value)} />}
            </Field>
          ) : null}
          {model === "annual" || model === "mssp_partner" ? (
            <Field label="Billing interval">
              {(p) => (
                <Select {...p} value={interval} onChange={(e) => setInterval(e.target.value as BillingInterval)}>
                  <option value="monthly">Monthly</option>
                  <option value="annual_upfront">Annually upfront (extra {Math.round(o.priceBook.annualUpfrontDiscount * 100)}% off)</option>
                </Select>
              )}
            </Field>
          ) : null}
        </div>
        <div className="rounded border border-line bg-surface-2 p-3 text-sm" data-testid="quote">
          <div className="flex justify-between">
            <span className="text-fg-muted">List price</span>
            <span className="tabular-nums">{formatMoney(q.listUnitPrice, q.currency)}</span>
          </div>
          {q.discounts.map((d) => (
            <div key={d.label} className="flex justify-between text-healthy">
              <span>{d.label}</span>
              <span>-{Math.round(d.rate * 100)}%</span>
            </div>
          ))}
          <div className="mt-1 flex justify-between border-t border-line pt-1">
            <span className="text-fg-muted">
              {q.billedUnits} {unit}s × {formatMoney(q.unitPrice, q.currency)}
            </span>
            <span className="font-semibold tabular-nums">{formatMoney(q.monthlyTotal, q.currency)} / month</span>
          </div>
          {q.interval === "annual_upfront" ? (
            <div className="flex justify-between">
              <span className="text-fg-muted">Billed today for 12 months</span>
              <span className="font-semibold tabular-nums">{formatMoney(q.invoiceTotal, q.currency)}</span>
            </div>
          ) : null}
          <div className="mt-2 flex items-center justify-end gap-2">
            {subscribe.isError ? <span className="mr-auto text-xs text-sev-critical">{errorMessage(subscribe.error)}</span> : null}
            {subscribe.isSuccess ? <span className="mr-auto text-xs text-healthy">Plan updated.</span> : null}
            <Button variant="primary" disabled={!canWrite} loading={subscribe.isPending} onClick={() => subscribe.mutate({ product, model, ...(model !== "payg" ? { minimum: min } : {}), ...(q.interval !== "monthly" ? { interval: q.interval } : {}) })}>
              {current ? "Switch to this plan" : "Subscribe"}
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );
}

const METHOD_ICON = { card: CreditCard, paypal: CreditCard, crypto: Bitcoin, bank_transfer: Landmark } as const;

function PaymentMethods({ o, canWrite }: { o: Overview; canWrite: boolean }) {
  const [adding, setAdding] = useState(false);
  const setDefault = useSetDefaultPaymentMethod();
  const remove = useRemovePaymentMethod();
  return (
    <Card
      title="Payment methods"
      actions={
        canWrite && o.providers.length > 0 ? (
          <Button size="xs" icon={Plus} onClick={() => setAdding(true)}>
            Add
          </Button>
        ) : null
      }
    >
      {o.paymentMethods.length === 0 ? (
        <EmptyState compact icon={CreditCard} title="No payment method yet" description={o.providers.length ? "Add a card, crypto or bank transfer." : "Payments are not configured on this platform yet — contact your account team."} />
      ) : (
        <ul className="divide-y divide-line text-sm">
          {o.paymentMethods.map((m) => {
            const Icon = METHOD_ICON[m.kind];
            return (
              <li key={m.id} className="flex items-center gap-2 py-2">
                <Icon size={16} className="text-fg-muted" aria-hidden />
                <span className="font-medium">{m.label}</span>
                {m.expMonth && m.expYear ? <span className="text-xs text-fg-muted">expires {String(m.expMonth).padStart(2, "0")}/{m.expYear}</span> : null}
                {m.isDefault ? <Badge size="xs" tone="success">Default</Badge> : null}
                <span className="ml-auto flex gap-1">
                  {canWrite && !m.isDefault ? (
                    <Button size="xs" icon={Star} onClick={() => setDefault.mutate(m.id)}>
                      Make default
                    </Button>
                  ) : null}
                  {canWrite ? <Button size="xs" icon={Trash2} aria-label={`Remove ${m.label}`} onClick={() => remove.mutate(m.id)} /> : null}
                </span>
              </li>
            );
          })}
        </ul>
      )}
      <p className="mt-2 flex items-start gap-1.5 text-xs text-fg-muted">
        <ShieldCheck size={13} className="mt-0.5 shrink-0 text-healthy" aria-hidden />
        Card details are entered on the payment provider's secure page. Bloody never sees or stores card numbers — only the brand, last 4 digits and expiry.
      </p>
      {adding ? <AddPaymentMethod o={o} onClose={() => setAdding(false)} /> : null}
    </Card>
  );
}

function AddPaymentMethod({ o, onClose }: { o: Overview; onClose: () => void }) {
  const setupCard = useSetupCard();
  const pref = useAddPaymentPreference();
  const cardProvider = o.providers.find((p) => p.canSaveCard);
  const firstPaymentCard = o.providers.find((p) => (p.kinds as readonly string[]).includes("card") && !p.canSaveCard);
  const crypto = o.providers.filter((p) => (p.kinds as readonly string[]).includes("crypto"));
  const bank = o.providers.find((p) => p.key === "bank_transfer");
  const error = setupCard.error ?? pref.error;
  return (
    <Dialog open onClose={onClose} title="Add a payment method" description="How should we collect your invoices?" footer={<Button onClick={onClose}>Close</Button>}>
      <div className="space-y-2 text-sm">
        {cardProvider ? (
          <MethodOption icon={CreditCard} title="Credit or debit card" note={`Opens ${cardProvider.label}'s secure page to save your card.`} action="Add card" loading={setupCard.isPending} onClick={() => setupCard.mutate({ provider: cardProvider.key }, { onSuccess: (r) => go(r.url) })} />
        ) : firstPaymentCard ? (
          <MethodOption icon={CreditCard} title="Card or PayPal" note={`Choose "Pay" on an invoice: ${firstPaymentCard.label} saves your card during the first payment.`} />
        ) : null}
        {crypto.map((c) => (
          <MethodOption key={c.key} icon={Bitcoin} title={`Crypto via ${c.label}`} note={c.note} action="Use crypto" loading={pref.isPending} onClick={() => pref.mutate({ kind: "crypto", provider: c.key }, { onSuccess: onClose })} />
        ))}
        {bank ? <MethodOption icon={Landmark} title="Bank transfer (wire)" note="Pay invoices by international wire; we confirm receipt." action="Use bank transfer" loading={pref.isPending} onClick={() => pref.mutate({ kind: "bank_transfer", provider: "bank_transfer" }, { onSuccess: onClose })} /> : null}
        {error ? (
          <p role="alert" className="text-sev-critical">
            {errorMessage(error)}
          </p>
        ) : null}
      </div>
    </Dialog>
  );
}

function MethodOption({ icon: Icon, title, note, action, loading, onClick }: { icon: typeof CreditCard; title: string; note: string; action?: string; loading?: boolean; onClick?: () => void }) {
  return (
    <div className="flex items-start gap-3 rounded border border-line p-3">
      <Icon size={18} className="mt-0.5 text-fg-muted" aria-hidden />
      <div className="flex-1">
        <p className="font-medium text-heading">{title}</p>
        <p className="text-xs text-fg-muted">{note}</p>
      </div>
      {action && onClick ? (
        <Button size="sm" loading={loading} onClick={onClick}>
          {action}
        </Button>
      ) : null}
    </div>
  );
}

function AddressBlock({ title, a }: { title: string; a: BillingProfile["billingAddress"] }) {
  const lines = [a.line1, a.line2, [a.city, a.region, a.postalCode].filter(Boolean).join(", "), a.country].filter(Boolean);
  return (
    <div className="rounded border border-line p-3 text-sm">
      <p className="mb-1 font-medium text-heading">{title}</p>
      {lines.length ? lines.map((l) => <p key={l}>{l}</p>) : <p className="text-fg-subtle">Not set</p>}
    </div>
  );
}

function Addresses({ o, canWrite }: { o: Overview; canWrite: boolean }) {
  const [editing, setEditing] = useState(false);
  const p = o.profile;
  return (
    <Card
      title="Billing details & addresses"
      actions={
        canWrite ? (
          <Button size="xs" onClick={() => setEditing(true)}>
            Update
          </Button>
        ) : null
      }
    >
      <dl className="mb-2 grid grid-cols-[120px_1fr] gap-1 text-sm">
        <dt className="text-fg-muted">Company</dt>
        <dd>{p.companyName || <span className="text-fg-subtle">Not set</span>}</dd>
        <dt className="text-fg-muted">Invoices to</dt>
        <dd>{p.billingEmail ? <span className="inline-flex items-center gap-1"><Mail size={12} aria-hidden /> {p.billingEmail}</span> : <span className="text-fg-subtle">Not set</span>}</dd>
        <dt className="text-fg-muted">Tax / VAT ID</dt>
        <dd>{p.taxId || <span className="text-fg-subtle">—</span>}</dd>
      </dl>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <AddressBlock title="Billing address" a={p.billingAddress} />
        <AddressBlock title="Shipping address" a={p.shippingAddress} />
      </div>
      {editing ? <ProfileDialog profile={p} onClose={() => setEditing(false)} /> : null}
    </Card>
  );
}

function ProfileDialog({ profile, onClose }: { profile: BillingProfile; onClose: () => void }) {
  const save = useSaveBillingProfile();
  const [v, setV] = useState<BillingProfile>(profile);
  const [sameAsBilling, setSame] = useState(false);
  const addr = (which: "billingAddress" | "shippingAddress", key: keyof BillingProfile["billingAddress"], value: string) => setV((cur) => ({ ...cur, [which]: { ...cur[which], [key]: value } }));
  const fields: Array<[keyof BillingProfile["billingAddress"], string]> = [
    ["line1", "Address"],
    ["line2", "Address line 2"],
    ["city", "City"],
    ["region", "State / region"],
    ["postalCode", "Postal code"],
    ["country", "Country (2 letters)"],
  ];
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Billing details"
      footer={
        <>
          {save.isError ? <span role="alert" className="mr-auto text-sm text-sev-critical">{errorMessage(save.error)}</span> : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} onClick={() => save.mutate(sameAsBilling ? { ...v, shippingAddress: v.billingAddress } : v, { onSuccess: onClose })}>
            Save
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Field label="Company name">{(p) => <Input {...p} value={v.companyName} onChange={(e) => setV({ ...v, companyName: e.target.value })} />}</Field>
        <Field label="Invoice e-mail">{(p) => <Input {...p} type="email" value={v.billingEmail} onChange={(e) => setV({ ...v, billingEmail: e.target.value })} />}</Field>
        <Field label="Tax / VAT ID">{(p) => <Input {...p} value={v.taxId} onChange={(e) => setV({ ...v, taxId: e.target.value })} />}</Field>
      </div>
      {(["billingAddress", "shippingAddress"] as const).map((which) =>
        which === "shippingAddress" && sameAsBilling ? null : (
          <fieldset key={which} className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
            <legend className="mb-1 text-sm font-medium text-heading">{which === "billingAddress" ? "Billing address" : "Shipping address"}</legend>
            {fields.map(([key, label]) => (
              <Field key={key} label={label}>
                {(p) => <Input {...p} value={v[which][key]} maxLength={key === "country" ? 2 : 200} onChange={(e) => addr(which, key, key === "country" ? e.target.value.toUpperCase() : e.target.value)} />}
              </Field>
            ))}
          </fieldset>
        ),
      )}
      <label className="mt-2 flex items-center gap-2 text-sm">
        <input type="checkbox" checked={sameAsBilling} onChange={(e) => setSame(e.target.checked)} /> Shipping address is the same as billing
      </label>
    </Dialog>
  );
}

function Invoices({ o, canWrite }: { o: Overview; canWrite: boolean }) {
  const [paying, setPaying] = useState<InvoiceRow | null>(null);
  const [viewing, setViewing] = useState<InvoiceRow | null>(null);
  const columns: DataTableColumn<InvoiceRow>[] = [
    { id: "date", header: "Date", accessor: (i) => new Date(i.createdAt), cell: (i) => formatDate(i.createdAt), hideable: false },
    { id: "number", header: "Invoice", accessor: (i) => i.number, cell: (i) => <span className="font-mono text-xs">{i.number}</span> },
    { id: "period", header: "Period", accessor: (i) => new Date(i.periodStart), cell: (i) => `${formatDate(i.periodStart)} – ${formatDate(new Date(Date.parse(i.periodEnd) - 1).toISOString())}` },
    { id: "products", header: "Products", accessor: (i) => i.lines.map((l) => l.product.toUpperCase()).join(", ") },
    { id: "amount", header: "Amount", accessor: (i) => i.total, cell: (i) => <span className="tabular-nums">{formatMoney(i.total, i.currency)}</span> },
    { id: "due", header: "Due", accessor: (i) => new Date(i.dueAt), cell: (i) => formatDate(i.dueAt) },
    { id: "status", header: "Status", accessor: (i) => i.status, cell: (i) => <StatusBadge status={i.status} size="xs" /> },
    {
      id: "actions",
      header: "",
      sortable: false,
      exportable: false,
      cell: (i) => (
        <span className="flex gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="xs" icon={FileText} onClick={() => setViewing(i)}>
            View
          </Button>
          {i.status === "open" && canWrite ? (
            <Button size="xs" variant="primary" onClick={() => setPaying(i)}>
              Pay
            </Button>
          ) : null}
        </span>
      ),
    },
  ];
  return (
    <>
      <DataTable caption="Invoices" columns={columns} rows={o.invoices} getRowId={(i) => i.id} exportFileName="bloody-invoices" emptyState={<EmptyState compact icon={FileText} title="No invoices yet" description="Invoices are issued monthly in arrears." />} />
      {paying ? <PayInvoice o={o} invoice={paying} onClose={() => setPaying(null)} /> : null}
      {viewing ? <InvoiceView o={o} invoice={viewing} onClose={() => setViewing(null)} /> : null}
    </>
  );
}

function PayInvoice({ o, invoice, onClose }: { o: Overview; invoice: InvoiceRow; onClose: () => void }) {
  const checkout = useInvoiceCheckout();
  const [wire, setWire] = useState(false);
  const online = o.providers.filter((p) => p.key !== "bank_transfer");
  const pay = (provider: PaymentProviderKey) => checkout.mutate({ invoiceId: invoice.id, provider }, { onSuccess: (r) => go(r.url) });
  return (
    <Dialog open onClose={onClose} title={`Pay ${invoice.number}`} description={`${formatMoney(invoice.total, invoice.currency)} due ${formatDate(invoice.dueAt)}`} footer={<Button onClick={onClose}>Close</Button>}>
      <div className="space-y-2 text-sm">
        {online.map((p) => (
          <MethodOption key={p.key} icon={(p.kinds as readonly string[]).includes("crypto") ? Bitcoin : CreditCard} title={p.label} note={p.note} action={`Pay with ${p.label}`} loading={checkout.isPending} onClick={() => pay(p.key)} />
        ))}
        {o.bankDetails ? (
          wire ? (
            <div className="rounded border border-line bg-surface-2 p-3" data-testid="wire-instructions">
              <p className="mb-1 font-medium text-heading">Bank transfer instructions</p>
              <pre className="whitespace-pre-wrap font-sans text-sm">{o.bankDetails}</pre>
              <p className="mt-2">
                Reference: <span className="font-mono font-semibold">{invoice.number}</span> <CopyButton value={invoice.number} label="Copy reference" />
              </p>
              <p className="text-xs text-fg-muted">The invoice is marked paid when the transfer arrives.</p>
            </div>
          ) : (
            <MethodOption icon={Landmark} title="Bank transfer" note="International wire; use the invoice number as reference." action="Show instructions" onClick={() => setWire(true)} />
          )
        ) : null}
        {online.length === 0 && !o.bankDetails ? <p className="text-fg-muted">No payment method is configured on this platform yet. Contact your account team.</p> : null}
        {checkout.isError ? <p role="alert" className="text-sev-critical">{errorMessage(checkout.error)}</p> : null}
      </div>
    </Dialog>
  );
}

function InvoiceView({ o, invoice, onClose }: { o: Overview; invoice: Invoice; onClose: () => void }) {
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={`Invoice ${invoice.number}`}
      footer={
        <>
          <Button onClick={() => window.print()}>Print / save as PDF</Button>
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm" data-testid="invoice-view">
        <div className="flex justify-between">
          <div>
            <p className="font-semibold text-heading">SCIAT AFRICA</p>
            <p className="text-fg-muted">Security operations services</p>
          </div>
          <div className="text-right">
            <p className="font-semibold text-heading">{o.profile.companyName || "—"}</p>
            {o.profile.taxId ? <p className="text-fg-muted">Tax ID {o.profile.taxId}</p> : null}
          </div>
        </div>
        <p className="text-fg-muted">
          Period {formatDate(invoice.periodStart)} – {formatDate(new Date(Date.parse(invoice.periodEnd) - 1).toISOString())} · issued {formatDate(invoice.createdAt)} · due {formatDate(invoice.dueAt)}
        </p>
        <table className="w-full text-left">
          <thead className="border-b border-line text-xs text-fg-muted">
            <tr>
              <th className="py-1">Description</th>
              <th className="py-1 text-right">Qty</th>
              <th className="py-1 text-right">Unit</th>
              <th className="py-1 text-right">Amount</th>
            </tr>
          </thead>
          <tbody>
            {invoice.lines.map((l, i) => (
              <tr key={i} className="border-b border-line">
                <td className="py-1">{l.description}</td>
                <td className="py-1 text-right tabular-nums">{l.quantity}</td>
                <td className="py-1 text-right tabular-nums">{formatMoney(l.unitPrice, invoice.currency)}</td>
                <td className="py-1 text-right tabular-nums">{formatMoney(l.amount, invoice.currency)}</td>
              </tr>
            ))}
          </tbody>
          <tfoot>
            <tr>
              <td colSpan={3} className="py-1 text-right font-semibold">
                Total
              </td>
              <td className="py-1 text-right font-semibold tabular-nums">{formatMoney(invoice.total, invoice.currency)}</td>
            </tr>
          </tfoot>
        </table>
        <p>
          Status: <StatusBadge status={invoice.status} size="xs" /> {invoice.paidAt ? `paid ${formatDate(invoice.paidAt)} via ${invoice.paidVia?.replace("_", " ")}` : null}
        </p>
      </div>
    </Dialog>
  );
}
