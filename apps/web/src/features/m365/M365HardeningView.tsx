import type { M365CheckArea, M365CheckResult, M365CheckStatus, M365Severity } from "@bloody/contracts";
import { ChevronDown, ChevronRight, Cloud, Mail, Play, ShieldCheck, Unplug, UserCog } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useAssessM365, useConnectM365, useDisconnectM365, useM365Overview, type M365Overview } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, Dialog, EmptyState, ErrorState, Field, Input, OrganizationSelect, RelativeTime, SkeletonText, StatTile, Tabs, useDefaultOrganization } from "../../components";

const STATUS_TONE: Record<M365CheckStatus, "success" | "danger" | "warning" | "neutral" | "info"> = { pass: "success", fail: "danger", warn: "warning", unknown: "neutral", manual: "info" };
const STATUS_LABEL: Record<M365CheckStatus, string> = { pass: "Pass", fail: "Fail", warn: "Needs attention", unknown: "Not readable", manual: "Check manually" };
const SEV_TONE: Record<M365Severity, "danger" | "warning" | "info" | "neutral"> = { critical: "danger", high: "warning", medium: "info", low: "neutral" };
const AREA: Record<M365CheckArea, { label: string; icon: typeof UserCog }> = { identity: { label: "Identity & access", icon: UserCog }, email: { label: "Email", icon: Mail }, apps: { label: "Apps", icon: Cloud } };
const ORDER: M365CheckStatus[] = ["fail", "warn", "unknown", "manual", "pass"];
const SEV_ORDER: M365Severity[] = ["critical", "high", "medium", "low"];

type Filter = "attention" | "all" | M365CheckStatus;

/** Step-by-step: create the read-only app registration in the customer's tenant, then connect. */
function ConnectGuide({ organizationId, overview, reconnect }: { organizationId: string; overview: M365Overview; reconnect?: boolean }) {
  const connect = useConnectM365();
  const [tenant, setTenant] = useState(overview.connection?.directoryTenantId ?? "");
  const [clientId, setClientId] = useState(overview.connection?.clientId ?? "");
  const [secret, setSecret] = useState("");
  const result = connect.data;
  return (
    <Card title={<span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4" aria-hidden /> {reconnect ? "Update the Microsoft 365 connection" : "Connect Microsoft 365"}</span>}>
      <div className="grid gap-6 text-sm lg:grid-cols-2">
        <ol className="list-decimal space-y-3 pl-5">
          <li>
            In the customer's <span className="font-medium">Microsoft Entra admin center</span> (entra.microsoft.com) go to <span className="font-medium">Identity → Applications → App registrations → New registration</span>. Name it e.g. "SCIAT Security (read-only)", single tenant, no redirect URI.
          </li>
          <li>
            Open <span className="font-medium">API permissions → Add a permission → Microsoft Graph → Application permissions</span> and add:
            <ul className="mt-1 space-y-1">
              {overview.permissions.map((p) => (
                <li key={p.name}>
                  <span className="font-mono text-xs">{p.name}</span> <span className="text-fg-muted">— {p.why}</span>
                </li>
              ))}
            </ul>
            Then select <span className="font-medium">Grant admin consent</span>. All permissions are read-only: SCIAT never changes the tenant.
          </li>
          <li>
            <span className="font-medium">Certificates & secrets → New client secret</span>; copy the secret's <span className="font-medium">Value</span> (shown once).
          </li>
          <li>
            From <span className="font-medium">Overview</span>, copy the <span className="font-medium">Directory (tenant) ID</span> and <span className="font-medium">Application (client) ID</span> into the form.
          </li>
        </ol>
        <div className="space-y-3">
          <Field label="Directory (tenant) ID" hint="GUID, or the tenant's domain such as contoso.onmicrosoft.com">
            {(f) => <Input {...f} value={tenant} onChange={(e) => setTenant(e.target.value.trim())} placeholder="00000000-0000-0000-0000-000000000000" />}
          </Field>
          <Field label="Application (client) ID">{(f) => <Input {...f} value={clientId} onChange={(e) => setClientId(e.target.value.trim())} placeholder="00000000-0000-0000-0000-000000000000" />}</Field>
          <Field label="Client secret value" hint="Stored encrypted; never shown again.">
            {(f) => <Input {...f} type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />}
          </Field>
          <Button variant="primary" icon={ShieldCheck} loading={connect.isPending} disabled={!tenant || !clientId || secret.length < 8} onClick={() => connect.mutate({ organizationId, directoryTenantId: tenant, clientId, clientSecret: secret })}>
            Connect and assess
          </Button>
          {connect.error ? <p role="alert" className="text-sev-critical">{errorMessage(connect.error)}</p> : null}
          {result?.error ? (
            <p role="alert" className="text-sev-critical">
              Saved, but Microsoft refused the sign-in: {result.error}
            </p>
          ) : null}
        </div>
      </div>
    </Card>
  );
}

function CheckCard({ r }: { r: M365CheckResult }) {
  const [open, setOpen] = useState(r.status === "fail");
  return (
    <div className="rounded border border-line">
      <button type="button" className="flex w-full items-start gap-3 p-3 text-left hover:bg-canvas" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        {open ? <ChevronDown className="mt-0.5 h-4 w-4 shrink-0" aria-hidden /> : <ChevronRight className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge size="xs" tone={STATUS_TONE[r.status]}>{STATUS_LABEL[r.status]}</Badge>
            <Badge size="xs" tone={SEV_TONE[r.severity]}>{r.severity}</Badge>
            <span className="font-medium">{r.title}</span>
            {r.requires ? <span className="text-xs text-fg-subtle">needs {r.requires}</span> : null}
          </div>
          <p className="mt-1 text-sm text-fg-muted">{r.summary}</p>
        </div>
      </button>
      {open ? (
        <div className="space-y-3 border-t border-line p-3 pl-10 text-sm">
          <div>
            <div className="font-medium">Why it matters</div>
            <p className="text-fg-muted">{r.why}</p>
          </div>
          {r.status !== "pass" ? (
            <div>
              <div className="font-medium">How to fix</div>
              <ol className="list-decimal space-y-1 pl-5 text-fg-muted">
                {r.howToFix.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ol>
            </div>
          ) : null}
          {r.evidence.length > 0 ? (
            <div>
              <div className="font-medium">Evidence</div>
              <ul className="list-disc space-y-0.5 pl-5 font-mono text-xs text-fg-muted">
                {r.evidence.map((e) => (
                  <li key={e} className="break-all">
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className="flex flex-wrap gap-1">
            {r.references.map((ref) => (
              <Badge key={ref} size="xs" tone="outline">
                {ref}
              </Badge>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

/** ITDR → Microsoft 365 hardening: connect a tenant, see what to fix and how, re-assess. */
export function M365HardeningView() {
  const session = useSession();
  const [organizationId, setOrganizationId] = useState<string | null>(useDefaultOrganization("identity:read"));
  const overview = useM365Overview(organizationId);
  const assess = useAssessM365();
  const disconnect = useDisconnectM365();
  const [filter, setFilter] = useState<Filter>("attention");
  const [reconnect, setReconnect] = useState(false);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  const canWrite = organizationId ? session.can("integration:write", organizationId) : false;
  const o = overview.data;
  const a = o?.assessment;

  const shown = useMemo(() => {
    const rs = a?.results ?? [];
    const f = filter === "all" ? rs : filter === "attention" ? rs.filter((r) => r.status === "fail" || r.status === "warn") : rs.filter((r) => r.status === filter);
    return [...f].sort((x, y) => ORDER.indexOf(x.status) - ORDER.indexOf(y.status) || SEV_ORDER.indexOf(x.severity) - SEV_ORDER.indexOf(y.severity));
  }, [a, filter]);

  return (
    <div className="space-y-4">
      <div className="max-w-sm">
        <OrganizationSelect value={organizationId} onChange={setOrganizationId} permission="identity:read" aria-label="Organization" />
      </div>
      {!organizationId ? (
        <EmptyState title="Pick an organization" />
      ) : overview.isPending ? (
        <SkeletonText lines={6} />
      ) : overview.isError ? (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      ) : !o ? null : !o.connection || reconnect ? (
        canWrite ? (
          <ConnectGuide organizationId={organizationId} overview={o} reconnect={reconnect} />
        ) : (
          <EmptyState title="Microsoft 365 is not connected" description="Ask an administrator with integration rights to connect this organization's tenant." />
        )
      ) : (
        <>
          <Card>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="text-lg font-semibold">{o.connection.displayName ?? o.connection.directoryTenantId}</div>
                <div className="text-sm text-fg-muted">
                  Microsoft 365 tenant · {o.connection.status === "error" ? <span className="text-sev-critical">connection error</span> : "connected read-only"}
                  {o.connection.lastAssessedAt ? (
                    <>
                      {" "}
                      · assessed <RelativeTime value={o.connection.lastAssessedAt} /> (re-checked daily)
                    </>
                  ) : null}
                </div>
                {o.connection.lastError ? <p className="mt-1 text-sm text-sev-critical">{o.connection.lastError}</p> : null}
              </div>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="primary" icon={Play} loading={assess.isPending} onClick={() => assess.mutate(o.connection!.id)}>
                  Run assessment now
                </Button>
                {canWrite ? (
                  <>
                    <Button size="sm" onClick={() => setReconnect(true)}>
                      Update credentials
                    </Button>
                    <Button size="sm" variant="ghost" icon={Unplug} onClick={() => setConfirmDisconnect(true)}>
                      Disconnect
                    </Button>
                  </>
                ) : null}
              </div>
            </div>
            {assess.error ? <p role="alert" className="mt-2 text-sm text-sev-critical">{errorMessage(assess.error)}</p> : null}
            {a ? (
              <div className="mt-4 grid gap-3 sm:grid-cols-5">
                <StatTile label="Hardening score" value={a.score} format={(v) => `${v ?? 0}%`} tone={a.score >= 80 ? "healthy" : a.score >= 50 ? "medium" : "high"} />
                <StatTile label="Failing" value={a.counts.fail} tone={a.counts.fail ? "high" : "healthy"} />
                <StatTile label="Needs attention" value={a.counts.warn} tone={a.counts.warn ? "medium" : "healthy"} />
                <StatTile label="Not readable" value={a.counts.unknown} />
                <StatTile label="Passing" value={a.counts.pass} tone="healthy" />
              </div>
            ) : null}
          </Card>
          {a ? (
            <Card>
              <div className="space-y-3">
                <Tabs
                  ariaLabel="Filter checks"
                  idPrefix="m365"
                  value={filter}
                  onChange={setFilter}
                  tabs={[
                    { id: "attention" as const, label: "To fix", count: a.counts.fail + a.counts.warn },
                    { id: "unknown" as const, label: "Not readable", count: a.counts.unknown },
                    { id: "manual" as const, label: "Check manually", count: a.counts.manual },
                    { id: "pass" as const, label: "Passing", count: a.counts.pass },
                    { id: "all" as const, label: "All", count: a.results.length },
                  ]}
                />
                {shown.length === 0 ? <EmptyState compact title="Nothing here" /> : null}
                {(Object.keys(AREA) as M365CheckArea[]).map((area) => {
                  const items = shown.filter((r) => r.area === area);
                  if (items.length === 0) return null;
                  const Icon = AREA[area].icon;
                  return (
                    <section key={area} className="space-y-2" aria-label={AREA[area].label}>
                      <h3 className="inline-flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-fg-muted">
                        <Icon className="h-4 w-4" aria-hidden /> {AREA[area].label}
                      </h3>
                      {items.map((r) => (
                        <CheckCard key={r.id} r={r} />
                      ))}
                    </section>
                  );
                })}
              </div>
            </Card>
          ) : (
            <EmptyState title="No assessment yet" description="Run an assessment to grade this tenant." />
          )}
          <Dialog
            open={confirmDisconnect}
            onClose={() => setConfirmDisconnect(false)}
            title="Disconnect Microsoft 365?"
            description="SCIAT stops assessing this tenant and deletes the stored app secret. Past assessments are removed too. Also delete the app registration in Entra to fully revoke access."
            footer={
              <>
                <Button variant="secondary" onClick={() => setConfirmDisconnect(false)}>
                  Cancel
                </Button>
                <Button variant="danger" icon={Unplug} loading={disconnect.isPending} onClick={() => disconnect.mutate(o.connection!.id, { onSuccess: () => setConfirmDisconnect(false) })}>
                  Disconnect
                </Button>
              </>
            }
          />
        </>
      )}
    </div>
  );
}
