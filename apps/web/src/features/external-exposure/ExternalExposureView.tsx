import type { ExposureFinding, ExposureTarget } from "@bloody/contracts";
import { CheckCircle2, EyeOff, Globe, Plus, Radar, ShieldCheck, ShieldOff, Trash2 } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import {
  useAddExposureTarget,
  useAuthorizeExposure,
  useDecideExposureTarget,
  useExposureOverview,
  useRemoveExposureTarget,
  useRevokeExposure,
  useStartExposureScan,
} from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, Checkbox, DataTable, Dialog, EmptyState, ErrorState, Field, Input, OrganizationSelect, RelativeTime, SeverityBadge, StatTile, useDefaultOrganization, type DataTableColumn } from "../../components";

const day = 86_400_000;
const isoDate = (ms: number) => new Date(ms).toISOString().slice(0, 10);

function AuthorizeDialog({ organizationId, current, onClose }: { organizationId: string; current: string | undefined; onClose: () => void }) {
  const authorize = useAuthorizeExposure();
  const [reference, setReference] = useState(current ?? "");
  const [until, setUntil] = useState(isoDate(Date.now() + 365 * day));
  const [attest, setAttest] = useState(false);
  const submit = () => authorize.mutate({ organizationId, reference: reference.trim(), expiresAt: new Date(`${until}T23:59:59Z`).toISOString(), attest: true }, { onSuccess: onClose });
  return (
    <Dialog
      open
      onClose={onClose}
      title="Authorize external testing"
      description="SCIAT only checks addresses an organization has authorized. Record what allows it, for example the contract clause or written approval, and when it ends."
      footer={
        <>
          {authorize.error ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(authorize.error)}
            </span>
          ) : null}
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" icon={ShieldCheck} loading={authorize.isPending} disabled={!attest || reference.trim().length < 3 || !until} onClick={submit}>
            Save authorization
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Authorization reference" hint="e.g. MSA-2026-014 §4, or the approval email's subject and date">
          {(f) => <Input {...f} value={reference} onChange={(e) => setReference(e.target.value)} maxLength={500} />}
        </Field>
        <Field label="Valid until" hint="At most one year; renew it when the contract renews.">
          {(f) => <Input {...f} type="date" value={until} min={isoDate(Date.now() + day)} max={isoDate(Date.now() + 365 * day)} onChange={(e) => setUntil(e.target.value)} />}
        </Field>
        <Checkbox
          checked={attest}
          onChange={(e) => setAttest(e.target.checked)}
          label="I confirm this organization owns the addresses we will confirm, or has authorized us in writing to test them."
        />
      </div>
    </Dialog>
  );
}

function AddAddressDialog({ organizationId, onClose }: { organizationId: string; onClose: () => void }) {
  const add = useAddExposureTarget();
  const [ip, setIp] = useState("");
  const [note, setNote] = useState("");
  return (
    <Dialog
      open
      onClose={onClose}
      title="Add a public address"
      description="An internet address the organization owns, such as an office's static IP. It is confirmed straight away."
      footer={
        <>
          {add.error ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(add.error)}
            </span>
          ) : null}
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={add.isPending} disabled={!ip.trim()} onClick={() => add.mutate({ organizationId, ip: ip.trim(), ...(note.trim() ? { note: note.trim() } : {}) }, { onSuccess: onClose })}>
            Add address
          </Button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Address" hint="IPv4 or IPv6, e.g. 41.90.64.10">
          {(f) => <Input {...f} value={ip} onChange={(e) => setIp(e.target.value)} maxLength={45} />}
        </Field>
        <Field label="Note (optional)" hint="e.g. Nairobi office fibre">
          {(f) => <Input {...f} value={note} onChange={(e) => setNote(e.target.value)} maxLength={200} />}
        </Field>
      </div>
    </Dialog>
  );
}

/** ESPM → External Exposure: what each organization exposes to the internet on its public addresses. */
export function ExternalExposureView() {
  const session = useSession();
  const [organizationId, setOrganizationId] = useState<string | null>(useDefaultOrganization("asset:read"));
  const [dialog, setDialog] = useState<"authorize" | "add" | null>(null);
  const overview = useExposureOverview(organizationId);
  const scan = useStartExposureScan();
  const revoke = useRevokeExposure();
  const decide = useDecideExposureTarget();
  const remove = useRemoveExposureTarget();
  const canWrite = organizationId ? session.can("asset:write", organizationId) : false;
  const o = overview.data;

  const auth = o?.authorization ?? null;
  const confirmed = o?.targets.filter((t) => t.status === "confirmed") ?? [];
  const discovered = o?.targets.filter((t) => t.status === "discovered") ?? [];
  const lastScan = o?.scans[0];
  const running = lastScan?.status === "running";
  const critical = o?.findings.filter((f) => f.severity === "critical").length ?? 0;
  const mutationError = scan.error ?? revoke.error ?? decide.error ?? remove.error;

  const findingCols: DataTableColumn<ExposureFinding>[] = [
    { id: "severity", header: "Severity", accessor: (f) => f.severity, cell: (f) => <SeverityBadge severity={f.severity} size="xs" />, filter: { kind: "select", options: ["critical", "high", "medium"].map((v) => ({ value: v, label: v })) } },
    { id: "where", header: "Address", accessor: (f) => `${f.ip}:${f.port}`, hideable: false, cell: (f) => <span className="font-mono text-xs">{f.ip}:{f.port}</span> },
    {
      id: "service",
      header: "Service",
      accessor: (f) => f.service,
      cell: (f) => (
        <div className="max-w-md">
          <div className="font-medium">{f.service}</div>
          <div className="text-xs text-fg-muted">{f.risk}</div>
          <div className="mt-0.5 text-xs">
            <span className="font-medium">Fix: </span>
            {f.fix}
          </div>
        </div>
      ),
    },
    { id: "hosts", header: "Computers behind it", accessor: (f) => f.hostnames.join(", "), cell: (f) => (f.hostnames.length ? f.hostnames.join(", ") : <span className="text-fg-muted">none reporting</span>) },
    { id: "first", header: "Open since", accessor: (f) => new Date(f.firstSeenAt), cell: (f) => <RelativeTime value={f.firstSeenAt} /> },
  ];

  const targetCols: DataTableColumn<ExposureTarget>[] = [
    { id: "ip", header: "Address", accessor: (t) => t.ip, hideable: false, cell: (t) => <span className="font-mono text-xs">{t.ip}</span> },
    {
      id: "status",
      header: "Status",
      accessor: (t) => t.status,
      cell: (t) => (
        <Badge size="xs" tone={t.status === "confirmed" ? "success" : t.status === "discovered" ? "warning" : "neutral"}>
          {t.status === "discovered" ? "Needs confirming" : t.status === "confirmed" ? "Confirmed" : "Ignored"}
        </Badge>
      ),
    },
    { id: "source", header: "Found by", accessor: (t) => (t.source === "agent" ? "SCIAT Agent check-ins" : "Added by an administrator"), cell: (t) => (t.source === "agent" ? "SCIAT Agent check-ins" : t.note ? `Added: ${t.note}` : "Added by an administrator") },
    { id: "hosts", header: "Computers behind it", accessor: (t) => t.hostnames.join(", "), cell: (t) => (t.hostnames.length ? t.hostnames.join(", ") : <span className="text-fg-muted">—</span>) },
    { id: "open", header: "Exposed services", accessor: (t) => t.openPorts, cell: (t) => (t.status !== "confirmed" ? "—" : t.openPorts ? <span className="font-semibold text-sev-critical">{t.openPorts}</span> : t.lastScannedAt ? <span className="text-healthy">0</span> : "not scanned") },
    { id: "scanned", header: "Last checked", accessor: (t) => (t.lastScannedAt ? new Date(t.lastScannedAt) : null), cell: (t) => (t.lastScannedAt ? <RelativeTime value={t.lastScannedAt} /> : "—") },
    {
      id: "act",
      header: "",
      exportable: false,
      sortable: false,
      cell: (t) =>
        canWrite ? (
          <span className="flex gap-1">
            {t.status !== "confirmed" ? (
              <Button size="xs" icon={CheckCircle2} aria-label={`Confirm ${t.ip}`} loading={decide.isPending && decide.variables?.id === t.id} onClick={() => decide.mutate({ id: t.id, status: "confirmed" })}>
                Confirm
              </Button>
            ) : null}
            {t.status !== "ignored" ? (
              <Button size="xs" variant="ghost" icon={EyeOff} aria-label={`Ignore ${t.ip}`} onClick={() => decide.mutate({ id: t.id, status: "ignored" })}>
                Not ours
              </Button>
            ) : null}
            {t.source === "manual" ? <Button size="xs" variant="ghost" icon={Trash2} aria-label={`Remove ${t.ip}`} onClick={() => remove.mutate(t.id)} /> : null}
          </span>
        ) : null,
    },
  ];

  return (
    <div className="space-y-4">
      <Card title="External Exposure">
        <div className="space-y-4">
          <p className="max-w-3xl text-sm text-fg-muted">
            SCIAT checks the organization's public internet addresses for services that should never be reachable from outside: remote desktop, file sharing, databases and admin consoles. Addresses are learned from SCIAT Agent check-ins (each office or home network's public IP), and only addresses you confirm are checked, under a recorded authorization.
          </p>
          <div className="max-w-sm">
            <OrganizationSelect value={organizationId} onChange={setOrganizationId} permission="asset:read" aria-label="Organization" />
          </div>
          {!organizationId ? (
            <EmptyState compact title="Pick an organization" />
          ) : overview.isError ? (
            <ErrorState compact error={overview.error} onRetry={() => void overview.refetch()} />
          ) : o ? (
            <>
              <div className="flex flex-wrap items-center gap-3 rounded border border-line bg-canvas px-3 py-2 text-sm" data-testid="exposure-authorization">
                {auth?.valid ? (
                  <>
                    <Badge tone="success" icon={ShieldCheck}>
                      Authorized
                    </Badge>
                    <span>
                      {auth.reference} · until {new Date(auth.expiresAt).toLocaleDateString()}
                    </span>
                  </>
                ) : (
                  <>
                    <Badge tone="danger" icon={ShieldOff}>
                      {auth ? "Authorization expired" : "Not authorized"}
                    </Badge>
                    <span className="text-fg-muted">No address is checked until an authorization is recorded.</span>
                  </>
                )}
                {canWrite ? (
                  <span className="ml-auto flex gap-2">
                    <Button size="sm" variant={auth?.valid ? "secondary" : "primary"} icon={ShieldCheck} onClick={() => setDialog("authorize")}>
                      {auth ? "Renew authorization" : "Authorize testing"}
                    </Button>
                    {auth ? (
                      <Button size="sm" variant="ghost" loading={revoke.isPending} onClick={() => revoke.mutate(organizationId)}>
                        Revoke
                      </Button>
                    ) : null}
                  </span>
                ) : null}
              </div>
              <div className="grid gap-3 sm:grid-cols-4">
                <StatTile label="Exposed services" value={o.findings.length} tone={o.findings.length ? "high" : "healthy"} />
                <StatTile label="Critical exposures" value={critical} tone={critical ? "critical" : "healthy"} />
                <StatTile label="Addresses checked" value={confirmed.length} />
                <StatTile label="Waiting for confirmation" value={discovered.length} tone={discovered.length ? "medium" : "default"} />
              </div>
              <div className="flex flex-wrap items-center gap-3 text-sm">
                {canWrite ? (
                  <Button size="sm" variant="primary" icon={Radar} loading={scan.isPending} disabled={running || !auth?.valid || confirmed.length === 0} onClick={() => scan.mutate(organizationId)}>
                    {running ? "Scan running…" : "Scan now"}
                  </Button>
                ) : null}
                <span className="text-fg-muted" role="status">
                  {lastScan ? (
                    lastScan.status === "running" ? (
                      <>Checking {lastScan.addresses} address{lastScan.addresses === 1 ? "" : "es"} on {o.portsChecked.length} ports…</>
                    ) : lastScan.status === "failed" ? (
                      <>Last scan failed: {lastScan.error}</>
                    ) : (
                      <>
                        Last scan <RelativeTime value={lastScan.finishedAt ?? lastScan.startedAt} />: {lastScan.addresses} address{lastScan.addresses === 1 ? "" : "es"}, {lastScan.openPorts} exposed service{lastScan.openPorts === 1 ? "" : "s"}. Rescanned daily.
                      </>
                    )
                  ) : (
                    "Not scanned yet."
                  )}
                </span>
              </div>
              {mutationError ? (
                <p role="alert" className="text-sm text-sev-critical">
                  {errorMessage(mutationError)}
                </p>
              ) : null}
            </>
          ) : null}
        </div>
      </Card>

      {organizationId && o ? (
        <>
          <Card title="Exposed services">
            <DataTable
              caption="Exposed services"
              columns={findingCols}
              rows={o.findings}
              getRowId={(f) => `${f.ip}:${f.port}`}
              searchable
              searchPlaceholder="Search addresses or services"
              exportFileName="external-exposure"
              emptyState={
                <EmptyState
                  compact
                  icon={Globe}
                  title={lastScan?.status === "finished" ? "Nothing risky is exposed" : "No results yet"}
                  description={lastScan?.status === "finished" ? `None of the ${o.portsChecked.length} risky ports checked is open on the confirmed addresses.` : "Authorize testing, confirm the organization's addresses, then scan."}
                />
              }
            />
          </Card>
          <Card title="Public addresses">
            <div className="space-y-3">
              {discovered.length ? (
                <p className="rounded border border-sev-medium/40 bg-sev-medium/5 px-3 py-2 text-sm">
                  {discovered.length} address{discovered.length === 1 ? " was" : "es were"} seen from SCIAT Agents. Confirm the ones that belong to the organization (office or data-centre connections). Mark home, hotel or café connections as <span className="font-medium">Not ours</span>: they are never checked.
                </p>
              ) : null}
              {canWrite ? (
                <div className="flex justify-end">
                  <Button size="sm" icon={Plus} onClick={() => setDialog("add")}>
                    Add address
                  </Button>
                </div>
              ) : null}
              <DataTable
                caption="Public addresses"
                columns={targetCols}
                rows={o.targets}
                getRowId={(t) => t.id}
                emptyState={<EmptyState compact title="No public addresses yet" description="They appear as SCIAT Agents check in, or add an office's static IP yourself." />}
              />
              <details className="text-sm">
                <summary className="cursor-pointer text-fg-muted">Ports checked ({o.portsChecked.length})</summary>
                <ul className="mt-2 grid gap-x-6 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
                  {o.portsChecked.map((p) => (
                    <li key={p.port} className="flex items-center gap-2">
                      <SeverityBadge severity={p.severity} size="xs" />
                      <span className="font-mono text-xs">{p.port}</span> {p.service}
                    </li>
                  ))}
                </ul>
              </details>
            </div>
          </Card>
        </>
      ) : null}

      {dialog === "authorize" && organizationId ? <AuthorizeDialog organizationId={organizationId} current={auth?.reference} onClose={() => setDialog(null)} /> : null}
      {dialog === "add" && organizationId ? <AddAddressDialog organizationId={organizationId} onClose={() => setDialog(null)} /> : null}
    </div>
  );
}
