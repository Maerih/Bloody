import { PATCH_SLA_DAYS, type MissingUpdate, type PatchEndpoint, type PatchState } from "@bloody/contracts";
import { useState } from "react";
import { usePatchingOverview } from "../../api/hooks";
import { Badge, Card, DataTable, Drawer, EmptyState, ErrorState, OrganizationSelect, RelativeTime, StatTile, useDefaultOrganization, type BadgeTone, type DataTableColumn } from "../../components";

const STATE: Record<PatchState, { label: string; tone: BadgeTone }> = {
  breached: { label: "Out of compliance", tone: "danger" },
  behind: { label: "Behind", tone: "warning" },
  current: { label: "Up to date", tone: "success" },
  unknown: { label: "Not reported", tone: "neutral" },
};

function OsCell({ e }: { e: PatchEndpoint }) {
  const s = e.osSupport;
  return (
    <div>
      <div>{e.os ?? "—"}</div>
      {s.status === "ended" ? (
        <Badge size="xs" tone="danger">
          Unsupported{s.endsOn ? ` since ${s.endsOn}` : ""}
        </Badge>
      ) : s.status === "ending_soon" ? (
        <Badge size="xs" tone="warning">
          Support ends {s.endsOn}
        </Badge>
      ) : null}
    </div>
  );
}

function EndpointDrawer({ e, onClose }: { e: PatchEndpoint; onClose: () => void }) {
  const security = e.pending.filter((p) => p.security);
  const other = e.pending.filter((p) => !p.security);
  return (
    <Drawer open onClose={onClose} title={e.hostname} subtitle={e.os ?? undefined}>
      <div className="space-y-4 p-4 text-sm">
        <div className="flex items-center gap-2">
          <Badge size="xs" tone={STATE[e.grade.state].tone}>
            {STATE[e.grade.state].label}
          </Badge>
        </div>
        {e.grade.reasons.length ? (
          <ul className="list-disc space-y-1 pl-5">
            {e.grade.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        ) : (
          <p className="text-fg-muted">Nothing is waiting to be installed.</p>
        )}
        {e.osSupport.note ? <p className="text-fg-muted">{e.osSupport.note}.</p> : null}
        <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1.5">
          <dt className="text-fg-muted">Last installed</dt>
          <dd>{e.lastInstalledAt ? <RelativeTime value={e.lastInstalledAt} /> : "—"}</dd>
          <dt className="text-fg-muted">Last looked for updates</dt>
          <dd>{e.lastCheckedAt ? <RelativeTime value={e.lastCheckedAt} /> : "—"}</dd>
          <dt className="text-fg-muted">Security updates waiting since</dt>
          <dd>{e.securityPendingSince ? <RelativeTime value={e.securityPendingSince} /> : "—"}</dd>
          <dt className="text-fg-muted">Reported</dt>
          <dd>{e.reportedAt ? <RelativeTime value={e.reportedAt} /> : "never"}</dd>
        </dl>
        {[
          ["Security updates", security],
          ["Other updates", other],
        ].map(([title, list]) =>
          (list as PatchEndpoint["pending"]).length ? (
            <div key={title as string}>
              <div className="mb-1 font-medium">
                {title as string} ({(list as PatchEndpoint["pending"]).length})
              </div>
              <ul aria-label={title as string} className="space-y-1">
                {(list as PatchEndpoint["pending"]).map((p) => (
                  <li key={`${p.id ?? ""}${p.title}`} className="flex justify-between gap-3">
                    <span className="min-w-0 break-words">
                      {p.title}
                      {p.version ? <span className="text-fg-muted"> → {p.version}</span> : null}
                    </span>
                    {p.severity !== "unspecified" ? (
                      <Badge size="xs" tone={p.severity === "critical" ? "danger" : p.severity === "important" ? "warning" : "neutral"}>
                        {p.severity}
                      </Badge>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null,
        )}
      </div>
    </Drawer>
  );
}

/** VM → Patch Compliance: OS updates outstanding per computer, restarts, unsupported operating systems. */
export function PatchComplianceView() {
  const [organizationId, setOrganizationId] = useState<string | null>(useDefaultOrganization("asset:read"));
  const [open, setOpen] = useState<string | null>(null);
  const overview = usePatchingOverview(organizationId);
  const o = overview.data;
  const selected = o?.endpoints.find((e) => e.agentId === open) ?? null;

  const columns: DataTableColumn<PatchEndpoint>[] = [
    { id: "host", header: "Computer", accessor: (e) => e.hostname, hideable: false, cell: (e) => <span className="font-medium">{e.hostname}</span> },
    { id: "os", header: "Operating system", accessor: (e) => e.os ?? "", cell: (e) => <OsCell e={e} /> },
    {
      id: "state",
      header: "Status",
      accessor: (e) => STATE[e.grade.state].label,
      cell: (e) => (
        <Badge size="xs" tone={STATE[e.grade.state].tone}>
          {STATE[e.grade.state].label}
        </Badge>
      ),
      filter: { kind: "select", options: Object.values(STATE).map((s) => ({ value: s.label, label: s.label })) },
    },
    {
      id: "security",
      header: "Security updates",
      accessor: (e) => e.securityCount,
      cell: (e) => (e.source ? <span>{e.securityCount}{e.criticalCount ? <span className="text-sev-critical"> ({e.criticalCount} critical)</span> : null}</span> : "—"),
    },
    { id: "pending", header: "All updates", accessor: (e) => e.pendingCount, cell: (e) => (e.source ? e.pendingCount : "—") },
    { id: "reboot", header: "Restart", accessor: (e) => (e.rebootRequired ? "needed" : ""), cell: (e) => (e.rebootRequired ? <Badge size="xs" tone="warning">Needed</Badge> : null) },
    { id: "installed", header: "Last installed", accessor: (e) => (e.lastInstalledAt ? new Date(e.lastInstalledAt) : null), cell: (e) => (e.lastInstalledAt ? <RelativeTime value={e.lastInstalledAt} /> : "—") },
    { id: "why", header: "Why", accessor: (e) => e.grade.reasons.join("; "), cell: (e) => <span className="text-xs">{e.grade.reasons[0] ?? ""}</span> },
  ];
  const missingColumns: DataTableColumn<MissingUpdate>[] = [
    { id: "title", header: "Update", accessor: (m) => m.title, hideable: false },
    { id: "id", header: "KB / package", accessor: (m) => m.id ?? "", cell: (m) => <span className="font-mono text-xs">{m.id ?? "—"}</span> },
    {
      id: "kind",
      header: "Type",
      accessor: (m) => (m.security ? "security" : "other"),
      cell: (m) => (m.security ? <Badge size="xs" tone={m.severity === "critical" ? "danger" : "warning"}>{m.severity === "unspecified" ? "Security" : `Security · ${m.severity}`}</Badge> : <span className="text-fg-muted">Other</span>),
      filter: { kind: "select", options: [{ value: "security", label: "Security" }, { value: "other", label: "Other" }] },
    },
    { id: "endpoints", header: "Computers missing it", accessor: (m) => m.endpoints },
  ];

  return (
    <div className="space-y-4">
      <Card title="Patch Compliance">
        <div className="space-y-4">
          <p className="max-w-3xl text-sm text-fg-muted">
            What each computer's operating system says is waiting to be installed, reported by the SCIAT Agent from Windows Update, apt, dnf / yum, zypper or macOS Software Update. A computer is out of
            compliance when security updates have waited more than {PATCH_SLA_DAYS} days or its operating system no longer gets security updates from the vendor.
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
              <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
                <StatTile label="Compliance" value={o.summary.compliance} format={(v) => (v == null ? "—" : `${v}%`)} tone={o.summary.compliance === null ? "default" : o.summary.compliance >= 90 ? "healthy" : o.summary.compliance >= 70 ? "medium" : "high"} />
                <StatTile label="Out of compliance" value={o.summary.breached} tone={o.summary.breached > 0 ? "critical" : "healthy"} />
                <StatTile label="Behind" value={o.summary.behind} tone={o.summary.behind > 0 ? "medium" : "default"} />
                <StatTile label="Security updates waiting" value={o.summary.securityUpdates} tone={o.summary.securityUpdates > 0 ? "high" : "default"} />
                <StatTile label="Unsupported OS" value={o.summary.unsupportedOs} tone={o.summary.unsupportedOs > 0 ? "critical" : "default"} />
                <StatTile label="Restart needed" value={o.summary.rebootPending} />
              </div>
              {o.summary.reporting < o.summary.endpoints ? (
                <p className="text-sm text-fg-muted">
                  {o.summary.endpoints - o.summary.reporting} of {o.summary.endpoints} computers have not reported update status yet. It comes with the inventory SCIAT Agent 1.5 or later sends every 30
                  minutes; older agents update themselves when automatic updates are on.
                </p>
              ) : null}
            </>
          ) : null}
        </div>
      </Card>
      {organizationId && o ? (
        <>
          <Card title="Computers">
            <DataTable
              caption="Computers"
              columns={columns}
              rows={o.endpoints}
              getRowId={(e) => e.agentId}
              onRowClick={(e) => setOpen(e.agentId)}
              searchable
              searchPlaceholder="Search computers or operating systems"
              exportFileName="patch-compliance"
              emptyState={<EmptyState compact title="No computers with the SCIAT Agent" description="Install the SCIAT Agent to see patch status." />}
            />
          </Card>
          <Card title="Missing updates">
            <DataTable
              caption="Missing updates"
              columns={missingColumns}
              rows={o.missing}
              getRowId={(m) => `${m.id ?? ""}|${m.title}`}
              searchable
              searchPlaceholder="Search updates, KBs or packages"
              exportFileName="missing-updates"
              emptyState={<EmptyState compact title="Nothing is waiting to be installed" />}
            />
          </Card>
        </>
      ) : null}
      {selected ? <EndpointDrawer key={selected.agentId} e={selected} onClose={() => setOpen(null)} /> : null}
    </div>
  );
}
