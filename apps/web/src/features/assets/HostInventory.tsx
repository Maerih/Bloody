import type { HostInventory } from "@bloody/contracts";
import { AppWindow, Cog, Cpu, Network, ShieldCheck, Users } from "lucide-react";
import { useState } from "react";
import { useAssetInventory } from "../../api/hooks";
import { Badge } from "../../components/Badge";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { RelativeTime } from "../../components/RelativeTime";
import { SkeletonText } from "../../components/Skeleton";
import { Tabs } from "../../components/Tabs";

type Tab = "software" | "services" | "users" | "processes" | "ports" | "protection";
type Row<K extends keyof HostInventory> = HostInventory[K] extends Array<infer T> ? T : never;

const yes = (v: boolean | null | undefined, on = "On", off = "Off") => (v === null || v === undefined ? <span className="text-fg-subtle">—</span> : v ? <span className="text-healthy">{on}</span> : <span className="text-sev-high">{off}</span>);

const softwareCols: DataTableColumn<Row<"software">>[] = [
  { id: "name", header: "Name", accessor: (r) => r.name, hideable: false },
  { id: "version", header: "Version", accessor: (r) => r.version, cell: (r) => <span className="font-mono text-xs">{r.version ?? "—"}</span> },
  { id: "publisher", header: "Publisher", accessor: (r) => r.publisher },
  { id: "installed", header: "Installed", accessor: (r) => r.installedAt, defaultHidden: true },
];
const serviceCols: DataTableColumn<Row<"services">>[] = [
  { id: "name", header: "Service", accessor: (r) => r.displayName ?? r.name, hideable: false, cell: (r) => <span title={r.name}>{r.displayName ?? r.name}</span> },
  {
    id: "state",
    header: "State",
    accessor: (r) => r.state,
    cell: (r) => <Badge size="xs" tone={r.state === "running" ? "success" : r.state === "failed" ? "danger" : "neutral"}>{r.state}</Badge>,
    filter: { kind: "select", options: ["running", "stopped", "exited", "dead", "failed"].map((v) => ({ value: v, label: v })) },
  },
  { id: "start", header: "Start", accessor: (r) => r.startMode, filter: { kind: "select", options: ["auto", "manual", "disabled"].map((v) => ({ value: v, label: v })) } },
  { id: "account", header: "Runs as", accessor: (r) => r.account },
  { id: "unit", header: "Name", accessor: (r) => r.name, defaultHidden: true },
];
const userCols: DataTableColumn<Row<"users">>[] = [
  { id: "name", header: "User", accessor: (r) => r.name, hideable: false, cell: (r) => <span className="font-medium">{r.name}</span> },
  { id: "full", header: "Full name", accessor: (r) => r.fullName },
  { id: "admin", header: "Admin", accessor: (r) => (r.admin ? "yes" : "no"), cell: (r) => (r.admin ? <Badge size="xs" tone="warning">Administrator</Badge> : <span className="text-fg-subtle">No</span>) },
  { id: "enabled", header: "Enabled", accessor: (r) => (r.enabled ? "yes" : "no"), cell: (r) => yes(r.enabled, "Enabled", "Disabled") },
  { id: "loggedIn", header: "Signed in", accessor: (r) => (r.loggedIn ? "yes" : "no"), cell: (r) => (r.loggedIn ? <Badge size="xs" tone="info">Signed in</Badge> : null) },
  { id: "lastLogon", header: "Last logon", accessor: (r) => (r.lastLogon ? new Date(r.lastLogon) : null), cell: (r) => (r.lastLogon ? <RelativeTime value={r.lastLogon} /> : null) },
];
const processCols: DataTableColumn<Row<"processes">>[] = [
  { id: "name", header: "Process", accessor: (r) => r.name, hideable: false },
  { id: "pid", header: "PID", accessor: (r) => r.pid },
  { id: "user", header: "User", accessor: (r) => r.user },
  { id: "path", header: "Path", accessor: (r) => r.path, cell: (r) => <span className="break-all font-mono text-xs">{r.path ?? "—"}</span> },
];
const portCols: DataTableColumn<Row<"ports">>[] = [
  { id: "port", header: "Port", accessor: (r) => r.port, hideable: false },
  { id: "protocol", header: "Protocol", accessor: (r) => r.protocol, filter: { kind: "select", options: [{ value: "tcp", label: "tcp" }, { value: "udp", label: "udp" }] } },
  { id: "address", header: "Listening on", accessor: (r) => r.address, cell: (r) => <span className="font-mono text-xs">{r.address}</span> },
  { id: "process", header: "Process", accessor: (r) => r.process },
];

function Protection({ inv }: { inv: HostInventory }) {
  return (
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">Antivirus</span>
        <Badge tone={inv.antivirusStatus === "protected" ? "success" : inv.antivirusStatus === "unhealthy" ? "danger" : "warning"}>{inv.antivirusStatus}</Badge>
        <span className="font-medium">Firewall</span>
        {inv.firewall ? <Badge tone={inv.firewall.enabled ? "success" : "danger"}>{inv.firewall.enabled ? "on" : "off"}</Badge> : <span className="text-fg-subtle">not reported</span>}
        {inv.firewall?.detail ? <span className="text-fg-muted">{inv.firewall.detail}</span> : null}
      </div>
      {inv.antivirusIssues.length > 0 ? (
        <ul className="list-disc space-y-0.5 pl-5 text-sev-high" aria-label="Antivirus issues">
          {inv.antivirusIssues.map((i) => (
            <li key={i}>{i}</li>
          ))}
        </ul>
      ) : null}
      {inv.antivirus.length === 0 ? (
        <p className="text-fg-muted">No antivirus product was found on this host.</p>
      ) : (
        <table className="w-full text-left">
          <thead className="text-xs text-fg-subtle">
            <tr>
              <th className="py-1 font-medium">Product</th>
              <th className="font-medium">Status</th>
              <th className="font-medium">Real-time</th>
              <th className="font-medium">Tamper protection</th>
              <th className="font-medium">Definitions</th>
            </tr>
          </thead>
          <tbody>
            {inv.antivirus.map((p) => (
              <tr key={p.name} className="border-t border-line">
                <td className="py-1.5 font-medium">{p.name}</td>
                <td>{yes(p.enabled)}</td>
                <td>{yes(p.realTimeProtection)}</td>
                <td>{yes(p.tamperProtection)}</td>
                <td>{p.upToDate === false ? <span className="text-sev-high">Out of date</span> : p.signatureAgeDays !== null ? `${p.signatureAgeDays} day${p.signatureAgeDays === 1 ? "" : "s"} old` : p.upToDate ? <span className="text-healthy">Up to date</span> : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/** Software, services, users, processes, listening ports and protection reported by the SCIAT Agent. */
export function HostInventorySection({ assetId }: { assetId: string }) {
  const q = useAssetInventory(assetId);
  const [tab, setTab] = useState<Tab>("software");
  if (q.isPending) return <SkeletonText lines={4} />;
  if (q.isError) return <ErrorState compact error={q.error} onRetry={() => void q.refetch()} />;
  const inv = q.data.inventory;
  if (!inv) {
    return <EmptyState compact title="No host inventory yet" description="Install the SCIAT Agent on this host: it reports installed software, services, users, processes, open ports and antivirus every 30 minutes." />;
  }
  const tabs = [
    { id: "software" as const, label: "Software", icon: AppWindow, count: inv.software.length },
    { id: "services" as const, label: "Services", icon: Cog, count: inv.services.length },
    { id: "users" as const, label: "Users", icon: Users, count: inv.users.length },
    { id: "processes" as const, label: "Processes", icon: Cpu, count: inv.processes.length },
    { id: "ports" as const, label: "Open ports", icon: Network, count: inv.ports.length },
    { id: "protection" as const, label: "Antivirus & firewall", icon: ShieldCheck, count: inv.antivirusIssues.length || null },
  ];
  const table = <T,>(rows: T[], columns: DataTableColumn<T>[], id: (r: T) => string, what: string) => (
    <DataTable caption={what} columns={columns} rows={rows} getRowId={id} searchable searchPlaceholder={`Search ${what.toLowerCase()}`} exportFileName={`${inv.hostname}-${what.toLowerCase().replace(/\s+/g, "-")}`} emptyState={<EmptyState compact title={`No ${what.toLowerCase()} reported`} />} />
  );
  return (
    <div className="space-y-3">
      <p className="text-xs text-fg-subtle">
        Reported by the SCIAT Agent on {inv.hostname} <RelativeTime value={inv.collectedAt} />
      </p>
      <Tabs ariaLabel="Host inventory" idPrefix="inv" tabs={tabs} value={tab} onChange={setTab} />
      {tab === "software" ? table(inv.software, softwareCols, (r) => `${r.name}|${r.version ?? ""}`, "Software") : null}
      {tab === "services" ? table(inv.services, serviceCols, (r) => r.name, "Services") : null}
      {tab === "users" ? table(inv.users, userCols, (r) => r.name, "Users") : null}
      {tab === "processes" ? table(inv.processes, processCols, (r) => String(r.pid), "Processes") : null}
      {tab === "ports" ? table(inv.ports, portCols, (r) => `${r.protocol}|${r.address}|${r.port}`, "Open ports") : null}
      {tab === "protection" ? <Protection inv={inv} /> : null}
    </div>
  );
}
