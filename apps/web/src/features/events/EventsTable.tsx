import type { CanonicalEvent } from "@bloody/contracts";
import type { ReactNode } from "react";
import { SeverityBadge } from "../../components/Badge";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { formatDateTime, formatNumber } from "../../lib/format";
import { eventHost, eventSummary, eventUser } from "./eventFormat";

export type EventColumnPreset = "default" | "process" | "network" | "dns" | "web" | "auth" | "cloud" | "file";

const time: DataTableColumn<CanonicalEvent> = {
  id: "time",
  header: "Time",
  accessor: (e) => new Date(e.timestamp),
  cell: (e) => <span className="whitespace-nowrap font-mono text-xs">{formatDateTime(e.timestamp)}</span>,
  width: "150px",
  hideable: false,
};
const sev: DataTableColumn<CanonicalEvent> = { id: "severity", header: "Sev", accessor: (e) => e.severity, cell: (e) => <SeverityBadge severity={e.severity} size="xs" />, width: "80px" };
const host: DataTableColumn<CanonicalEvent> = { id: "host", header: "Host", accessor: (e) => eventHost(e) };
const user: DataTableColumn<CanonicalEvent> = { id: "user", header: "User", accessor: (e) => eventUser(e) };
const mono = (id: string, header: string, get: (e: CanonicalEvent) => string | number | null | undefined, hidden = false): DataTableColumn<CanonicalEvent> => ({
  id,
  header,
  accessor: (e) => get(e) ?? null,
  cell: (e) => {
    const v = get(e);
    return v === null || v === undefined || v === "" ? <span className="text-fg-subtle">—</span> : <span className="block max-w-[360px] truncate font-mono text-xs" title={String(v)}>{String(v)}</span>;
  },
  defaultHidden: hidden,
});

const PRESETS: Record<EventColumnPreset, DataTableColumn<CanonicalEvent>[]> = {
  default: [
    time,
    sev,
    { id: "category", header: "Category", accessor: (e) => e.category },
    { id: "type", header: "Type", accessor: (e) => e.eventType },
    host,
    user,
    mono("summary", "Summary", eventSummary),
    { id: "source", header: "Source", accessor: (e) => e.source.product },
  ],
  process: [
    time,
    sev,
    host,
    user,
    mono("process", "Process", (e) => e.process?.name),
    mono("parent", "Parent", (e) => e.process?.parent?.name),
    mono("cmd", "Command line", (e) => e.process?.commandLine),
    mono("sha256", "SHA-256", (e) => e.process?.hashSha256, true),
  ],
  network: [
    time,
    sev,
    host,
    { id: "direction", header: "Dir", accessor: (e) => e.network?.direction ?? null },
    mono("src", "Source", (e) => (e.network?.srcIp ? `${e.network.srcIp}${e.network.srcPort ? `:${e.network.srcPort}` : ""}` : null)),
    mono("dst", "Destination", (e) => (e.network?.dstIp ? `${e.network.dstIp}${e.network.dstPort ? `:${e.network.dstPort}` : ""}` : null)),
    { id: "proto", header: "Proto", accessor: (e) => e.network?.protocol ?? null },
    { id: "out", header: "Bytes out", accessor: (e) => e.network?.bytesOut ?? null, cell: (e) => formatNumber(e.network?.bytesOut), align: "right" },
    { id: "in", header: "Bytes in", accessor: (e) => e.network?.bytesIn ?? null, cell: (e) => formatNumber(e.network?.bytesIn), align: "right", defaultHidden: true },
  ],
  dns: [time, sev, host, mono("query", "Query", (e) => e.network?.dnsQuery), mono("dst", "Resolver / answer", (e) => e.network?.dstIp), { id: "outcome", header: "Outcome", accessor: (e) => e.outcome ?? null }],
  web: [time, sev, host, mono("host", "HTTP host / SNI", (e) => e.network?.httpHost ?? e.network?.tlsSni), mono("url", "URL", (e) => e.network?.httpUrl), mono("ja3", "JA3", (e) => e.network?.ja3), mono("dst", "Destination", (e) => e.network?.dstIp, true)],
  auth: [
    time,
    sev,
    mono("principal", "Principal", (e) => e.identity?.principal ?? e.user?.name),
    { id: "provider", header: "Provider", accessor: (e) => e.identity?.provider ?? e.source.product },
    mono("ip", "Source IP", (e) => e.identity?.sourceIp ?? e.network?.srcIp),
    { id: "geo", header: "Location", accessor: (e) => [e.identity?.geo?.city, e.identity?.geo?.country].filter(Boolean).join(", ") || null },
    { id: "outcome", header: "Outcome", accessor: (e) => e.outcome ?? e.identity?.outcome ?? null },
    { id: "mfa", header: "MFA", accessor: (e) => (e.identity?.mfa === undefined ? null : e.identity.mfa ? "yes" : "no") },
  ],
  cloud: [
    time,
    sev,
    { id: "provider", header: "Provider", accessor: (e) => e.cloudResource?.provider ?? null },
    mono("account", "Account", (e) => e.cloudResource?.accountId),
    { id: "region", header: "Region", accessor: (e) => e.cloudResource?.region ?? null },
    mono("resource", "Resource", (e) => e.cloudResource?.resourceId ?? e.cloudResource?.resourceType),
    mono("action", "Action", (e) => e.cloudResource?.action ?? e.action),
    mono("summary", "Summary", eventSummary),
  ],
  file: [time, sev, host, user, { id: "action", header: "Action", accessor: (e) => e.file?.action ?? e.action ?? null }, mono("path", "Path", (e) => e.file?.path), mono("sha256", "SHA-256", (e) => e.file?.sha256)],
};

export function EventsTable({
  rows,
  preset = "default",
  loading,
  error,
  onRetry,
  onSelect,
  selectedId,
  emptyState,
  footer,
  toolbar,
  savedViewsKey,
  exportFileName = "bloody-events",
}: {
  rows: CanonicalEvent[] | undefined;
  preset?: EventColumnPreset;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  onSelect?: (e: CanonicalEvent) => void;
  selectedId?: string | null;
  emptyState?: ReactNode;
  footer?: ReactNode;
  toolbar?: ReactNode;
  savedViewsKey?: string;
  exportFileName?: string;
}) {
  return (
    <DataTable
      caption="Events"
      columns={PRESETS[preset]}
      rows={rows}
      getRowId={(e) => e.id}
      loading={loading}
      error={error}
      onRetry={onRetry}
      onRowClick={onSelect}
      selectedRowId={selectedId ?? null}
      emptyState={emptyState}
      footer={footer}
      toolbar={toolbar}
      initialState={{ sort: { columnId: "time", direction: "desc" }, pageSize: 50 }}
      savedViewsKey={savedViewsKey}
      exportFileName={exportFileName}
      searchPlaceholder="Filter loaded events…"
    />
  );
}
