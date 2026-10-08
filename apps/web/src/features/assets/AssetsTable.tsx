import { AssetKind, Criticality, type Asset } from "@bloody/contracts";
import { Server } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { useAssets } from "../../api/hooks";
import type { AssetFilters } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { Drawer } from "../../components/Overlay";
import { RelativeTime } from "../../components/RelativeTime";
import { RiskScore } from "../../components/RiskScore";
import { hrefForEntity } from "../../lib/entityLinks";
import { humanize } from "../../lib/format";
import { AssetDetailPanel } from "./AssetDetailPanel";

const CRIT_TONE = { low: "neutral", medium: "info", high: "warning", crown_jewel: "danger" } as const;

/** Asset inventory lens (server-side filters, client-side refinement, detail drawer). */
export function AssetsTable({
  filters = {},
  predicate,
  engines = ["osquery", "wazuh"],
  emptyTitle = "No assets match this view",
  description,
  extraColumns = [],
  initialAssetId = null,
  onSelect,
  savedViewsKey,
}: {
  filters?: AssetFilters;
  predicate?: (a: Asset) => boolean;
  engines?: string[];
  emptyTitle?: string;
  description?: ReactNode;
  extraColumns?: DataTableColumn<Asset>[];
  initialAssetId?: string | null;
  /** Controlled selection (e.g. the Assets page syncs ?id=). */
  onSelect?: (id: string | null) => void;
  savedViewsKey?: string;
}) {
  const session = useSession();
  const assets = useAssets({ sort: "risk", ...filters });
  const [local, setLocal] = useState<string | null>(initialAssetId);
  const selected = onSelect ? initialAssetId : local;
  const select = (id: string | null) => (onSelect ? onSelect(id) : setLocal(id));
  const rows = useMemo(() => assets.items?.filter((a) => (predicate ? predicate(a) : true)), [assets.items, predicate]);
  const selectedAsset = rows?.find((a) => a.id === selected);

  const columns: DataTableColumn<Asset>[] = [
    { id: "name", header: "Asset", accessor: (a) => a.name, hideable: false, cell: (a) => <span className="font-medium text-heading">{a.hostname ?? a.name}</span> },
    { id: "kind", header: "Kind", accessor: (a) => humanize(a.kind), filter: { kind: "select", options: AssetKind.options.map((k) => ({ value: humanize(k), label: humanize(k) })) } },
    { id: "criticality", header: "Criticality", accessor: (a) => humanize(a.criticality), cell: (a) => <Badge size="xs" tone={CRIT_TONE[a.criticality]}>{humanize(a.criticality)}</Badge>, filter: { kind: "select", options: Criticality.options.map((c) => ({ value: humanize(c), label: humanize(c) })) } },
    { id: "exposure", header: "Exposure", accessor: (a) => (a.internetFacing ? "Internet-facing" : "Internal"), cell: (a) => (a.internetFacing ? <Badge size="xs" tone="warning">Internet-facing</Badge> : <span className="text-fg-subtle">Internal</span>), filter: { kind: "select", options: [{ value: "Internet-facing", label: "Internet-facing" }, { value: "Internal", label: "Internal" }] } },
    { id: "ips", header: "IP addresses", accessor: (a) => a.ipAddresses.join(", "), cell: (a) => <span className="font-mono text-xs">{a.ipAddresses.slice(0, 3).join(", ") || "—"}</span> },
    { id: "os", header: "OS", accessor: (a) => a.os, defaultHidden: true },
    { id: "owner", header: "Owner", accessor: (a) => a.owner, defaultHidden: true },
    { id: "tags", header: "Tags", accessor: (a) => a.tags.join(", "), cell: (a) => <span className="line-clamp-1 max-w-[220px] text-xs text-fg-muted">{a.tags.join(", ") || "—"}</span>, defaultHidden: true },
    ...extraColumns,
    { id: "org", header: "Organization", accessor: (a) => session.organizationName(a.organizationId), defaultHidden: session.organizationId !== null },
    { id: "risk", header: "Risk", accessor: (a) => a.riskScore, cell: (a) => <RiskScore score={a.riskScore} size="sm" explanationHref={hrefForEntity("asset", a.id)} />, align: "right" },
    { id: "lastSeen", header: "Last seen", accessor: (a) => (a.lastSeenAt ? new Date(a.lastSeenAt) : null), cell: (a) => <RelativeTime value={a.lastSeenAt} /> },
  ];

  return (
    <>
      <DataTable
        caption="Assets"
        columns={columns}
        rows={rows}
        getRowId={(a) => a.id}
        loading={assets.isPending}
        error={assets.error}
        onRetry={() => void assets.refetch()}
        onRowClick={(a) => select(a.id)}
        selectedRowId={selected}
        initialState={{ sort: { columnId: "risk", direction: "desc" } }}
        savedViewsKey={savedViewsKey}
        exportFileName="bloody-assets"
        footer={
          assets.hasNextPage ? (
            <Button size="sm" onClick={() => void assets.fetchNextPage()} loading={assets.isFetchingNextPage}>
              Load more
            </Button>
          ) : null
        }
        emptyState={<ConnectEngineEmptyState compact icon={Server} title={emptyTitle} description={description} engines={engines} />}
      />
      {selected ? (
        <Drawer
          open
          onClose={() => select(null)}
          width="xl"
          title={selectedAsset ? (selectedAsset.hostname ?? selectedAsset.name) : "Asset"}
          subtitle={selectedAsset ? humanize(selectedAsset.kind) : undefined}
          headerActions={
            <ButtonLink size="sm" to={hrefForEntity("asset", selected)}>
              Open page
            </ButtonLink>
          }
        >
          <AssetDetailPanel assetId={selected} />
        </Drawer>
      ) : null}
    </>
  );
}
