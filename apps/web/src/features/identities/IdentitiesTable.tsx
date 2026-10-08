import { IdentityKind } from "@bloody/contracts";
import { Fingerprint } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { useIdentities } from "../../api/hooks";
import type { IdentityFilters, IdentityView } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { Drawer } from "../../components/Overlay";
import { RelativeTime } from "../../components/RelativeTime";
import { RiskScore } from "../../components/RiskScore";
import { humanize } from "../../lib/format";
import { IdentityDetailPanel } from "./IdentityDetailPanel";
import { daysInactive, identityName } from "./identityUtils";

/** Identity inventory lens (ISPM, ITDR, CIEM, SSPM) with posture columns and drill-down. */
export function IdentitiesTable({
  filters = {},
  predicate,
  engines = ["keycloak"],
  emptyTitle = "No identities match this view",
  description,
  initialIdentityId = null,
  savedViewsKey,
  dormantDays = 90,
}: {
  filters?: IdentityFilters;
  predicate?: (i: IdentityView) => boolean;
  engines?: string[];
  emptyTitle?: string;
  description?: ReactNode;
  initialIdentityId?: string | null;
  savedViewsKey?: string;
  dormantDays?: number;
}) {
  const session = useSession();
  const identities = useIdentities({ sort: "risk", ...filters });
  const [selected, setSelected] = useState<string | null>(initialIdentityId);
  const rows = useMemo(() => identities.items?.filter((i) => (predicate ? predicate(i) : true)), [identities.items, predicate]);
  const sel = rows?.find((i) => i.id === selected);

  const columns: DataTableColumn<IdentityView>[] = [
    { id: "name", header: "Identity", accessor: (i) => identityName(i), hideable: false, cell: (i) => <span><span className="block font-medium text-heading">{identityName(i)}</span>{i.displayName ? <span className="block font-mono text-2xs text-fg-subtle">{i.principal}</span> : null}</span> },
    { id: "kind", header: "Kind", accessor: (i) => humanize(i.kind), filter: { kind: "select", options: IdentityKind.options.map((k) => ({ value: humanize(k), label: humanize(k) })) } },
    { id: "provider", header: "Provider", accessor: (i) => i.provider, filter: { kind: "text" } },
    { id: "privileged", header: "Privileged", accessor: (i) => (i.privileged ? "Privileged" : "Standard"), cell: (i) => (i.privileged ? <Badge size="xs" tone="warning">Privileged</Badge> : <span className="text-fg-subtle">Standard</span>), filter: { kind: "select", options: [{ value: "Privileged", label: "Privileged" }, { value: "Standard", label: "Standard" }] } },
    { id: "mfa", header: "MFA", accessor: (i) => (i.mfaEnabled ? "Enforced" : "Missing"), cell: (i) => (i.mfaEnabled ? <Badge size="xs" tone="success">Enforced</Badge> : <Badge size="xs" tone="danger">Missing</Badge>), filter: { kind: "select", options: [{ value: "Enforced", label: "Enforced" }, { value: "Missing", label: "Missing" }] } },
    { id: "enabled", header: "State", accessor: (i) => (i.enabled === false ? "Disabled" : "Enabled"), defaultHidden: true },
    {
      id: "activity",
      header: "Last activity",
      accessor: (i) => (i.lastActivityAt ? new Date(i.lastActivityAt) : null),
      cell: (i) => {
        const d = daysInactive(i);
        return (
          <span className={d === null || d >= dormantDays ? "text-sev-high" : undefined} title={d === null ? "No recorded activity" : `${d} days ago`}>
            {i.lastActivityAt ? <RelativeTime value={i.lastActivityAt} /> : "Never"}
          </span>
        );
      },
    },
    { id: "org", header: "Organization", accessor: (i) => session.organizationName(i.organizationId), defaultHidden: session.organizationId !== null },
    { id: "risk", header: "Risk", accessor: (i) => i.riskScore, cell: (i) => <RiskScore score={i.riskScore} size="sm" label="Identity risk" />, align: "right" },
  ];

  return (
    <>
      <DataTable
        caption="Identities"
        columns={columns}
        rows={rows}
        getRowId={(i) => i.id}
        loading={identities.isPending}
        error={identities.error}
        onRetry={() => void identities.refetch()}
        onRowClick={(i) => setSelected(i.id)}
        selectedRowId={selected}
        initialState={{ sort: { columnId: "risk", direction: "desc" } }}
        savedViewsKey={savedViewsKey}
        exportFileName="bloody-identities"
        footer={
          identities.hasNextPage ? (
            <Button size="sm" onClick={() => void identities.fetchNextPage()} loading={identities.isFetchingNextPage}>
              Load more
            </Button>
          ) : null
        }
        emptyState={<ConnectEngineEmptyState compact icon={Fingerprint} title={emptyTitle} description={description ?? "Identities sync from your identity providers (Entra ID, Okta, Active Directory, Google Workspace) and cloud IAM."} engines={engines} />}
      />
      {selected ? (
        <Drawer open onClose={() => setSelected(null)} width="lg" title={sel ? identityName(sel) : "Identity"} subtitle={sel ? `${humanize(sel.kind)} · ${sel.provider}` : undefined}>
          <IdentityDetailPanel identityId={selected} />
        </Drawer>
      ) : null}
    </>
  );
}
