import { AssetKind, Criticality } from "@bloody/contracts";
import { Crown, Earth, Plus, Search, Server, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAssets } from "../../api/hooks";
import type { AssetFilters } from "../../api/types";
import { useSession } from "../../app/session";
import { Button } from "../../components/Button";
import { Checkbox, Input, Select } from "../../components/Form";
import { PageHeader } from "../../components/PageHeader";
import { StatTile } from "../../components/StatTile";
import { AssetEditDialog } from "../../features/assets/AssetEditDialog";
import { AssetsTable } from "../../features/assets/AssetsTable";
import { KpiGrid } from "../../features/modules/ModuleWorkspace";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { humanize } from "../../lib/format";

const KINDS = AssetKind.options;
const CRITS = Criticality.options;

/**
 * /assets — the shared asset inventory (endpoints, servers, cloud, SaaS, external hosts) with the
 * asset drill-down drawer (?id=): explained risk, vulnerabilities, identities with access,
 * attack paths and graph pivot. Filters live in the URL so views are shareable.
 */
export default function AssetsPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const term = useDebouncedValue(q, 300);
  const [adding, setAdding] = useState(false);
  const kind = KINDS.find((k) => k === params.get("kind"));
  const criticality = CRITS.find((c) => c === params.get("criticality"));
  const internet = params.get("internet") === "1";
  const highRisk = params.get("risk") === "high";
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };
  const filters: AssetFilters = useMemo(
    () => ({ ...(term.trim() ? { q: term.trim() } : {}), ...(kind ? { kind: [kind] } : {}), ...(criticality ? { criticality: [criticality] } : {}), ...(internet ? { internetFacing: true } : {}), ...(highRisk ? { minRisk: 70 } : {}) }),
    [term, kind, criticality, internet, highRisk],
  );
  // KPI counts come from dedicated filtered queries (server-side), not from the visible page.
  const crown = useAssets({ criticality: ["crown_jewel"], limit: 500 });
  const exposed = useAssets({ internetFacing: true, limit: 500 });
  const risky = useAssets({ minRisk: 70, limit: 500 });
  // Same key as the unfiltered table query, so the cache is shared.
  const all = useAssets({ sort: "risk" });
  const count = (r: typeof all) => (r.items ? r.items.length : null);
  const more = (r: typeof all) => (r.hasNextPage ? `First ${r.items?.length ?? 0}` : undefined);

  return (
    <div>
      <PageHeader
        title="Assets"
        subtitle="Endpoints, servers, cloud workloads, SaaS and external hosts — with explained risk, exposure and the identities that can reach them."
        actions={
          session.canAnywhere("asset:write") ? (
            <Button variant="primary" icon={Plus} onClick={() => setAdding(true)}>
              Add asset
            </Button>
          ) : null
        }
      />
      <KpiGrid>
        <StatTile label="Assets" value={count(all)} loading={all.isPending} icon={Server} hint={more(all)} href="/assets" />
        <StatTile label="Crown jewels" value={count(crown)} loading={crown.isPending} icon={Crown} tone="brand" hint={more(crown)} href="/assets?criticality=crown_jewel" />
        <StatTile label="Internet-facing" value={count(exposed)} loading={exposed.isPending} icon={Earth} tone="high" hint={more(exposed)} href="/assets?internet=1" />
        <StatTile label="High risk (≥ 70)" value={count(risky)} loading={risky.isPending} icon={ShieldAlert} tone={(count(risky) ?? 0) > 0 ? "critical" : "healthy"} hint={more(risky)} href="/assets?risk=high" />
      </KpiGrid>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <label className="relative w-full max-w-xs">
          <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
          <Input value={q} onChange={(e) => setQ(e.target.value)} onBlur={() => set("q", q.trim() || null)} placeholder="Name, hostname or IP…" className="pl-7" aria-label="Search assets" />
        </label>
        <Select value={kind ?? ""} onChange={(e) => set("kind", e.target.value || null)} className="w-44" aria-label="Kind">
          <option value="">All kinds</option>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {humanize(k)}
            </option>
          ))}
        </Select>
        <Select value={criticality ?? ""} onChange={(e) => set("criticality", e.target.value || null)} className="w-40" aria-label="Criticality">
          <option value="">Any criticality</option>
          {CRITS.map((c) => (
            <option key={c} value={c}>
              {humanize(c)}
            </option>
          ))}
        </Select>
        <Checkbox label="Internet-facing only" checked={internet} onChange={(e) => set("internet", e.target.checked ? "1" : null)} />
        <Checkbox label="High risk only" checked={highRisk} onChange={(e) => set("risk", e.target.checked ? "high" : null)} />
      </div>
      <AssetsTable
        key={JSON.stringify(filters)}
        filters={filters}
        initialAssetId={params.get("id")}
        onSelect={(id) => set("id", id)}
        emptyTitle={Object.keys(filters).length > 0 ? "No assets match these filters" : "No assets in the inventory yet"}
        description="Assets are discovered by endpoint agents, network sensors, cloud and attack-surface scans, or added manually."
        savedViewsKey="assets"
      />
      {adding ? <AssetEditDialog asset={null} onClose={() => setAdding(false)} onSaved={(a) => set("id", a.id)} /> : null}
    </div>
  );
}
