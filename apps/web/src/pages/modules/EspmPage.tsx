import type { Asset } from "@bloody/contracts";
import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAttackPaths } from "../../api/hooks";
import type { DataTableColumn } from "../../components/DataTable";
import { AssetsTable } from "../../features/assets/AssetsTable";
import { AttackPathsView } from "../../features/attackPaths/AttackPathsView";
import { ExposureBreakdown } from "../../features/exposure/ExposureBreakdown";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { VulnerabilitiesTable } from "../../features/vulns/VulnerabilitiesTable";
import { pathsTouchingAsset } from "../../lib/attackPaths";
import { AttackPathsWidget, VulnerabilitiesWidget } from "../command-center/widgets";

function CrownJewels() {
  const paths = useAttackPaths({});
  const columns = useMemo<DataTableColumn<Asset>[]>(
    () => [
      {
        id: "paths",
        header: "Attack paths",
        align: "right",
        accessor: (a) => (paths.data ? pathsTouchingAsset(paths.data.paths, a.id).length : null),
        cell: (a) => {
          if (!paths.data) return <span className="text-fg-subtle">…</span>;
          const n = pathsTouchingAsset(paths.data.paths, a.id).length;
          return n > 0 ? (
            <Link to={`/attack-paths?target=${encodeURIComponent(paths.data.paths.find((p) => pathsTouchingAsset([p], a.id).length > 0)?.target.id ?? "")}`} className="font-semibold text-sev-critical hover:underline" onClick={(e) => e.stopPropagation()}>
              {n}
            </Link>
          ) : (
            <span className="text-healthy">0</span>
          );
        },
      },
    ],
    [paths.data],
  );
  return (
    <AssetsTable
      filters={{ criticality: ["crown_jewel"] }}
      extraColumns={columns}
      emptyTitle="No crown jewels designated"
      description="Mark business-critical assets (domain controllers, customer databases, payment systems) as crown jewels so attack paths and exposure prioritize them."
      savedViewsKey="espm-crown-jewels"
    />
  );
}

/** ESPM workspace: unified explained exposure, attack paths, crown jewels, findings, remediation plan. */
export default function EspmPage() {
  const [params] = useSearchParams();
  const crownOnly = params.get("target") === "crown_jewel";
  return (
    <ModuleWorkspace
      moduleId="espm"
      sections={{
        "": () => (
          <div className="space-y-4">
            <ExposureBreakdown />
            <SummaryWidgets widgets={[AttackPathsWidget, VulnerabilitiesWidget]} columns={2} />
          </div>
        ),
        "attack-paths": () => <AttackPathsView initialCrownOnly={crownOnly} />,
        "crown-jewels": () => <CrownJewels />,
        findings: () => <VulnerabilitiesTable filters={{ status: ["open", "in_remediation"] }} emptyTitle="No open exposure findings" savedViewsKey="espm-findings" />,
        remediation: () => <AttackPathsView focus="remediation" />,
      }}
    />
  );
}
