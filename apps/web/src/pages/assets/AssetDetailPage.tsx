import { Pencil } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { useAsset } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Button, ButtonLink } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { PageHeader } from "../../components/PageHeader";
import { CardSkeleton } from "../../components/Skeleton";
import { AssetDetailPanel } from "../../features/assets/AssetDetailPanel";
import { AssetEditDialog } from "../../features/assets/AssetEditDialog";
import { humanize } from "../../lib/format";

/** /assets/:id — full-page asset drill-down (same panel as the inventory drawer) with editing. */
export default function AssetDetailPage() {
  const { id = "" } = useParams();
  const session = useSession();
  const asset = useAsset(id);
  const [editing, setEditing] = useState(false);
  if (asset.isPending) return <CardSkeleton rows={8} />;
  if (asset.isError) {
    return (
      <div className="rounded border border-line bg-surface shadow-card">
        {asset.error.isNotFound ? (
          <EmptyState title="Asset not found" description="It may belong to an organization you can't access, or it was removed from the inventory." action={<ButtonLink to="/assets" size="sm">All assets</ButtonLink>} />
        ) : (
          <ErrorState error={asset.error} onRetry={() => void asset.refetch()} />
        )}
      </div>
    );
  }
  const a = asset.data;
  return (
    <div>
      <PageHeader
        title={a.hostname ?? a.name}
        subtitle={`${humanize(a.kind)} · ${session.organizationName(a.organizationId) ?? "Organization"}${a.owner ? ` · owned by ${a.owner}` : ""}`}
        breadcrumbs={[{ label: "Assets", href: "/assets" }, { label: a.hostname ?? a.name }]}
        actions={
          session.can("asset:write", a.organizationId) ? (
            <Button icon={Pencil} onClick={() => setEditing(true)}>
              Edit asset
            </Button>
          ) : null
        }
      />
      <div className="rounded border border-line bg-surface shadow-card">
        <AssetDetailPanel assetId={a.id} />
      </div>
      {editing ? <AssetEditDialog asset={a} onClose={() => setEditing(false)} /> : null}
    </div>
  );
}
