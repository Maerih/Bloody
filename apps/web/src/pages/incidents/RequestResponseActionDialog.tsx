import type { IncidentDetail } from "../../api/types";
import { RequestActionDialog } from "../../features/response/RequestActionDialog";

/**
 * Request a SOAR response action scoped to an incident (targets: the incident's assets,
 * identities or the incident itself). High-risk actions are queued for approval.
 */
export function RequestResponseActionDialog({ incident, open, onClose }: { incident: IncidentDetail; open: boolean; onClose: () => void }) {
  return (
    <RequestActionDialog
      open={open}
      onClose={onClose}
      organizationId={incident.organizationId}
      incidentId={incident.id}
      defaultAction="collect_evidence"
      description={`Incident #${incident.number} · requests are audited and attributed to you.`}
      targets={{
        asset: incident.assets?.map((a) => ({ id: a.id, label: a.hostname ?? a.name })) ?? incident.assetIds.map((id) => ({ id })),
        identity: incident.identities?.map((i) => ({ id: i.id, label: i.displayName ?? i.principal })) ?? incident.identityIds.map((id) => ({ id })),
        incident: [{ id: incident.id, label: `#${incident.number} ${incident.title}` }],
      }}
    />
  );
}
