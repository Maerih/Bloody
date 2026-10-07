import { useParams } from "react-router-dom";
import { useIncident } from "../../api/hooks";
import { PageHeader } from "../../components/PageHeader";
import { IncidentDetailPanel } from "./IncidentDetailPanel";

/** /incidents/:id — full-page incident view (same panel as the drawer, deep-linkable). */
export default function IncidentDetailPage() {
  const { id = "" } = useParams();
  const incident = useIncident(id);
  const title = incident.data ? `#${incident.data.number} ${incident.data.title}` : "Incident";
  return (
    <div>
      <PageHeader title={title} breadcrumbs={[{ label: "Incidents", href: "/incidents" }, { label: incident.data ? `#${incident.data.number}` : "…" }]} />
      <div className="max-w-5xl rounded border border-line bg-surface shadow-card">
        <IncidentDetailPanel incidentId={id} />
      </div>
    </div>
  );
}
