import { PageHeader } from "../../components/PageHeader";
import { RetentionPanel } from "../../features/settings/RetentionPanel";

/** Data & retention: per-organization hot retention within the plan, archive tiers and evidence preservation. */
export default function DataArchivePage() {
  return (
    <div>
      <PageHeader
        title="Data & Retention"
        subtitle="How long normalized events stay searchable per organization, and where raw events, evidence and reports are archived."
        breadcrumbs={[{ label: "Settings", href: "/settings" }, { label: "Data & Retention" }]}
      />
      <RetentionPanel />
    </div>
  );
}
