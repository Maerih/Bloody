import type { Alert } from "@bloody/contracts";
import { ClipboardList } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { Card } from "../../components/Card";
import { ReportMenu } from "../../components/ReportMenu";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { AssetsTable } from "../../features/assets/AssetsTable";
import { EventsLens } from "../../features/events/EventsLens";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { alertDomain } from "../../lib/domains";
import { CloudPostureWidget, ExposureWidget } from "../command-center/widgets";

const CLOUD_ENGINES = ["trivy", "kube_bench"];
const CLOUD_ASSETS = ["cloud_instance", "cloud_storage", "container", "kubernetes_cluster", "data_store"] as const;
const isCloudAlert = (a: Alert) => alertDomain(a) === "cloud";
const label = (e: { labels?: Record<string, string> }, key: string) => e.labels?.[key] ?? null;

/** Misconfiguration lens shared by the dashboard and the findings tab (Trivy IaC / cloud / K8s checks). */
function Misconfigurations({ title = "Misconfigurations", hideTitle = false }: { title?: string; hideTitle?: boolean }) {
  return (
    <EventsLens
      title={title}
      hideTitle={hideTitle}
      query="eventType:trivy.misconfiguration AND outcome:failure"
      preset="cloud"
      engines={CLOUD_ENGINES}
      defaultRange={{ preset: "30d" }}
      description="Failed checks from IaC, cloud-account and cluster scans (Trivy, kube-bench)."
      aggregations={[
        { title: "Failed checks", field: "detection.ruleName", value: (e) => e.detection?.ruleName ?? label(e, "misconfig.id") },
        { title: "Check types", field: "labels.misconfig.type", value: (e) => label(e, "misconfig.type") },
        { title: "Resources", field: "cloudResource.resourceId", value: (e) => e.cloudResource?.resourceId ?? label(e, "artifact.name") },
      ]}
    />
  );
}

/** CSPM workspace: cloud posture, accounts, misconfigurations, public exposure, benchmarks, workloads. */
export default function CspmPage() {
  const [params] = useSearchParams();
  return (
    <ModuleWorkspace
      moduleId="cspm"
      sections={{
        "": () => (
          <div className="space-y-4">
            <SummaryWidgets widgets={[CloudPostureWidget, ExposureWidget]} columns={2} />
            <AlertsLens title="Cloud detections" predicate={isCloudAlert} engines={["trivy", "falco"]} emptyTitle="No cloud detections" description="Detections from cloud audit logs (CloudTrail and equivalents), runtime sensors and posture scans." savedViewsKey="cspm-alerts" />
            <Misconfigurations />
          </div>
        ),
        accounts: () => (
          <div className="space-y-4">
            <Card title="Cloud connections" padded={false} info="Cloud accounts are connected through audit-log ingestion (e.g. CloudTrail → /ingest/aws_cloudtrail) and scanner integrations; credentials are stored in the secret store.">
              <IntegrationStatusList engines={CLOUD_ENGINES} />
            </Card>
            <EventsLens
              title="Cloud accounts & regions seen in audit logs"
              query="category:cloud"
              preset="cloud"
              engines={CLOUD_ENGINES}
              defaultRange={{ preset: "7d" }}
              aggregations={[
                { title: "Accounts", field: "cloudResource.accountId", value: (e) => (e.cloudResource ? `${e.cloudResource.provider}:${e.cloudResource.accountId ?? "?"}` : null) },
                { title: "Regions", field: "cloudResource.region", value: (e) => e.cloudResource?.region },
                { title: "API actions", field: "cloudResource.action", value: (e) => e.cloudResource?.action },
              ]}
            />
          </div>
        ),
        findings: () => <Misconfigurations hideTitle />,
        exposure: () => (
          <div className="space-y-4">
            <AssetsTable filters={{ kind: [...CLOUD_ASSETS], internetFacing: true }} engines={CLOUD_ENGINES} emptyTitle="No publicly exposed cloud resources" description="Public storage buckets, instances with open security groups and internet-reachable data stores." savedViewsKey="cspm-exposure" />
            <EventsLens
              title="Changes that widened exposure"
              query="category:cloud AND cloudResource.action:(PutBucketPolicy OR PutBucketAcl OR AuthorizeSecurityGroupIngress OR ModifyDBInstance OR PutPublicAccessBlock OR DeletePublicAccessBlock)"
              preset="cloud"
              engines={["trivy"]}
              defaultRange={{ preset: "30d" }}
            />
          </div>
        ),
        compliance: () => (
          <div className="space-y-4">
            <Card
              title="Compliance posture report"
              actions={<ClipboardList size={14} className="text-fg-muted" aria-hidden />}
              info="Benchmarks are evaluated from scanner results (CIS via kube-bench, Trivy cloud / IaC checks); the report maps failed checks to controls."
            >
              <div className="flex flex-wrap items-center gap-3">
                <p className="min-w-0 flex-1 text-sm text-fg-muted">Generate the compliance posture report for auditors and executives, or schedule it by email.</p>
                <ReportMenu reports={["compliance"]} defaultReport="compliance" />
              </div>
            </Card>
            <EventsLens
              title="Benchmark checks"
              query="eventType:trivy.misconfiguration"
              preset="cloud"
              engines={CLOUD_ENGINES}
              defaultRange={{ preset: "30d" }}
              aggregations={[
                { title: "Failing checks", field: "detection.ruleId", value: (e) => (e.outcome === "failure" ? (e.detection?.ruleId ?? label(e, "misconfig.id")) : null) },
                { title: "Passing checks", field: "detection.ruleId", value: (e) => (e.outcome === "success" ? (e.detection?.ruleId ?? label(e, "misconfig.id")) : null) },
              ]}
            />
          </div>
        ),
        workloads: () => <AssetsTable filters={{ kind: [...CLOUD_ASSETS] }} initialAssetId={params.get("id")} engines={CLOUD_ENGINES} emptyTitle="No cloud workloads in the inventory" savedViewsKey="cspm-workloads" />,
      }}
    />
  );
}
