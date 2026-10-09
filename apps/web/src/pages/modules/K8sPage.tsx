import type { Alert } from "@bloody/contracts";
import { Boxes, Container, ShieldAlert } from "lucide-react";
import { useMemo } from "react";
import { useAssets } from "../../api/hooks";
import { ButtonLink } from "../../components/Button";
import { Card } from "../../components/Card";
import { StatTile } from "../../components/StatTile";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { AssetsTable } from "../../features/assets/AssetsTable";
import { EventsLens } from "../../features/events/EventsLens";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";

const K8S_ENGINES = ["falco", "trivy", "kube_bench"];
const isRuntimeAlert = (a: Alert) => /falco|k8s|kubernetes|container/i.test(`${a.source} ${a.ruleId ?? ""}`);
const label = (e: { labels?: Record<string, string> }, key: string) => e.labels?.[key] ?? null;

function ContainerOverview() {
  const assets = useAssets({ kind: ["kubernetes_cluster", "container"], limit: 500 });
  const counts = useMemo(() => {
    const items = assets.items ?? [];
    return { clusters: items.filter((a) => a.kind === "kubernetes_cluster").length, containers: items.filter((a) => a.kind === "container").length };
  }, [assets.items]);
  return (
    <div className="space-y-4">
      <KpiGrid>
        <StatTile label="Clusters" value={assets.items ? counts.clusters : null} loading={assets.isPending} icon={Boxes} href="/k8s/clusters" />
        <StatTile label="Container workloads" value={assets.items ? counts.containers : null} loading={assets.isPending} icon={Container} href="/k8s/clusters" />
      </KpiGrid>
      <AlertsLens title="Runtime detections" predicate={isRuntimeAlert} engines={["falco"]} emptyTitle="No container runtime detections" description="Falco detects shells in containers, privilege escalation, sensitive mounts and Kubernetes API abuse." savedViewsKey="k8s-alerts" />
      <Card title="Sensors & scanners" padded={false}>
        <IntegrationStatusList engines={K8S_ENGINES} />
      </Card>
    </div>
  );
}

/** Container & Kubernetes workspace: clusters, image vulnerabilities, runtime detections, posture. */
export default function K8sPage() {
  return (
    <ModuleWorkspace
      moduleId="k8s"
      sections={{
        "": () => <ContainerOverview />,
        clusters: () => <AssetsTable filters={{ kind: ["kubernetes_cluster", "container"] }} engines={K8S_ENGINES} emptyTitle="No clusters or container workloads in the inventory" savedViewsKey="k8s-clusters" />,
        images: () => (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <p className="min-w-0 flex-1 text-sm text-fg-muted">Vulnerable packages in container images from registry and cluster scans (Trivy, Grype). Findings on inventoried workloads are prioritized in Vulnerability Management.</p>
              <ButtonLink size="sm" icon={ShieldAlert} to="/vm/vulnerabilities">
                Prioritized vulnerabilities
              </ButtonLink>
            </div>
            <EventsLens
              title="Image vulnerabilities"
              hideTitle
              query="eventType:trivy.vulnerability"
              engines={["trivy", "grype"]}
              defaultRange={{ preset: "30d" }}
              aggregations={[
                { title: "Images", field: "labels.artifact.name", value: (e) => label(e, "artifact.name") },
                { title: "Vulnerable packages", field: "labels.pkg.name", value: (e) => (label(e, "pkg.name") ? `${label(e, "pkg.name")}@${label(e, "pkg.installed_version") ?? "?"}` : null) },
                { title: "CVEs", field: "labels.vuln.id", value: (e) => label(e, "vuln.id") },
              ]}
            />
          </div>
        ),
        runtime: () => (
          <div className="space-y-4">
            <AlertsLens title="Runtime detections" predicate={isRuntimeAlert} engines={["falco"]} emptyTitle="No container runtime detections" savedViewsKey="k8s-runtime" />
            <EventsLens
              title="Runtime events"
              query="source.product:falco"
              engines={["falco"]}
              aggregations={[
                { title: "Rules", field: "detection.ruleName", value: (e) => e.detection?.ruleName },
                { title: "Namespaces", field: "labels.k8s.namespace", value: (e) => label(e, "k8s.namespace") },
                { title: "Images", field: "labels.container.image", value: (e) => label(e, "container.image") },
              ]}
            />
          </div>
        ),
        posture: () => (
          <EventsLens
            title="Kubernetes posture checks"
            query="eventType:trivy.misconfiguration AND cloudResource.provider:kubernetes"
            preset="cloud"
            engines={["kube_bench", "trivy"]}
            defaultRange={{ preset: "30d" }}
            description="CIS benchmark and workload misconfiguration checks for clusters (kube-bench, Trivy k8s)."
            aggregations={[
              { title: "Failing checks", field: "detection.ruleName", value: (e) => (e.outcome === "failure" ? (e.detection?.ruleName ?? label(e, "misconfig.id")) : null) },
              { title: "Resources", field: "cloudResource.resourceId", value: (e) => e.cloudResource?.resourceId },
              { title: "Clusters", field: "cloudResource.accountId", value: (e) => e.cloudResource?.accountId },
            ]}
          />
        ),
      }}
    />
  );
}
