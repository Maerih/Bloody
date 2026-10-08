import { useSearchParams } from "react-router-dom";
import { PageHeader } from "../../components/PageHeader";
import { ReportMenu } from "../../components/ReportMenu";
import { AttackPathsView } from "../../features/attackPaths/AttackPathsView";

/** /attack-paths — explainable attack paths and remediation priorities (ESPM lens). */
export default function AttackPathsPage() {
  const [params] = useSearchParams();
  const targetParam = params.get("target");
  const crownOnly = targetParam === "crown_jewel";
  const target = targetParam && !crownOnly ? targetParam : undefined;
  return (
    <div>
      <PageHeader
        title="Attack Paths"
        subtitle="Exploitable routes from entry points to your crown jewels, ranked by explained risk — and the fixes that break the most of them."
        breadcrumbs={[{ label: "Exposure", href: "/espm" }, { label: "Attack Paths" }]}
        actions={<ReportMenu reports={["vulnerability", "executive"]} defaultReport="vulnerability" />}
      />
      <AttackPathsView {...(target ? { targetId: target } : {})} initialCrownOnly={crownOnly} />
    </div>
  );
}
