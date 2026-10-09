import type { Alert } from "@bloody/contracts";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { AssetsTable } from "../../features/assets/AssetsTable";
import { EventsLens } from "../../features/events/EventsLens";
import { IdentitiesTable } from "../../features/identities/IdentitiesTable";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { IDENTITY_DETECTIONS, matchCategory } from "../../lib/classify";

const SAAS_ENGINES = ["keycloak"];
const isSaasAlert = (a: Alert) => /saas|m365|office|workspace|salesforce|github|slack|okta|oauth/i.test(`${a.source} ${a.ruleId ?? ""} ${a.title}`);
const isOauthAbuse = (a: Alert) => matchCategory(a, IDENTITY_DETECTIONS)?.category.key === "oauth_abuse";

/** SSPM workspace: SaaS applications, misconfigurations, third-party OAuth apps and data sharing. */
export default function SspmPage() {
  return (
    <ModuleWorkspace
      moduleId="sspm"
      sections={{
        "": () => (
          <div className="space-y-4">
            <AlertsLens title="SaaS detections" predicate={isSaasAlert} engines={SAAS_ENGINES} emptyTitle="No SaaS detections" description="Detections from SaaS audit logs: risky configuration changes, external sharing, suspicious OAuth consent." savedViewsKey="sspm-alerts" />
            <div>
              <h2 className="mb-2 text-md font-semibold text-fg">SaaS applications</h2>
              <AssetsTable filters={{ kind: ["saas_app"] }} engines={SAAS_ENGINES} emptyTitle="No SaaS applications in the inventory" description="Sanctioned SaaS tenants (Microsoft 365, Google Workspace, Salesforce, GitHub…) appear when their audit logs are connected or they are added to the inventory." savedViewsKey="sspm-apps-overview" />
            </div>
          </div>
        ),
        apps: () => <AssetsTable filters={{ kind: ["saas_app"] }} engines={SAAS_ENGINES} emptyTitle="No SaaS applications in the inventory" savedViewsKey="sspm-apps" />,
        findings: () => (
          <EventsLens
            title="SaaS configuration changes"
            query="category:saas AND severity:(low OR medium OR high OR critical)"
            engines={SAAS_ENGINES}
            defaultRange={{ preset: "30d" }}
            description="Security-relevant SaaS setting changes (MFA policy, admin roles, external access, retention) reported by SaaS audit logs."
            aggregations={[
              { title: "Applications", field: "source.product", value: (e) => e.source.product },
              { title: "Changes", field: "action", value: (e) => e.action ?? e.eventType },
              { title: "Changed by", field: "user.email", value: (e) => e.user?.email ?? e.identity?.principal },
            ]}
          />
        ),
        oauth: () => (
          <div className="space-y-4">
            <AlertsLens title="Suspicious OAuth consent" predicate={isOauthAbuse} categories={IDENTITY_DETECTIONS} engines={SAAS_ENGINES} emptyTitle="No suspicious OAuth consent" savedViewsKey="sspm-oauth-alerts" />
            <div>
              <h2 className="mb-2 text-md font-semibold text-fg">Third-party applications & service principals</h2>
              <IdentitiesTable filters={{ kind: ["service_principal"] }} engines={SAAS_ENGINES} emptyTitle="No third-party applications" savedViewsKey="sspm-oauth-apps" />
            </div>
          </div>
        ),
        sharing: () => (
          <EventsLens
            title="External sharing"
            query="category:saas AND action:*share*"
            engines={SAAS_ENGINES}
            defaultRange={{ preset: "30d" }}
            description="Files, folders and sites shared outside the organization or made public."
            aggregations={[
              { title: "Shared by", field: "user.email", value: (e) => e.user?.email ?? e.identity?.principal },
              { title: "Applications", field: "source.product", value: (e) => e.source.product },
              { title: "Recipients", field: "labels.share.target", value: (e) => e.labels?.["share.target"] ?? e.labels?.["target_user"] ?? null },
            ]}
          />
        ),
      }}
    />
  );
}
