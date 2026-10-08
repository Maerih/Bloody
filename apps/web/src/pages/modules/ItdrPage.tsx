import type { Alert } from "@bloody/contracts";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { useIdentities } from "../../api/hooks";
import { Card } from "../../components/Card";
import { TopList, countBy } from "../../components/TopList";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { CategorySummary } from "../../features/alerts/CategorySummary";
import { EventsLens } from "../../features/events/EventsLens";
import { IdentitiesTable } from "../../features/identities/IdentitiesTable";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { IDENTITY_DETECTIONS, matchCategory } from "../../lib/classify";
import { IdentityRiskWidget } from "../command-center/widgets";

const IDENTITY_ENGINES = ["keycloak", "wazuh"];
const isIdentityAlert = (a: Alert) => a.identityId !== null || matchCategory(a, IDENTITY_DETECTIONS) !== null;

function useCategoryParam(): [string | null, (k: string | null) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get("category");
  const set = useCallback(
    (k: string | null) => {
      const next = new URLSearchParams(params);
      if (k) next.set("category", k);
      else next.delete("category");
      setParams(next, { replace: true });
    },
    [params, setParams],
  );
  return [IDENTITY_DETECTIONS.some((c) => c.key === value) ? value : null, set];
}

function Detections({ withIdentities = false }: { withIdentities?: boolean }) {
  const [category, setCategory] = useCategoryParam();
  const predicate = useMemo(() => (category ? (a: Alert) => matchCategory(a, IDENTITY_DETECTIONS)?.category.key === category : isIdentityAlert), [category]);
  const label = IDENTITY_DETECTIONS.find((c) => c.key === category)?.label;
  return (
    <div className="space-y-4">
      <CategorySummary categories={IDENTITY_DETECTIONS} predicate={isIdentityAlert} selected={category} onSelect={setCategory} />
      <AlertsLens
        title={label ? `${label} detections` : "Identity detections"}
        predicate={predicate}
        categories={IDENTITY_DETECTIONS}
        engines={IDENTITY_ENGINES}
        emptyTitle={label ? `No ${label.toLowerCase()} detections` : "No identity detections"}
        description="Identity threats are detected from IdP, directory and VPN authentication events (impossible travel, MFA fatigue, password spraying, token theft, privilege escalation)."
        savedViewsKey="itdr-detections"
      />
      {withIdentities ? (
        <div>
          <h2 className="mb-2 text-md font-semibold text-fg">Identities by risk</h2>
          <IdentitiesTable engines={IDENTITY_ENGINES} savedViewsKey="itdr-identities" />
        </div>
      ) : null}
    </div>
  );
}

function IdentitySources() {
  const identities = useIdentities({ limit: 500 });
  const providers = useMemo(() => countBy(identities.items ?? [], (i) => i.provider), [identities.items]);
  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_360px]">
      <Card title="Identity source connections" padded={false} info="Directory, IdP and VPN sources feeding identity telemetry and inventory.">
        <IntegrationStatusList engines={["keycloak", "wazuh", "copilot"]} />
      </Card>
      <Card title="Identities by provider" info="Providers seen in the identity inventory (loaded page).">
        <TopList items={providers} emptyText="No identities synced yet." ariaLabel="Identities by provider" />
      </Card>
    </div>
  );
}

/** ITDR workspace: identity detections by category, risky sign-ins, token abuse, OAuth, sources. */
export default function ItdrPage() {
  return (
    <ModuleWorkspace
      moduleId="itdr"
      sections={{
        "": () => (
          <div className="space-y-4">
            <SummaryWidgets widgets={[IdentityRiskWidget]} columns={2} />
            <Detections withIdentities />
          </div>
        ),
        detections: () => <Detections />,
        "sign-ins": () => (
          <EventsLens
            title="Sign-ins"
            query="category:authentication"
            preset="auth"
            engines={IDENTITY_ENGINES}
            aggregations={[
              { title: "Countries", field: "identity.geo.country", value: (e) => e.identity?.geo?.country },
              { title: "Source IPs", field: "identity.sourceIp", value: (e) => e.identity?.sourceIp },
              { title: "Failed sign-ins by principal", field: "identity.principal", value: (e) => ((e.outcome ?? e.identity?.outcome) === "failure" ? (e.identity?.principal ?? e.user?.name) : null) },
            ]}
          />
        ),
        sessions: () => (
          <div className="space-y-4">
            <AlertsLens title="Token, session & MFA abuse" predicate={(a) => ["token_theft", "mfa_manipulation"].includes(matchCategory(a, IDENTITY_DETECTIONS)?.category.key ?? "")} categories={IDENTITY_DETECTIONS} engines={IDENTITY_ENGINES} emptyTitle="No token or MFA abuse detected" savedViewsKey="itdr-sessions" />
            <EventsLens title="Token & session events" query="category:authentication AND eventType:*token*" preset="auth" engines={["keycloak"]} defaultRange={{ preset: "7d" }} />
          </div>
        ),
        "oauth-apps": () => (
          <div className="space-y-4">
            <AlertsLens title="OAuth abuse" predicate={(a) => matchCategory(a, IDENTITY_DETECTIONS)?.category.key === "oauth_abuse"} categories={IDENTITY_DETECTIONS} engines={IDENTITY_ENGINES} emptyTitle="No suspicious OAuth consent" savedViewsKey="itdr-oauth" />
            <div>
              <h2 className="mb-2 text-md font-semibold text-fg">Applications & service principals</h2>
              <IdentitiesTable filters={{ kind: ["service_principal"] }} emptyTitle="No OAuth applications or service principals" savedViewsKey="itdr-apps" />
            </div>
          </div>
        ),
        sources: () => <IdentitySources />,
      }}
    />
  );
}
