import type { Alert } from "@bloody/contracts";
import { Crown, KeyRound, ShieldOff, UserCog, UserX } from "lucide-react";
import { useMemo } from "react";
import { useIdentities } from "../../api/hooks";
import type { IdentityView } from "../../api/types";
import { StatTile } from "../../components/StatTile";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { EventsLens } from "../../features/events/EventsLens";
import { IdentitiesTable } from "../../features/identities/IdentitiesTable";
import { isDormant, NON_HUMAN_KINDS } from "../../features/identities/identityUtils";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { hasTechnique } from "../../lib/classify";

/** Cloud identity providers (IAM, Entra ID, GCP IAM). Matching is on the provider name the source reports. */
export const CLOUD_PROVIDER_RE = /\b(aws|amazon|iam|azure|entra|gcp|google[\s_-]?cloud)\b/i;
export const isCloudIdentity = (i: Pick<IdentityView, "provider">) => CLOUD_PROVIDER_RE.test(i.provider);

const ENGINES = ["keycloak"];
const IAM_POLICY_ACTIONS = "eventType:(aws.iam.AttachUserPolicy OR aws.iam.AttachRolePolicy OR aws.iam.AttachGroupPolicy OR aws.iam.PutUserPolicy OR aws.iam.PutRolePolicy OR aws.iam.PutGroupPolicy OR aws.iam.CreatePolicyVersion OR aws.iam.CreateAccessKey)";
const TRUST_ACTIONS = "eventType:(aws.iam.UpdateAssumeRolePolicy OR aws.iam.CreateRole OR aws.sts.AssumeRole)";

const isCloudIdentityAlert = (a: Alert) => /cloudtrail|aws|azure|gcp|iam/i.test(`${a.source} ${a.ruleId ?? ""}`) && (a.identityId !== null || hasTechnique(a, ["T1098", "T1078.004", "T1556.006", "T1136.003"]));

function CiemOverview() {
  const identities = useIdentities({ limit: 500 });
  const cloud = useMemo(() => identities.items?.filter(isCloudIdentity), [identities.items]);
  const loading = identities.isPending;
  const n = (pred: (i: IdentityView) => boolean) => (cloud ? cloud.filter(pred).length : null);
  return (
    <div className="space-y-4">
      <KpiGrid>
        <StatTile label="Cloud identities" value={cloud?.length} loading={loading} icon={UserCog} href="/ciem/identities" hint={identities.hasNextPage ? "First page of identities" : undefined} />
        <StatTile label="Privileged" value={n((i) => i.privileged)} loading={loading} icon={Crown} href="/ciem/permissions" />
        <StatTile label="Privileged without MFA" value={n((i) => i.privileged && !i.mfaEnabled && !NON_HUMAN_KINDS.includes(i.kind))} loading={loading} icon={ShieldOff} tone={(n((i) => i.privileged && !i.mfaEnabled && !NON_HUMAN_KINDS.includes(i.kind)) ?? 0) > 0 ? "critical" : "healthy"} />
        <StatTile label="Machine identities & keys" value={n((i) => NON_HUMAN_KINDS.includes(i.kind))} loading={loading} icon={KeyRound} href="/ciem/identities" />
        <StatTile label="Dormant (90 days)" value={n((i) => isDormant(i, 90))} loading={loading} icon={UserX} tone={(n((i) => isDormant(i, 90) && i.privileged) ?? 0) > 0 ? "high" : "default"} href="/ciem/reviews" />
      </KpiGrid>
      <AlertsLens title="Cloud identity detections" predicate={isCloudIdentityAlert} engines={ENGINES} emptyTitle="No cloud identity detections" description="IAM policy attachment, access-key creation, MFA removal and trust-policy changes detected from cloud audit logs." savedViewsKey="ciem-alerts" />
      <IdentitiesTable predicate={isCloudIdentity} engines={ENGINES} emptyTitle="No cloud identities synced" description="Cloud IAM users, roles, service principals and access keys appear once cloud audit logs or identity sources are connected." savedViewsKey="ciem-overview" />
    </div>
  );
}

/** CIEM workspace: cloud identities, excessive permissions, cross-account trust and access reviews. */
export default function CiemPage() {
  return (
    <ModuleWorkspace
      moduleId="ciem"
      sections={{
        "": () => <CiemOverview />,
        identities: () => <IdentitiesTable predicate={isCloudIdentity} engines={ENGINES} emptyTitle="No cloud identities synced" savedViewsKey="ciem-identities" />,
        permissions: () => (
          <div className="space-y-4">
            <div>
              <h2 className="mb-2 text-md font-semibold text-fg">Privileged cloud identities</h2>
              <IdentitiesTable filters={{ privileged: true }} predicate={isCloudIdentity} engines={ENGINES} emptyTitle="No privileged cloud identities" savedViewsKey="ciem-privileged" />
            </div>
            <EventsLens
              title="Permission grants"
              query={IAM_POLICY_ACTIONS}
              preset="cloud"
              engines={["trivy"]}
              defaultRange={{ preset: "30d" }}
              description="Policy attachments, inline policies and access keys granted through the cloud control plane."
              aggregations={[
                { title: "Granted by", field: "identity.principal", value: (e) => e.identity?.principal ?? e.user?.name },
                { title: "Actions", field: "eventType", value: (e) => e.eventType },
              ]}
            />
          </div>
        ),
        trust: () => (
          <EventsLens
            title="Cross-account trust & role assumption"
            query={TRUST_ACTIONS}
            preset="cloud"
            engines={["trivy"]}
            defaultRange={{ preset: "30d" }}
            description="Trust-policy changes and role assumptions across accounts — the paths an attacker uses to pivot between cloud accounts."
            aggregations={[
              { title: "Accounts", field: "cloudResource.accountId", value: (e) => e.cloudResource?.accountId },
              { title: "Principals", field: "identity.principal", value: (e) => e.identity?.principal },
              { title: "Source IPs", field: "identity.sourceIp", value: (e) => e.identity?.sourceIp },
            ]}
          />
        ),
        reviews: () => (
          <div className="space-y-2">
            <p className="text-sm text-fg-muted">Access review candidates: privileged or machine cloud identities with no activity in 90 days. Disabling an identity is a high-risk response action and goes through the approval gate.</p>
            <IdentitiesTable
              predicate={(i: IdentityView) => isCloudIdentity(i) && isDormant(i, 90) && (i.privileged || NON_HUMAN_KINDS.includes(i.kind))}
              engines={ENGINES}
              emptyTitle="No stale privileged cloud identities"
              savedViewsKey="ciem-reviews"
            />
          </div>
        ),
      }}
    />
  );
}
