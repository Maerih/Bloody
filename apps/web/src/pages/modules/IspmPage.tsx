import { Crown, Fingerprint, KeyRound, ShieldOff, UserCog, UserX } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useIdentities } from "../../api/hooks";
import type { IdentityView } from "../../api/types";
import { SeverityBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { Select } from "../../components/Form";
import { Meter } from "../../components/Meter";
import { SkeletonText } from "../../components/Skeleton";
import { StatTile } from "../../components/StatTile";
import { IdentitiesTable } from "../../features/identities/IdentitiesTable";
import { isDormant, NON_HUMAN_KINDS } from "../../features/identities/identityUtils";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { formatInteger, formatPercent } from "../../lib/format";
import { computePosture, identityRecommendations, type IdentityPosture } from "../../lib/identityPosture";
import { IdentityRiskWidget } from "../command-center/widgets";

const ENGINES = ["keycloak", "wazuh"];
const DORMANCY = [30, 60, 90, 180, 365];

function usePosture(dormantDays: number) {
  const identities = useIdentities({ limit: 500 });
  const posture = useMemo(() => (identities.items ? computePosture(identities.items, dormantDays) : null), [identities.items, dormantDays]);
  return { identities, posture };
}

function SampleNote({ loaded, more, onMore, loading }: { loaded: number; more: boolean; onMore: () => void; loading: boolean }) {
  if (!more) return null;
  return (
    <p className="-mt-2 mb-3 flex items-center gap-2 text-xs text-fg-muted">
      Computed from the first {formatInteger(loaded)} identities.
      <Button size="xs" onClick={onMore} loading={loading}>
        Load more
      </Button>
    </p>
  );
}

function PostureKpis({ posture, loading }: { posture: IdentityPosture | null; loading: boolean }) {
  return (
    <KpiGrid>
      <StatTile label="Identities" value={posture?.total} loading={loading} icon={Fingerprint} href="/ispm/identities" />
      <StatTile label="Privileged" value={posture?.privileged} loading={loading} icon={Crown} href="/ispm/privileged" />
      <StatTile label="Privileged without MFA" value={posture?.privilegedWithoutMfa} loading={loading} icon={ShieldOff} tone={(posture?.privilegedWithoutMfa ?? 0) > 0 ? "critical" : "healthy"} href="/ispm/mfa?privileged=1" />
      <StatTile label="MFA coverage" value={posture?.mfaCoverage === null || posture?.mfaCoverage === undefined ? null : Math.round(posture.mfaCoverage * 100)} format={(v) => (v === null || v === undefined ? "—" : `${v}%`)} loading={loading} icon={KeyRound} tone={(posture?.mfaCoverage ?? 1) < 0.9 ? "high" : "healthy"} href="/ispm/mfa" />
      <StatTile label="Dormant" value={posture?.dormant} loading={loading} icon={UserX} tone={(posture?.dormantPrivileged ?? 0) > 0 ? "high" : "default"} href="/ispm/dormant" hint={posture && posture.dormantPrivileged > 0 ? `${posture.dormantPrivileged} privileged` : undefined} />
      <StatTile label="Risky service accounts" value={posture?.riskyNonHuman} loading={loading} icon={UserCog} tone={(posture?.riskyNonHuman ?? 0) > 0 ? "high" : "default"} href="/ispm/service-accounts?risky=1" />
    </KpiGrid>
  );
}

function Recommendations({ posture, dormantDays }: { posture: IdentityPosture | null; dormantDays: number }) {
  if (!posture) return <SkeletonText lines={4} />;
  const recs = identityRecommendations(posture, dormantDays);
  if (recs.length === 0) return <EmptyState compact tone="success" title="No identity posture issues found" description="Privileged identities have MFA, nothing is dormant and service accounts are not over-privileged." />;
  return (
    <ol className="divide-y divide-line" aria-label="Identity recommendations">
      {recs.map((r) => (
        <li key={r.key} className="flex items-start gap-2 py-2">
          <SeverityBadge severity={r.impact} size="xs" />
          <span className="min-w-0 flex-1">
            <Link to={r.href} className="block font-medium text-heading hover:underline">
              {r.title}
            </Link>
            <span className="block text-xs text-fg-muted">{r.why}</span>
          </span>
        </li>
      ))}
    </ol>
  );
}

function MfaByProvider({ posture }: { posture: IdentityPosture | null }) {
  if (!posture) return <SkeletonText lines={3} />;
  if (posture.byProvider.length === 0) return <p className="text-sm text-fg-muted">No user identities synced yet.</p>;
  return (
    <div className="space-y-2.5">
      {posture.byProvider.map((p) => (
        <Meter key={p.provider} label={p.provider} used={p.mfa} limit={p.total} hint={`${formatPercent(p.mfa, p.total)} of ${formatInteger(p.total)} users enforce MFA`} />
      ))}
    </div>
  );
}

/** ISPM workspace: identity inventory, privilege, MFA coverage, dormancy, service accounts, risk. */
export default function IspmPage() {
  const [params] = useSearchParams();
  const [dormantDays, setDormantDays] = useState(90);
  const { identities, posture } = usePosture(dormantDays);
  const privilegedParam = params.get("privileged") === "1";
  const minRisk = params.get("risk") === "high" ? 70 : undefined;
  const initialId = params.get("id");
  const sample = <SampleNote loaded={identities.items?.length ?? 0} more={Boolean(identities.hasNextPage)} onMore={() => void identities.fetchNextPage()} loading={identities.isFetchingNextPage} />;

  return (
    <ModuleWorkspace
      moduleId="ispm"
      sections={{
        "": () => (
          <div className="space-y-4">
            <PostureKpis posture={posture} loading={identities.isPending} />
            {sample}
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-3">
              <SummaryWidgets widgets={[IdentityRiskWidget]} columns={2} />
              <Card title="Recommendations" info="Ranked by impact; each one states exactly how many identities it fixes.">
                <Recommendations posture={posture} dormantDays={dormantDays} />
              </Card>
              <Card title="MFA coverage by provider">
                <MfaByProvider posture={posture} />
              </Card>
            </div>
            <IdentitiesTable engines={ENGINES} savedViewsKey="ispm-overview" dormantDays={dormantDays} />
          </div>
        ),
        identities: () => <IdentitiesTable engines={ENGINES} filters={minRisk ? { minRisk } : {}} initialIdentityId={initialId} savedViewsKey="ispm-identities" dormantDays={dormantDays} emptyTitle={minRisk ? "No high-risk identities" : undefined} />,
        privileged: () => <IdentitiesTable engines={ENGINES} filters={{ privileged: true }} emptyTitle="No privileged identities" savedViewsKey="ispm-privileged" dormantDays={dormantDays} />,
        mfa: () => (
          <div className="space-y-4">
            <Card title="MFA coverage by provider" info="Enabled human identities that enforce MFA.">
              <MfaByProvider posture={posture} />
            </Card>
            {sample}
            <IdentitiesTable
              engines={ENGINES}
              filters={{ mfa: false, ...(privilegedParam ? { privileged: true } : {}) }}
              predicate={(i: IdentityView) => !i.mfaEnabled && !NON_HUMAN_KINDS.includes(i.kind)}
              emptyTitle={privilegedParam ? "Every privileged identity enforces MFA" : "Every user enforces MFA"}
              savedViewsKey="ispm-mfa"
            />
          </div>
        ),
        dormant: () => (
          <div className="space-y-3">
            <label className="flex items-center gap-2 text-sm text-fg-muted">
              Dormant after
              <Select value={dormantDays} onChange={(e) => setDormantDays(Number(e.target.value))} className="h-7 w-28" aria-label="Dormancy threshold">
                {DORMANCY.map((d) => (
                  <option key={d} value={d}>
                    {d} days
                  </option>
                ))}
              </Select>
              without activity
            </label>
            <IdentitiesTable
              engines={ENGINES}
              predicate={(i: IdentityView) => isDormant(i, dormantDays) && (!privilegedParam || i.privileged)}
              emptyTitle="No dormant accounts"
              savedViewsKey="ispm-dormant"
              dormantDays={dormantDays}
            />
          </div>
        ),
        "service-accounts": () => (
          <IdentitiesTable
            engines={ENGINES}
            filters={{ kind: NON_HUMAN_KINDS }}
            predicate={params.get("risky") === "1" ? (i: IdentityView) => i.privileged || (i.riskScore ?? 0) >= 70 : undefined}
            emptyTitle="No service accounts, service principals or API keys"
            savedViewsKey="ispm-service-accounts"
          />
        ),
        recommendations: () => (
          <div className="space-y-3">
            {sample}
            <Card title="Identity recommendations" info="Computed from the identity inventory: privilege, MFA, dormancy and non-human identity risk.">
              <Recommendations posture={posture} dormantDays={dormantDays} />
            </Card>
          </div>
        ),
      }}
    />
  );
}
