import { Ban, Fingerprint, KeyRound, Network, Sparkles } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useIdentity } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { DescriptionList } from "../../components/DescriptionList";
import { ErrorState } from "../../components/ErrorState";
import { RelativeTime } from "../../components/RelativeTime";
import { RiskScore } from "../../components/RiskScore";
import { SkeletonText } from "../../components/Skeleton";
import { hrefForEntity } from "../../lib/entityLinks";
import { humanize } from "../../lib/format";
import { RequestActionDialog } from "../response/RequestActionDialog";
import { daysInactive, identityName } from "./identityUtils";

/** Identity drill-down: posture (privilege, MFA, activity), alerts, graph access, containment. */
export function IdentityDetailPanel({ identityId }: { identityId: string }) {
  const session = useSession();
  const identity = useIdentity(identityId);
  const [respond, setRespond] = useState(false);
  if (identity.isPending) {
    return (
      <div className="p-4">
        <SkeletonText lines={8} />
      </div>
    );
  }
  if (identity.isError) return <ErrorState error={identity.error} onRetry={() => void identity.refetch()} />;
  const i = identity.data;
  const inactive = daysInactive(i);
  const canAi = session.isModuleEnabled("ai_soc") && session.can("ai:use", i.organizationId);
  return (
    <div>
      <div className="space-y-2 border-b border-line px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="outline">{humanize(i.kind)}</Badge>
          <Badge tone="neutral">{i.provider}</Badge>
          {i.privileged ? <Badge tone="warning">Privileged</Badge> : null}
          {i.mfaEnabled ? <Badge tone="success">MFA</Badge> : <Badge tone="danger">No MFA</Badge>}
          {i.enabled === false ? <Badge>Disabled</Badge> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          {canAi ? (
            <ButtonLink size="sm" variant="primary" icon={Sparkles} to={`/ai?context=${encodeURIComponent(`identity:${i.id}`)}`}>
              Ask AI
            </ButtonLink>
          ) : null}
          <ButtonLink size="sm" icon={Network} to={`/graph?q=${encodeURIComponent(i.principal)}`}>
            Graph pivot
          </ButtonLink>
          <ButtonLink size="sm" icon={Fingerprint} to={`/siem/search?q=${encodeURIComponent(`identity.principal:"${i.principal.replace(/(["\\])/g, "\\$1")}"`)}`}>
            Sign-in events
          </ButtonLink>
          {session.can("response:request", i.organizationId) ? (
            <Button size="sm" variant="danger" icon={Ban} onClick={() => setRespond(true)}>
              Contain identity
            </Button>
          ) : null}
        </div>
      </div>
      <div className="space-y-3 border-b border-line px-4 py-3">
        <RiskScore score={i.riskScore} size="lg" label="Identity risk" />
        <DescriptionList
          items={[
            { label: "Principal", value: <span className="break-all font-mono text-xs">{i.principal}</span> },
            { label: "Display name", value: i.displayName },
            { label: "Last activity", value: i.lastActivityAt ? <RelativeTime value={i.lastActivityAt} /> : "Never" },
            { label: "Inactive for", value: inactive === null ? "No recorded activity" : `${inactive} days` },
            { label: "Organization", value: session.organizationName(i.organizationId) },
          ]}
        />
      </div>
      <section className="border-b border-line px-4 py-3">
        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">
          <KeyRound size={12} aria-hidden /> Access {i.access ? `(${i.access.length})` : ""}
        </h3>
        {i.access === null || i.access === undefined ? (
          <p className="text-sm text-fg-subtle">Graph access is not available for your role.</p>
        ) : i.access.length === 0 ? (
          <p className="text-sm text-fg-subtle">No recorded access to assets.</p>
        ) : (
          <ul className="space-y-1">
            {i.access.map((a, idx) => (
              <li key={`${a.assetId ?? a.label}-${idx}`} className="flex items-center gap-2 text-sm">
                <span className="text-xs text-fg-subtle">{a.kind.replace(/_/g, " ")}</span>
                {a.assetId ? (
                  <Link to={hrefForEntity("asset", a.assetId)} className="text-heading hover:underline">
                    {a.label}
                  </Link>
                ) : (
                  <span>{a.label}</span>
                )}
                {a.criticality ? <Badge size="xs" tone={a.criticality === "crown_jewel" ? "danger" : "neutral"}>{humanize(a.criticality)}</Badge> : null}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="px-4 py-3">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Identity alerts {i.alerts ? `(${i.alerts.length})` : ""}</h3>
        {!i.alerts || i.alerts.length === 0 ? (
          <p className="text-sm text-fg-subtle">{i.alerts === null ? "Alert data is not available for your role." : "No alerts for this identity."}</p>
        ) : (
          <ul className="divide-y divide-line rounded border border-line">
            {i.alerts.map((a) => (
              <li key={a.id} className="flex items-center gap-2 px-2.5 py-1.5 text-sm">
                <SeverityBadge severity={a.severity} size="xs" />
                <Link to={hrefForEntity("alert", a.id)} className="min-w-0 flex-1 truncate hover:underline">
                  {a.title}
                </Link>
                <StatusBadge status={a.status} size="xs" />
                <RelativeTime value={a.lastSeenAt} className="text-xs text-fg-subtle" />
              </li>
            ))}
          </ul>
        )}
      </section>
      {respond ? (
        <RequestActionDialog
          open
          onClose={() => setRespond(false)}
          organizationId={i.organizationId}
          actions={["disable_identity", "revoke_sessions", "revoke_token"]}
          defaultAction="revoke_sessions"
          targets={{ identity: [{ id: i.id, label: identityName(i) }] }}
          description={`${identityName(i)} · ${i.provider}`}
        />
      ) : null}
    </div>
  );
}
