import { IncidentStatus, Severity, type UpdateIncidentInput } from "@bloody/contracts";
import { ExternalLink, Fingerprint, Network, Search, Server, Sparkles, Terminal } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useAlerts, useIncident, useResponseActions, useUpdateIncident, useUsers } from "../../api/hooks";
import type { IncidentDetail } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { DescriptionList } from "../../components/DescriptionList";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { Select } from "../../components/Form";
import { RelativeTime } from "../../components/RelativeTime";
import { ReportMenu } from "../../components/ReportMenu";
import { RiskScore } from "../../components/RiskScore";
import { SkeletonText } from "../../components/Skeleton";
import { hrefForEntity } from "../../lib/entityLinks";
import { formatDateTime, humanize } from "../../lib/format";
import { RequestResponseActionDialog } from "./RequestResponseActionDialog";

function Section({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="border-b border-line px-4 py-3 last:border-b-0">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">{title}</h3>
        {actions}
      </div>
      {children}
    </section>
  );
}

/** Incident summary + editing + pivots. Used by the drawer on /incidents and by /incidents/:id. */
export function IncidentDetailPanel({ incidentId }: { incidentId: string }) {
  const incident = useIncident(incidentId);
  if (incident.isPending) {
    return (
      <div className="p-4">
        <SkeletonText lines={8} />
      </div>
    );
  }
  if (incident.isError) return <ErrorState error={incident.error} onRetry={() => void incident.refetch()} />;
  return <IncidentDetailBody incident={incident.data} />;
}

function IncidentDetailBody({ incident }: { incident: IncidentDetail }) {
  const session = useSession();
  const orgId = incident.organizationId;
  const canWrite = session.can("incident:write", orgId);
  const canRespond = session.can("response:request", orgId);
  const canAi = session.can("ai:use", orgId) && session.isModuleEnabled("ai_soc");
  const update = useUpdateIncident(incident.id);
  const users = useUsers({ enabled: canWrite && session.can("user:read", orgId) });
  const alerts = useAlerts({ incidentId: incident.id, organizationId: orgId, limit: 50 }, { enabled: !incident.alerts });
  const actions = useResponseActions({ incidentId: incident.id, organizationId: orgId });
  const [requestOpen, setRequestOpen] = useState(false);

  const patch = (input: UpdateIncidentInput) => update.mutate(input);
  const alertList = incident.alerts ?? alerts.data?.items ?? [];
  const orgName = incident.organizationName ?? session.organizationName(orgId);

  return (
    <div>
      <div className="space-y-3 border-b border-line px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
          {orgName ? <Badge tone="outline">{orgName}</Badge> : null}
          <span className="text-sm text-fg-subtle">
            Detected <RelativeTime value={incident.detectedAt} />
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {canAi ? (
            <ButtonLink to={`/ai?context=${encodeURIComponent(`incident:${incident.id}`)}`} size="sm" variant="primary" icon={Sparkles}>
              Ask AI
            </ButtonLink>
          ) : null}
          <ButtonLink to={`/investigations?incidentId=${encodeURIComponent(incident.id)}`} size="sm" icon={Search}>
            Investigation
          </ButtonLink>
          <ButtonLink to={`/xdr/graph?incident=${encodeURIComponent(incident.id)}`} size="sm" icon={Network}>
            Graph
          </ButtonLink>
          {canRespond ? (
            <Button size="sm" icon={Terminal} onClick={() => setRequestOpen(true)}>
              Response action
            </Button>
          ) : null}
          <ReportMenu reports={["incident"]} defaultReport="incident" organizationId={orgId} parameters={{ incidentId: incident.id }} />
        </div>
      </div>

      <Section title="Triage">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <label className="space-y-1 text-sm text-fg-muted">
            Severity
            <Select value={incident.severity} disabled={!canWrite || update.isPending} onChange={(e) => patch({ severity: Severity.parse(e.target.value) })} aria-label="Severity">
              {Severity.options.map((s) => (
                <option key={s} value={s}>
                  {humanize(s)}
                </option>
              ))}
            </Select>
          </label>
          <label className="space-y-1 text-sm text-fg-muted">
            Status
            <Select value={incident.status} disabled={!canWrite || update.isPending} onChange={(e) => patch({ status: IncidentStatus.parse(e.target.value) })} aria-label="Status">
              {IncidentStatus.options.map((s) => (
                <option key={s} value={s}>
                  {humanize(s)}
                </option>
              ))}
            </Select>
          </label>
          <label className="space-y-1 text-sm text-fg-muted">
            Assignee
            <Select
              value={incident.assigneeId ?? ""}
              disabled={!canWrite || update.isPending || !users.data}
              onChange={(e) => patch({ assigneeId: e.target.value || null })}
              aria-label="Assignee"
            >
              <option value="">Unassigned</option>
              {incident.assigneeId && !users.data?.some((u) => u.id === incident.assigneeId) ? (
                <option value={incident.assigneeId}>{incident.assigneeName ?? "Current assignee"}</option>
              ) : null}
              {(users.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>
                  {u.displayName ?? u.email}
                </option>
              ))}
            </Select>
          </label>
        </div>
        {update.isError ? (
          <p role="alert" className="mt-2 text-sm text-sev-critical">
            {errorMessage(update.error)}
          </p>
        ) : null}
        {!canWrite ? <p className="mt-2 text-xs text-fg-subtle">You have read-only access to this incident.</p> : null}
      </Section>

      <Section title="Summary">
        {incident.summary ? <p className="whitespace-pre-wrap text-base text-fg">{incident.summary}</p> : <p className="text-sm text-fg-subtle">No summary yet.</p>}
      </Section>

      <Section title="Risk">
        <div className="flex items-start gap-3">
          <RiskScore score={incident.riskScore} factors={incident.risk?.factors} summary={incident.risk?.summary} modelVersion={incident.risk?.modelVersion} size="lg" label="Incident risk" />
          <div className="min-w-0 flex-1 text-sm text-fg-muted">
            {incident.risk ? (
              <>
                <p className="text-fg">{incident.risk.summary}</p>
                <p className="mt-1">
                  Likelihood {(incident.risk.likelihood * 100).toFixed(0)}% · impact {(incident.risk.impact * 100).toFixed(0)}% · {incident.risk.factors.length} contributing factors
                </p>
              </>
            ) : (
              <p>Select the score to see its explanation.</p>
            )}
          </div>
        </div>
      </Section>

      <Section title={`MITRE ATT&CK (${incident.attack.length})`}>
        {incident.attack.length === 0 ? (
          <p className="text-sm text-fg-subtle">No techniques mapped.</p>
        ) : (
          <ul className="flex flex-wrap gap-1.5">
            {incident.attack.map((t) => (
              <li key={t.id}>
                <a
                  href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded border border-line-strong bg-surface-2 px-1.5 py-0.5 text-xs hover:border-primary"
                  title={t.tactic ? `Tactic: ${t.tactic}` : undefined}
                >
                  <span className="font-mono font-semibold">{t.id}</span>
                  {t.name ? <span className="text-fg-muted">{t.name}</span> : null}
                  <ExternalLink size={10} aria-hidden className="text-fg-subtle" />
                </a>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={`Alerts (${incident.alertCount})`}>
        {alerts.isLoading ? (
          <SkeletonText lines={3} />
        ) : alertList.length === 0 ? (
          <p className="text-sm text-fg-subtle">{alerts.isError ? errorMessage(alerts.error) : "No alerts linked."}</p>
        ) : (
          <ul className="divide-y divide-line rounded border border-line">
            {alertList.slice(0, 25).map((a) => (
              <li key={a.id} className="flex items-center gap-2 px-2.5 py-1.5">
                <SeverityBadge severity={a.severity} size="xs" />
                <Link to={hrefForEntity("alert", a.id)} className="min-w-0 flex-1 truncate text-base text-heading hover:underline">
                  {a.title}
                </Link>
                <span className="text-xs text-fg-subtle">{a.source}</span>
                <RelativeTime value={a.lastSeenAt} className="text-xs text-fg-subtle" />
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Affected entities">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <EntityList
            icon={Server}
            title="Assets"
            items={incident.assets ? incident.assets.map((a) => ({ id: a.id, label: a.hostname ?? a.name, hint: humanize(a.kind) })) : incident.assetIds.map((id) => ({ id, label: id }))}
            kind="asset"
          />
          <EntityList
            icon={Fingerprint}
            title="Identities"
            items={incident.identities ? incident.identities.map((i) => ({ id: i.id, label: i.displayName ?? i.principal, hint: i.privileged ? "privileged" : i.provider })) : incident.identityIds.map((id) => ({ id, label: id }))}
            kind="identity"
          />
        </div>
      </Section>

      <Section title="Response actions">
        {actions.isLoading ? (
          <SkeletonText lines={2} />
        ) : actions.isError ? (
          <p className="text-sm text-fg-subtle">{errorMessage(actions.error)}</p>
        ) : (actions.data?.items.length ?? 0) === 0 ? (
          <EmptyState compact icon={Terminal} title="No response actions yet" action={canRespond ? <Button size="sm" onClick={() => setRequestOpen(true)}>Request action</Button> : undefined} />
        ) : (
          <ul className="divide-y divide-line rounded border border-line">
            {actions.data!.items.map((a) => (
              <li key={a.id} className="flex items-center gap-2 px-2.5 py-1.5 text-base">
                <span className="min-w-0 flex-1 truncate">
                  {humanize(a.action)}
                  {a.target.label ? <span className="text-fg-muted"> · {a.target.label}</span> : null}
                </span>
                <Badge size="xs" tone="outline">
                  via {a.requestedVia}
                </Badge>
                <StatusBadge status={a.status} size="xs" />
                <RelativeTime value={a.createdAt} className="text-xs text-fg-subtle" />
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Timeline">
        <DescriptionList
          items={[
            { label: "Detected", value: formatDateTime(incident.detectedAt) },
            { label: "Acknowledged", value: incident.acknowledgedAt ? formatDateTime(incident.acknowledgedAt) : null },
            { label: "Contained", value: incident.containedAt ? formatDateTime(incident.containedAt) : null },
            { label: "Closed", value: incident.closedAt ? formatDateTime(incident.closedAt) : null },
            { label: "Last updated", value: formatDateTime(incident.updatedAt) },
            { label: "Incident ID", value: <span className="font-mono text-xs">{incident.id}</span> },
          ]}
        />
      </Section>

      {requestOpen ? <RequestResponseActionDialog incident={incident} open onClose={() => setRequestOpen(false)} /> : null}
    </div>
  );
}

function EntityList({ icon: Icon, title, items, kind }: { icon: typeof Server; title: string; items: { id: string; label: string; hint?: string }[]; kind: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center gap-1.5 text-sm font-medium text-fg">
        <Icon size={13} aria-hidden className="text-fg-muted" /> {title} ({items.length})
      </div>
      {items.length === 0 ? (
        <p className="text-sm text-fg-subtle">None</p>
      ) : (
        <ul className="space-y-0.5">
          {items.slice(0, 20).map((i) => (
            <li key={i.id} className="flex items-center gap-2 text-base">
              <Link to={hrefForEntity(kind, i.id)} className="min-w-0 truncate text-heading hover:underline">
                {i.label}
              </Link>
              {i.hint ? <span className="text-xs text-fg-subtle">{i.hint}</span> : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
