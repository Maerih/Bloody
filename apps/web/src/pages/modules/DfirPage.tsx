import { clsx } from "clsx";
import { Archive, FileSearch, FolderLock, FolderSearch, History, Plus, Search } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useInvestigation, useInvestigations, useResponseActions } from "../../api/hooks";
import type { InvestigationDetail, InvestigationSummary } from "../../api/types";
import { useSession } from "../../app/session";
import { SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { Input } from "../../components/Form";
import { RelativeTime } from "../../components/RelativeTime";
import { ReportMenu } from "../../components/ReportMenu";
import { CardSkeleton, SkeletonText } from "../../components/Skeleton";
import { StatTile } from "../../components/StatTile";
import { AgentsTable } from "../../features/agents/AgentsTable";
import { EventsLens } from "../../features/events/EventsLens";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { CustodyPanel, EvidencePanel } from "../../features/investigations/EvidencePanel";
import { CreateInvestigationDialog, InvestigationsTable } from "../../features/investigations/InvestigationsTable";
import { TimelinePanel } from "../../features/investigations/TimelinePanel";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { ResponseActionsTable } from "../../features/response/ResponseActionsTable";
import { DetectionRulesView } from "../../features/siem/DetectionRulesView";
import { useActorName } from "../../features/users/useActorName";
import { hrefForEntity } from "../../lib/entityLinks";
import { formatInteger } from "../../lib/format";

const OPEN_STATUSES: InvestigationSummary["status"][] = ["open", "in_progress", "awaiting_customer"];

/** Compact, selectable list of cases (master side of the DFIR master/detail views). */
function CaseList({ rows, selected, onSelect, emptyTitle }: { rows: InvestigationSummary[]; selected: string | null; onSelect: (id: string) => void; emptyTitle: string }) {
  const [q, setQ] = useState("");
  const shown = useMemo(() => {
    const term = q.trim().toLowerCase();
    return rows.filter((r) => !term || r.title.toLowerCase().includes(term) || String(r.incidentNumber ?? "").includes(term));
  }, [rows, q]);
  return (
    <div className="flex min-h-0 flex-col">
      <div className="border-b border-line p-2">
        <label className="relative block">
          <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter cases" className="h-7 pl-6 text-sm" aria-label="Filter cases" />
        </label>
      </div>
      {shown.length === 0 ? (
        <EmptyState compact icon={FolderSearch} title={emptyTitle} />
      ) : (
        <ul className="max-h-[560px] overflow-y-auto scrollbar-thin" aria-label="Cases">
          {shown.map((r) => (
            <li key={r.id}>
              <button
                type="button"
                onClick={() => onSelect(r.id)}
                aria-current={r.id === selected ? "true" : undefined}
                className={clsx("block w-full border-l-2 px-3 py-2 text-left hover:bg-surface-2", r.id === selected ? "border-primary bg-primary-soft/50" : "border-transparent")}
              >
                <span className="block truncate text-sm font-medium text-fg">{r.title}</span>
                <span className="flex items-center gap-1.5 text-2xs text-fg-subtle">
                  {r.incidentSeverity ? <SeverityBadge severity={r.incidentSeverity} size="xs" /> : null}
                  {r.incidentNumber ? <span>#{r.incidentNumber}</span> : null}
                  <StatusBadge status={r.status} size="xs" />
                  {r.evidenceCount !== undefined ? <span>{r.evidenceCount} evidence</span> : null}
                  <RelativeTime value={r.updatedAt} className="ml-auto shrink-0" />
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Master/detail over cases: pick an investigation on the left, render its detail on the right.
 * `?case=<id>` preselects one. Every view reads the same investigation records as the workspace.
 */
function CaseMasterDetail({ title, filter, emptyTitle, render }: { title: string; filter?: (i: InvestigationSummary) => boolean; emptyTitle: string; render: (inv: InvestigationDetail) => ReactNode }) {
  const [params, setParams] = useSearchParams();
  const list = useInvestigations({ limit: 200 });
  const rows = useMemo(() => (list.data?.items ?? []).filter((i) => (filter ? filter(i) : true)), [list.data, filter]);
  const selectedId = params.get("case") ?? rows[0]?.id ?? null;
  const detail = useInvestigation(selectedId);
  const select = (id: string) => {
    const next = new URLSearchParams(params);
    next.set("case", id);
    setParams(next, { replace: true });
  };
  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[300px_minmax(0,1fr)]">
      <Card title="Cases" count={list.data ? rows.length : null} padded={false}>
        {list.isPending ? (
          <div className="p-3">
            <SkeletonText lines={5} />
          </div>
        ) : list.isError ? (
          <ErrorState error={list.error} compact onRetry={() => void list.refetch()} />
        ) : (
          <CaseList rows={rows} selected={selectedId} onSelect={select} emptyTitle={emptyTitle} />
        )}
      </Card>
      <div className="min-w-0">
        {!selectedId ? (
          <div className="rounded border border-line bg-surface shadow-card">
            <EmptyState icon={FolderLock} title={emptyTitle} description="Evidence, timelines and forensic reports belong to investigations. Open one from an incident to start a case." action={<ButtonLink to="/investigations" size="sm">Investigations</ButtonLink>} />
          </div>
        ) : detail.isPending ? (
          <CardSkeleton rows={6} />
        ) : detail.isError ? (
          <div className="rounded border border-line bg-surface shadow-card">
            <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
          </div>
        ) : (
          <Card
            title={
              <Link to={hrefForEntity("investigation", detail.data.id)} className="hover:underline">
                {title} · {detail.data.title}
              </Link>
            }
            subtitle={detail.data.incident ? `Incident #${detail.data.incident.number} ${detail.data.incident.title}` : "No linked incident"}
            actions={<ButtonLink size="xs" to={hrefForEntity("investigation", detail.data.id)}>Open workspace</ButtonLink>}
          >
            {render(detail.data)}
          </Card>
        )}
      </div>
    </div>
  );
}

function Cases() {
  const session = useSession();
  const list = useInvestigations({ limit: 200 });
  const [creating, setCreating] = useState(false);
  const items = list.data?.items ?? [];
  const open = items.filter((i) => OPEN_STATUSES.includes(i.status));
  const evidence = items.reduce((n, i) => n + (i.evidenceCount ?? 0), 0);
  const canCreate = session.canAnywhere("investigation:write");
  return (
    <div className="space-y-3">
      <KpiGrid>
        <StatTile label="Open cases" value={list.data ? open.length : null} loading={list.isPending} icon={FolderLock} href="/investigations" />
        <StatTile label="Awaiting customer" value={list.data ? items.filter((i) => i.status === "awaiting_customer").length : null} loading={list.isPending} tone="high" href="/investigations?status=awaiting_customer" />
        <StatTile label="Evidence items" value={list.data ? evidence : null} loading={list.isPending} icon={Archive} href="/dfir/evidence" hint={list.data?.nextCursor ? "Across loaded cases" : undefined} />
        <StatTile label="Closed cases" value={list.data ? items.filter((i) => i.status === "closed").length : null} loading={list.isPending} />
      </KpiGrid>
      <div className="flex items-center gap-2">
        <h2 className="text-md font-semibold text-fg">Cases</h2>
        {canCreate ? (
          <Button size="sm" variant="primary" icon={Plus} className="ml-auto" onClick={() => setCreating(true)}>
            Open case
          </Button>
        ) : null}
      </div>
      <InvestigationsTable filters={{ status: OPEN_STATUSES }} emptyTitle="No open cases" onCreate={canCreate ? () => setCreating(true) : undefined} savedViewsKey="dfir-cases" />
      {creating ? <CreateInvestigationDialog onClose={() => setCreating(false)} /> : null}
    </div>
  );
}

function Timelines() {
  const { name } = useActorName();
  return (
    <div className="space-y-3">
      <CaseMasterDetail title="Timeline" emptyTitle="No cases yet" render={(inv) => <TimelinePanel entries={inv.timeline} actorName={name} />} />
      <Card title="Super-timelines" padded={false} info="Plaso extracts super-timelines from disk and memory evidence as a separate job container; Timesketch is optional for very large timelines.">
        <IntegrationStatusList engines={["plaso", "timesketch"]} />
      </Card>
    </div>
  );
}

function Collections() {
  const actions = useResponseActions({ limit: 200 });
  const rows = actions.data?.items.filter((a) => a.action === "collect_evidence");
  return (
    <div className="space-y-4">
      <div>
        <h2 className="mb-1 text-md font-semibold text-fg">Collect from an endpoint</h2>
        <p className="mb-2 text-sm text-fg-muted">Artifact and memory collection runs through Velociraptor as a response action. The collected file's SHA-256 opens its chain of custody when it is attached to a case.</p>
        <AgentsTable mode="live-response" engines={["velociraptor"]} savedViewsKey="dfir-collect" />
      </div>
      <div>
        <h2 className="mb-2 text-md font-semibold text-fg">Collections</h2>
        <ResponseActionsTable rows={rows} loading={actions.isPending} error={actions.error} onRetry={() => void actions.refetch()} emptyTitle="No collections requested yet" savedViewsKey="dfir-collections" exportFileName="bloody-collections" />
      </div>
    </div>
  );
}

function Yara() {
  const actions = useResponseActions({ limit: 200 });
  const rows = actions.data?.items.filter((a) => a.action === "run_yara_scan");
  return (
    <div className="space-y-4">
      <div>
        <h2 className="mb-2 text-md font-semibold text-fg">YARA rules</h2>
        <DetectionRulesView kinds={["yara"]} />
      </div>
      <div>
        <h2 className="mb-2 text-md font-semibold text-fg">YARA scans</h2>
        <ResponseActionsTable rows={rows} loading={actions.isPending} error={actions.error} onRetry={() => void actions.refetch()} emptyTitle="No YARA scans requested yet" emptyDescription="Request “Run YARA scan” on an endpoint from EDR live response or an investigation." savedViewsKey="dfir-yara-scans" />
      </div>
      <EventsLens title="YARA matches" query="detection.engine:yara OR labels.osquery.query:*yara*" engines={["yara", "osquery"]} defaultRange={{ preset: "30d" }} preset="file" aggregations={[{ title: "Rules", field: "detection.ruleName", value: (e) => e.detection?.ruleName }, { title: "Hosts", field: "asset.hostname", value: (e) => e.asset?.hostname }]} />
    </div>
  );
}

function ForensicReports() {
  const filter = useMemo(() => (i: InvestigationSummary) => Boolean(i.incidentId), []);
  return (
    <CaseMasterDetail
      title="Forensic report"
      filter={filter}
      emptyTitle="No case is linked to an incident"
      render={(inv) => (
        <div className="space-y-3">
          <p className="text-sm text-fg-muted">The incident report includes the timeline, evidence with SHA-256 and chain of custody, response actions with approvals, and the root-cause narrative. Generate it as PDF / HTML for the customer or JSON / CSV for archiving.</p>
          <dl className="grid grid-cols-2 gap-2 text-sm md:grid-cols-4">
            <div>
              <dt className="text-fg-muted">Timeline entries</dt>
              <dd className="font-semibold">{formatInteger(inv.timeline.length)}</dd>
            </div>
            <div>
              <dt className="text-fg-muted">Evidence items</dt>
              <dd className="font-semibold">{formatInteger(inv.evidence.length)}</dd>
            </div>
            <div>
              <dt className="text-fg-muted">Notes</dt>
              <dd className="font-semibold">{formatInteger(inv.notes.length)}</dd>
            </div>
            <div>
              <dt className="text-fg-muted">Status</dt>
              <dd>
                <StatusBadge status={inv.status} size="xs" />
              </dd>
            </div>
          </dl>
          {inv.incidentId ? <ReportMenu reports={["incident"]} defaultReport="incident" organizationId={inv.organizationId} parameters={{ incidentId: inv.incidentId, investigationId: inv.id }} label="Generate forensic report" /> : null}
        </div>
      )}
    />
  );
}

/** DFIR workspace: cases, evidence locker with chain of custody, timelines, collections, YARA, reports. */
export default function DfirPage() {
  const { name } = useActorName();
  const withEvidence = useMemo(() => (i: InvestigationSummary) => i.evidenceCount === undefined || i.evidenceCount > 0, []);
  return (
    <ModuleWorkspace
      moduleId="dfir"
      sections={{
        "": () => <Cases />,
        evidence: () => (
          <CaseMasterDetail
            title="Evidence"
            filter={withEvidence}
            emptyTitle="No case holds evidence yet"
            render={(inv) => (
              <div className="space-y-4">
                <EvidencePanel investigation={inv} />
                <div>
                  <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">
                    <History size={12} aria-hidden /> Chain of custody
                  </h3>
                  <CustodyPanel investigation={inv} actorName={name} />
                </div>
              </div>
            )}
          />
        ),
        timelines: () => <Timelines />,
        collections: () => <Collections />,
        yara: () => <Yara />,
        reports: () => <ForensicReports />,
      }}
      actions={
        <ButtonLink size="sm" icon={FileSearch} to="/investigations">
          All investigations
        </ButtonLink>
      }
    />
  );
}

