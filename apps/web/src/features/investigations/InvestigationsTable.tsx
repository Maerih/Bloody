import { InvestigationStatus, Severity } from "@bloody/contracts";
import { FolderSearch, Plus } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useCreateInvestigation, useIncident, useInvestigations } from "../../api/hooks";
import type { InvestigationFilters, InvestigationSummary } from "../../api/types";
import { useSession } from "../../app/session";
import { SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { Field, Input, Select, Textarea } from "../../components/Form";
import { OrganizationSelect, useDefaultOrganization } from "../../components/OrganizationSelect";
import { Dialog } from "../../components/Overlay";
import { RelativeTime } from "../../components/RelativeTime";
import { hrefForEntity } from "../../lib/entityLinks";
import { humanize } from "../../lib/format";
import { useActorName, userLabel } from "../users/useActorName";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Open an investigation (optionally from an incident). The lead defaults to the creator. */
export function CreateInvestigationDialog({ onClose, incidentId: initialIncident = "" }: { onClose: () => void; incidentId?: string }) {
  const session = useSession();
  const navigate = useNavigate();
  const create = useCreateInvestigation();
  const { users } = useActorName();
  const defaultOrg = useDefaultOrganization("investigation:write");
  const [incidentId, setIncidentId] = useState(initialIncident);
  const incident = useIncident(UUID_RE.test(incidentId.trim()) ? incidentId.trim() : null);
  const [orgId, setOrgId] = useState<string | null>(defaultOrg);
  const [title, setTitle] = useState("");
  const [hypothesis, setHypothesis] = useState("");
  const [leadId, setLeadId] = useState(session.principal.kind === "user" ? session.principal.id : "");
  const [submitted, setSubmitted] = useState(false);
  const effectiveOrg = incident.data?.organizationId ?? orgId;
  const effectiveTitle = title.trim() || (incident.data ? `Investigation: #${incident.data.number} ${incident.data.title}` : "");
  const errors = {
    title: effectiveTitle.length >= 3 ? null : "Give the investigation a title (min. 3 characters)",
    org: effectiveOrg ? null : "Choose the organization",
    incident: incidentId.trim() && !UUID_RE.test(incidentId.trim()) ? "Incident id must be a UUID" : incident.isError ? errorMessage(incident.error) : null,
  };
  const submit = () => {
    setSubmitted(true);
    if (errors.title || errors.org || errors.incident) return;
    create.mutate(
      {
        title: effectiveTitle.slice(0, 300),
        organizationId: effectiveOrg!,
        ...(incident.data ? { incidentId: incident.data.id } : {}),
        ...(hypothesis.trim() ? { hypothesis: hypothesis.trim() } : {}),
        ...(leadId ? { leadId } : {}),
      },
      { onSuccess: (inv) => navigate(hrefForEntity("investigation", inv.id)) },
    );
  };
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Open investigation"
      description="An investigation workspace collects the timeline, evidence (with chain of custody), notes, tasks and response actions."
      footer={
        <>
          {create.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(create.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={create.isPending}>
            Open investigation
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Incident (optional)" hint={incident.data ? `#${incident.data.number} ${incident.data.title}` : "Link the incident this investigation explains"} error={submitted || incidentId ? errors.incident : null} className="sm:col-span-2">
          {(p) => <Input {...p} value={incidentId} onChange={(e) => setIncidentId(e.target.value)} placeholder="Incident id" className="font-mono text-xs" />}
        </Field>
        <Field label="Title" required error={submitted ? errors.title : null} className="sm:col-span-2">
          {(p) => <Input {...p} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={300} placeholder={incident.data ? `Investigation: #${incident.data.number} ${incident.data.title}` : "Suspected credential theft on finance workstations"} />}
        </Field>
        <Field label="Organization" required error={submitted ? errors.org : null}>
          {(p) =>
            incident.data ? (
              <Input {...p} value={session.organizationName(incident.data.organizationId) ?? incident.data.organizationId} disabled readOnly />
            ) : (
              <OrganizationSelect {...p} value={orgId} onChange={setOrgId} permission="investigation:write" />
            )
          }
        </Field>
        <Field label="Lead">
          {(p) => (
            <Select {...p} value={leadId} onChange={(e) => setLeadId(e.target.value)}>
              <option value="">Unassigned</option>
              {session.principal.kind === "user" && !users.some((u) => u.id === session.principal.id) ? <option value={session.principal.id}>{session.principal.displayName ?? session.principal.email ?? "Me"}</option> : null}
              {users
                .filter((u) => u.status !== "disabled" && u.disabled !== true)
                .map((u) => (
                  <option key={u.id} value={u.id}>
                    {userLabel(u)}
                  </option>
                ))}
            </Select>
          )}
        </Field>
        <Field label="Hypothesis" hint="What you believe happened — refined as evidence comes in." className="sm:col-span-2">
          {(p) => <Textarea {...p} value={hypothesis} onChange={(e) => setHypothesis(e.target.value)} maxLength={10_000} />}
        </Field>
      </div>
    </Dialog>
  );
}

/** Investigations / DFIR cases table: status, linked incident, lead, open tasks, evidence. */
export function InvestigationsTable({ filters = {}, emptyTitle = "No investigations yet", onCreate, savedViewsKey }: { filters?: InvestigationFilters; emptyTitle?: string; onCreate?: () => void; savedViewsKey?: string }) {
  const session = useSession();
  const navigate = useNavigate();
  const investigations = useInvestigations(filters);
  const { name } = useActorName();
  const rows = investigations.data?.items;
  const columns = useMemo<DataTableColumn<InvestigationSummary>[]>(
    () => [
      { id: "title", header: "Investigation", accessor: (i) => i.title, hideable: false, cell: (i) => <Link to={hrefForEntity("investigation", i.id)} className="font-medium text-heading hover:underline" onClick={(e) => e.stopPropagation()}>{i.title}</Link> },
      { id: "status", header: "Status", accessor: (i) => i.status, cell: (i) => <StatusBadge status={i.status} size="xs" />, filter: { kind: "select", options: InvestigationStatus.options.map((s) => ({ value: s, label: humanize(s) })) } },
      {
        id: "incident",
        header: "Incident",
        accessor: (i) => (i.incidentNumber ? `#${i.incidentNumber}` : i.incidentId ? "linked" : null),
        cell: (i) =>
          i.incidentId ? (
            <Link to={hrefForEntity("incident", i.incidentId)} className="inline-flex items-center gap-1.5 text-primary hover:underline" onClick={(e) => e.stopPropagation()}>
              {i.incidentSeverity ? <SeverityBadge severity={i.incidentSeverity} size="xs" /> : null}
              {i.incidentNumber ? `#${i.incidentNumber}` : "Incident"}
            </Link>
          ) : (
            <span className="text-fg-subtle">—</span>
          ),
      },
      { id: "severity", header: "Severity", accessor: (i) => (i.incidentSeverity ? Severity.options.indexOf(i.incidentSeverity) : null), cell: (i) => (i.incidentSeverity ? <SeverityBadge severity={i.incidentSeverity} size="xs" /> : "—"), defaultHidden: true },
      { id: "lead", header: "Lead", accessor: (i) => (i.leadId ? name(i.leadId) : null) },
      { id: "tasks", header: "Open tasks", accessor: (i) => i.openTasks ?? null, align: "right" },
      { id: "evidence", header: "Evidence", accessor: (i) => i.evidenceCount ?? null, align: "right" },
      { id: "org", header: "Organization", accessor: (i) => i.organizationName ?? session.organizationName(i.organizationId), defaultHidden: session.organizationId !== null },
      { id: "updated", header: "Updated", accessor: (i) => new Date(i.updatedAt), cell: (i) => <RelativeTime value={i.updatedAt} /> },
    ],
    [name, session],
  );
  return (
    <DataTable
      caption="Investigations"
      columns={columns}
      rows={rows}
      getRowId={(i) => i.id}
      loading={investigations.isPending}
      error={investigations.error}
      onRetry={() => void investigations.refetch()}
      onRowClick={(i) => navigate(hrefForEntity("investigation", i.id))}
      initialState={{ sort: { columnId: "updated", direction: "desc" } }}
      savedViewsKey={savedViewsKey}
      exportFileName="bloody-investigations"
      emptyState={
        <EmptyState
          icon={FolderSearch}
          title={emptyTitle}
          description="Open an investigation from an incident, or start one for a hunt or hypothesis."
          action={onCreate && session.canAnywhere("investigation:write") ? <Button size="sm" variant="primary" icon={Plus} onClick={onCreate}>Open investigation</Button> : undefined}
        />
      }
    />
  );
}
