import type { RmmFinding } from "@bloody/contracts";
import { Ban, CheckCircle2, Undo2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useBlockRmmTools, useRmmGuardOverview, useSetRmmApproved } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, DataTable, Dialog, EmptyState, ErrorState, OrganizationSelect, RelativeTime, StatTile, useDefaultOrganization, type DataTableColumn } from "../../components";

const latest = (f: RmmFinding) => f.endpoints.reduce((m, e) => (e.seenAt > m ? e.seenAt : m), "");

function BlockDialog({ organizationId, finding, appControl, onClose }: { organizationId: string; finding: RmmFinding; appControl: string; onClose: () => void }) {
  const block = useBlockRmmTools();
  const done = block.data;
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Block ${finding.tool.name}`}
      description="RMM Guard adds App Control block rules for this tool's programs on every computer in the organization."
      footer={
        <>
          {block.error ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(block.error)}
            </span>
          ) : null}
          {done ? (
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          ) : (
            <>
              <Button variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button variant="danger" icon={Ban} loading={block.isPending} onClick={() => block.mutate({ organizationId, tools: [finding.tool.key] })}>
                Add block rules
              </Button>
            </>
          )}
        </>
      }
    >
      {done ? (
        <p role="status" className="text-sm">
          {done.created} block rule{done.created === 1 ? "" : "s"} added{done.skipped ? `, ${done.skipped} already in place` : ""}.{" "}
          {done.appControl === "enforce" ? "SCIAT Agents will stop the tool within a few minutes." : done.appControl === "audit" ? "App Control is in audit mode: the tool is reported but not stopped until you switch to Enforce." : "App Control is off for this organization: turn it on to apply these rules."}
        </p>
      ) : (
        <div className="space-y-2 text-sm">
          <p>
            Found on {finding.endpoints.length} computer{finding.endpoints.length === 1 ? "" : "s"}: {finding.endpoints.map((e) => e.hostname).join(", ")}.
          </p>
          {appControl !== "enforce" ? <p className="text-fg-muted">App Control is currently {appControl === "off" ? "off" : "in audit mode"}, so the rules will only stop the tool once it is set to Enforce.</p> : null}
          <p className="text-fg-muted">Make sure no one in the organization relies on this tool for support before blocking it.</p>
        </div>
      )}
    </Dialog>
  );
}

/** ESPM → RMM Guard: remote-access and RMM tools on the organization's computers, approved or not. */
export function RmmGuardView() {
  const session = useSession();
  const [organizationId, setOrganizationId] = useState<string | null>(useDefaultOrganization("asset:read"));
  const [blocking, setBlocking] = useState<RmmFinding | null>(null);
  const overview = useRmmGuardOverview(organizationId);
  const setApproved = useSetRmmApproved();
  const canWrite = organizationId ? session.can("asset:write", organizationId) : false;
  const o = overview.data;

  const toggle = (key: string, approve: boolean) => {
    if (!organizationId || !o) return;
    const next = approve ? [...new Set([...o.approved, key])] : o.approved.filter((k) => k !== key);
    setApproved.mutate({ organizationId, approved: next });
  };

  const columns: DataTableColumn<RmmFinding>[] = [
    {
      id: "tool",
      header: "Tool",
      accessor: (f) => f.tool.name,
      hideable: false,
      cell: (f) => (
        <div>
          <div className="font-medium">{f.tool.name}</div>
          <div className="text-xs text-fg-muted">{f.tool.vendor}</div>
        </div>
      ),
    },
    {
      id: "status",
      header: "Status",
      accessor: (f) => (f.approved ? "approved" : "unapproved"),
      cell: (f) => (
        <Badge size="xs" tone={f.approved ? "success" : "danger"}>
          {f.approved ? "Approved" : "Unapproved"}
        </Badge>
      ),
      filter: { kind: "select", options: [{ value: "unapproved", label: "Unapproved" }, { value: "approved", label: "Approved" }] },
    },
    {
      id: "endpoints",
      header: "Computers",
      accessor: (f) => f.endpoints.map((e) => e.hostname).join(", "),
      cell: (f) => (
        <ul className="space-y-0.5">
          {f.endpoints.map((e) => (
            <li key={e.agentId}>
              <span className="font-medium">{e.hostname}</span> <span className="text-xs text-fg-muted">— {e.evidence.map((x) => (x.kind === "process" ? `running: ${x.value}` : `installed: ${x.value}`)).join("; ")}</span>
            </li>
          ))}
        </ul>
      ),
    },
    { id: "seen", header: "Last seen", accessor: (f) => new Date(latest(f)), cell: (f) => <RelativeTime value={latest(f)} /> },
    {
      id: "act",
      header: "",
      exportable: false,
      sortable: false,
      cell: (f) =>
        canWrite ? (
          f.approved ? (
            <Button size="xs" variant="ghost" icon={Undo2} aria-label={`Remove approval for ${f.tool.name}`} loading={setApproved.isPending} onClick={() => toggle(f.tool.key, false)}>
              Unapprove
            </Button>
          ) : (
            <span className="flex gap-1">
              <Button size="xs" icon={CheckCircle2} aria-label={`Approve ${f.tool.name}`} loading={setApproved.isPending} onClick={() => toggle(f.tool.key, true)}>
                Approve
              </Button>
              <Button size="xs" variant="danger" icon={Ban} aria-label={`Block ${f.tool.name}`} onClick={() => setBlocking(f)}>
                Block
              </Button>
            </span>
          )
        ) : null,
    },
  ];

  const unapproved = o?.findings.filter((f) => !f.approved) ?? [];
  const affected = new Set(unapproved.flatMap((f) => f.endpoints.map((e) => e.agentId))).size;
  const approvedNames = o ? o.approved.map((k) => o.catalog.find((c) => c.key === k)?.name ?? k) : [];

  return (
    <div className="space-y-4">
      <Card title="RMM Guard">
        <div className="space-y-4">
          <p className="max-w-3xl text-sm text-fg-muted">
            Remote-access and RMM tools (AnyDesk, TeamViewer, ScreenConnect and others) give full control of a computer and are a favourite of attackers. Approve the tools your organization really uses; anything else found by the SCIAT Agent is flagged here and can be blocked with App Control.
          </p>
          <div className="max-w-sm">
            <OrganizationSelect value={organizationId} onChange={setOrganizationId} permission="asset:read" aria-label="Organization" />
          </div>
          {!organizationId ? (
            <EmptyState compact title="Pick an organization" />
          ) : overview.isError ? (
            <ErrorState compact error={overview.error} onRetry={() => void overview.refetch()} />
          ) : o ? (
            <>
              <div className="grid gap-3 sm:grid-cols-4">
                <StatTile label="Unapproved tools" value={unapproved.length} tone={unapproved.length > 0 ? "high" : "healthy"} />
                <StatTile label="Computers affected" value={affected} tone={affected > 0 ? "high" : "healthy"} />
                <StatTile label="Approved tools" value={o.approved.length} />
                <StatTile label="Computers reporting" value={o.endpointsWithInventory} />
              </div>
              {o.appControl !== "enforce" ? (
                <p className="text-sm text-fg-muted">
                  App Control is {o.appControl === "off" ? "off" : "in audit mode"} for this organization, so blocked tools are {o.appControl === "off" ? "not checked" : "reported but not stopped"}.{" "}
                  <Link to="/espm/app-control" className="text-brand hover:underline">
                    Open App Control
                  </Link>
                </p>
              ) : null}
              {o.endpointsWithInventory === 0 ? <p className="text-sm text-fg-muted">No computer has reported its software yet. RMM Guard uses the inventory the SCIAT Agent sends every 30 minutes.</p> : null}
            </>
          ) : null}
        </div>
      </Card>
      {organizationId && o ? (
        <Card title="Remote-access tools found">
          <div className="space-y-3">
            {setApproved.error ? (
              <p role="alert" className="text-sm text-sev-critical">
                {errorMessage(setApproved.error)}
              </p>
            ) : null}
            <DataTable
              caption="Remote-access tools found"
              columns={columns}
              rows={o.findings}
              getRowId={(f) => f.tool.key}
              searchable
              searchPlaceholder="Search tools or computers"
              exportFileName="rmm-guard"
              emptyState={<EmptyState compact title="No remote-access tools found" description="None of the computers reporting to SCIAT has a known RMM or remote-access tool installed or running." />}
            />
            <div className="text-sm">
              <span className="font-medium">Approved for this organization: </span>
              {approvedNames.length ? approvedNames.join(", ") : <span className="text-fg-muted">none yet</span>}
            </div>
          </div>
        </Card>
      ) : null}
      {blocking && organizationId && o ? <BlockDialog organizationId={organizationId} finding={blocking} appControl={o.appControl} onClose={() => setBlocking(null)} /> : null}
    </div>
  );
}
