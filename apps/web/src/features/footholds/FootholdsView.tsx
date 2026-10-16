import { AUTORUN_KIND_LABELS, type Foothold, type FootholdVerdict } from "@bloody/contracts";
import { CheckCircle2, ShieldAlert, Skull, Undo2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useFootholdsOverview, useSetFootholdVerdict } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, DataTable, Drawer, EmptyState, ErrorState, Field, OrganizationSelect, RelativeTime, StatTile, Textarea, useDefaultOrganization, type BadgeTone, type DataTableColumn } from "../../components";

const LEVEL_TONE: Record<Foothold["assessment"]["level"], BadgeTone> = { high: "danger", medium: "warning", low: "neutral" };

function Rating({ f }: { f: Foothold }) {
  if (f.verdict?.verdict === "malicious") return <Badge size="xs" tone="danger" icon={Skull}>Malicious</Badge>;
  if (f.verdict?.verdict === "expected") return <Badge size="xs" tone="success">Expected</Badge>;
  return (
    <Badge size="xs" tone={LEVEL_TONE[f.assessment.level]}>
      {f.assessment.level === "low" ? "Low" : f.assessment.level === "medium" ? "Suspicious" : "Highly suspicious"}
    </Badge>
  );
}

function FootholdDrawer({ organizationId, f, canWrite, onClose }: { organizationId: string; f: Foothold; canWrite: boolean; onClose: () => void }) {
  const setVerdict = useSetFootholdVerdict();
  const [note, setNote] = useState(f.verdict?.note ?? "");
  const decide = (verdict: FootholdVerdict | null) =>
    setVerdict.mutate({ organizationId, fingerprints: [f.fingerprint], verdict, ...(note.trim() ? { note: note.trim() } : {}) }, { onSuccess: onClose });
  return (
    <Drawer
      open
      onClose={onClose}
      title={f.name}
      subtitle={`${AUTORUN_KIND_LABELS[f.kind]} on ${f.endpointCount} computer${f.endpointCount === 1 ? "" : "s"}`}
      footer={
        canWrite ? (
          <div className="flex flex-wrap items-center gap-2">
            {setVerdict.error ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {errorMessage(setVerdict.error)}
              </span>
            ) : null}
            {f.verdict ? (
              <Button variant="ghost" icon={Undo2} loading={setVerdict.isPending} onClick={() => decide(null)}>
                Clear verdict
              </Button>
            ) : null}
            <Button variant="secondary" icon={CheckCircle2} loading={setVerdict.isPending} onClick={() => decide("expected")}>
              Mark expected
            </Button>
            <Button variant="danger" icon={Skull} loading={setVerdict.isPending} onClick={() => decide("malicious")}>
              Mark malicious
            </Button>
          </div>
        ) : undefined
      }
    >
      <div className="space-y-4 p-4 text-sm">
        <div className="flex items-center gap-2">
          <Rating f={f} />
          <span className="text-fg-muted">Score {f.assessment.score} / 100</span>
        </div>
        <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1.5">
          <dt className="text-fg-muted">Runs</dt>
          <dd className="break-all font-mono text-xs">{f.command ?? "—"}</dd>
          <dt className="text-fg-muted">Registered in</dt>
          <dd className="break-all font-mono text-xs">{f.location}</dd>
          {f.signed !== null ? (
            <>
              <dt className="text-fg-muted">Signature</dt>
              <dd>{f.signed ? `Signed${f.signer ? ` by ${f.signer}` : ""}` : "Not signed by a trusted publisher"}</dd>
            </>
          ) : null}
          <dt className="text-fg-muted">First seen</dt>
          <dd>
            <RelativeTime value={f.firstSeen} />
            {f.isNew ? " — added after the computer's baseline" : " — present since SCIAT started watching"}
          </dd>
        </dl>
        <div>
          <div className="mb-1 font-medium">Why it was rated this way</div>
          {f.assessment.reasons.length ? (
            <ul className="space-y-1">
              {f.assessment.reasons.map((r) => (
                <li key={r.text} className="flex justify-between gap-3">
                  <span>{r.text}</span>
                  <span className="text-fg-muted">+{r.points}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-fg-muted">Nothing unusual about where it runs from or what it runs.</p>
          )}
        </div>
        <div>
          <div className="mb-1 font-medium">Computers</div>
          <ul aria-label="Computers with this entry" className="space-y-1">
            {f.endpoints.map((e) => (
              <li key={e.agentId} className="flex justify-between gap-3">
                <span>
                  <span className="font-medium">{e.hostname}</span>
                  {e.user ? <span className="text-fg-muted"> · {e.user}</span> : null}
                  {!e.baseline ? (
                    <Badge size="xs" tone="info" className="ml-2">
                      New
                    </Badge>
                  ) : null}
                </span>
                <span className="text-fg-muted">
                  since <RelativeTime value={e.firstSeen} />
                </span>
              </li>
            ))}
          </ul>
          {f.endpointCount > f.endpoints.length ? <p className="mt-1 text-fg-muted">…and {f.endpointCount - f.endpoints.length} more.</p> : null}
        </div>
        {f.verdict ? (
          <p className="text-fg-muted">
            Marked {f.verdict.verdict} by {f.verdict.by ?? "someone"} <RelativeTime value={f.verdict.at} />
            {f.verdict.note ? `: “${f.verdict.note}”` : "."}
          </p>
        ) : null}
        {canWrite ? (
          <Field label="Note (optional)" hint="Saved with the verdict, e.g. the ticket or who confirmed it.">
            {(field) => <Textarea {...field} rows={2} value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />}
          </Field>
        ) : null}
        {f.verdict?.verdict === "malicious" || (!f.verdict && f.assessment.level === "high") ? (
          <p className="rounded border border-sev-critical/40 bg-sev-critical/5 p-3">
            If nobody can explain this entry, isolate the affected computers from{" "}
            <Link to="/edr" className="font-medium text-brand hover:underline">
              EDR → Endpoints &amp; agents
            </Link>
            , then remove the entry. Marking it malicious makes it stand out — and alert — on every other computer where it appears.
          </p>
        ) : null}
      </div>
    </Drawer>
  );
}

/** EDR → Persistent Footholds: autostart entries on the organization's computers, graded and reviewable. */
export function FootholdsView() {
  const session = useSession();
  const [organizationId, setOrganizationId] = useState<string | null>(useDefaultOrganization("asset:read"));
  const [open, setOpen] = useState<string | null>(null);
  const overview = useFootholdsOverview(organizationId);
  const canWrite = organizationId ? session.can("asset:write", organizationId) : false;
  const o = overview.data;
  const selected = o?.footholds.find((f) => f.fingerprint === open) ?? null;

  const columns: DataTableColumn<Foothold>[] = [
    {
      id: "entry",
      header: "Entry",
      accessor: (f) => `${f.name} ${f.command ?? ""}`,
      hideable: false,
      cell: (f) => (
        <div className="min-w-0 max-w-xl">
          <div className="font-medium">
            {f.name}
            {f.isNew ? (
              <Badge size="xs" tone="info" className="ml-2">
                New
              </Badge>
            ) : null}
          </div>
          <div className="truncate font-mono text-xs text-fg-muted" title={f.command ?? undefined}>
            {f.command ?? f.location}
          </div>
        </div>
      ),
    },
    {
      id: "kind",
      header: "Type",
      accessor: (f) => AUTORUN_KIND_LABELS[f.kind],
      filter: { kind: "select", options: Object.values(AUTORUN_KIND_LABELS).map((l) => ({ value: l, label: l })) },
    },
    {
      id: "rating",
      header: "Rating",
      accessor: (f) => (f.verdict ? f.verdict.verdict : f.assessment.level),
      cell: (f) => <Rating f={f} />,
      filter: {
        kind: "select",
        options: [
          { value: "malicious", label: "Malicious" },
          { value: "high", label: "Highly suspicious" },
          { value: "medium", label: "Suspicious" },
          { value: "low", label: "Low" },
          { value: "expected", label: "Expected" },
        ],
      },
    },
    { id: "why", header: "Why", accessor: (f) => f.assessment.reasons.map((r) => r.text).join("; "), cell: (f) => <span className="text-xs">{f.assessment.reasons[0]?.text ?? "—"}</span> },
    { id: "computers", header: "Computers", accessor: (f) => f.endpointCount, cell: (f) => (f.endpointCount === 1 ? f.endpoints[0]!.hostname : `${f.endpointCount} computers`) },
    { id: "first", header: "First seen", accessor: (f) => new Date(f.firstSeen), cell: (f) => <RelativeTime value={f.firstSeen} /> },
  ];

  return (
    <div className="space-y-4">
      <Card title="Persistent Footholds">
        <div className="space-y-4">
          <p className="max-w-3xl text-sm text-fg-muted">
            Attackers make sure they come back after a reboot: a Run key, a scheduled task, a service, a launch daemon, a cron job or an SSH key. The SCIAT Agent reports every autostart entry; entries
            added after a computer's first report are marked new, and each one is rated on the traits attackers rely on. Mark what you recognise as expected — once for every computer — and anything
            hostile as malicious.
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
              <div className="grid gap-3 sm:grid-cols-5">
                <StatTile label="Suspicious, not reviewed" value={o.summary.suspicious} tone={o.summary.suspicious > 0 ? "high" : "healthy"} />
                <StatTile label="Marked malicious" value={o.summary.malicious} tone={o.summary.malicious > 0 ? "critical" : "default"} />
                <StatTile label="New in the last 7 days" value={o.summary.newLast7Days} tone={o.summary.newLast7Days > 0 ? "medium" : "default"} />
                <StatTile label="Autostart entries" value={o.summary.entries} />
                <StatTile label="Computers reporting" value={o.summary.endpointsReporting} />
              </div>
              {o.summary.endpointsReporting === 0 ? (
                <p className="text-sm text-fg-muted">
                  No computer has reported its autostart entries yet. They come with the inventory the SCIAT Agent (version 1.4 or later) sends every 30 minutes; older agents update themselves when
                  automatic updates are on.
                </p>
              ) : null}
              {o.truncated ? <p className="text-sm text-fg-muted">Showing the highest-rated entries only — mark expected software to narrow the list.</p> : null}
            </>
          ) : null}
        </div>
      </Card>
      {organizationId && o ? (
        <Card title={<span className="inline-flex items-center gap-2"><ShieldAlert className="h-4 w-4" aria-hidden /> Autostart entries</span>}>
          <DataTable
            caption="Autostart entries"
            columns={columns}
            rows={o.footholds}
            getRowId={(f) => f.fingerprint}
            onRowClick={(f) => setOpen(f.fingerprint)}
            searchable
            searchPlaceholder="Search entries, commands or computers"
            exportFileName="persistent-footholds"
            emptyState={<EmptyState compact title="No autostart entries reported" description="Entries appear once the organization's computers run SCIAT Agent 1.4 or later." />}
          />
        </Card>
      ) : null}
      {selected && organizationId ? <FootholdDrawer key={selected.fingerprint} organizationId={organizationId} f={selected} canWrite={canWrite} onClose={() => setOpen(null)} /> : null}
    </div>
  );
}
