import type { AwarenessAssignment, AwarenessEnrolment, AwarenessLearner } from "@bloody/contracts";
import { BookOpen, Clock, Link2, Mail, Plus, Trash2, UserPlus, Users } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import {
  useAddLearner,
  useAwarenessLessons,
  useAwarenessOverview,
  useCreateAssignment,
  useImportLearners,
  useLearnerLink,
  useRemoveLearner,
  useSendInvitations,
  type AwarenessOverview,
} from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, CopyButton, DataTable, Dialog, Drawer, EmptyState, ErrorState, Field, Input, OrganizationSelect, RelativeTime, StatTile, useDefaultOrganization, type DataTableColumn } from "../../components";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";

type Links = Array<{ enrolmentId: string; name: string; email: string; url: string }>;

function useOrg() {
  return useState<string | null>(useDefaultOrganization("org:read"));
}

function OrgPicker({ value, onChange }: { value: string | null; onChange: (v: string | null) => void }) {
  return (
    <div className="max-w-sm">
      <OrganizationSelect value={value} onChange={onChange} permission="org:read" aria-label="Organization" />
    </div>
  );
}

function LinksDialog({ links, onClose }: { links: Links; onClose: () => void }) {
  const all = links.map((l) => `${l.name} <${l.email}>: ${l.url}`).join("\n");
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Personal training links"
      description="Each learner has a personal link (no password needed). Copy them now: for security only a fingerprint is stored, so you can create a new link later but not see this one again."
      footer={
        <>
          <CopyButton value={all} label="Copy all" />
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      <ul className="max-h-80 space-y-2 overflow-y-auto text-sm">
        {links.map((l) => (
          <li key={l.enrolmentId} className="flex items-center gap-2">
            <div className="min-w-0 flex-1">
              <div className="font-medium">{l.name}</div>
              <div className="truncate font-mono text-xs text-fg-muted">{l.url}</div>
            </div>
            <CopyButton value={l.url} />
          </li>
        ))}
      </ul>
    </Dialog>
  );
}

function NewAssignmentDialog({ organizationId, learners, onClose, onCreated }: { organizationId: string; learners: number; onClose: () => void; onCreated: (links: Links) => void }) {
  const lessons = useAwarenessLessons();
  const create = useCreateAssignment();
  const [title, setTitle] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [due, setDue] = useState("");
  const minutes = (lessons.data?.items ?? []).filter((l) => picked.includes(l.key)).reduce((n, l) => n + l.minutes, 0);
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Assign training"
      description={`Every active learner of the organization (${learners}) gets a personal link. Learners pass a lesson by scoring at least ${lessons.data?.passMark ?? 75}% on its quiz.`}
      footer={
        <>
          {create.error ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(create.error)}
            </span>
          ) : null}
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={title.trim().length < 3 || picked.length === 0}
            onClick={() =>
              create.mutate(
                { organizationId, title: title.trim(), lessons: picked, ...(due ? { dueAt: new Date(`${due}T23:59:59Z`).toISOString() } : {}) },
                { onSuccess: (r) => onCreated(r.links) },
              )
            }
          >
            Assign{minutes ? ` (${minutes} min)` : ""}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Title">{(f) => <Input {...f} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Q4 phishing & fraud" maxLength={200} />}</Field>
          <Field label="Due date (optional)">{(f) => <Input {...f} type="date" value={due} onChange={(e) => setDue(e.target.value)} />}</Field>
        </div>
        <fieldset>
          <legend className="mb-1 text-sm font-medium">Lessons</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {(lessons.data?.items ?? []).map((l) => (
              <label key={l.key} className="flex cursor-pointer items-start gap-2 rounded border border-line p-2 text-sm hover:bg-canvas">
                <input type="checkbox" className="mt-0.5" checked={picked.includes(l.key)} onChange={(e) => setPicked((p) => (e.target.checked ? [...p, l.key] : p.filter((k) => k !== l.key)))} aria-label={l.title} />
                <span>
                  <span className="font-medium">{l.title}</span>
                  <span className="block text-xs text-fg-muted">{l.minutes} min · {l.questions} questions</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
      </div>
    </Dialog>
  );
}

function AssignmentDrawer({ assignment, canWrite, onClose }: { assignment: AwarenessAssignment; canWrite: boolean; onClose: () => void }) {
  const link = useLearnerLink();
  const [shown, setShown] = useState<Record<string, string>>({});
  const columns: DataTableColumn<AwarenessEnrolment>[] = [
    { id: "name", header: "Learner", accessor: (e) => e.learnerName, hideable: false, cell: (e) => <div><div className="font-medium">{e.learnerName}</div><div className="text-xs text-fg-muted">{e.learnerEmail}</div></div> },
    {
      id: "status",
      header: "Status",
      accessor: (e) => (e.completedAt ? "completed" : e.lessonsPassed ? "in progress" : "not started"),
      cell: (e) => (e.completedAt ? <Badge size="xs" tone="success">Completed</Badge> : e.lessonsPassed ? <Badge size="xs" tone="warning">{e.lessonsPassed} of {assignment.lessons.length}</Badge> : <Badge size="xs">Not started</Badge>),
    },
    { id: "score", header: "Score", align: "right", accessor: (e) => e.averageScore, cell: (e) => (e.averageScore === null ? "—" : `${e.averageScore}%`) },
    { id: "invited", header: "Invited", accessor: (e) => (e.invitedAt ? new Date(e.invitedAt) : null), cell: (e) => (e.invitedAt ? <RelativeTime value={e.invitedAt} /> : "—") },
    {
      id: "link",
      header: "",
      exportable: false,
      sortable: false,
      cell: (e) =>
        !canWrite || e.completedAt ? null : shown[e.id] ? (
          <CopyButton value={shown[e.id]!} label="Copy link" />
        ) : (
          <Button size="xs" variant="ghost" icon={Link2} loading={link.isPending && link.variables === e.id} onClick={() => link.mutate(e.id, { onSuccess: (r) => setShown((s) => ({ ...s, [e.id]: r.url })) })}>
            New link
          </Button>
        ),
    },
  ];
  return (
    <Drawer open onClose={onClose} title={assignment.title} subtitle={`${assignment.lessons.length} lessons${assignment.dueAt ? ` · due ${new Date(assignment.dueAt).toLocaleDateString()}` : ""}`}>
      <div className="space-y-2 p-4">
        <p className="text-xs text-fg-muted">A new link replaces the learner's previous one.</p>
        <DataTable caption="Learners in this assignment" columns={columns} rows={assignment.enrolments} getRowId={(e) => e.id} searchable exportFileName="awareness-assignment" />
      </div>
    </Drawer>
  );
}

function Overview() {
  const session = useSession();
  const [organizationId, setOrganizationId] = useOrg();
  const overview = useAwarenessOverview(organizationId);
  const invite = useSendInvitations();
  const [creating, setCreating] = useState(false);
  const [links, setLinks] = useState<Links | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const canWrite = organizationId ? session.can("org:write", organizationId) : false;
  const o = overview.data;

  const columns: DataTableColumn<AwarenessAssignment>[] = [
    { id: "title", header: "Assignment", accessor: (a) => a.title, hideable: false, cell: (a) => <span className="font-medium">{a.title}</span> },
    { id: "lessons", header: "Lessons", align: "right", accessor: (a) => a.lessons.length },
    {
      id: "progress",
      header: "Completed",
      accessor: (a) => a.enrolments.filter((e) => e.completedAt).length / Math.max(1, a.enrolments.length),
      cell: (a) => {
        const done = a.enrolments.filter((e) => e.completedAt).length;
        return (
          <span className={done === a.enrolments.length ? "font-semibold text-healthy" : ""}>
            {done} of {a.enrolments.length}
          </span>
        );
      },
    },
    { id: "due", header: "Due", accessor: (a) => (a.dueAt ? new Date(a.dueAt) : null), cell: (a) => (a.dueAt ? <span className={new Date(a.dueAt).getTime() < Date.now() && a.enrolments.some((e) => !e.completedAt) ? "text-sev-critical" : ""}>{new Date(a.dueAt).toLocaleDateString()}</span> : "—") },
    { id: "created", header: "Assigned", accessor: (a) => new Date(a.createdAt), cell: (a) => <RelativeTime value={a.createdAt} /> },
    {
      id: "act",
      header: "",
      exportable: false,
      sortable: false,
      cell: (a) =>
        canWrite && o?.canEmail && a.enrolments.some((e) => !e.completedAt) ? (
          <Button size="xs" icon={Mail} loading={invite.isPending && invite.variables === a.id} onClick={(ev) => (ev.stopPropagation(), invite.mutate(a.id))}>
            Email invitations
          </Button>
        ) : null,
    },
  ];
  const assignment = open ? o?.assignments.find((a) => a.id === open) : undefined;

  return (
    <div className="space-y-4">
      <Card title="Security Awareness Training">
        <div className="space-y-4">
          <p className="max-w-3xl text-sm text-fg-muted">
            Short lessons on phishing, payment fraud, passwords and MFA, SIM-swap and mobile-money fraud, ransomware, safe devices and data protection, each ending with a quiz. Learners open a personal link: no account or password needed.
          </p>
          <div className="flex flex-wrap items-end justify-between gap-3">
            <OrgPicker value={organizationId} onChange={setOrganizationId} />
            {canWrite && o ? (
              <Button variant="primary" icon={Plus} disabled={o.summary.learners === 0} onClick={() => setCreating(true)}>
                Assign training
              </Button>
            ) : null}
          </div>
          {!organizationId ? (
            <EmptyState compact title="Pick an organization" />
          ) : overview.isError ? (
            <ErrorState compact error={overview.error} onRetry={() => void overview.refetch()} />
          ) : o ? (
            <>
              <div className="grid gap-3 sm:grid-cols-4">
                <StatTile label="Learners" value={o.summary.learners} icon={Users} href="/awareness/learners" />
                <StatTile label="Completion" value={o.summary.completionRate ?? 0} format={(v) => (o.summary.completionRate === null ? "—" : `${v}%`)} tone={o.summary.completionRate === null ? "default" : o.summary.completionRate >= 80 ? "healthy" : "medium"} />
                <StatTile label="Average quiz score" value={o.summary.averageScore ?? 0} format={(v) => (o.summary.averageScore === null ? "—" : `${v}%`)} />
                <StatTile label="Overdue" value={o.summary.overdue} icon={Clock} tone={o.summary.overdue ? "high" : "healthy"} />
              </div>
              {o.summary.learners === 0 ? <p className="text-sm text-fg-muted">No learners yet: add the organization's people under Learners (or import them from its directory) before assigning training.</p> : null}
              {!o.canEmail ? <p className="text-sm text-fg-muted">Email is not configured on this platform (SMTP), so share the personal links shown after assigning, or create a new link per learner.</p> : null}
              {invite.data ? <p role="status" className="text-sm">Invitations sent: {invite.data.sent}{invite.data.failed ? `, ${invite.data.failed} failed` : ""}.</p> : null}
              {invite.error ? <p role="alert" className="text-sm text-sev-critical">{errorMessage(invite.error)}</p> : null}
            </>
          ) : null}
        </div>
      </Card>
      {organizationId && o ? (
        <Card title="Assignments">
          <DataTable caption="Assignments" columns={columns} rows={o.assignments} getRowId={(a) => a.id} onRowClick={(a) => setOpen(a.id)} emptyState={<EmptyState compact icon={BookOpen} title="No training assigned yet" />} />
        </Card>
      ) : null}
      {creating && organizationId && o ? (
        <NewAssignmentDialog
          organizationId={organizationId}
          learners={o.summary.learners}
          onClose={() => setCreating(false)}
          onCreated={(l) => {
            setCreating(false);
            setLinks(l);
          }}
        />
      ) : null}
      {links ? <LinksDialog links={links} onClose={() => setLinks(null)} /> : null}
      {assignment ? <AssignmentDrawer assignment={assignment} canWrite={canWrite} onClose={() => setOpen(null)} /> : null}
    </div>
  );
}

function AddLearnerDialog({ organizationId, onClose }: { organizationId: string; onClose: () => void }) {
  const add = useAddLearner();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  return (
    <Dialog
      open
      onClose={onClose}
      title="Add a learner"
      footer={
        <>
          {add.error ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(add.error)}
            </span>
          ) : null}
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={add.isPending} disabled={!name.trim() || !email.includes("@")} onClick={() => add.mutate({ organizationId, name: name.trim(), email: email.trim() }, { onSuccess: onClose })}>
            Add learner
          </Button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name">{(f) => <Input {...f} value={name} onChange={(e) => setName(e.target.value)} maxLength={200} />}</Field>
        <Field label="Email">{(f) => <Input {...f} type="email" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={320} />}</Field>
      </div>
    </Dialog>
  );
}

function Learners() {
  const session = useSession();
  const [organizationId, setOrganizationId] = useOrg();
  const overview = useAwarenessOverview(organizationId);
  const importer = useImportLearners();
  const remove = useRemoveLearner();
  const [adding, setAdding] = useState(false);
  const canWrite = organizationId ? session.can("org:write", organizationId) : false;
  const o: AwarenessOverview | undefined = overview.data;
  const columns: DataTableColumn<AwarenessLearner>[] = [
    { id: "name", header: "Name", accessor: (l) => l.name, hideable: false, cell: (l) => <span className="font-medium">{l.name}</span> },
    { id: "email", header: "Email", accessor: (l) => l.email },
    { id: "source", header: "Source", accessor: (l) => (l.source === "directory" ? "Directory" : "Added by hand") },
    { id: "done", header: "Completed", align: "right", accessor: (l) => l.completed, cell: (l) => `${l.completed} of ${l.assigned}` },
    { id: "score", header: "Average score", align: "right", accessor: (l) => l.averageScore, cell: (l) => (l.averageScore === null ? "—" : `${l.averageScore}%`) },
    {
      id: "remove",
      header: "",
      exportable: false,
      sortable: false,
      cell: (l) => (canWrite ? <Button size="xs" variant="ghost" icon={Trash2} aria-label={`Remove ${l.name}`} onClick={() => remove.mutate(l.id)} /> : null),
    },
  ];
  return (
    <Card title="Learners">
      <div className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <OrgPicker value={organizationId} onChange={setOrganizationId} />
          {canWrite && organizationId ? (
            <span className="flex gap-2">
              <Button icon={Users} loading={importer.isPending} onClick={() => importer.mutate(organizationId)}>
                Import from directory
              </Button>
              <Button variant="primary" icon={UserPlus} onClick={() => setAdding(true)}>
                Add learner
              </Button>
            </span>
          ) : null}
        </div>
        {importer.data ? <p role="status" className="text-sm">{importer.data.added ? `${importer.data.added} learner${importer.data.added === 1 ? "" : "s"} imported from the directory.` : "Everyone in the directory is already a learner."}</p> : null}
        {overview.isError ? <ErrorState compact error={overview.error} onRetry={() => void overview.refetch()} /> : null}
        {organizationId ? (
          <DataTable
            caption="Learners"
            columns={columns}
            rows={o?.learners}
            loading={overview.isPending}
            getRowId={(l) => l.id}
            searchable
            exportFileName="awareness-learners"
            emptyState={<EmptyState compact title="No learners yet" description="Import the organization's users from its connected directory (Entra ID, Okta, Google) or add people by hand." />}
          />
        ) : (
          <EmptyState compact title="Pick an organization" />
        )}
      </div>
      {adding && organizationId ? <AddLearnerDialog organizationId={organizationId} onClose={() => setAdding(false)} /> : null}
    </Card>
  );
}

function Lessons() {
  const lessons = useAwarenessLessons();
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {(lessons.data?.items ?? []).map((l) => (
        <Card key={l.key} title={l.title}>
          <p className="text-sm text-fg-muted">{l.summary}</p>
          <p className="mt-2 text-xs text-fg-subtle">
            {l.minutes} minutes · {l.questions}-question quiz · pass mark {lessons.data?.passMark}%
          </p>
        </Card>
      ))}
    </div>
  );
}

/** Security Awareness Training workspace: assignments, learners, lesson library. */
export default function AwarenessPage() {
  return <ModuleWorkspace moduleId="sat" sections={{ "": () => <Overview />, learners: () => <Learners />, lessons: () => <Lessons /> }} />;
}

// Re-exported for tests.
export { Overview as AwarenessOverviewSection, Learners as AwarenessLearnersSection };
