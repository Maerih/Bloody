import { clsx } from "clsx";
import { CheckCircle2, Circle, CircleDot, Crown, Eye, Lock, MessageSquare, Plus, Send, UserPlus, XCircle, type LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useAddInvestigationNote, useCreateInvestigationTask, useUpdateInvestigation, useUpdateInvestigationTask } from "../../api/hooks";
import type { InvestigationDetail, InvestigationTask, TaskStatus } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/Form";
import { RelativeTime } from "../../components/RelativeTime";
import { formatDate, humanize } from "../../lib/format";
import { actorId, userLabel, useActorName } from "../users/useActorName";

function useCanWrite(investigation: InvestigationDetail): boolean {
  const session = useSession();
  return session.can("investigation:write", investigation.organizationId) && investigation.status !== "closed";
}

// ─── Notes ──────────────────────────────────────────────────────────────────

/** Analyst notes; "customer" visibility is shown in the customer portal and reports. */
export function NotesPanel({ investigation }: { investigation: InvestigationDetail }) {
  const canWrite = useCanWrite(investigation);
  const add = useAddInvestigationNote(investigation.id);
  const { name } = useActorName();
  const [body, setBody] = useState("");
  const [customer, setCustomer] = useState(false);
  const notes = [...investigation.notes].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const submit = () => {
    const text = body.trim();
    if (!text) return;
    add.mutate({ body: text, visibility: customer ? "customer" : "internal" }, { onSuccess: () => { setBody(""); setCustomer(false); } });
  };
  return (
    <div className="space-y-3">
      {canWrite ? (
        <form
          className="space-y-2 rounded border border-line p-3"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
          aria-label="Add note"
        >
          <Textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                submit();
              }
            }}
            maxLength={20_000}
            placeholder="Add a finding, decision or hand-over note… (Ctrl+Enter to add)"
            aria-label="Note"
          />
          <div className="flex flex-wrap items-center gap-3">
            <Checkbox label="Visible to the customer" checked={customer} onChange={(e) => setCustomer(e.target.checked)} />
            {add.isError ? (
              <span role="alert" className="text-sm text-sev-critical">
                {errorMessage(add.error)}
              </span>
            ) : null}
            <Button type="submit" size="sm" variant="primary" icon={Send} className="ml-auto" disabled={!body.trim()} loading={add.isPending}>
              Add note
            </Button>
          </div>
        </form>
      ) : null}
      {notes.length === 0 ? (
        <EmptyState compact icon={MessageSquare} title="No notes yet" description="Notes are timestamped, attributed and added to the timeline." />
      ) : (
        <ul className="space-y-2" aria-label="Notes">
          {notes.map((n) => (
            <li key={n.id} className="rounded border border-line px-3 py-2">
              <div className="mb-1 flex flex-wrap items-center gap-2 text-xs text-fg-muted">
                <span className="font-medium text-fg">{n.authorLabel ?? name(n.authorId)}</span>
                <RelativeTime value={n.createdAt} />
                {n.visibility === "customer" ? (
                  <Badge size="xs" tone="purple" icon={Eye}>
                    Customer-visible
                  </Badge>
                ) : (
                  <Badge size="xs" icon={Lock}>
                    Internal
                  </Badge>
                )}
              </div>
              <p className="whitespace-pre-wrap break-words text-base text-fg">{n.body}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ─── Tasks ──────────────────────────────────────────────────────────────────

const TASK_META: Record<TaskStatus, { icon: LucideIcon; tone: string; label: string }> = {
  open: { icon: Circle, tone: "text-fg-muted", label: "Open" },
  in_progress: { icon: CircleDot, tone: "text-primary", label: "In progress" },
  done: { icon: CheckCircle2, tone: "text-healthy", label: "Done" },
  cancelled: { icon: XCircle, tone: "text-fg-subtle", label: "Cancelled" },
};
const NEXT_STATUS: Record<TaskStatus, TaskStatus> = { open: "in_progress", in_progress: "done", done: "open", cancelled: "open" };

function NewTaskForm({ investigation, onDone }: { investigation: InvestigationDetail; onDone: () => void }) {
  const create = useCreateInvestigationTask(investigation.id);
  const { users } = useActorName();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [assigneeId, setAssigneeId] = useState("");
  const [due, setDue] = useState("");
  const dueIso = due ? new Date(`${due}T17:00:00`).toISOString() : undefined;
  const valid = title.trim().length >= 2 && (!due || Date.parse(`${due}T17:00:00`) > Date.now() - 86_400_000);
  return (
    <form
      className="grid grid-cols-1 gap-2 rounded border border-line p-3 sm:grid-cols-[minmax(0,1fr)_180px_150px]"
      onSubmit={(e) => {
        e.preventDefault();
        if (!valid) return;
        create.mutate({ title: title.trim(), ...(description.trim() ? { description: description.trim() } : {}), ...(assigneeId ? { assigneeId } : {}), ...(dueIso ? { dueAt: dueIso } : {}) }, { onSuccess: onDone });
      }}
      aria-label="New task"
    >
      <Field label="Task" required>
        {(p) => <Input {...p} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={300} placeholder="Collect memory image from fin-ws-07" autoFocus />}
      </Field>
      <Field label="Assignee">
        {(p) => (
          <Select {...p} value={assigneeId} onChange={(e) => setAssigneeId(e.target.value)}>
            <option value="">Unassigned</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {userLabel(u)}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label="Due">{(p) => <Input {...p} type="date" value={due} onChange={(e) => setDue(e.target.value)} />}</Field>
      <Field label="Details" className="sm:col-span-3">
        {(p) => <Textarea {...p} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={5000} className="min-h-[48px]" />}
      </Field>
      <div className="flex items-center gap-2 sm:col-span-3">
        {create.isError ? (
          <span role="alert" className="text-sm text-sev-critical">
            {errorMessage(create.error)}
          </span>
        ) : null}
        <Button size="sm" className="ml-auto" onClick={onDone}>
          Cancel
        </Button>
        <Button type="submit" size="sm" variant="primary" icon={Plus} disabled={!valid} loading={create.isPending}>
          Add task
        </Button>
      </div>
    </form>
  );
}

export function TasksPanel({ investigation }: { investigation: InvestigationDetail }) {
  const canWrite = useCanWrite(investigation);
  const update = useUpdateInvestigationTask(investigation.id);
  const { name, users } = useActorName();
  const [adding, setAdding] = useState(false);
  const [showDone, setShowDone] = useState(true);
  const tasks = useMemo(() => {
    const order: Record<TaskStatus, number> = { in_progress: 0, open: 1, done: 2, cancelled: 3 };
    return [...investigation.tasks].filter((t) => showDone || (t.status !== "done" && t.status !== "cancelled")).sort((a, b) => order[a.status] - order[b.status] || (a.dueAt ?? "9").localeCompare(b.dueAt ?? "9"));
  }, [investigation.tasks, showDone]);
  const open = investigation.tasks.filter((t) => t.status === "open" || t.status === "in_progress").length;
  const setTask = (t: InvestigationTask, patch: Parameters<typeof update.mutate>[0]["patch"]) => update.mutate({ taskId: t.id, patch });
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm text-fg-muted">
          {open} open of {investigation.tasks.length}
        </p>
        <Checkbox label="Show completed" checked={showDone} onChange={(e) => setShowDone(e.target.checked)} />
        {canWrite && !adding ? (
          <Button size="sm" variant="primary" icon={Plus} className="ml-auto" onClick={() => setAdding(true)}>
            New task
          </Button>
        ) : null}
      </div>
      {adding ? <NewTaskForm investigation={investigation} onDone={() => setAdding(false)} /> : null}
      {update.isError ? (
        <p role="alert" className="text-sm text-sev-critical">
          {errorMessage(update.error)}
        </p>
      ) : null}
      {tasks.length === 0 ? (
        <EmptyState compact icon={CheckCircle2} title={investigation.tasks.length === 0 ? "No tasks yet" : "No open tasks"} description="Break the investigation into owned, dated tasks." />
      ) : (
        <ul className="divide-y divide-line rounded border border-line" aria-label="Tasks">
          {tasks.map((t) => {
            const meta = TASK_META[t.status];
            const overdue = t.overdue ?? (t.dueAt !== null && Date.parse(t.dueAt) < Date.now() && t.status !== "done" && t.status !== "cancelled");
            return (
              <li key={t.id} className="flex items-start gap-2 px-3 py-2" data-status={t.status}>
                <button
                  type="button"
                  className={clsx("mt-0.5 shrink-0", meta.tone, !canWrite && "cursor-default")}
                  disabled={!canWrite || update.isPending}
                  onClick={() => setTask(t, { status: NEXT_STATUS[t.status] })}
                  aria-label={`${meta.label}: mark ${humanize(NEXT_STATUS[t.status]).toLowerCase()}`}
                  title={canWrite ? `Mark ${humanize(NEXT_STATUS[t.status]).toLowerCase()}` : meta.label}
                >
                  <meta.icon size={16} aria-hidden />
                </button>
                <div className="min-w-0 flex-1">
                  <div className={clsx("text-base", t.status === "done" || t.status === "cancelled" ? "text-fg-subtle line-through" : "text-fg")}>{t.title}</div>
                  {t.description ? <p className="whitespace-pre-wrap text-sm text-fg-muted">{t.description}</p> : null}
                  <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-fg-subtle">
                    <span>{meta.label}</span>
                    {t.dueAt ? <span className={overdue ? "font-semibold text-sev-critical" : undefined}>Due {formatDate(t.dueAt)}{overdue ? " · overdue" : ""}</span> : null}
                    {t.completedAt ? <span>Completed <RelativeTime value={t.completedAt} /></span> : null}
                  </div>
                </div>
                {canWrite ? (
                  <Select value={t.assigneeId ?? ""} onChange={(e) => setTask(t, { assigneeId: e.target.value || null })} className="h-7 w-40 text-xs" aria-label={`Assignee for ${t.title}`}>
                    <option value="">Unassigned</option>
                    {t.assigneeId && !users.some((u) => u.id === t.assigneeId) ? <option value={t.assigneeId}>{name(t.assigneeId)}</option> : null}
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {userLabel(u)}
                      </option>
                    ))}
                  </Select>
                ) : (
                  <span className="text-xs text-fg-muted">{t.assigneeId ? name(t.assigneeId) : "Unassigned"}</span>
                )}
                {canWrite && t.status !== "cancelled" && t.status !== "done" ? (
                  <Button size="xs" variant="ghost" onClick={() => setTask(t, { status: "cancelled" })}>
                    Cancel
                  </Button>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

// ─── Collaborators ──────────────────────────────────────────────────────────

interface Collaborator {
  id: string;
  roles: Set<string>;
  notes: number;
  tasks: number;
  evidence: number;
  events: number;
  lastActiveAt: string | null;
}

/** Everyone working the investigation, derived from attributed activity; the lead is assignable. */
export function CollaboratorsPanel({ investigation }: { investigation: InvestigationDetail }) {
  const canWrite = useCanWrite(investigation);
  const update = useUpdateInvestigation(investigation.id);
  const { name, users } = useActorName();
  const [leadId, setLeadId] = useState(investigation.leadId ?? "");

  const people = useMemo(() => {
    const map = new Map<string, Collaborator>();
    const touch = (raw: string | null | undefined, role: string | null, at: string | null, field?: "notes" | "tasks" | "evidence" | "events") => {
      if (!raw || raw === "system" || raw.startsWith("ai") || raw.startsWith("playbook:")) return;
      const id = actorId(raw);
      const c = map.get(id) ?? { id, roles: new Set<string>(), notes: 0, tasks: 0, evidence: 0, events: 0, lastActiveAt: null };
      if (role) c.roles.add(role);
      if (field) c[field] += 1;
      if (at && (!c.lastActiveAt || at > c.lastActiveAt)) c.lastActiveAt = at;
      map.set(id, c);
    };
    touch(investigation.leadId, "Lead", null);
    for (const n of investigation.notes) touch(n.authorId, "Contributor", n.createdAt, "notes");
    for (const t of investigation.tasks) {
      touch(t.assigneeId, "Assignee", t.updatedAt, "tasks");
      touch(t.createdBy, "Contributor", t.createdAt);
    }
    for (const e of investigation.evidence) {
      touch(e.collectedBy, "Evidence collector", e.createdAt, "evidence");
      for (const c of e.custody) touch(c.actor, "Custodian", c.at);
    }
    for (const t of investigation.timeline) touch(t.actorId, null, t.at, "events");
    return [...map.values()].sort((a, b) => Number(b.roles.has("Lead")) - Number(a.roles.has("Lead")) || (b.lastActiveAt ?? "").localeCompare(a.lastActiveAt ?? ""));
  }, [investigation]);

  return (
    <div className="space-y-3">
      {canWrite ? (
        <div className="flex flex-wrap items-end gap-2 rounded border border-line p-3">
          <Field label="Investigation lead" className="min-w-[240px]">
            {(p) => (
              <Select {...p} value={leadId} onChange={(e) => setLeadId(e.target.value)}>
                <option value="">Unassigned</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {userLabel(u)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Button size="sm" icon={UserPlus} disabled={(leadId || null) === investigation.leadId} loading={update.isPending} onClick={() => update.mutate({ leadId: leadId || null })}>
            Assign lead
          </Button>
          {update.isError ? (
            <span role="alert" className="text-sm text-sev-critical">
              {errorMessage(update.error)}
            </span>
          ) : null}
          <p className="w-full text-xs text-fg-muted">Collaborators join by contributing notes, tasks, evidence or actions; every contribution is attributed in the timeline and audit log.</p>
        </div>
      ) : null}
      {people.length === 0 ? (
        <EmptyState compact icon={UserPlus} title="No collaborators yet" description="Assign a lead or add a task to bring analysts in." />
      ) : (
        <ul className="divide-y divide-line rounded border border-line" aria-label="Collaborators">
          {people.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
              <span className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-primary-soft text-xs font-semibold text-primary" aria-hidden>
                {name(c.id).slice(0, 2).toUpperCase()}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block font-medium text-fg">{name(c.id)}</span>
                <span className="block text-xs text-fg-subtle">
                  {[c.notes ? `${c.notes} note(s)` : null, c.tasks ? `${c.tasks} task(s)` : null, c.evidence ? `${c.evidence} evidence item(s)` : null, c.events ? `${c.events} timeline entr${c.events === 1 ? "y" : "ies"}` : null].filter(Boolean).join(" · ") || "No activity yet"}
                </span>
              </span>
              {[...c.roles].map((r) => (
                <Badge key={r} size="xs" tone={r === "Lead" ? "info" : "neutral"} icon={r === "Lead" ? Crown : undefined}>
                  {r}
                </Badge>
              ))}
              {c.lastActiveAt ? <RelativeTime value={c.lastActiveAt} className="text-xs text-fg-subtle" /> : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
