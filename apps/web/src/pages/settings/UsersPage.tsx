import type { RoleBinding, RoleKey } from "@bloody/contracts";
import { ShieldCheck, Trash2, UserPlus, Users, UsersRound, X } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { errorMessage } from "../../api/client";
import {
  useAddTeamMember,
  useCreateTeam,
  useCreateUser,
  useDeleteTeam,
  useGrantTeamRole,
  useGrantUserRole,
  useRemoveTeamMember,
  useRevokeTeamRole,
  useRevokeUserRole,
  useTeams,
  useUpdateUser,
  useUsers,
} from "../../api/hooks";
import type { TeamView, UserSummary } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button, IconButton } from "../../components/Button";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { DescriptionList } from "../../components/DescriptionList";
import { EmptyState } from "../../components/EmptyState";
import { Field, Input, Select, Textarea } from "../../components/Form";
import { Dialog, Drawer } from "../../components/Overlay";
import { PageHeader } from "../../components/PageHeader";
import { RelativeTime } from "../../components/RelativeTime";
import { Tabs } from "../../components/Tabs";
import { userLabel } from "../../features/users/useActorName";
import { humanize } from "../../lib/format";
import { bindingLabel, permissionCount, roleLabel, sameBinding, USER_ROLES } from "../../lib/roles";

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/** Role + scope picker. Scopes offered are the organizations where the principal may manage users. */
function BindingPicker({ onAdd, pending, fixedOrganization }: { onAdd: (b: RoleBinding) => void; pending?: boolean; fixedOrganization?: string | null }) {
  const session = useSession();
  const [role, setRole] = useState<RoleKey>("soc_analyst_t1");
  const orgs = session.organizations.filter((o) => session.can("user:write", o.id));
  const tenantOk = session.can("user:write", null);
  const [org, setOrg] = useState<string>(fixedOrganization !== undefined ? (fixedOrganization ?? "") : tenantOk ? "" : (orgs[0]?.id ?? ""));
  return (
    <div className="flex flex-wrap items-end gap-2">
      <label className="flex flex-col text-2xs text-fg-muted">
        Role
        <Select value={role} onChange={(e) => setRole(e.target.value as RoleKey)} className="h-7 w-52" aria-label="Role">
          {USER_ROLES.map((r) => (
            <option key={r} value={r}>
              {roleLabel(r)} ({permissionCount(r)} permissions)
            </option>
          ))}
        </Select>
      </label>
      <label className="flex flex-col text-2xs text-fg-muted">
        Scope
        <Select value={org} onChange={(e) => setOrg(e.target.value)} className="h-7 w-52" aria-label="Scope" disabled={fixedOrganization !== undefined}>
          {tenantOk || fixedOrganization === null ? <option value="">All organizations</option> : null}
          {orgs.map((o) => (
            <option key={o.id} value={o.id}>
              {o.name}
            </option>
          ))}
        </Select>
      </label>
      <Button size="sm" icon={ShieldCheck} loading={pending} onClick={() => onAdd({ role, organizationId: org || null })} disabled={!tenantOk && !org}>
        Grant role
      </Button>
    </div>
  );
}

function BindingList({ bindings, onRevoke, revoking, canRevoke }: { bindings: RoleBinding[]; onRevoke: (b: RoleBinding) => void; revoking: RoleBinding | null; canRevoke: (b: RoleBinding) => boolean }) {
  const session = useSession();
  if (bindings.length === 0) return <p className="text-sm text-fg-subtle">No role bindings — this principal can't see anything yet.</p>;
  return (
    <ul className="divide-y divide-line rounded border border-line">
      {bindings.map((b) => (
        <li key={`${b.role}:${b.organizationId ?? "*"}`} className="flex items-center gap-2 px-2.5 py-1.5 text-sm">
          <span className="min-w-0 flex-1">{bindingLabel(b, session.organizationName)}</span>
          {b.organizationId === null ? <Badge size="xs" tone="warning">tenant-wide</Badge> : null}
          {canRevoke(b) ? <IconButton icon={X} label={`Revoke ${bindingLabel(b, session.organizationName)}`} disabled={revoking !== null && sameBinding(revoking, b)} onClick={() => onRevoke(b)} /> : null}
        </li>
      ))}
    </ul>
  );
}

function UserDrawer({ user, onClose }: { user: UserSummary; onClose: () => void }) {
  const session = useSession();
  const grant = useGrantUserRole();
  const revoke = useRevokeUserRole();
  const update = useUpdateUser();
  const isSelf = user.id === session.principal.id;
  const canWrite = session.canAnywhere("user:write") && !isSelf;
  const [displayName, setDisplayName] = useState(user.displayName ?? "");
  const [title, setTitle] = useState(user.title ?? "");
  const disabled = user.status === "disabled" || user.disabled === true;
  const error = grant.error ?? revoke.error ?? update.error;
  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      title={userLabel(user)}
      subtitle={user.email}
      footer={
        canWrite ? (
          <div className="flex flex-wrap items-center gap-2">
            {error ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {errorMessage(error)}
              </span>
            ) : null}
            <Button size="sm" variant={disabled ? "primary" : "danger"} loading={update.isPending && update.variables?.patch.status !== undefined} onClick={() => update.mutate({ id: user.id, patch: { status: disabled ? "active" : "disabled" } })}>
              {disabled ? "Re-enable user" : "Disable user"}
            </Button>
          </div>
        ) : null
      }
    >
      <div className="space-y-4 p-4">
        <DescriptionList
          items={[
            { label: "Status", value: <Badge tone={disabled ? "neutral" : user.status === "invited" ? "info" : "success"}>{humanize(user.status ?? (disabled ? "disabled" : "active"))}</Badge> },
            { label: "MFA", value: user.mfaEnabled ? <Badge tone="success">Enrolled</Badge> : <Badge tone="danger">Not enrolled</Badge> },
            { label: "Last sign-in", value: user.lastLoginAt ? <RelativeTime value={user.lastLoginAt} /> : "Never" },
            { label: "Home organization", value: user.organizationId ? session.organizationName(user.organizationId) : "Tenant (MSSP / account)" },
            { label: "Teams", value: (user.teams ?? []).map((t) => `${t.name}${t.memberRole === "lead" ? " (lead)" : ""}`).join(", ") || null, wide: true },
            ...(user.locked ? [{ label: "Lockout", value: <Badge tone="warning">Temporarily locked after failed sign-ins</Badge> }] : []),
          ]}
        />
        {canWrite ? (
          <form
            className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              update.mutate({ id: user.id, patch: { displayName: displayName.trim() || null, title: title.trim() || null } });
            }}
          >
            <Field label="Display name">{(p) => <Input {...p} value={displayName} maxLength={200} onChange={(e) => setDisplayName(e.target.value)} />}</Field>
            <Field label="Title">{(p) => <Input {...p} value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} />}</Field>
            <Button type="submit" size="sm" loading={update.isPending && update.variables?.patch.status === undefined}>
              Save
            </Button>
          </form>
        ) : null}
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Role bindings</h3>
          <BindingList
            bindings={user.bindings ?? []}
            revoking={revoke.isPending ? (revoke.variables?.binding ?? null) : null}
            canRevoke={(b) => canWrite && session.can("user:write", b.organizationId)}
            onRevoke={(b) => revoke.mutate({ userId: user.id, binding: b })}
          />
          {isSelf ? <p className="mt-2 text-xs text-fg-subtle">You can't change your own role bindings.</p> : null}
          {canWrite ? (
            <div className="mt-3">
              <BindingPicker pending={grant.isPending} onAdd={(b) => grant.mutate({ userId: user.id, binding: b })} />
              <p className="mt-1 text-2xs text-fg-subtle">You can only grant roles you could hold yourself, in organizations you administer. Every change is audited.</p>
            </div>
          ) : null}
        </section>
      </div>
    </Drawer>
  );
}

function InviteUserDialog({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const create = useCreateUser();
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [title, setTitle] = useState("");
  const [bindings, setBindings] = useState<RoleBinding[]>([]);
  const [submitted, setSubmitted] = useState(false);
  const errors = { email: EMAIL_RE.test(email.trim()) ? null : "Enter a valid e-mail address", bindings: bindings.length > 0 ? null : "Grant at least one role" };
  const homeOrg = bindings.length > 0 && bindings.every((b) => b.organizationId !== null && b.organizationId === bindings[0]!.organizationId) ? bindings[0]!.organizationId : null;
  const submit = () => {
    setSubmitted(true);
    if (errors.email || errors.bindings) return;
    create.mutate({ email: email.trim().toLowerCase(), displayName: displayName.trim() || null, title: title.trim() || null, organizationId: homeOrg, roles: bindings }, { onSuccess: () => onClose() });
  };
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Invite user"
      description="The user receives an invitation to set a password (or signs in with SSO). MFA enrolment is enforced at first sign-in when your policy requires it."
      footer={
        <>
          {create.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(create.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" icon={UserPlus} loading={create.isPending} onClick={submit}>
            Invite
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="E-mail" required error={submitted ? errors.email : null} className="sm:col-span-3">
            {(p) => <Input {...p} type="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="analyst@example.com" />}
          </Field>
          <Field label="Display name" className="sm:col-span-2">
            {(p) => <Input {...p} value={displayName} maxLength={200} onChange={(e) => setDisplayName(e.target.value)} />}
          </Field>
          <Field label="Title">{(p) => <Input {...p} value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} />}</Field>
        </div>
        <section>
          <h3 className="mb-1 text-sm font-medium text-fg">
            Roles<span className="ml-0.5 text-sev-critical">*</span>
          </h3>
          {bindings.length > 0 ? (
            <ul className="mb-2 flex flex-wrap gap-1.5">
              {bindings.map((b, i) => (
                <li key={`${b.role}:${b.organizationId ?? "*"}`} className="inline-flex items-center gap-1 rounded-full border border-primary/30 bg-primary-soft py-0.5 pl-2 pr-0.5 text-xs">
                  {bindingLabel(b, session.organizationName)}
                  <IconButton icon={X} size={11} className="h-5 w-5" label={`Remove ${roleLabel(b.role)}`} onClick={() => setBindings((all) => all.filter((_, j) => j !== i))} />
                </li>
              ))}
            </ul>
          ) : null}
          <BindingPicker onAdd={(b) => setBindings((all) => (all.some((x) => sameBinding(x, b)) ? all : [...all, b]))} />
          {submitted && errors.bindings ? <p className="mt-1 text-xs text-sev-critical">{errors.bindings}</p> : null}
        </section>
      </div>
    </Dialog>
  );
}

function TeamDrawer({ team, users, onClose }: { team: TeamView; users: UserSummary[]; onClose: () => void }) {
  const session = useSession();
  const add = useAddTeamMember();
  const remove = useRemoveTeamMember();
  const grant = useGrantTeamRole();
  const revoke = useRevokeTeamRole();
  const del = useDeleteTeam();
  const canWrite = session.can("team:write", team.organizationId);
  const [userId, setUserId] = useState("");
  const [memberRole, setMemberRole] = useState<"member" | "lead">("member");
  const [confirm, setConfirm] = useState(false);
  const candidates = users.filter((u) => !team.members.some((m) => m.userId === u.id));
  const error = add.error ?? remove.error ?? grant.error ?? revoke.error ?? del.error;
  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      title={team.name}
      subtitle={team.organizationId ? session.organizationName(team.organizationId) : "Tenant-wide team"}
      footer={
        canWrite ? (
          <div className="flex flex-wrap items-center gap-2">
            {error ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {errorMessage(error)}
              </span>
            ) : null}
            {confirm ? (
              <>
                <span className="text-sm text-fg-muted">Members lose the team's roles.</span>
                <Button size="sm" onClick={() => setConfirm(false)}>
                  Cancel
                </Button>
                <Button size="sm" variant="danger" loading={del.isPending} onClick={() => del.mutate(team.id, { onSuccess: onClose })}>
                  Delete team
                </Button>
              </>
            ) : (
              <Button size="sm" variant="ghost" icon={Trash2} onClick={() => setConfirm(true)}>
                Delete team
              </Button>
            )}
          </div>
        ) : null
      }
    >
      <div className="space-y-4 p-4">
        {team.description ? <p className="text-sm text-fg-muted">{team.description}</p> : null}
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Members ({team.members.length})</h3>
          {team.members.length === 0 ? (
            <p className="text-sm text-fg-subtle">No members yet.</p>
          ) : (
            <ul className="divide-y divide-line rounded border border-line">
              {team.members.map((m) => (
                <li key={m.userId} className="flex items-center gap-2 px-2.5 py-1.5 text-sm">
                  <span className="min-w-0 flex-1 truncate">
                    {m.displayName ?? m.email}
                    <span className="ml-1 text-xs text-fg-subtle">{m.email}</span>
                  </span>
                  {m.memberRole === "lead" ? <Badge size="xs" tone="info">Lead</Badge> : null}
                  {canWrite ? <IconButton icon={X} label={`Remove ${m.email}`} onClick={() => remove.mutate({ teamId: team.id, userId: m.userId })} /> : null}
                </li>
              ))}
            </ul>
          )}
          {canWrite ? (
            <div className="mt-2 flex flex-wrap items-end gap-2">
              <Select value={userId} onChange={(e) => setUserId(e.target.value)} className="h-7 w-64" aria-label="User to add">
                <option value="">Add a member…</option>
                {candidates.map((u) => (
                  <option key={u.id} value={u.id}>
                    {userLabel(u)} — {u.email}
                  </option>
                ))}
              </Select>
              <Select value={memberRole} onChange={(e) => setMemberRole(e.target.value as "member" | "lead")} className="h-7 w-28" aria-label="Member role">
                <option value="member">Member</option>
                <option value="lead">Lead</option>
              </Select>
              <Button size="sm" disabled={!userId} loading={add.isPending} onClick={() => add.mutate({ teamId: team.id, userId, memberRole }, { onSuccess: () => setUserId("") })}>
                Add
              </Button>
            </div>
          ) : null}
        </section>
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Team roles</h3>
          <p className="mb-2 text-xs text-fg-subtle">Every member inherits these role bindings.</p>
          <BindingList bindings={team.bindings} revoking={revoke.isPending ? (revoke.variables?.binding ?? null) : null} canRevoke={() => canWrite} onRevoke={(b) => revoke.mutate({ teamId: team.id, binding: b })} />
          {canWrite ? (
            <div className="mt-3">
              <BindingPicker pending={grant.isPending} fixedOrganization={team.organizationId ?? undefined} onAdd={(b) => grant.mutate({ teamId: team.id, binding: b })} />
            </div>
          ) : null}
        </section>
      </div>
    </Drawer>
  );
}

function CreateTeamDialog({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const create = useCreateTeam();
  const tenantOk = session.can("team:write", null);
  const orgs = session.organizations.filter((o) => session.can("team:write", o.id));
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [org, setOrg] = useState<string>(tenantOk ? "" : (session.organizationId ?? orgs[0]?.id ?? ""));
  const [submitted, setSubmitted] = useState(false);
  const nameError = name.trim() ? null : "Name is required";
  return (
    <Dialog
      open
      onClose={onClose}
      title="Create team"
      description="Teams group analysts (e.g. Tier 1 EMEA, customer success) so roles and assignments are managed once."
      footer={
        <>
          {create.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(create.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={create.isPending}
            onClick={() => {
              setSubmitted(true);
              if (nameError) return;
              create.mutate({ name: name.trim(), organizationId: org || null, description: description.trim() || null }, { onSuccess: () => onClose() });
            }}
          >
            Create team
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Name" required error={submitted ? nameError : null}>
          {(p) => <Input {...p} autoFocus value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Field label="Scope">
          {(p) => (
            <Select {...p} value={org} onChange={(e) => setOrg(e.target.value)}>
              {tenantOk ? <option value="">Tenant-wide (all organizations)</option> : null}
              {orgs.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Description">{(p) => <Textarea {...p} value={description} maxLength={2000} onChange={(e) => setDescription(e.target.value)} />}</Field>
      </div>
    </Dialog>
  );
}

type View = "users" | "teams";

/** Users & Teams: invite users, role bindings per organization, MFA status, teams and their roles. */
export default function UsersPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const view: View = params.get("tab") === "teams" ? "teams" : "users";
  const users = useUsers({ enabled: session.canAnywhere("user:read") });
  const teams = useTeams({ enabled: session.canAnywhere("user:read") });
  const [inviting, setInviting] = useState(false);
  const [creatingTeam, setCreatingTeam] = useState(false);
  const selectedUser = users.data?.find((u) => u.id === params.get("id")) ?? null;
  const selectedTeam = teams.data?.find((t) => t.id === params.get("team")) ?? null;
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const userColumns = useMemo<DataTableColumn<UserSummary>[]>(
    () => [
      { id: "name", header: "User", accessor: (u) => userLabel(u), hideable: false, cell: (u) => <span><span className="block font-medium text-heading">{userLabel(u)}</span><span className="block text-2xs text-fg-subtle">{u.email}</span></span> },
      { id: "title", header: "Title", accessor: (u) => u.title ?? null, defaultHidden: true },
      { id: "status", header: "Status", accessor: (u) => u.status ?? (u.disabled ? "disabled" : "active"), cell: (u) => <Badge size="xs" tone={u.disabled || u.status === "disabled" ? "neutral" : u.status === "invited" ? "info" : "success"}>{humanize(u.status ?? (u.disabled ? "disabled" : "active"))}</Badge>, filter: { kind: "select", options: ["active", "invited", "disabled"].map((s) => ({ value: s, label: humanize(s) })) } },
      { id: "mfa", header: "MFA", accessor: (u) => (u.mfaEnabled ? "Enrolled" : "Missing"), cell: (u) => (u.mfaEnabled ? <Badge size="xs" tone="success">Enrolled</Badge> : <Badge size="xs" tone="danger">Missing</Badge>), filter: { kind: "select", options: [{ value: "Enrolled", label: "Enrolled" }, { value: "Missing", label: "Missing" }] } },
      {
        id: "roles",
        header: "Roles",
        accessor: (u) => (u.bindings ?? []).map((b) => bindingLabel(b, session.organizationName)).join("; "),
        cell: (u) => (
          <span className="flex max-w-[360px] flex-wrap gap-1">
            {(u.bindings ?? []).slice(0, 4).map((b) => (
              <Badge key={`${b.role}:${b.organizationId ?? "*"}`} size="xs" tone={b.organizationId === null ? "warning" : "outline"} title={bindingLabel(b, session.organizationName)}>
                {roleLabel(b.role)}
                {b.organizationId ? ` · ${session.organizationName(b.organizationId) ?? "org"}` : ""}
              </Badge>
            ))}
            {(u.bindings?.length ?? 0) > 4 ? <span className="text-2xs text-fg-subtle">+{u.bindings!.length - 4}</span> : null}
          </span>
        ),
      },
      { id: "teams", header: "Teams", accessor: (u) => (u.teams ?? []).map((t) => t.name).join(", "), cell: (u) => <span className="text-xs text-fg-muted">{(u.teams ?? []).map((t) => t.name).join(", ") || "—"}</span> },
      { id: "home", header: "Home organization", accessor: (u) => (u.organizationId ? session.organizationName(u.organizationId) : "Tenant"), defaultHidden: true },
      { id: "lastLogin", header: "Last sign-in", accessor: (u) => (u.lastLoginAt ? new Date(u.lastLoginAt) : null), cell: (u) => (u.lastLoginAt ? <RelativeTime value={u.lastLoginAt} /> : <span className="text-fg-subtle">Never</span>) },
    ],
    [session],
  );

  const teamColumns: DataTableColumn<TeamView>[] = [
    { id: "name", header: "Team", accessor: (t) => t.name, hideable: false, cell: (t) => <span><span className="block font-medium text-heading">{t.name}</span>{t.description ? <span className="block max-w-[360px] truncate text-2xs text-fg-subtle">{t.description}</span> : null}</span> },
    { id: "scope", header: "Scope", accessor: (t) => (t.organizationId ? session.organizationName(t.organizationId) : "Tenant-wide") },
    { id: "members", header: "Members", accessor: (t) => t.members.length, align: "right" },
    { id: "leads", header: "Leads", accessor: (t) => t.members.filter((m) => m.memberRole === "lead").map((m) => m.displayName ?? m.email).join(", ") },
    { id: "roles", header: "Roles", accessor: (t) => t.bindings.map((b) => roleLabel(b.role)).join(", "), cell: (t) => <span className="text-xs">{t.bindings.map((b) => bindingLabel(b, session.organizationName)).join("; ") || "—"}</span> },
    { id: "created", header: "Created", accessor: (t) => new Date(t.createdAt), cell: (t) => <RelativeTime value={t.createdAt} /> },
  ];

  if (!session.canAnywhere("user:read")) {
    return (
      <div>
        <PageHeader title="Users & Teams" />
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState icon={Users} title="You don't have access to users" description="Ask an administrator for the user:read permission." />
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Users & Teams"
        subtitle="People, teams and the roles they hold — tenant-wide (MSSP staff) or per customer organization (delegated administration)."
        breadcrumbs={[{ label: "Settings", href: "/settings" }, { label: "Users & Teams" }]}
        actions={
          view === "users" && session.canAnywhere("user:write") ? (
            <Button variant="primary" icon={UserPlus} onClick={() => setInviting(true)}>
              Invite user
            </Button>
          ) : view === "teams" && session.canAnywhere("team:write") ? (
            <Button variant="primary" icon={UsersRound} onClick={() => setCreatingTeam(true)}>
              Create team
            </Button>
          ) : null
        }
      >
        <Tabs<View>
          ariaLabel="Users and teams"
          idPrefix="users"
          value={view}
          onChange={(v) => set("tab", v === "users" ? null : v)}
          tabs={[
            { id: "users", label: "Users", icon: Users, count: users.data ? users.data.length : null },
            { id: "teams", label: "Teams", icon: UsersRound, count: teams.data ? teams.data.length : null },
          ]}
        />
      </PageHeader>
      {view === "users" ? (
        <DataTable
          caption="Users"
          columns={userColumns}
          rows={users.data}
          getRowId={(u) => u.id}
          loading={users.isPending}
          error={users.error}
          onRetry={() => void users.refetch()}
          onRowClick={(u) => set("id", u.id)}
          selectedRowId={selectedUser?.id ?? null}
          initialState={{ sort: { columnId: "name", direction: "asc" } }}
          savedViewsKey="users"
          exportFileName="bloody-users"
          emptyState={<EmptyState icon={Users} title="No users yet" description="Invite analysts and customer administrators, then grant roles per organization." />}
        />
      ) : (
        <DataTable
          caption="Teams"
          columns={teamColumns}
          rows={teams.data}
          getRowId={(t) => t.id}
          loading={teams.isPending}
          error={teams.error}
          onRetry={() => void teams.refetch()}
          onRowClick={(t) => set("team", t.id)}
          selectedRowId={selectedTeam?.id ?? null}
          initialState={{ sort: { columnId: "name", direction: "asc" } }}
          savedViewsKey="teams"
          exportFileName="bloody-teams"
          emptyState={<EmptyState icon={UsersRound} title="No teams yet" description="Group analysts into teams to grant roles and route work once." />}
        />
      )}
      {selectedUser ? <UserDrawer key={selectedUser.id} user={selectedUser} onClose={() => set("id", null)} /> : null}
      {selectedTeam ? <TeamDrawer key={selectedTeam.id} team={selectedTeam} users={users.data ?? []} onClose={() => set("team", null)} /> : null}
      {inviting ? <InviteUserDialog onClose={() => setInviting(false)} /> : null}
      {creatingTeam ? <CreateTeamDialog onClose={() => setCreatingTeam(false)} /> : null}
    </div>
  );
}
