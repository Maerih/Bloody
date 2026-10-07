import { CreateOrganizationInput, type Organization } from "@bloody/contracts";
import { Building2, LayoutDashboard, Plus } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { errorMessage } from "../api/client";
import { useCreateOrganization, useOrganizations, useUpdateOrganization } from "../api/hooks";
import { useSession } from "../app/session";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { DataTable, type DataTableColumn } from "../components/DataTable";
import { DescriptionList } from "../components/DescriptionList";
import { EmptyState } from "../components/EmptyState";
import { Field, Input, Select } from "../components/Form";
import { Dialog, Drawer } from "../components/Overlay";
import { PageHeader } from "../components/PageHeader";
import { formatDate, formatDateTime, slugify } from "../lib/format";

const RETENTION_PRESETS = [14, 30, 90, 180, 365, 730];

/** Organizations (customers / business units) of the account, with create & edit. */
export default function OrganizationsPage() {
  const session = useSession();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const orgs = useOrganizations();
  const canCreate = session.can("org:write", null);
  const [createOpen, setCreateOpen] = useState(params.get("create") === "1" && canCreate);
  const selectedId = params.get("id");
  const list = orgs.data ?? (orgs.isError ? undefined : session.organizations);
  const selected = list?.find((o) => o.id === selectedId) ?? null;
  const byId = useMemo(() => new Map((list ?? []).map((o) => [o.id, o])), [list]);

  const setParam = (key: string, value: string | null) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value === null) next.delete(key);
      else next.set(key, value);
      return next;
    });

  const columns: DataTableColumn<Organization>[] = [
    {
      id: "name",
      header: "Organization",
      accessor: (o) => o.name,
      hideable: false,
      cell: (o) => (
        <span className="flex items-center gap-2">
          <Building2 size={13} className="text-fg-muted" aria-hidden />
          <span className="font-medium text-heading">{o.name}</span>
          {o.id === session.organizationId ? <Badge tone="info" size="xs">Current</Badge> : null}
        </span>
      ),
    },
    { id: "slug", header: "Slug", accessor: (o) => o.slug, cell: (o) => <span className="font-mono text-sm text-fg-muted">{o.slug}</span> },
    { id: "parent", header: "Parent", accessor: (o) => (o.parentOrganizationId ? (byId.get(o.parentOrganizationId)?.name ?? "—") : null) },
    { id: "retention", header: "Retention", accessor: (o) => o.retentionDays, align: "right", cell: (o) => `${o.retentionDays} days` },
    { id: "created", header: "Created", accessor: (o) => new Date(o.createdAt), cell: (o) => formatDate(o.createdAt) },
    {
      id: "open",
      header: "",
      sortable: false,
      hideable: false,
      cell: (o) => (
        <Button
          size="xs"
          icon={LayoutDashboard}
          onClick={(e) => {
            e.stopPropagation();
            navigate(`/?org=${encodeURIComponent(o.id)}`);
          }}
        >
          Dashboard
        </Button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Organizations"
        subtitle={`${session.account.name} · ${session.account.kind === "mssp" ? "customer organizations you manage" : "business units"}`}
        actions={
          canCreate ? (
            <Button variant="primary" icon={Plus} onClick={() => setCreateOpen(true)}>
              Create organization
            </Button>
          ) : null
        }
      />
      <DataTable
        caption="Organizations"
        columns={columns}
        rows={list}
        getRowId={(o) => o.id}
        loading={orgs.isPending && !list}
        error={orgs.error}
        onRetry={() => void orgs.refetch()}
        onRowClick={(o) => setParam("id", o.id)}
        selectedRowId={selectedId}
        initialState={{ sort: { columnId: "name", direction: "asc" } }}
        savedViewsKey="organizations"
        exportFileName="bloody-organizations"
        emptyState={
          <EmptyState
            icon={Building2}
            title="No organizations yet"
            description="Organizations scope every asset, incident, integration and report."
            action={canCreate ? <Button variant="primary" size="sm" icon={Plus} onClick={() => setCreateOpen(true)}>Create organization</Button> : undefined}
          />
        }
      />
      {createOpen ? (
        <CreateOrganizationDialog
          organizations={list ?? []}
          onClose={() => {
            setCreateOpen(false);
            setParam("create", null);
          }}
        />
      ) : null}
      <Drawer open={Boolean(selected)} onClose={() => setParam("id", null)} title={selected?.name ?? "Organization"} subtitle={selected?.slug} width="md">
        {selected ? <OrganizationDetail org={selected} organizations={list ?? []} /> : null}
      </Drawer>
    </div>
  );
}

function OrganizationDetail({ org, organizations }: { org: Organization; organizations: Organization[] }) {
  const session = useSession();
  const navigate = useNavigate();
  const canEdit = session.can("org:write", org.id);
  const update = useUpdateOrganization(org.id);
  const [name, setName] = useState(org.name);
  const [retention, setRetention] = useState(org.retentionDays);
  useEffect(() => {
    setName(org.name);
    setRetention(org.retentionDays);
  }, [org]);
  const dirty = name.trim() !== org.name || retention !== org.retentionDays;
  const parent = org.parentOrganizationId ? organizations.find((o) => o.id === org.parentOrganizationId) : null;
  return (
    <div className="space-y-4 p-4">
      <DescriptionList
        items={[
          { label: "Organization ID", value: <span className="font-mono text-xs">{org.id}</span>, wide: true },
          { label: "Parent", value: parent?.name ?? null },
          { label: "Created", value: formatDateTime(org.createdAt) },
        ]}
      />
      <Button size="sm" icon={LayoutDashboard} onClick={() => navigate(`/?org=${encodeURIComponent(org.id)}`)}>
        Open Command Center for {org.name}
      </Button>
      <form
        className="space-y-3 border-t border-line pt-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (dirty) update.mutate({ name: name.trim(), retentionDays: retention });
        }}
      >
        <Field label="Name">{(p) => <Input {...p} value={name} disabled={!canEdit} maxLength={200} onChange={(e) => setName(e.target.value)} />}</Field>
        <Field label="Data retention" hint="Applies to events and alerts of this organization. Plan limits still apply.">
          {(p) => (
            <Select {...p} value={retention} disabled={!canEdit} onChange={(e) => setRetention(Number(e.target.value))}>
              {[...new Set([...RETENTION_PRESETS, org.retentionDays])].sort((a, b) => a - b).map((d) => (
                <option key={d} value={d}>
                  {d} days
                </option>
              ))}
            </Select>
          )}
        </Field>
        {update.isError ? <p className="text-sm text-sev-critical">{errorMessage(update.error)}</p> : null}
        {update.isSuccess && !dirty ? <p className="text-sm text-healthy">Saved.</p> : null}
        {canEdit ? (
          <Button type="submit" variant="primary" size="sm" disabled={!dirty || name.trim().length === 0} loading={update.isPending}>
            Save changes
          </Button>
        ) : (
          <p className="text-xs text-fg-subtle">You have read-only access to this organization.</p>
        )}
      </form>
    </div>
  );
}

function CreateOrganizationDialog({ organizations, onClose }: { organizations: Organization[]; onClose: () => void }) {
  const navigate = useNavigate();
  const create = useCreateOrganization();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [retentionDays, setRetentionDays] = useState(90);
  const [parentId, setParentId] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const input = { name: name.trim(), slug, retentionDays, parentOrganizationId: parentId || null };
  const parsed = CreateOrganizationInput.safeParse(input);
  const fieldErrors = parsed.success ? {} : parsed.error.flatten().fieldErrors;
  const slugTaken = organizations.some((o) => o.slug === slug);
  const err = (key: keyof typeof fieldErrors) => (submitted ? (fieldErrors[key]?.[0] ?? null) : null);

  const submit = () => {
    setSubmitted(true);
    if (!parsed.success || slugTaken) return;
    create.mutate(parsed.data, {
      onSuccess: (org) => {
        onClose();
        navigate(`/organizations?id=${encodeURIComponent(org.id)}`);
      },
    });
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title="Create organization"
      description="A customer or business unit. All data, users and integrations are scoped to it."
      footer={
        <>
          {create.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(create.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={create.isPending}>
            Create
          </Button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field label="Name" required error={err("name")}>
          {(p) => (
            <Input
              {...p}
              autoFocus
              value={name}
              maxLength={200}
              onChange={(e) => {
                setName(e.target.value);
                if (!slugTouched) setSlug(slugify(e.target.value));
              }}
            />
          )}
        </Field>
        <Field
          label="Slug"
          required
          hint="Lowercase letters, numbers and dashes. Used in URLs and storage paths."
          error={submitted && slugTaken ? "This slug is already in use" : err("slug") ? "Use 2–63 lowercase letters, numbers or dashes" : null}
        >
          {(p) => (
            <Input
              {...p}
              value={slug}
              maxLength={63}
              className="font-mono"
              onChange={(e) => {
                setSlug(e.target.value.toLowerCase());
                setSlugTouched(true);
              }}
            />
          )}
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Data retention">
            {(p) => (
              <Select {...p} value={retentionDays} onChange={(e) => setRetentionDays(Number(e.target.value))}>
                {RETENTION_PRESETS.map((d) => (
                  <option key={d} value={d}>
                    {d} days
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Parent organization">
            {(p) => (
              <Select {...p} value={parentId} onChange={(e) => setParentId(e.target.value)}>
                <option value="">None (top level)</option>
                {organizations.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
