import type { RoleKey } from "@bloody/contracts";
import { KeyRound, Plus, ShieldAlert, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useApiKeys, useCreateApiKey, useRevokeApiKey } from "../../api/hooks";
import type { ApiKeyView, CreateApiKeyResult } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { CopyButton } from "../../components/CopyButton";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { Checkbox, Field, Input, Select } from "../../components/Form";
import { OrganizationSelect, useDefaultOrganization } from "../../components/OrganizationSelect";
import { Dialog } from "../../components/Overlay";
import { PageHeader } from "../../components/PageHeader";
import { RelativeTime } from "../../components/RelativeTime";
import { useActorName } from "../../features/users/useActorName";
import { API_BASE } from "../../api/client";
import { formatDate } from "../../lib/format";
import { API_KEY_ROLES, roleLabel } from "../../lib/roles";

const EXPIRY_OPTIONS = [30, 90, 180, 365, 730];

export function keyState(k: Pick<ApiKeyView, "revokedAt" | "expiresAt" | "active">, now = Date.now()): "active" | "revoked" | "expired" {
  if (k.revokedAt) return "revoked";
  if (k.expiresAt && Date.parse(k.expiresAt) <= now) return "expired";
  return k.active ? "active" : "expired";
}

function CreateKeyDialog({ onClose }: { onClose: () => void }) {
  const create = useCreateApiKey();
  const defaultOrg = useDefaultOrganization("apikey:write", true);
  const [name, setName] = useState("");
  const [org, setOrg] = useState<string | null>(defaultOrg);
  const [roles, setRoles] = useState<RoleKey[]>(["api_service"]);
  const [expires, setExpires] = useState<number | "">(90);
  const [submitted, setSubmitted] = useState(false);
  const [created, setCreated] = useState<CreateApiKeyResult | null>(null);
  const errors = { name: name.trim() ? null : "Name is required", roles: roles.length === 0 ? "Choose at least one role" : roles.length > 10 ? "At most 10 roles" : null };

  if (created) {
    return (
      <Dialog
        open
        onClose={onClose}
        title="API key created"
        description="Copy the key now. Only its SHA-256 hash is stored — it can never be shown again."
        footer={
          <Button variant="primary" onClick={onClose}>
            I stored the key
          </Button>
        }
      >
        <div className="space-y-3">
          <div className="flex items-start gap-2 rounded border border-sev-high/40 bg-sev-high/5 p-2 text-sm">
            <TriangleAlert size={14} className="mt-0.5 shrink-0 text-sev-high" aria-hidden />
            Treat this key like a password: store it in your secret manager or collector configuration. Anyone holding it acts with the roles below.
          </div>
          <div className="flex items-center gap-2">
            <code className="min-w-0 flex-1 break-all rounded border border-line bg-surface-2 px-2 py-1.5 font-mono text-xs" data-testid="new-api-key">
              {created.key}
            </code>
            <CopyButton value={created.key} label="Copy API key" />
          </div>
          <p className="text-xs text-fg-muted">
            Use it as <code>Authorization: Bearer {created.apiKey.prefix}…</code> against <code>{API_BASE}</code>. Roles: {created.apiKey.roles.map((r) => roleLabel(r.role)).join(", ")}.
          </p>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title="Create API key"
      description="Service keys authenticate collectors, ingestion and integrations. They carry only roles you could hold yourself."
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
            icon={KeyRound}
            loading={create.isPending}
            onClick={() => {
              setSubmitted(true);
              if (errors.name || errors.roles) return;
              create.mutate({ name: name.trim(), organizationId: org, roles, ...(expires !== "" ? { expiresInDays: expires } : {}) }, { onSuccess: setCreated });
            }}
          >
            Create key
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Name" required error={submitted ? errors.name : null} hint="Where it is used, e.g. “Vector collector — Frankfurt”.">
          {(p) => <Input {...p} autoFocus value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Field label="Organization" hint="A key bound to one organization can only read or ingest for it.">
          {(p) => <OrganizationSelect {...p} value={org} onChange={setOrg} permission="apikey:write" allowTenantWide tenantWideLabel="All organizations (tenant-wide)" />}
        </Field>
        <fieldset>
          <legend className="mb-1 text-sm font-medium text-fg">
            Roles<span className="ml-0.5 text-sev-critical">*</span>
          </legend>
          <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
            {API_KEY_ROLES.map((r) => (
              <Checkbox key={r} label={roleLabel(r)} checked={roles.includes(r)} onChange={(e) => setRoles((cur) => (e.target.checked ? [...cur, r] : cur.filter((x) => x !== r)))} />
            ))}
          </div>
          {submitted && errors.roles ? <p className="mt-1 text-xs text-sev-critical">{errors.roles}</p> : null}
          <p className="mt-1 text-2xs text-fg-subtle">Ingestion needs only “API service” (event:ingest, asset read/write).</p>
        </fieldset>
        <Field label="Expires">
          {(p) => (
            <Select {...p} value={expires} onChange={(e) => setExpires(e.target.value === "" ? "" : Number(e.target.value))}>
              {EXPIRY_OPTIONS.map((d) => (
                <option key={d} value={d}>
                  In {d} days
                </option>
              ))}
              <option value="">Never (not recommended)</option>
            </Select>
          )}
        </Field>
      </div>
    </Dialog>
  );
}

/** API credentials: service keys (prefix only after creation), scopes, roles, usage and revocation. */
export default function ApiCredentialsPage() {
  const session = useSession();
  const keys = useApiKeys({ enabled: session.canAnywhere("apikey:write") });
  const revoke = useRevokeApiKey();
  const { name } = useActorName();
  const [creating, setCreating] = useState(false);
  const [confirm, setConfirm] = useState<ApiKeyView | null>(null);

  const columns: DataTableColumn<ApiKeyView>[] = [
    { id: "name", header: "Key", accessor: (k) => k.name, hideable: false, cell: (k) => <span><span className="block font-medium text-heading">{k.name}</span><span className="block font-mono text-2xs text-fg-subtle">{k.prefix}…</span></span> },
    {
      id: "state",
      header: "State",
      accessor: (k) => keyState(k),
      cell: (k) => {
        const s = keyState(k);
        return <Badge size="xs" tone={s === "active" ? "success" : s === "revoked" ? "neutral" : "warning"}>{s}</Badge>;
      },
      filter: { kind: "select", options: ["active", "expired", "revoked"].map((s) => ({ value: s, label: s })) },
    },
    { id: "scope", header: "Scope", accessor: (k) => (k.organizationId ? session.organizationName(k.organizationId) : "Tenant-wide") },
    { id: "roles", header: "Roles", accessor: (k) => k.roles.map((r) => roleLabel(r.role)).join(", "), cell: (k) => <span className="text-xs">{k.roles.map((r) => roleLabel(r.role)).join(", ")}</span> },
    { id: "createdBy", header: "Created by", accessor: (k) => name(k.createdBy) },
    { id: "created", header: "Created", accessor: (k) => new Date(k.createdAt), cell: (k) => <RelativeTime value={k.createdAt} /> },
    { id: "lastUsed", header: "Last used", accessor: (k) => (k.lastUsedAt ? new Date(k.lastUsedAt) : null), cell: (k) => (k.lastUsedAt ? <span title={k.lastUsedIp ?? undefined}><RelativeTime value={k.lastUsedAt} />{k.lastUsedIp ? <span className="ml-1 font-mono text-2xs text-fg-subtle">{k.lastUsedIp}</span> : null}</span> : <span className="text-fg-subtle">Never</span>) },
    { id: "expires", header: "Expires", accessor: (k) => (k.expiresAt ? new Date(k.expiresAt) : null), cell: (k) => (k.expiresAt ? formatDate(k.expiresAt) : <span className="text-sev-high">Never</span>) },
    {
      id: "actions",
      header: "",
      sortable: false,
      hideable: false,
      exportable: false,
      cell: (k) =>
        keyState(k) === "active" && session.can("apikey:write", k.organizationId) ? (
          <Button size="xs" variant="ghost" icon={ShieldAlert} onClick={(e) => (e.stopPropagation(), setConfirm(k))}>
            Revoke
          </Button>
        ) : null,
    },
  ];

  if (!session.canAnywhere("apikey:write")) {
    return (
      <div>
        <PageHeader title="API Credentials" />
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState icon={KeyRound} title="You don't have access to API credentials" description="Managing API keys requires the apikey:write permission." />
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="API Credentials"
        subtitle="Service API keys for collectors, ingestion and integrations. Keys are shown once, stored as SHA-256 hashes and can be revoked at any time."
        breadcrumbs={[{ label: "Settings", href: "/settings" }, { label: "API Credentials" }]}
        actions={
          <Button variant="primary" icon={Plus} onClick={() => setCreating(true)}>
            Create API key
          </Button>
        }
      />
      <Card className="mb-3" title="Using a key">
        <pre className="overflow-x-auto rounded border border-line bg-surface-2 p-2 font-mono text-2xs text-fg">{`curl -H "Authorization: Bearer bk_…" -H "Content-Type: application/x-ndjson" \\\n     --data-binary @events.ndjson ${API_BASE}/ingest/<adapter>`}</pre>
      </Card>
      {revoke.isError ? (
        <p role="alert" className="mb-2 text-sm text-sev-critical">
          {errorMessage(revoke.error)}
        </p>
      ) : null}
      <DataTable
        caption="API keys"
        columns={columns}
        rows={keys.data}
        getRowId={(k) => k.id}
        loading={keys.isPending}
        error={keys.error}
        onRetry={() => void keys.refetch()}
        initialState={{ sort: { columnId: "created", direction: "desc" } }}
        savedViewsKey="api-keys"
        exportFileName="bloody-api-keys"
        emptyState={<EmptyState icon={KeyRound} title="No API keys yet" description="Create a key with the API service role for each collector or integration." action={<Button size="sm" variant="primary" icon={Plus} onClick={() => setCreating(true)}>Create API key</Button>} />}
      />
      {creating ? <CreateKeyDialog onClose={() => setCreating(false)} /> : null}
      {confirm ? (
        <Dialog
          open
          size="sm"
          onClose={() => setConfirm(null)}
          title={`Revoke ${confirm.name}?`}
          description="Requests using this key are rejected immediately. This cannot be undone."
          footer={
            <>
              <Button onClick={() => setConfirm(null)}>Cancel</Button>
              <Button variant="danger" loading={revoke.isPending} onClick={() => revoke.mutate(confirm.id, { onSuccess: () => setConfirm(null) })}>
                Revoke key
              </Button>
            </>
          }
        />
      ) : null}
    </div>
  );
}
