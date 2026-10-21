import { ANDROID_PASSWORD_LABELS, ANDROID_PASSWORD_LEVELS, type AndroidPolicySettings, type MobileCompliance, type MobileDevice, type MobileEnrollmentToken, type MobileOverview } from "@bloody/contracts";
import { AlertTriangle, Building2, CheckCircle2, KeyRound, Lock, QrCode as QrIcon, RefreshCw, ShieldAlert, Smartphone, Trash2, Unplug, UserRound } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { errorMessage } from "../../api/client";
import {
  useCreateEnrollmentCode,
  useLinkAndroidEnterprise,
  useMobileOverview,
  useRemoveGoogleAccount,
  useRevokeEnrollmentCode,
  useSaveAndroidPolicy,
  useSaveGoogleAccount,
  useStartAndroidSignup,
  useSyncMobileDevices,
  useUnlinkAndroidEnterprise,
} from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, Checkbox, CopyButton, DataTable, Dialog, Drawer, EmptyState, ErrorState, Field, Input, OrganizationSelect, RelativeTime, Select, SkeletonText, StatTile, Textarea, useDefaultOrganization, type DataTableColumn } from "../../components";
import { QrCode } from "../../components/QrCode";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { RequestActionDialog } from "../../features/response/RequestActionDialog";

const COMPLIANCE: Record<MobileCompliance, { label: string; tone: "success" | "danger" | "warning" | "neutral" | "info" }> = {
  compliant: { label: "Compliant", tone: "success" },
  non_compliant: { label: "Not compliant", tone: "warning" },
  at_risk: { label: "At risk", tone: "danger" },
  stale: { label: "Not reporting", tone: "neutral" },
  pending: { label: "Enrolling", tone: "info" },
};
const SEV_TONE = { critical: "danger", high: "warning", medium: "info", low: "neutral" } as const;

/** Self-service enrollment link for a work profile on a personal phone. */
export const personalEnrollLink = (token: MobileEnrollmentToken) => `https://enterprise.google.com/android/enroll?et=${encodeURIComponent(token.value)}`;

function useMdmOrg() {
  const [params] = useSearchParams();
  return useState<string | null>(params.get("organizationId") ?? useDefaultOrganization("asset:read"));
}

function OrgPicker({ value, onChange }: { value: string | null; onChange: (v: string | null) => void }) {
  return (
    <div className="max-w-sm">
      <OrganizationSelect value={value} onChange={onChange} permission="asset:read" aria-label="Organization" />
    </div>
  );
}

/** Shown on every section until the Google account and the organization's enterprise exist. */
function SetupNeeded({ o }: { o: MobileOverview }) {
  if (o.account.configured && o.enterprise?.status === "active") return null;
  return (
    <EmptyState
      icon={Smartphone}
      title={o.account.configured ? "This organization has no Android Enterprise yet" : "Connect your Google account first"}
      description={
        o.account.configured
          ? "Create the customer's Android Enterprise (a short Google sign-up), then enroll phones with a QR code."
          : "Android phones are managed through Google's Android Management API. Connect your Google Cloud service account once; then each customer gets its own Android Enterprise."
      }
      action={
        <Button variant="primary" onClick={() => window.location.assign(`/mdm/setup?organizationId=${o.organizationId}`)}>
          Open setup
        </Button>
      }
    />
  );
}

// ─── Devices ─────────────────────────────────────────────────────────────────

function DeviceDrawer({ device, onClose, onAction }: { device: MobileDevice; onClose: () => void; onAction: () => void }) {
  const session = useSession();
  return (
    <Drawer
      open
      onClose={onClose}
      title={device.name}
      subtitle={[device.assignee ?? device.userName, device.ownership === "personal" ? "Personal phone (work profile)" : device.ownership === "company" ? "Company phone" : null].filter(Boolean).join(" · ")}
      headerActions={
        device.assetId && session.can("response:request", device.organizationId) ? (
          <Button size="sm" icon={Lock} onClick={onAction}>
            Lock / wipe
          </Button>
        ) : null
      }
    >
      <div className="space-y-4 p-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={COMPLIANCE[device.compliance].tone}>{COMPLIANCE[device.compliance].label}</Badge>
          <span className="text-fg-muted">
            Last report <RelativeTime value={device.lastStatusAt} />
          </span>
        </div>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2">
          {[
            ["Model", [device.manufacturer, device.model].filter(Boolean).join(" ") || "—"],
            ["Serial number", device.serialNumber ?? "—"],
            ["Android", device.osVersion ?? "—"],
            ["Security patch", device.securityPatchLevel ?? "—"],
            ["Management", device.managementMode === "PROFILE_OWNER" ? "Work profile" : device.managementMode === "DEVICE_OWNER" ? "Fully managed" : (device.managementMode ?? "—")],
            ["Enrolled", device.enrolledAt ? new Date(device.enrolledAt).toLocaleDateString() : "—"],
          ].map(([k, v]) => (
            <div key={k}>
              <dt className="text-xs text-fg-muted">{k}</dt>
              <dd className="font-medium">{v}</dd>
            </div>
          ))}
        </dl>
        <div>
          <h3 className="mb-2 font-medium">Findings</h3>
          {device.findings.length === 0 ? (
            <p className="inline-flex items-center gap-2 text-healthy">
              <CheckCircle2 className="h-4 w-4" aria-hidden /> Meets the mobile policy
            </p>
          ) : (
            <ul className="space-y-2">
              {device.findings.map((f) => (
                <li key={f.key} className="rounded border border-line p-2">
                  <div className="flex items-center gap-2">
                    <Badge size="xs" tone={SEV_TONE[f.severity]}>
                      {f.severity}
                    </Badge>
                    <span className="font-medium">{f.title}</span>
                  </div>
                  {f.detail ? <p className="mt-1 text-xs text-fg-muted">{f.detail}</p> : null}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Drawer>
  );
}

function Devices() {
  const [org, setOrg] = useMdmOrg();
  const overview = useMobileOverview(org);
  const sync = useSyncMobileDevices();
  const [open, setOpen] = useState<MobileDevice | null>(null);
  const [acting, setActing] = useState<MobileDevice | null>(null);
  const o = overview.data;
  const columns: Array<DataTableColumn<MobileDevice>> = [
    {
      id: "name",
      header: "Device",
      accessor: (d) => d.name,
      sortable: true,
      cell: (d) => (
        <div>
          <div className="font-medium">{d.name}</div>
          <div className="text-xs text-fg-muted">{d.ownership === "personal" ? "Personal · work profile" : "Company phone"}</div>
        </div>
      ),
    },
    { id: "assignee", header: "Assigned to", accessor: (d) => d.assignee ?? d.userName ?? "", sortable: true },
    { id: "os", header: "Android", accessor: (d) => d.osVersion ?? "", sortable: true },
    { id: "patch", header: "Security patch", accessor: (d) => d.securityPatchLevel ?? "", sortable: true },
    { id: "compliance", header: "Compliance", accessor: (d) => COMPLIANCE[d.compliance].label, sortable: true, cell: (d) => <Badge tone={COMPLIANCE[d.compliance].tone}>{COMPLIANCE[d.compliance].label}</Badge> },
    { id: "issues", header: "Issues", accessor: (d) => d.findings.length, sortable: true, align: "right" },
    { id: "last", header: "Last report", accessor: (d) => d.lastStatusAt ?? "", sortable: true, cell: (d) => <RelativeTime value={d.lastStatusAt} /> },
  ];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <OrgPicker value={org} onChange={setOrg} />
        {o?.enterprise?.status === "active" ? (
          <div className="flex items-center gap-3 text-sm text-fg-muted">
            <span>
              Synced <RelativeTime value={o.enterprise.lastSyncAt} />
            </span>
            <Button size="sm" icon={RefreshCw} loading={sync.isPending} onClick={() => org && sync.mutate(org)}>
              Sync now
            </Button>
          </div>
        ) : null}
      </div>
      {sync.error ? <p role="alert" className="text-sm text-sev-critical">{errorMessage(sync.error)}</p> : null}
      {!org ? (
        <EmptyState icon={Building2} title="Choose an organization" />
      ) : overview.isLoading ? (
        <SkeletonText lines={6} />
      ) : overview.error ? (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      ) : o ? (
        <>
          <SetupNeeded o={o} />
          {o.enterprise?.status === "active" ? (
            <>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
                <StatTile label="Phones" value={o.counts.total} icon={Smartphone} />
                <StatTile label="Compliant" value={o.counts.compliant} tone="healthy" icon={CheckCircle2} />
                <StatTile label="Not compliant" value={o.counts.non_compliant} tone="medium" icon={AlertTriangle} />
                <StatTile label="At risk" value={o.counts.at_risk} tone="critical" icon={ShieldAlert} />
                <StatTile label="Not reporting" value={o.counts.stale} icon={RefreshCw} />
              </div>
              {o.enterprise.lastError ? <p role="alert" className="text-sm text-sev-critical">Google: {o.enterprise.lastError}</p> : null}
              <DataTable
                caption="Mobile devices"
                columns={columns}
                rows={o.devices}
                getRowId={(d) => d.id}
                onRowClick={setOpen}
                exportFileName="mobile-devices"
                emptyState={<EmptyState compact icon={QrIcon} title="No phones enrolled yet" description="Create an enrollment QR code under Enroll Devices." />}
              />
            </>
          ) : null}
        </>
      ) : null}
      {open ? <DeviceDrawer device={open} onClose={() => setOpen(null)} onAction={() => setActing(open)} /> : null}
      {acting?.assetId ? (
        <RequestActionDialog
          open
          onClose={() => setActing(null)}
          organizationId={acting.organizationId}
          targets={{ asset: [{ id: acting.assetId, label: acting.name }] }}
          actions={["lock_device", "wipe_device"]}
          defaultAction="lock_device"
          description={
            acting.ownership === "personal"
              ? "Lock takes effect as soon as the phone is online. Wipe removes only the work profile from this personal phone; the owner's own data is untouched. Wipe needs a second person's approval."
              : "Lock takes effect as soon as the phone is online. Wipe factory-resets this company phone and erases everything on it. Wipe needs a second person's approval."
          }
          onSubmitted={() => {
            setActing(null);
            setOpen(null);
          }}
        />
      ) : null}
    </div>
  );
}

// ─── Enroll ──────────────────────────────────────────────────────────────────

function EnrollmentCode({ token, canWrite, organizationId }: { token: MobileEnrollmentToken; canWrite: boolean; organizationId: string }) {
  const revoke = useRevokeEnrollmentCode();
  const [confirm, setConfirm] = useState(false);
  const company = token.ownership === "company";
  return (
    <Card
      title={
        <span className="inline-flex items-center gap-2">
          {company ? <Building2 className="h-4 w-4" aria-hidden /> : <UserRound className="h-4 w-4" aria-hidden />}
          {company ? "Company phone" : "Personal phone (work profile)"}
          {token.assignee ? <span className="font-normal text-fg-muted">for {token.assignee}</span> : null}
        </span>
      }
      actions={
        canWrite ? (
          <Button size="sm" variant="ghost" icon={Trash2} onClick={() => setConfirm(true)}>
            Revoke
          </Button>
        ) : null
      }
    >
      <div className="grid gap-4 text-sm md:grid-cols-[auto_1fr]">
        <QrCode value={company ? token.qrCode : personalEnrollLink(token)} label={`Enrollment QR code${token.assignee ? ` for ${token.assignee}` : ""}`} />
        <div className="space-y-3">
          {company ? (
            <ol className="list-decimal space-y-1 pl-5">
              <li>Start with a new or factory-reset phone (Android 10 or later).</li>
              <li>On the first Welcome screen, tap the same spot six times — a QR scanner opens.</li>
              <li>Connect to Wi-Fi when asked and scan this code. The phone installs Google's Android Device Policy and applies the policy.</li>
            </ol>
          ) : (
            <ol className="list-decimal space-y-1 pl-5">
              <li>On the person's own phone, scan this code with the camera (or open the link below).</li>
              <li>Follow the steps to create a work profile. Work apps get a briefcase badge; personal apps and data stay private.</li>
            </ol>
          )}
          <div>
            <div className="text-xs text-fg-muted">{company ? "Enrollment code (type it if the phone asks for one)" : "Enrollment link"}</div>
            <div className="flex items-center gap-2">
              <code className="break-all font-mono text-xs">{company ? token.value : personalEnrollLink(token)}</code>
              <CopyButton value={company ? token.value : personalEnrollLink(token)} />
            </div>
          </div>
          <p className="text-xs text-fg-muted">
            Valid until {new Date(token.expiresAt).toLocaleString()} · can enroll several phones until then
          </p>
        </div>
      </div>
      {confirm ? (
        <Dialog
          open
          onClose={() => setConfirm(false)}
          title="Revoke this enrollment code?"
          description="Phones already enrolled stay enrolled. No new phone can use the code."
          footer={
            <>
              <Button onClick={() => setConfirm(false)}>Cancel</Button>
              <Button variant="danger" loading={revoke.isPending} onClick={() => revoke.mutate(token.id, { onSuccess: () => setConfirm(false) })}>
                Revoke
              </Button>
            </>
          }
        >
          {revoke.error ? <p role="alert" className="text-sm text-sev-critical">{errorMessage(revoke.error)}</p> : <span className="sr-only">{organizationId}</span>}
        </Dialog>
      ) : null}
    </Card>
  );
}

function Enroll() {
  const session = useSession();
  const [org, setOrg] = useMdmOrg();
  const overview = useMobileOverview(org);
  const create = useCreateEnrollmentCode();
  const [ownership, setOwnership] = useState<"company" | "personal">("company");
  const [assignee, setAssignee] = useState("");
  const [days, setDays] = useState(7);
  const o = overview.data;
  const canWrite = org ? session.can("asset:write", org) : false;
  return (
    <div className="space-y-4">
      <OrgPicker value={org} onChange={setOrg} />
      {!org ? null : overview.isLoading ? (
        <SkeletonText lines={4} />
      ) : overview.error ? (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      ) : o ? (
        <>
          <SetupNeeded o={o} />
          {o.enterprise?.status === "active" ? (
            <>
              {canWrite ? (
                <Card title={<span className="inline-flex items-center gap-2"><QrIcon className="h-4 w-4" aria-hidden /> New enrollment code</span>}>
                  <div className="grid gap-4 text-sm md:grid-cols-4">
                    <Field label="Whose phone">
                      {(f) => (
                        <Select {...f} value={ownership} onChange={(e) => setOwnership(e.target.value as "company" | "personal")}>
                          <option value="company">Company phone — fully managed</option>
                          <option value="personal">Personal phone — work profile only</option>
                        </Select>
                      )}
                    </Field>
                    <Field label="For (optional)" hint="Shown on the device record">
                      {(f) => <Input {...f} value={assignee} maxLength={120} onChange={(e) => setAssignee(e.target.value)} placeholder="Amina Mushi" />}
                    </Field>
                    <Field label="Valid for">
                      {(f) => (
                        <Select {...f} value={days} onChange={(e) => setDays(Number(e.target.value))}>
                          <option value={1}>1 day</option>
                          <option value={7}>7 days</option>
                          <option value={30}>30 days</option>
                          <option value={90}>90 days</option>
                        </Select>
                      )}
                    </Field>
                    <div className="flex items-end">
                      <Button variant="primary" icon={QrIcon} loading={create.isPending} onClick={() => org && create.mutate({ organizationId: org, ownership, validDays: days, ...(assignee.trim() ? { assignee: assignee.trim() } : {}) }, { onSuccess: () => setAssignee("") })}>
                        Create QR code
                      </Button>
                    </div>
                  </div>
                  {create.error ? <p role="alert" className="mt-2 text-sm text-sev-critical">{errorMessage(create.error)}</p> : null}
                </Card>
              ) : null}
              {o.tokens.length === 0 ? (
                <EmptyState compact icon={QrIcon} title="No active enrollment codes" description="Create one above; it shows a QR code to scan on the phone." />
              ) : (
                o.tokens.map((t) => <EnrollmentCode key={t.id} token={t} canWrite={canWrite} organizationId={o.organizationId} />)
              )}
            </>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

// ─── Policy ──────────────────────────────────────────────────────────────────

function PolicyForm({ organizationId, initial, canWrite }: { organizationId: string; initial: AndroidPolicySettings; canWrite: boolean }) {
  const save = useSaveAndroidPolicy();
  const [s, setS] = useState<AndroidPolicySettings>(initial);
  const [saved, setSaved] = useState(false);
  useEffect(() => setS(initial), [initial]);
  const set = <K extends keyof AndroidPolicySettings>(k: K, v: AndroidPolicySettings[K]) => {
    setS((p) => ({ ...p, [k]: v }));
    setSaved(false);
  };
  const toggles: Array<[keyof AndroidPolicySettings, string]> = [
    ["blockUnknownSources", "Block apps from unknown sources (only Google Play)"],
    ["enforcePlayProtect", "Keep Google Play Protect app scanning on"],
    ["blockDeveloperOptions", "Block developer options and USB debugging"],
    ["autoSystemUpdates", "Install Android system updates automatically"],
    ["blockScreenCapture", "Block screenshots and screen recording"],
    ["blockCamera", "Block the camera"],
  ];
  return (
    <Card title="Mobile security baseline" subtitle="Applied to every phone of this organization through Google; compliance limits are checked by SCIAT.">
      <fieldset disabled={!canWrite} className="space-y-5 text-sm">
        <div className="grid gap-4 md:grid-cols-3">
          <Field label="Screen lock">
            {(f) => (
              <Select {...f} value={s.password} onChange={(e) => set("password", e.target.value as AndroidPolicySettings["password"])}>
                {ANDROID_PASSWORD_LEVELS.map((l) => (
                  <option key={l} value={l}>
                    {ANDROID_PASSWORD_LABELS[l]}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Lock after idle (minutes)" hint="0 = the user decides">
            {(f) => <Input {...f} type="number" min={0} max={60} value={s.screenLockMinutes} onChange={(e) => set("screenLockMinutes", Math.max(0, Math.min(60, Number(e.target.value) || 0)))} />}
          </Field>
          <Field label="Minimum Android version" hint="Older phones cannot enroll">
            {(f) => (
              <Select {...f} value={s.minAndroidVersion} onChange={(e) => set("minAndroidVersion", Number(e.target.value))}>
                <option value={0}>Any</option>
                {[10, 11, 12, 13, 14, 15].map((v) => (
                  <option key={v} value={v}>
                    Android {v}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Security patch at most (days old)" hint="Older is reported as not compliant">
            {(f) => <Input {...f} type="number" min={7} max={730} value={s.maxPatchAgeDays} onChange={(e) => set("maxPatchAgeDays", Number(e.target.value) || 7)} />}
          </Field>
        </div>
        <div className="grid gap-2 md:grid-cols-2">
          {toggles.map(([k, label]) => (
            <Checkbox key={k} label={label} checked={Boolean(s[k])} onChange={(e) => set(k, e.target.checked as never)} />
          ))}
        </div>
        {canWrite ? (
          <div className="flex items-center gap-3">
            <Button variant="primary" loading={save.isPending} onClick={() => save.mutate({ organizationId, settings: s }, { onSuccess: () => setSaved(true) })}>
              Save and apply to phones
            </Button>
            {saved ? <span className="text-healthy">Saved — phones pick it up within minutes</span> : null}
            {save.error ? <span role="alert" className="text-sev-critical">{errorMessage(save.error)}</span> : null}
          </div>
        ) : null}
      </fieldset>
    </Card>
  );
}

function Policy() {
  const session = useSession();
  const [org, setOrg] = useMdmOrg();
  const overview = useMobileOverview(org);
  const o = overview.data;
  return (
    <div className="space-y-4">
      <OrgPicker value={org} onChange={setOrg} />
      {!org ? null : overview.isLoading ? (
        <SkeletonText lines={4} />
      ) : overview.error ? (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      ) : o ? (
        <>
          <SetupNeeded o={o} />
          {o.enterprise?.status === "active" ? <PolicyForm organizationId={o.organizationId} initial={o.enterprise.policy} canWrite={session.can("asset:write", o.organizationId)} /> : null}
        </>
      ) : null}
    </div>
  );
}

// ─── Setup ───────────────────────────────────────────────────────────────────

function GoogleAccountCard({ o }: { o: MobileOverview }) {
  const session = useSession();
  const save = useSaveGoogleAccount();
  const remove = useRemoveGoogleAccount();
  const [json, setJson] = useState("");
  const [editing, setEditing] = useState(!o.account.configured);
  const canWrite = session.can("integration:write", null);
  const a = o.account;
  const readFile = async (file: File | undefined) => {
    if (file) setJson(await file.text());
  };
  return (
    <Card title={<span className="inline-flex items-center gap-2"><KeyRound className="h-4 w-4" aria-hidden /> Google account (all customers)</span>}>
      <div className="grid gap-6 text-sm lg:grid-cols-2">
        <ol className="list-decimal space-y-2 pl-5">
          <li>
            In <span className="font-medium">console.cloud.google.com</span>, create a project for SCIAT (e.g. "sciat-mdm"), then open <span className="font-medium">APIs & Services → Library</span> and enable the <span className="font-medium">Android Management API</span>.
          </li>
          <li>
            <span className="font-medium">IAM & Admin → Service accounts → Create service account</span> (e.g. "sciat-mdm"), and grant it the role <span className="font-medium">Android Management User</span>.
          </li>
          <li>
            Open the service account → <span className="font-medium">Keys → Add key → Create new key → JSON</span>. A .json file downloads; upload it here. It is stored encrypted and never shown again.
          </li>
          <li>One Google account serves all your customers: each gets its own Android Enterprise under it.</li>
        </ol>
        <div className="space-y-3">
          {a.configured && !editing ? (
            <>
              <div className="flex items-center gap-2">
                <Badge tone={a.status === "ok" ? "success" : "danger"}>{a.status === "ok" ? "Connected" : "Error"}</Badge>
                <span className="font-mono text-xs">{a.clientEmail}</span>
              </div>
              <div className="text-fg-muted">
                Project <span className="font-mono">{a.projectId}</span> · updated <RelativeTime value={a.updatedAt} />
              </div>
              {a.lastError ? <p className="text-sev-critical">{a.lastError}</p> : null}
              {canWrite ? (
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => setEditing(true)}>
                    Replace key
                  </Button>
                  <Button size="sm" variant="ghost" icon={Unplug} loading={remove.isPending} onClick={() => remove.mutate(undefined)}>
                    Disconnect
                  </Button>
                </div>
              ) : null}
            </>
          ) : canWrite ? (
            <>
              <Field label="Service account key (.json)">{(f) => <Input {...f} type="file" accept="application/json,.json" onChange={(e) => void readFile(e.target.files?.[0])} />}</Field>
              <Field label="…or paste its contents">{(f) => <Textarea {...f} rows={5} value={json} onChange={(e) => setJson(e.target.value)} placeholder='{"type": "service_account", "project_id": …}' className="font-mono text-xs" />}</Field>
              <div className="flex gap-2">
                <Button variant="primary" loading={save.isPending} disabled={json.trim().length < 50} onClick={() => save.mutate(json, { onSuccess: () => { setJson(""); setEditing(false); } })}>
                  Check and connect
                </Button>
                {a.configured ? <Button onClick={() => setEditing(false)}>Cancel</Button> : null}
              </div>
              {save.error ? <p role="alert" className="text-sev-critical">{errorMessage(save.error)}</p> : null}
            </>
          ) : (
            <p className="text-fg-muted">An account administrator connects the Google account.</p>
          )}
        </div>
      </div>
    </Card>
  );
}

function EnterpriseCard({ o }: { o: MobileOverview }) {
  const session = useSession();
  const signup = useStartAndroidSignup();
  const link = useLinkAndroidEnterprise();
  const unlink = useUnlinkAndroidEnterprise();
  const [adminEmail, setAdminEmail] = useState("");
  const [existing, setExisting] = useState("");
  const [confirm, setConfirm] = useState(false);
  const canWrite = session.can("asset:write", o.organizationId);
  const e = o.enterprise;
  const orgName = session.organizationName(o.organizationId) ?? "this organization";
  return (
    <Card title={<span className="inline-flex items-center gap-2"><Building2 className="h-4 w-4" aria-hidden /> Android Enterprise for {orgName}</span>}>
      {!o.account.configured ? (
        <p className="text-sm text-fg-muted">Connect the Google account first.</p>
      ) : e?.status === "active" ? (
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <Badge tone="success">Active</Badge>
            <span className="font-medium">{e.displayName ?? e.enterpriseName}</span>
            <span className="font-mono text-xs text-fg-muted">{e.enterpriseName}</span>
          </div>
          <div className="text-fg-muted">
            Policy applied <RelativeTime value={e.policySyncedAt} /> · devices synced <RelativeTime value={e.lastSyncAt} />
          </div>
          {e.lastError ? <p className="text-sev-critical">{e.lastError}</p> : null}
          {canWrite ? (
            <Button size="sm" variant="ghost" icon={Unplug} onClick={() => setConfirm(true)}>
              Unlink from SCIAT
            </Button>
          ) : null}
        </div>
      ) : canWrite ? (
        <div className="grid gap-6 text-sm lg:grid-cols-2">
          <div className="space-y-3">
            <p>
              Creates the customer's own Android Enterprise. Google opens a short sign-up: the customer's IT contact (or you, on their behalf) signs in with a work email and accepts Google's terms, then returns here.
            </p>
            {e?.status === "pending_signup" ? <p className="text-fg-muted">A sign-up was started but not finished — start again if the Google page was closed.</p> : null}
            {e?.status === "error" ? <p className="text-sev-critical">{e.lastError}</p> : null}
            <Field label="Customer admin email (optional)" hint="Pre-filled on Google's sign-up page">
              {(f) => <Input {...f} type="email" value={adminEmail} onChange={(ev) => setAdminEmail(ev.target.value)} placeholder="it@customer.example" />}
            </Field>
            <Button variant="primary" loading={signup.isPending} onClick={() => signup.mutate({ organizationId: o.organizationId, ...(adminEmail.trim() ? { adminEmail: adminEmail.trim() } : {}) }, { onSuccess: (r) => window.location.assign(r.url) })}>
              Create Android Enterprise with Google
            </Button>
            {signup.error ? <p role="alert" className="text-sev-critical">{errorMessage(signup.error)}</p> : null}
          </div>
          <div className="space-y-3">
            <p className="text-fg-muted">Already created one under the same Google project? Link it instead.</p>
            <Field label="Enterprise name">{(f) => <Input {...f} value={existing} onChange={(ev) => setExisting(ev.target.value.trim())} placeholder="enterprises/LC0abc123" />}</Field>
            <Button loading={link.isPending} disabled={!/^enterprises\/[A-Za-z0-9_-]{4,64}$/.test(existing)} onClick={() => link.mutate({ organizationId: o.organizationId, enterpriseName: existing })}>
              Link enterprise
            </Button>
            {link.error ? <p role="alert" className="text-sev-critical">{errorMessage(link.error)}</p> : null}
          </div>
        </div>
      ) : (
        <p className="text-sm text-fg-muted">Not set up yet.</p>
      )}
      {confirm ? (
        <Dialog
          open
          onClose={() => setConfirm(false)}
          title="Unlink the Android Enterprise?"
          description="SCIAT stops managing and reporting these phones. The enterprise and its phones stay in Google; link it again to resume."
          footer={
            <>
              <Button onClick={() => setConfirm(false)}>Cancel</Button>
              <Button variant="danger" loading={unlink.isPending} onClick={() => unlink.mutate(o.organizationId, { onSuccess: () => setConfirm(false) })}>
                Unlink
              </Button>
            </>
          }
        >
          {unlink.error ? <p role="alert" className="text-sm text-sev-critical">{errorMessage(unlink.error)}</p> : null}
        </Dialog>
      ) : null}
    </Card>
  );
}

const SIGNUP_ERRORS: Record<string, string> = {
  cancelled: "The Google sign-up was cancelled — nothing was created.",
  error: "Google sign-up could not be completed. Start again below; if it keeps failing check the Google account connection.",
};

function Setup() {
  const [params] = useSearchParams();
  const [org, setOrg] = useMdmOrg();
  const overview = useMobileOverview(org);
  const result = params.get("android");
  return (
    <div className="space-y-4">
      {result === "connected" ? (
        <p role="status" className="rounded border border-healthy/40 bg-healthy/5 p-3 text-sm">
          Android Enterprise created and the SCIAT baseline applied. Next: <a className="font-medium text-primary underline" href={`/mdm/enroll?organizationId=${org ?? ""}`}>enroll phones</a>.
        </p>
      ) : result && SIGNUP_ERRORS[result] ? (
        <p role="alert" className="rounded border border-sev-medium/40 bg-sev-medium/5 p-3 text-sm">
          {SIGNUP_ERRORS[result]}
        </p>
      ) : null}
      <OrgPicker value={org} onChange={setOrg} />
      {!org ? null : overview.isLoading ? (
        <SkeletonText lines={6} />
      ) : overview.error ? (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      ) : overview.data ? (
        <>
          <GoogleAccountCard o={overview.data} />
          <EnterpriseCard o={overview.data} />
        </>
      ) : null}
    </div>
  );
}

export default function MdmPage() {
  return <ModuleWorkspace moduleId="mdm" sections={{ "": () => <Devices />, enroll: () => <Enroll />, policy: () => <Policy />, setup: () => <Setup /> }} />;
}

export { Devices as MdmDevicesSection, Enroll as MdmEnrollSection, Setup as MdmSetupSection };
