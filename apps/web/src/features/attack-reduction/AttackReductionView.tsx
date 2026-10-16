import type { AttackReductionEndpoint, HardeningCheckInfo, HardeningStatus } from "@bloody/contracts";
import { CheckCircle2, CircleHelp, ShieldAlert, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useAttackReductionOverview, useRemoveHardeningException, useSetHardeningException, type AttackReductionOverview } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, CopyButton, DataTable, Drawer, EmptyState, ErrorState, Field, OrganizationSelect, RelativeTime, SeverityBadge, StatTile, Textarea, useDefaultOrganization, type DataTableColumn } from "../../components";

const PLATFORM: Record<string, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };
const CATEGORY: Record<string, string> = { credentials: "Credential theft", network: "Network", exploitation: "Exploitation", encryption: "Encryption", patching: "Patching", logging: "Logging", access: "Access" };
const STATUS_META: Record<HardeningStatus, { label: string; tone: "success" | "danger" | "neutral"; icon: typeof CheckCircle2 }> = {
  pass: { label: "Pass", tone: "success", icon: CheckCircle2 },
  fail: { label: "Fail", tone: "danger", icon: XCircle },
  unknown: { label: "Not reported", tone: "neutral", icon: CircleHelp },
  na: { label: "Not applicable", tone: "neutral", icon: CircleHelp },
};

type CheckRow = HardeningCheckInfo & { failing: number; passing: number; unknown: number; exception: AttackReductionOverview["checks"][number]["exception"] };

const scoreTone = (s: number | null) => (s === null ? "default" : s >= 85 ? "healthy" : s >= 60 ? "medium" : "high");

function CheckDrawer({ organizationId, check, endpoints, canWrite, onClose }: { organizationId: string; check: CheckRow; endpoints: AttackReductionEndpoint[]; canWrite: boolean; onClose: () => void }) {
  const set = useSetHardeningException();
  const remove = useRemoveHardeningException();
  const [reason, setReason] = useState("");
  const failing = endpoints.flatMap((e) => {
    const r = e.results.find((x) => x.key === check.key);
    return r?.status === "fail" ? [{ hostname: e.hostname, detail: r.detail }] : [];
  });
  const error = set.error ?? remove.error;
  return (
    <Drawer open onClose={onClose} title={check.title} subtitle={`${CATEGORY[check.category]} · ${check.attack}`}>
      <div className="space-y-4 p-4 text-sm">
        <div className="flex flex-wrap gap-2">
          <SeverityBadge severity={check.severity} />
          {check.platforms.map((p) => (
            <Badge key={p} size="xs">
              {PLATFORM[p]}
            </Badge>
          ))}
          {check.exception ? <Badge tone="warning">Accepted risk</Badge> : null}
        </div>
        <section>
          <h3 className="font-semibold text-heading">Why it matters</h3>
          <p className="mt-1 text-fg-muted">{check.why}</p>
        </section>
        <section>
          <h3 className="font-semibold text-heading">How to fix it</h3>
          <p className="mt-1">{check.fix}</p>
          {check.script ? (
            <div className="mt-2 rounded border border-line bg-canvas">
              <div className="flex items-center justify-between border-b border-line px-2 py-1 text-xs text-fg-muted">
                <span>Fix on one computer (test first; use Group Policy, Intune or your MDM at scale)</span>
                <CopyButton value={check.script} />
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all p-2 font-mono text-xs">{check.script}</pre>
            </div>
          ) : null}
        </section>
        <section>
          <h3 className="font-semibold text-heading">Failing on {failing.length} computer{failing.length === 1 ? "" : "s"}</h3>
          {failing.length ? (
            <ul className="mt-1 space-y-0.5">
              {failing.map((f) => (
                <li key={f.hostname}>
                  <span className="font-medium">{f.hostname}</span>
                  {f.detail ? <span className="text-fg-muted"> — {f.detail}</span> : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-1 text-fg-muted">None.</p>
          )}
        </section>
        <section className="rounded border border-line p-3">
          <h3 className="font-semibold text-heading">Accepted risk</h3>
          {check.exception ? (
            <div className="mt-1 space-y-2">
              <p>{check.exception.reason}</p>
              <p className="text-xs text-fg-muted">
                Recorded <RelativeTime value={check.exception.createdAt} />. The check stays visible but no longer counts against the score.
              </p>
              {canWrite ? (
                <Button size="sm" variant="secondary" loading={remove.isPending} onClick={() => remove.mutate({ organizationId, key: check.key }, { onSuccess: onClose })}>
                  Remove exception
                </Button>
              ) : null}
            </div>
          ) : canWrite ? (
            <div className="mt-1 space-y-2">
              <p className="text-fg-muted">If the organization cannot apply this yet (for example a legacy system depends on it), record why. It stays visible but leaves the score.</p>
              <Field label="Reason">{(f) => <Textarea {...f} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} />}</Field>
              <Button size="sm" loading={set.isPending} disabled={reason.trim().length < 10} onClick={() => set.mutate({ organizationId, key: check.key, reason: reason.trim() }, { onSuccess: onClose })}>
                Accept risk
              </Button>
            </div>
          ) : (
            <p className="mt-1 text-fg-muted">No exception recorded.</p>
          )}
          {error ? (
            <p role="alert" className="mt-2 text-sev-critical">
              {errorMessage(error)}
            </p>
          ) : null}
        </section>
      </div>
    </Drawer>
  );
}

function EndpointDrawer({ endpoint, catalog, accepted, onClose }: { endpoint: AttackReductionEndpoint; catalog: Map<string, HardeningCheckInfo>; accepted: Set<string>; onClose: () => void }) {
  const rows = [...endpoint.results].sort((a, b) => Number(b.status === "fail") - Number(a.status === "fail"));
  return (
    <Drawer open onClose={onClose} title={endpoint.hostname} subtitle={`${PLATFORM[endpoint.platform] ?? endpoint.platform} · score ${endpoint.score ?? "—"}`}>
      <ul className="divide-y divide-line px-4 text-sm">
        {rows.map((r) => {
          const c = catalog.get(r.key);
          const meta = STATUS_META[r.status];
          return (
            <li key={r.key} className="flex items-start gap-3 py-2">
              <Badge size="xs" tone={meta.tone} icon={meta.icon}>
                {meta.label}
              </Badge>
              <div className="min-w-0">
                <div className="font-medium">
                  {c?.title ?? r.key}
                  {accepted.has(r.key) ? (
                    <Badge size="xs" tone="warning" className="ml-2">
                      Accepted risk
                    </Badge>
                  ) : null}
                </div>
                {r.detail ? <div className="text-xs text-fg-muted">{r.detail}</div> : null}
              </div>
            </li>
          );
        })}
      </ul>
    </Drawer>
  );
}

/** ESPM → Attack Reduction: how hard each endpoint is to attack, and what to change. */
export function AttackReductionView() {
  const session = useSession();
  const [organizationId, setOrganizationId] = useState<string | null>(useDefaultOrganization("asset:read"));
  const [openCheck, setOpenCheck] = useState<string | null>(null);
  const [openEndpoint, setOpenEndpoint] = useState<string | null>(null);
  const overview = useAttackReductionOverview(organizationId);
  const canWrite = organizationId ? session.can("asset:write", organizationId) : false;
  const o = overview.data;

  const catalog = useMemo(() => new Map((o?.catalog ?? []).map((c) => [c.key, c])), [o]);
  const accepted = useMemo(() => new Set((o?.checks ?? []).filter((c) => c.exception).map((c) => c.key)), [o]);
  const checks: CheckRow[] = useMemo(
    () =>
      (o?.checks ?? [])
        .map((s) => ({ ...catalog.get(s.key)!, ...s }))
        .sort((a, b) => Number(!!a.exception) - Number(!!b.exception) || b.failing - a.failing || ["high", "medium", "low"].indexOf(a.severity) - ["high", "medium", "low"].indexOf(b.severity)),
    [o, catalog],
  );
  const gaps = checks.filter((c) => c.failing > 0 && !c.exception);
  const weak = o?.endpoints.filter((e) => e.score !== null && e.score < 60).length ?? 0;

  const checkCols: DataTableColumn<CheckRow>[] = [
    { id: "severity", header: "Severity", accessor: (c) => c.severity, cell: (c) => <SeverityBadge severity={c.severity} size="xs" />, filter: { kind: "select", options: ["high", "medium", "low"].map((v) => ({ value: v, label: v })) } },
    {
      id: "title",
      header: "Check",
      accessor: (c) => c.title,
      hideable: false,
      cell: (c) => (
        <div>
          <div className="font-medium">{c.title}</div>
          <div className="text-xs text-fg-muted">{c.attack}</div>
        </div>
      ),
    },
    { id: "category", header: "Area", accessor: (c) => CATEGORY[c.category], filter: { kind: "select", options: Object.values(CATEGORY).map((v) => ({ value: v, label: v })) } },
    {
      id: "failing",
      header: "Failing",
      align: "right",
      accessor: (c) => c.failing,
      cell: (c) =>
        c.exception ? (
          <Badge size="xs" tone="warning">
            Accepted risk
          </Badge>
        ) : c.failing ? (
          <span className="font-semibold text-sev-critical">
            {c.failing} of {c.failing + c.passing}
          </span>
        ) : c.passing ? (
          <span className="text-healthy">0 of {c.passing}</span>
        ) : (
          <span className="text-fg-muted">not reported</span>
        ),
    },
  ];
  const endpointCols: DataTableColumn<AttackReductionEndpoint>[] = [
    { id: "host", header: "Computer", accessor: (e) => e.hostname, hideable: false, cell: (e) => <span className="font-medium">{e.hostname}</span> },
    { id: "platform", header: "Platform", accessor: (e) => PLATFORM[e.platform] ?? e.platform },
    {
      id: "score",
      header: "Score",
      align: "right",
      accessor: (e) => e.score,
      cell: (e) => (e.score === null ? <span className="text-fg-muted">—</span> : <span className={e.score >= 85 ? "font-semibold text-healthy" : e.score >= 60 ? "font-semibold text-sev-medium" : "font-semibold text-sev-critical"}>{e.score}</span>),
    },
    { id: "gaps", header: "Gaps", align: "right", accessor: (e) => e.results.filter((r) => r.status === "fail" && !accepted.has(r.key)).length },
    { id: "seen", header: "Last report", accessor: (e) => new Date(e.collectedAt), cell: (e) => <RelativeTime value={e.collectedAt} /> },
  ];

  const check = openCheck ? checks.find((c) => c.key === openCheck) : undefined;
  const endpoint = openEndpoint ? o?.endpoints.find((e) => e.agentId === openEndpoint) : undefined;

  return (
    <div className="space-y-4">
      <Card title="Attack Reduction">
        <div className="space-y-4">
          <p className="max-w-3xl text-sm text-fg-muted">
            The settings attackers rely on once they reach a computer: credential theft (LLMNR, WDigest, LSASS), old protocols (SMBv1, NTLMv1), weak remote access, missing encryption and patches. The SCIAT Agent reports them with each inventory; every gap comes with the ATT&amp;CK technique it enables and the fix.
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
                <StatTile label="Hardening score" value={o.score ?? 0} format={(v) => (o.score === null ? "—" : `${v}%`)} tone={scoreTone(o.score)} />
                <StatTile label="Gaps to close" value={gaps.length} tone={gaps.length ? "high" : "healthy"} />
                <StatTile label="Computers below 60" value={weak} tone={weak ? "high" : "healthy"} />
                <StatTile label="Computers assessed" value={o.endpoints.length} />
              </div>
              {o.endpoints.length === 0 ? <p className="text-sm text-fg-muted">No computer has reported yet. Attack Reduction needs SCIAT Agent 1.2 or later; agents report every 30 minutes.</p> : null}
            </>
          ) : null}
        </div>
      </Card>
      {organizationId && o && o.endpoints.length ? (
        <>
          <Card title="Checks">
            <DataTable
              caption="Hardening checks"
              columns={checkCols}
              rows={checks}
              getRowId={(c) => c.key}
              onRowClick={(c) => setOpenCheck(c.key)}
              searchable
              searchPlaceholder="Search checks"
              exportFileName="attack-reduction-checks"
              emptyState={<EmptyState compact icon={ShieldAlert} title="No checks reported" />}
            />
          </Card>
          <Card title="Computers">
            <DataTable caption="Computers" columns={endpointCols} rows={o.endpoints} getRowId={(e) => e.agentId} onRowClick={(e) => setOpenEndpoint(e.agentId)} searchable searchPlaceholder="Search computers" exportFileName="attack-reduction-computers" />
          </Card>
        </>
      ) : null}
      {check && organizationId && o ? <CheckDrawer organizationId={organizationId} check={check} endpoints={o.endpoints} canWrite={canWrite} onClose={() => setOpenCheck(null)} /> : null}
      {endpoint ? <EndpointDrawer endpoint={endpoint} catalog={catalog} accepted={accepted} onClose={() => setOpenEndpoint(null)} /> : null}
    </div>
  );
}
