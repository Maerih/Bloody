import { AUTORUN_KIND_LABELS, ENDPOINT_ACTIVITY_KINDS, ENDPOINT_ACTIVITY_LABELS, type EndpointActivity, type EndpointActivityKind, type EndpointDossier } from "@bloody/contracts";
import { clsx } from "clsx";
import { AlertTriangle, Bot, FileDown, Lock, Printer, ShieldAlert, ShieldCheck, Siren, Skull, Workflow, Wrench, type LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useEndpointDossier, useGenerateReport } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge, type BadgeTone } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Field, Select } from "../../components/Form";
import { Popover } from "../../components/Popover";
import { RelativeTime } from "../../components/RelativeTime";
import { SkeletonText } from "../../components/Skeleton";
import { triggerDownload } from "../../lib/download";
import { formatDate } from "../../lib/format";

const KIND_ICON: Record<EndpointActivityKind, LucideIcon> = {
  agent: Bot,
  isolation: Lock,
  response: Workflow,
  alert: Siren,
  incident: AlertTriangle,
  persistence: Skull,
  app_control: ShieldCheck,
  change: Wrench,
};
const OUTCOME: Record<NonNullable<EndpointActivity["outcome"]>, { label: string; tone: BadgeTone }> = {
  success: { label: "Done", tone: "success" },
  failure: { label: "Failed", tone: "danger" },
  pending: { label: "Requested", tone: "warning" },
};
const PERIODS = [
  { days: 7, label: "Last 7 days" },
  { days: 30, label: "Last 30 days" },
  { days: 90, label: "Last 90 days" },
  { days: 365, label: "Last 12 months" },
];

/** "Download report" for one computer: the endpoint posture report about this computer as PDF / HTML. */
export function ComputerReportButton({ assetId, organizationId, size = "sm", label = "Download report" }: { assetId: string; organizationId: string; size?: "xs" | "sm"; label?: string }) {
  const session = useSession();
  const generate = useGenerateReport();
  const [days, setDays] = useState(30);
  const [format, setFormat] = useState<"pdf" | "html">("pdf");
  if (!session.can("report:read", organizationId)) return null;
  const download = (close: () => void) =>
    generate.mutate(
      { type: "endpoint_posture", format, organizationId, periodDays: days, options: { assetId } },
      {
        onSuccess: (res) => {
          triggerDownload(res.blob, res.filename ?? `computer-report-${new Date().toISOString().slice(0, 10)}.${format}`);
          close();
        },
      },
    );
  return (
    <Popover
      align="end"
      label="Computer report"
      panelClassName="w-72 p-3"
      trigger={(props) => (
        <Button {...props} size={size} icon={FileDown} onClick={(e) => (e.stopPropagation(), props.onClick())}>
          {label}
        </Button>
      )}
    >
      {(close) => (
        <div className="space-y-3" onClick={(e) => e.stopPropagation()}>
          <p className="text-xs text-fg-muted">Everything about this computer: agent and isolation, protection, patching, hardening, persistence, vulnerabilities, detections, activity and inventory.</p>
          <Field label="Activity period">
            {(p) => (
              <Select {...p} value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {PERIODS.map((x) => (
                  <option key={x.days} value={x.days}>
                    {x.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Format">
            {(p) => (
              <Select {...p} value={format} onChange={(e) => setFormat(e.target.value as "pdf" | "html")}>
                <option value="pdf">PDF (print-ready)</option>
                <option value="html">HTML</option>
              </Select>
            )}
          </Field>
          {generate.error ? (
            <p role="alert" className="text-xs text-sev-critical">
              {errorMessage(generate.error)}
            </p>
          ) : null}
          <Button variant="primary" icon={FileDown} className="w-full" loading={generate.isPending} onClick={() => download(close)}>
            Download
          </Button>
        </div>
      )}
    </Popover>
  );
}

/** Print the page (navigation is hidden and the light theme is used for paper). */
export function PrintButton({ size = "sm" }: { size?: "xs" | "sm" }) {
  return (
    <Button size={size} icon={Printer} onClick={() => window.print()}>
      Print
    </Button>
  );
}

function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: "good" | "warn" | "bad" }) {
  return (
    <div className="rounded border border-line px-2.5 py-2">
      <div className="text-2xs uppercase tracking-wide text-fg-subtle">{label}</div>
      <div className={clsx("text-sm font-semibold", tone === "bad" ? "text-sev-critical" : tone === "warn" ? "text-sev-medium" : tone === "good" ? "text-healthy" : "text-heading")}>{value}</div>
    </div>
  );
}

/** Protection & posture: patching, hardening, persistence and remote-access tools for this computer. */
export function ComputerPosture({ assetId }: { assetId: string }) {
  const dossier = useEndpointDossier(assetId);
  if (dossier.isPending) return <SkeletonText lines={4} />;
  if (dossier.isError) return <p className="text-sm text-fg-subtle">{errorMessage(dossier.error)}</p>;
  return <PostureBody d={dossier.data} />;
}

function PostureBody({ d }: { d: EndpointDossier }) {
  const p = d.patching;
  const h = d.hardening;
  const flagged = d.footholds.filter((f) => f.verdict === "malicious" || (f.verdict === null && f.level !== "low"));
  const failing = (h?.checks ?? []).filter((c) => c.status === "fail" && !c.accepted);
  const sciat = d.agents.find((a) => a.engine === "sciat");
  if (!sciat) return <p className="text-sm text-fg-subtle">Install the SCIAT Agent on this computer to see patching, hardening and persistence.</p>;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Stat
          label="Patching"
          value={p ? (p.grade.state === "current" ? "Up to date" : p.grade.state === "breached" ? "Out of compliance" : p.grade.state === "behind" ? `${p.securityCount} security update${p.securityCount === 1 ? "" : "s"} waiting` : "Not reported") : "Not reported"}
          tone={p ? (p.grade.state === "breached" ? "bad" : p.grade.state === "behind" ? "warn" : p.grade.state === "current" ? "good" : undefined) : undefined}
        />
        <Stat label="Hardening score" value={h?.score ?? "—"} tone={h?.score == null ? undefined : h.score >= 80 ? "good" : h.score >= 60 ? "warn" : "bad"} />
        <Stat label="Suspicious autostart" value={flagged.length} tone={flagged.length ? "bad" : "good"} />
        <Stat label="Remote-access tools" value={d.remoteAccess.length ? d.remoteAccess.map((r) => r.name).join(", ") : "None"} tone={d.remoteAccess.some((r) => !r.approved) ? "bad" : undefined} />
      </div>
      {p ? (
        <div className="text-sm">
          {p.grade.reasons.length ? (
            <ul className="list-disc pl-5">
              {p.grade.reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          ) : null}
          <p className="text-fg-muted">
            {p.os ?? "Operating system unknown"}
            {p.osSupport.status === "ended" ? (
              <Badge size="xs" tone="danger" className="ml-2">
                Unsupported{p.osSupport.endsOn ? ` since ${p.osSupport.endsOn}` : ""}
              </Badge>
            ) : p.osSupport.status === "ending_soon" ? (
              <Badge size="xs" tone="warning" className="ml-2">
                Support ends {p.osSupport.endsOn}
              </Badge>
            ) : null}
            {p.rebootRequired ? (
              <Badge size="xs" tone="warning" className="ml-2">
                Restart needed
              </Badge>
            ) : null}
            {p.lastInstalledAt ? <> · last update installed {formatDate(p.lastInstalledAt)}</> : null}
          </p>
          {p.pending.length ? (
            <ul aria-label="Updates waiting" className="mt-1 space-y-0.5">
              {[...p.pending]
                .sort((a, b) => Number(b.security) - Number(a.security))
                .slice(0, 8)
                .map((u) => (
                  <li key={`${u.id ?? ""}${u.title}`} className="flex items-center gap-2 text-xs">
                    {u.security ? <Badge size="xs" tone={u.severity === "critical" ? "danger" : "warning"}>{u.severity === "unspecified" ? "Security" : u.severity}</Badge> : <Badge size="xs">Other</Badge>}
                    <span className="min-w-0 flex-1 truncate">{u.title}</span>
                    {u.id ? <span className="font-mono text-fg-subtle">{u.id}</span> : null}
                  </li>
                ))}
              {p.pending.length > 8 ? <li className="text-xs text-fg-subtle">…and {p.pending.length - 8} more (see the report or VM → Patch Compliance).</li> : null}
            </ul>
          ) : null}
        </div>
      ) : null}
      {failing.length ? (
        <div>
          <div className="mb-1 text-xs font-medium text-fg-muted">Failing hardening checks</div>
          <ul className="space-y-0.5">
            {failing.map((c) => (
              <li key={c.key} className="flex items-center gap-2 text-sm">
                <Badge size="xs" tone={c.severity === "high" ? "danger" : c.severity === "medium" ? "warning" : "neutral"}>
                  {c.severity}
                </Badge>
                <span>{c.title}</span>
                {c.detail ? <span className="truncate text-xs text-fg-subtle">{c.detail}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {flagged.length ? (
        <div>
          <div className="mb-1 text-xs font-medium text-fg-muted">Autostart entries needing review</div>
          <ul className="space-y-1">
            {flagged.map((f) => (
              <li key={`${f.kind}:${f.location}:${f.name}`} className="text-sm">
                <div className="flex items-center gap-2">
                  <Badge size="xs" tone={f.verdict === "malicious" || f.level === "high" ? "danger" : "warning"} icon={f.verdict === "malicious" ? Skull : ShieldAlert}>
                    {f.verdict === "malicious" ? "Malicious" : f.level === "high" ? "Highly suspicious" : "Suspicious"}
                  </Badge>
                  <span className="font-medium">{f.name}</span>
                  <span className="text-xs text-fg-subtle">{AUTORUN_KIND_LABELS[f.kind]}</span>
                  {f.isNew ? (
                    <Badge size="xs" tone="info">
                      New
                    </Badge>
                  ) : null}
                </div>
                <div className="truncate font-mono text-xs text-fg-muted" title={f.command ?? f.location}>
                  {f.command ?? f.location}
                </div>
              </li>
            ))}
          </ul>
          <Link to="/edr/persistence" className="text-xs text-brand hover:underline print:hidden">
            Review in EDR → Persistent Footholds
          </Link>
        </div>
      ) : null}
      {d.remoteAccess.length ? (
        <div className="text-sm">
          <div className="mb-1 text-xs font-medium text-fg-muted">Remote-access software</div>
          {d.remoteAccess.map((r) => (
            <div key={r.name} className="flex items-center gap-2">
              <Badge size="xs" tone={r.approved ? "success" : "danger"}>
                {r.approved ? "Approved" : "Not approved"}
              </Badge>
              <span className="font-medium">{r.name}</span>
              <span className="text-xs text-fg-subtle">{r.evidence.join("; ")}</span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

/** Everything that happened to the computer, newest first, with type and period filters. */
export function ComputerActivity({ assetId }: { assetId: string }) {
  const [days, setDays] = useState(90);
  const [kinds, setKinds] = useState<Set<EndpointActivityKind>>(new Set());
  const dossier = useEndpointDossier(assetId, days);
  const all = useMemo(() => dossier.data?.activity ?? [], [dossier.data]);
  const present = useMemo(() => ENDPOINT_ACTIVITY_KINDS.filter((k) => all.some((e) => e.kind === k)), [all]);
  const shown = kinds.size ? all.filter((e) => kinds.has(e.kind)) : all;
  const byDay = useMemo(() => {
    const groups: Array<{ day: string; items: EndpointActivity[] }> = [];
    for (const e of shown) {
      const day = e.at.slice(0, 10);
      const g = groups.at(-1);
      if (g && g.day === day) g.items.push(e);
      else groups.push({ day, items: [e] });
    }
    return groups;
  }, [shown]);
  const toggle = (k: EndpointActivityKind) =>
    setKinds((cur) => {
      const next = new Set(cur);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1.5 print:hidden">
        <div className="w-40">
          <Select aria-label="Activity period" className="h-7 text-xs" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {PERIODS.map((x) => (
              <option key={x.days} value={x.days}>
                {x.label}
              </option>
            ))}
          </Select>
        </div>
        {present.map((k) => {
          const Icon = KIND_ICON[k];
          const on = kinds.has(k);
          return (
            <button
              key={k}
              type="button"
              aria-pressed={on}
              onClick={() => toggle(k)}
              className={clsx("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs", on ? "border-primary bg-primary-soft text-primary" : "border-line text-fg-muted hover:bg-surface-2")}
            >
              <Icon size={11} aria-hidden />
              {ENDPOINT_ACTIVITY_LABELS[k]} ({all.filter((e) => e.kind === k).length})
            </button>
          );
        })}
      </div>
      {dossier.isPending ? (
        <SkeletonText lines={5} />
      ) : dossier.isError ? (
        <p className="text-sm text-fg-subtle">{errorMessage(dossier.error)}</p>
      ) : shown.length === 0 ? (
        <p className="text-sm text-fg-subtle">Nothing was recorded for this computer in this period.</p>
      ) : (
        <ol aria-label="Activity" className="space-y-3">
          {byDay.map((g) => (
            <li key={g.day}>
              <div className="mb-1 text-xs font-semibold text-fg-muted">{formatDate(g.day)}</div>
              <ol className="space-y-1 border-l border-line pl-3">
                {g.items.map((e, i) => {
                  const Icon = KIND_ICON[e.kind];
                  return (
                    <li key={`${e.at}-${i}`} className="relative text-sm">
                      <span className="absolute -left-[19px] top-0.5 flex h-4 w-4 items-center justify-center rounded-full border border-line bg-surface">
                        <Icon size={9} aria-hidden className="text-fg-muted" />
                      </span>
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        <span className="text-xs tabular-nums text-fg-subtle">{new Date(e.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                        <span className="font-medium">{e.title}</span>
                        {e.severity ? <SeverityBadge severity={e.severity} size="xs" /> : null}
                        {e.outcome ? (
                          <Badge size="xs" tone={OUTCOME[e.outcome].tone}>
                            {OUTCOME[e.outcome].label}
                          </Badge>
                        ) : null}
                        <span className="text-xs text-fg-subtle">
                          {ENDPOINT_ACTIVITY_LABELS[e.kind]}
                          {e.actor ? ` · ${e.actor}` : ""}
                        </span>
                      </div>
                      {e.detail ? <div className="break-words text-xs text-fg-muted">{e.detail}</div> : null}
                    </li>
                  );
                })}
              </ol>
            </li>
          ))}
        </ol>
      )}
      {dossier.data?.activityTruncated ? <p className="text-xs text-fg-subtle">Showing the latest {all.length} entries; pick a shorter period to see older days in full.</p> : null}
      {dossier.data ? (
        <p className="text-xs text-fg-subtle print:hidden">
          Updated <RelativeTime value={dossier.data.generatedAt} />.
        </p>
      ) : null}
    </div>
  );
}
