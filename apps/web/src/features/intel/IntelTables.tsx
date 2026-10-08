import { IndicatorType, Severity, type Indicator } from "@bloody/contracts";
import { Ban, Crosshair, Network, Plus, Search, Target } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useCreateIndicator, useIndicators, useIntelMatches } from "../../api/hooks";
import type { CreateIndicatorInput, IndicatorFilters, IntelMatch, IntelMatchFilters } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { DescriptionList } from "../../components/DescriptionList";
import { Field, Input, Select } from "../../components/Form";
import { OrganizationSelect, useDefaultOrganization } from "../../components/OrganizationSelect";
import { Dialog, Drawer } from "../../components/Overlay";
import { RelativeTime } from "../../components/RelativeTime";
import { pivotQuery, searchHref } from "../events/eventFormat";
import { hrefForEntity } from "../../lib/entityLinks";
import { formatDateTime, humanize } from "../../lib/format";
import { RequestActionDialog } from "../response/RequestActionDialog";

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;
const VALIDATORS: Record<IndicatorType, (v: string) => boolean> = {
  ip: (v) => IPV4.test(v) || (v.includes(":") && IPV6.test(v)),
  domain: (v) => /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(v),
  url: (v) => {
    try {
      const u = new URL(v);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  },
  sha256: (v) => /^[0-9a-f]{64}$/i.test(v),
  sha1: (v) => /^[0-9a-f]{40}$/i.test(v),
  md5: (v) => /^[0-9a-f]{32}$/i.test(v),
  email: (v) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v),
  cve: (v) => /^CVE-\d{4}-\d{4,}$/i.test(v),
  ja3: (v) => /^[0-9a-f]{32}$/i.test(v),
  user_agent: (v) => v.length >= 3,
};

/** Infer the indicator type from a pasted value (analyst convenience; editable). */
export function inferIndicatorType(value: string): IndicatorType | null {
  const v = value.trim();
  for (const t of ["sha256", "sha1", "md5", "cve", "url", "email", "ip", "domain"] as IndicatorType[]) if (VALIDATORS[t](v)) return t;
  return null;
}

export function validateIndicator(type: IndicatorType, value: string): string | null {
  const v = value.trim();
  if (!v) return "Enter the indicator value";
  if (v.length > 2048) return "Value is too long";
  return VALIDATORS[type](v) ? null : `Not a valid ${type.replace("_", " ")}`;
}

export function AddIndicatorDialog({ open, onClose, initialValue = "" }: { open: boolean; onClose: () => void; initialValue?: string }) {
  const create = useCreateIndicator();
  const defaultOrg = useDefaultOrganization("intel:write", true);
  const [value, setValue] = useState(initialValue);
  const [type, setType] = useState<IndicatorType>(inferIndicatorType(initialValue) ?? "ip");
  const [severity, setSeverity] = useState<Severity>("high");
  const [confidence, setConfidence] = useState("75");
  const [source, setSource] = useState("analyst");
  const [actor, setActor] = useState("");
  const [malware, setMalware] = useState("");
  const [campaign, setCampaign] = useState("");
  const [tags, setTags] = useState("");
  const [expires, setExpires] = useState("");
  const [orgId, setOrgId] = useState<string | null>(defaultOrg);
  const [submitted, setSubmitted] = useState(false);
  const conf = Number(confidence);
  const errors = {
    value: validateIndicator(type, value),
    confidence: Number.isInteger(conf) && conf >= 0 && conf <= 100 ? null : "0–100",
    source: source.trim() ? null : "Where does this indicator come from?",
    expires: expires && Number.isNaN(Date.parse(expires)) ? "Invalid date" : null,
  };
  const submit = () => {
    setSubmitted(true);
    if (Object.values(errors).some(Boolean)) return;
    const input: CreateIndicatorInput = {
      organizationId: orgId,
      type,
      value: type === "domain" || type === "sha256" || type === "sha1" || type === "md5" ? value.trim().toLowerCase() : value.trim(),
      confidence: conf,
      severity,
      source: source.trim(),
      threatActor: actor.trim() || null,
      malware: malware.trim() || null,
      campaign: campaign.trim() || null,
      tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      expiresAt: expires ? new Date(`${expires}T23:59:59Z`).toISOString() : null,
    };
    create.mutate(input, { onSuccess: onClose });
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add indicator of compromise"
      description="New indicators are matched against telemetry, identities and cloud events of the chosen scope."
      size="lg"
      footer={
        <>
          {create.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(create.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" icon={Plus} onClick={submit} loading={create.isPending}>
            Add IOC
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Value" required error={submitted ? errors.value : null} className="sm:col-span-2">
          {(p) => (
            <Input
              {...p}
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
                const t = inferIndicatorType(e.target.value);
                if (t) setType(t);
              }}
              placeholder="203.0.113.10, evil.example, sha256…"
              className="font-mono"
            />
          )}
        </Field>
        <Field label="Type" required>
          {(p) => (
            <Select {...p} value={type} onChange={(e) => setType(e.target.value as IndicatorType)}>
              {IndicatorType.options.map((t) => (
                <option key={t} value={t}>
                  {humanize(t)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Severity" required>
          {(p) => (
            <Select {...p} value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
              {Severity.options.map((s) => (
                <option key={s} value={s}>
                  {humanize(s)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Confidence (0–100)" required error={submitted ? errors.confidence : null}>
          {(p) => <Input {...p} value={confidence} inputMode="numeric" onChange={(e) => setConfidence(e.target.value)} />}
        </Field>
        <Field label="Source" required error={submitted ? errors.source : null}>
          {(p) => <Input {...p} value={source} onChange={(e) => setSource(e.target.value)} placeholder="analyst, MISP, partner report…" />}
        </Field>
        <Field label="Threat actor">{(p) => <Input {...p} value={actor} onChange={(e) => setActor(e.target.value)} />}</Field>
        <Field label="Malware">{(p) => <Input {...p} value={malware} onChange={(e) => setMalware(e.target.value)} />}</Field>
        <Field label="Campaign">{(p) => <Input {...p} value={campaign} onChange={(e) => setCampaign(e.target.value)} />}</Field>
        <Field label="Expires" error={submitted ? errors.expires : null} hint="Empty = never">
          {(p) => <Input {...p} type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />}
        </Field>
        <Field label="Tags" hint="Comma-separated" className="sm:col-span-2">
          {(p) => <Input {...p} value={tags} onChange={(e) => setTags(e.target.value)} />}
        </Field>
        <Field label="Scope" className="sm:col-span-2">
          {(p) => <OrganizationSelect {...p} value={orgId} onChange={setOrgId} permission="intel:write" allowTenantWide tenantWideLabel="All organizations (tenant-wide feed)" />}
        </Field>
      </div>
    </Dialog>
  );
}

function IndicatorDrawer({ indicator, onClose }: { indicator: Indicator; onClose: () => void }) {
  const session = useSession();
  const matches = useIntelMatches({ indicatorId: indicator.id, organizationId: null });
  const [block, setBlock] = useState(false);
  const blockAction = indicator.type === "ip" ? "block_ip" : indicator.type === "domain" ? "block_domain" : null;
  const orgForAction = indicator.organizationId ?? session.organizationId;
  const field = indicator.type === "ip" ? "network.dstIp" : indicator.type === "domain" ? "network.dnsQuery" : "indicators.value";
  return (
    <Drawer open onClose={onClose} width="lg" title={<span className="font-mono">{indicator.value}</span>} subtitle={`${humanize(indicator.type)} · ${indicator.source}`}>
      <div className="flex flex-wrap gap-2 border-b border-line px-4 py-3">
        <ButtonLink size="sm" icon={Search} to={searchHref(pivotQuery(field, indicator.value), "30d")}>
          Search events
        </ButtonLink>
        <ButtonLink size="sm" icon={Network} to={`/graph?q=${encodeURIComponent(indicator.value)}`}>
          Graph pivot
        </ButtonLink>
        {blockAction && orgForAction && session.can("response:request", orgForAction) ? (
          <Button size="sm" variant="danger" icon={Ban} onClick={() => setBlock(true)}>
            {blockAction === "block_ip" ? "Block IP" : "Block domain"}
          </Button>
        ) : null}
      </div>
      <div className="space-y-3 px-4 py-3">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={indicator.severity} />
          <Badge tone="outline">confidence {indicator.confidence}</Badge>
          {indicator.organizationId === null ? <Badge tone="info">Tenant-wide</Badge> : null}
        </div>
        <DescriptionList
          items={[
            { label: "Threat actor", value: indicator.threatActor },
            { label: "Malware", value: indicator.malware },
            { label: "Campaign", value: indicator.campaign },
            { label: "Tags", value: indicator.tags.join(", ") || null },
            { label: "First seen", value: formatDateTime(indicator.firstSeenAt) },
            { label: "Last seen", value: formatDateTime(indicator.lastSeenAt) },
            { label: "Expires", value: indicator.expiresAt ? formatDateTime(indicator.expiresAt) : "Never" },
          ]}
        />
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Environment matches {matches.data ? `(${matches.data.items.length})` : ""}</h3>
          <IntelMatchesList matches={matches.data?.items} loading={matches.isPending} error={matches.error} />
        </div>
      </div>
      {block && blockAction && orgForAction ? (
        <RequestActionDialog open onClose={() => setBlock(false)} organizationId={orgForAction} actions={[blockAction]} defaultAction={blockAction} indicatorValue={indicator.value} />
      ) : null}
    </Drawer>
  );
}

function IntelMatchesList({ matches, loading, error }: { matches: IntelMatch[] | undefined; loading: boolean; error: unknown }) {
  if (loading) return <p className="text-sm text-fg-subtle">Loading…</p>;
  if (error) return <p className="text-sm text-fg-subtle">{errorMessage(error)}</p>;
  if (!matches || matches.length === 0) return <p className="text-sm text-fg-subtle">Not observed in this environment.</p>;
  return (
    <ul className="divide-y divide-line rounded border border-line">
      {matches.slice(0, 25).map((m) => (
        <li key={m.id} className="flex items-center gap-2 px-2.5 py-1.5 text-sm">
          <Badge size="xs" tone="outline">
            {m.entityKind}
          </Badge>
          {m.entityId ? (
            <Link to={hrefForEntity(m.entityKind, m.entityId)} className="min-w-0 flex-1 truncate text-heading hover:underline">
              {m.entityLabel ?? m.entityId}
            </Link>
          ) : (
            <span className="min-w-0 flex-1 truncate">{m.entityLabel ?? m.field ?? "event"}</span>
          )}
          {m.incidentId ? (
            <Link to={hrefForEntity("incident", m.incidentId)} className="text-xs text-primary hover:underline">
              Incident
            </Link>
          ) : null}
          <RelativeTime value={m.matchedAt} className="text-xs text-fg-subtle" />
        </li>
      ))}
    </ul>
  );
}

export function IndicatorsTable({
  filters = {},
  predicate,
  initialQuery = "",
  initialId = null,
  toolbar,
  emptyTitle = "No indicators yet",
  description,
}: {
  filters?: IndicatorFilters;
  predicate?: (i: Indicator) => boolean;
  initialQuery?: string;
  initialId?: string | null;
  toolbar?: ReactNode;
  emptyTitle?: string;
  description?: ReactNode;
}) {
  const session = useSession();
  const indicators = useIndicators({ ...filters, ...(initialQuery ? { q: initialQuery } : {}) });
  const [selected, setSelected] = useState<string | null>(initialId);
  const [adding, setAdding] = useState(false);
  const rows = useMemo(() => indicators.items?.filter((i) => (predicate ? predicate(i) : true)), [indicators.items, predicate]);
  const sel = rows?.find((i) => i.id === selected) ?? null;
  const canWrite = session.canAnywhere("intel:write");

  const columns: DataTableColumn<Indicator>[] = [
    { id: "value", header: "Indicator", accessor: (i) => i.value, hideable: false, cell: (i) => <span className="block max-w-[320px] truncate font-mono text-xs font-semibold" title={i.value}>{i.value}</span> },
    { id: "type", header: "Type", accessor: (i) => i.type, filter: { kind: "select", options: IndicatorType.options.map((t) => ({ value: t, label: humanize(t) })) } },
    { id: "severity", header: "Severity", accessor: (i) => Severity.options.indexOf(i.severity), cell: (i) => <SeverityBadge severity={i.severity} size="xs" /> },
    { id: "confidence", header: "Confidence", accessor: (i) => i.confidence, align: "right" },
    { id: "actor", header: "Actor", accessor: (i) => i.threatActor },
    { id: "campaign", header: "Campaign / malware", accessor: (i) => i.campaign ?? i.malware },
    { id: "source", header: "Source", accessor: (i) => i.source, filter: { kind: "text" } },
    { id: "scope", header: "Scope", accessor: (i) => (i.organizationId ? (session.organizationName(i.organizationId) ?? "Organization") : "Tenant-wide") },
    { id: "lastSeen", header: "Last seen", accessor: (i) => new Date(i.lastSeenAt), cell: (i) => <RelativeTime value={i.lastSeenAt} /> },
  ];

  return (
    <>
      <DataTable
        caption="Indicators"
        columns={columns}
        rows={rows}
        getRowId={(i) => i.id}
        loading={indicators.isPending}
        error={indicators.error}
        onRetry={() => void indicators.refetch()}
        onRowClick={(i) => setSelected(i.id)}
        selectedRowId={selected}
        initialState={{ sort: { columnId: "lastSeen", direction: "desc" } }}
        savedViewsKey="cti-indicators"
        exportFileName="bloody-indicators"
        toolbar={
          <>
            {toolbar}
            {canWrite ? (
              <Button size="sm" variant="primary" icon={Plus} onClick={() => setAdding(true)}>
                Add IOC
              </Button>
            ) : null}
          </>
        }
        footer={
          indicators.hasNextPage ? (
            <Button size="sm" onClick={() => void indicators.fetchNextPage()} loading={indicators.isFetchingNextPage}>
              Load more
            </Button>
          ) : null
        }
        emptyState={
          <ConnectEngineEmptyState
            compact
            icon={Target}
            title={emptyTitle}
            description={description}
            engines={["misp", "opencti"]}
            extraAction={canWrite ? <Button size="sm" icon={Plus} onClick={() => setAdding(true)}>Add IOC</Button> : undefined}
          />
        }
      />
      {sel ? <IndicatorDrawer indicator={sel} onClose={() => setSelected(null)} /> : null}
      {adding ? <AddIndicatorDialog open onClose={() => setAdding(false)} initialValue={initialQuery} /> : null}
    </>
  );
}

export function IntelMatchesTable({ filters = {}, predicate, emptyTitle = "No indicator matches in this environment" }: { filters?: IntelMatchFilters; predicate?: (m: IntelMatch) => boolean; emptyTitle?: string }) {
  const session = useSession();
  const matches = useIntelMatches(filters);
  const rows = useMemo(() => matches.data?.items.filter((m) => (predicate ? predicate(m) : true)), [matches.data, predicate]);
  const columns: DataTableColumn<IntelMatch>[] = [
    { id: "indicator", header: "Indicator", accessor: (m) => m.indicator?.value ?? m.value ?? m.indicatorId, cell: (m) => <span className="font-mono text-xs font-semibold">{m.indicator?.value ?? m.value ?? m.indicatorId}</span>, hideable: false },
    { id: "type", header: "Type", accessor: (m) => m.indicator?.type ?? null },
    { id: "severity", header: "Severity", accessor: (m) => (m.indicator ? Severity.options.indexOf(m.indicator.severity) : null), cell: (m) => (m.indicator ? <SeverityBadge severity={m.indicator.severity} size="xs" /> : "—") },
    { id: "actor", header: "Actor / campaign", accessor: (m) => m.indicator?.threatActor ?? m.indicator?.campaign ?? null },
    { id: "where", header: "Seen on", accessor: (m) => `${m.entityKind} ${m.entityLabel ?? ""}`, cell: (m) => (m.entityId ? <Link to={hrefForEntity(m.entityKind, m.entityId)} className="text-primary hover:underline">{m.entityLabel ?? m.entityId}</Link> : <span>{m.entityLabel ?? m.entityKind}</span>) },
    { id: "field", header: "Field", accessor: (m) => m.field, cell: (m) => <span className="font-mono text-xs">{m.field ?? "—"}</span> },
    { id: "incident", header: "Incident", accessor: (m) => m.incidentId, cell: (m) => (m.incidentId ? <Link to={hrefForEntity("incident", m.incidentId)} className="text-primary hover:underline">Open</Link> : <span className="text-fg-subtle">—</span>) },
    { id: "org", header: "Organization", accessor: (m) => session.organizationName(m.organizationId), defaultHidden: session.organizationId !== null },
    { id: "at", header: "Matched", accessor: (m) => new Date(m.matchedAt), cell: (m) => <RelativeTime value={m.matchedAt} /> },
  ];
  return (
    <DataTable
      caption="Environment matches"
      columns={columns}
      rows={rows}
      getRowId={(m) => m.id}
      loading={matches.isPending}
      error={matches.error}
      onRetry={() => void matches.refetch()}
      initialState={{ sort: { columnId: "at", direction: "desc" } }}
      exportFileName="bloody-intel-matches"
      emptyState={<ConnectEngineEmptyState compact icon={Crosshair} title={emptyTitle} description="Matches appear when an indicator from your feeds is observed in telemetry, identities or cloud events." engines={["misp", "opencti"]} />}
    />
  );
}
