import type { CanonicalEvent } from "@bloody/contracts";
import { Network, Search, Server, Sparkles, Target } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge } from "../../components/Badge";
import { ButtonLink } from "../../components/Button";
import { DescriptionList, type DescriptionItem } from "../../components/DescriptionList";
import { JsonView } from "../../components/JsonView";
import { Drawer } from "../../components/Overlay";
import { hrefForEntity } from "../../lib/entityLinks";
import { formatDateTime, formatNumber } from "../../lib/format";
import { eventHost, eventSummary, pivotQuery, searchHref } from "./eventFormat";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-b border-line px-4 py-3">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">{title}</h3>
      {children}
    </section>
  );
}

function compact(items: (DescriptionItem | false | null | undefined)[]): DescriptionItem[] {
  return items.filter((i): i is DescriptionItem => Boolean(i) && (i as DescriptionItem).value !== undefined && (i as DescriptionItem).value !== null && (i as DescriptionItem).value !== "");
}

/** Event detail: normalized fields, pivots (host, hash, IP, graph, intel, AI) and raw JSON. */
export function EventDrawer({ event, onClose }: { event: CanonicalEvent | null; onClose: () => void }) {
  const session = useSession();
  if (!event) return null;
  const e = event;
  const host = eventHost(e);
  const canAi = session.isModuleEnabled("ai_soc") && session.can("ai:use", e.organizationId);
  const ip = e.network?.dstIp ?? e.identity?.sourceIp;
  const hash = e.process?.hashSha256 ?? e.file?.sha256;
  return (
    <Drawer
      open
      onClose={onClose}
      width="xl"
      title={eventSummary(e)}
      subtitle={
        <span className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={e.severity} size="xs" />
          <Badge size="xs" tone="outline">
            {e.category}
          </Badge>
          <span className="font-mono text-xs">{e.eventType}</span>
          <span>{formatDateTime(e.timestamp)}</span>
        </span>
      }
    >
      <div className="flex flex-wrap gap-2 border-b border-line px-4 py-3">
        {host ? (
          <ButtonLink size="sm" icon={Search} to={searchHref(pivotQuery("asset.hostname", host))} onClick={onClose}>
            Events on {host}
          </ButtonLink>
        ) : null}
        {e.asset?.id ? (
          <ButtonLink size="sm" icon={Server} to={hrefForEntity("asset", e.asset.id)} onClick={onClose}>
            Open asset
          </ButtonLink>
        ) : null}
        {hash ? (
          <ButtonLink size="sm" icon={Target} to={`/cti/indicators?q=${encodeURIComponent(hash)}`} onClick={onClose}>
            Look up hash
          </ButtonLink>
        ) : null}
        {ip ? (
          <ButtonLink size="sm" icon={Network} to={`/graph?q=${encodeURIComponent(ip)}`} onClick={onClose}>
            Pivot {ip} in graph
          </ButtonLink>
        ) : null}
        {canAi && e.asset?.id ? (
          <ButtonLink size="sm" variant="primary" icon={Sparkles} to={`/ai?context=${encodeURIComponent(`asset:${e.asset.id}`)}`} onClick={onClose}>
            Ask AI about this host
          </ButtonLink>
        ) : null}
      </div>
      <Section title="Event">
        <DescriptionList
          items={compact([
            { label: "Timestamp", value: formatDateTime(e.timestamp) },
            { label: "Source", value: `${e.source.product} (${e.source.kind})` },
            { label: "Action", value: e.action },
            { label: "Outcome", value: e.outcome },
            { label: "Risk", value: e.risk !== undefined ? String(e.risk) : null },
            { label: "Organization", value: session.organizationName(e.organizationId) },
            e.detection ? { label: "Detection", value: `${e.detection.ruleName ?? e.detection.ruleId ?? "rule"}${e.detection.engine ? ` · ${e.detection.engine}` : ""}` } : null,
            e.attack.length > 0 ? { label: "ATT&CK", value: e.attack.map((t) => `${t.id}${t.name ? ` ${t.name}` : ""}`).join(", "), wide: true } : null,
            e.message ? { label: "Message", value: e.message, wide: true } : null,
          ])}
        />
      </Section>
      {e.asset || e.user || e.identity ? (
        <Section title="Who & where">
          <DescriptionList
            items={compact([
              { label: "Hostname", value: e.asset?.hostname },
              { label: "Asset IPs", value: e.asset?.ip?.join(", ") },
              { label: "OS", value: e.asset?.os },
              { label: "User", value: e.user ? [e.user.domain, e.user.name].filter(Boolean).join("\\") || e.user.email : null },
              { label: "Identity", value: e.identity?.principal },
              { label: "Provider", value: e.identity?.provider },
              { label: "Sign-in IP", value: e.identity?.sourceIp },
              { label: "Location", value: [e.identity?.geo?.city, e.identity?.geo?.country].filter(Boolean).join(", ") },
              { label: "MFA", value: e.identity?.mfa === undefined ? null : e.identity.mfa ? "Yes" : "No" },
              { label: "Privileged", value: e.identity?.privileged === undefined ? null : e.identity.privileged ? "Yes" : "No" },
            ])}
          />
        </Section>
      ) : null}
      {e.process ? (
        <Section title="Process">
          <DescriptionList
            items={compact([
              { label: "Name", value: e.process.name },
              { label: "PID", value: e.process.pid !== undefined ? String(e.process.pid) : null },
              { label: "Path", value: e.process.path, wide: true },
              { label: "Command line", value: e.process.commandLine ? <code className="break-all font-mono text-xs">{e.process.commandLine}</code> : null, wide: true },
              { label: "User", value: e.process.user },
              { label: "SHA-256", value: e.process.hashSha256 ? <code className="break-all font-mono text-xs">{e.process.hashSha256}</code> : null, wide: true },
              { label: "Parent", value: e.process.parent ? `${e.process.parent.name ?? "?"}${e.process.parent.pid !== undefined ? ` (pid ${e.process.parent.pid})` : ""}` : null },
              { label: "Parent command", value: e.process.parent?.commandLine ? <code className="break-all font-mono text-xs">{e.process.parent.commandLine}</code> : null, wide: true },
            ])}
          />
        </Section>
      ) : null}
      {e.network ? (
        <Section title="Network">
          <DescriptionList
            items={compact([
              { label: "Direction", value: e.network.direction },
              { label: "Protocol", value: e.network.protocol },
              { label: "Source", value: e.network.srcIp ? `${e.network.srcIp}${e.network.srcPort ? `:${e.network.srcPort}` : ""}` : null },
              { label: "Destination", value: e.network.dstIp ? `${e.network.dstIp}${e.network.dstPort ? `:${e.network.dstPort}` : ""}` : null },
              { label: "Bytes out / in", value: e.network.bytesOut !== undefined || e.network.bytesIn !== undefined ? `${formatNumber(e.network.bytesOut)} / ${formatNumber(e.network.bytesIn)}` : null },
              { label: "DNS query", value: e.network.dnsQuery },
              { label: "HTTP", value: e.network.httpHost ? `${e.network.httpHost}${e.network.httpUrl ?? ""}` : null, wide: true },
              { label: "TLS SNI", value: e.network.tlsSni },
              { label: "JA3", value: e.network.ja3 },
            ])}
          />
        </Section>
      ) : null}
      {e.file ? (
        <Section title="File">
          <DescriptionList
            items={compact([
              { label: "Action", value: e.file.action },
              { label: "Path", value: e.file.path, wide: true },
              { label: "SHA-256", value: e.file.sha256 ? <code className="break-all font-mono text-xs">{e.file.sha256}</code> : null, wide: true },
              { label: "Size", value: e.file.size !== undefined ? formatNumber(e.file.size) : null },
            ])}
          />
        </Section>
      ) : null}
      {e.indicators.length > 0 ? (
        <Section title={`Indicators (${e.indicators.length})`}>
          <ul className="flex flex-wrap gap-1.5">
            {e.indicators.map((i) => (
              <li key={`${i.type}:${i.value}`}>
                <Link to={`/cti/indicators?q=${encodeURIComponent(i.value)}`} onClick={onClose} className="inline-flex items-center gap-1 rounded border border-line-strong px-1.5 py-0.5 font-mono text-xs hover:border-primary">
                  <span className="text-fg-subtle">{i.type}</span> {i.value}
                </Link>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      <Section title="Raw canonical event (BCE)">
        <JsonView value={e} />
        <p className="mt-1 text-2xs text-fg-subtle">
          Normalized by {e.provenance.adapter} {e.provenance.adapterVersion} · received {formatDateTime(e.provenance.receivedAt)}
        </p>
      </Section>
    </Drawer>
  );
}
