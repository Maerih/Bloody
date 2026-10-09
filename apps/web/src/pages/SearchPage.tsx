import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { errorMessage } from "../api/client";
import { useGlobalSearch } from "../api/hooks";
import type { SearchHit } from "../api/types";
import { useSession } from "../app/session";
import { SeverityBadge } from "../components/Badge";
import { Card } from "../components/Card";
import { EmptyState } from "../components/EmptyState";
import { Input } from "../components/Form";
import { PageHeader } from "../components/PageHeader";
import { SkeletonText } from "../components/Skeleton";
import { humanize } from "../lib/format";
import { hrefForEntity } from "../lib/entityLinks";

/** /search?q= — tenant- and permission-aware global search results, grouped by entity kind. */
export default function SearchPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const [draft, setDraft] = useState(q);
  const search = useGlobalSearch(q, { minLength: 2 });
  const groups = useMemo(() => {
    const m = new Map<string, SearchHit[]>();
    for (const h of search.data ?? []) m.set(h.kind, [...(m.get(h.kind) ?? []), h]);
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [search.data]);
  return (
    <div className="max-w-5xl">
      <PageHeader title="Search" subtitle={`Incidents, assets, identities, indicators and more across ${session.organization ? session.organization.name : "all organizations you can access"}.`} />
      <form
        className="mb-3 flex gap-2"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          const next = new URLSearchParams(params);
          if (draft.trim()) next.set("q", draft.trim());
          else next.delete("q");
          setParams(next);
        }}
      >
        <label className="relative flex-1">
          <Search size={14} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
          <Input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="Hostname, user, IP, hash, CVE, incident…" className="pl-7" aria-label="Search" autoFocus />
        </label>
      </form>
      {q.trim().length < 2 ? (
        <EmptyState compact icon={Search} title="Type at least two characters" />
      ) : search.isPending ? (
        <SkeletonText lines={6} />
      ) : search.isError ? (
        <p role="alert" className="text-sm text-sev-critical">
          {errorMessage(search.error)}
        </p>
      ) : groups.length === 0 ? (
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState icon={Search} title={`Nothing matches “${q}”`} description="Search covers the records you are permitted to read. Try the Security Graph or SIEM event search for raw telemetry." />
        </div>
      ) : (
        <div className="space-y-3">
          {groups.map(([kind, hits]) => (
            <Card key={kind} title={humanize(kind)} count={hits.length} padded={false}>
              <ul className="divide-y divide-line">
                {hits.map((h) => (
                  <li key={`${h.kind}:${h.id}`}>
                    <Link to={h.href ?? hrefForEntity(h.kind, h.id)} className="flex items-center gap-2 px-3 py-2 hover:bg-surface-2">
                      {h.severity ? <SeverityBadge severity={h.severity} size="xs" /> : null}
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium text-heading">{h.title}</span>
                        {h.subtitle ? <span className="block truncate text-xs text-fg-muted">{h.subtitle}</span> : null}
                      </span>
                      {h.organizationName ?? (h.organizationId ? session.organizationName(h.organizationId) : null) ? <span className="text-2xs text-fg-subtle">{h.organizationName ?? session.organizationName(h.organizationId)}</span> : null}
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
