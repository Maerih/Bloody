import type { Investigation } from "@bloody/contracts";
import { FolderSearch, Plus, Search, Siren, X } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useIncident } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Button } from "../../components/Button";
import { Input } from "../../components/Form";
import { PageHeader } from "../../components/PageHeader";
import { Tabs } from "../../components/Tabs";
import { CreateInvestigationDialog, InvestigationsTable } from "../../features/investigations/InvestigationsTable";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { hrefForEntity } from "../../lib/entityLinks";

type View = "active" | "awaiting_customer" | "closed" | "all";
const VIEW_STATUS: Record<View, Investigation["status"][] | undefined> = {
  active: ["open", "in_progress", "awaiting_customer"],
  awaiting_customer: ["awaiting_customer"],
  closed: ["closed"],
  all: undefined,
};

/** /investigations — list (?status=, ?q=, ?incidentId=) and entry point to the workspace. */
export default function InvestigationsPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const view = (["active", "awaiting_customer", "closed", "all"] as View[]).find((v) => v === params.get("status")) ?? "active";
  const incidentId = params.get("incidentId") ?? undefined;
  const incident = useIncident(incidentId);
  const [q, setQ] = useState(params.get("q") ?? "");
  const term = useDebouncedValue(q, 300);
  const [creating, setCreating] = useState(false);
  const canCreate = session.canAnywhere("investigation:write");

  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value === null || value === "") next.delete(key);
    else next.set(key, value);
    setParams(next, { replace: true });
  };

  return (
    <div>
      <PageHeader
        title="Investigations"
        subtitle="Investigation workspaces: timeline, evidence with chain of custody, graph, notes, tasks and response actions."
        actions={
          canCreate ? (
            <Button variant="primary" icon={Plus} onClick={() => setCreating(true)}>
              Open investigation
            </Button>
          ) : null
        }
      >
        <Tabs<View>
          ariaLabel="Investigation status"
          idPrefix="inv-status"
          value={view}
          onChange={(v) => set("status", v === "active" ? null : v)}
          tabs={[
            { id: "active", label: "Active", icon: FolderSearch },
            { id: "awaiting_customer", label: "Awaiting customer" },
            { id: "closed", label: "Closed" },
            { id: "all", label: "All" },
          ]}
        />
      </PageHeader>
      {incidentId ? (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded border border-line bg-surface px-3 py-2 text-sm shadow-card">
          <Siren size={14} className="text-sev-high" aria-hidden />
          <span>
            Investigations for incident{" "}
            <Link to={hrefForEntity("incident", incidentId)} className="font-medium text-primary hover:underline">
              {incident.data ? `#${incident.data.number} ${incident.data.title}` : "…"}
            </Link>
          </span>
          {canCreate ? (
            <Button size="xs" variant="primary" icon={Plus} onClick={() => setCreating(true)}>
              Investigate this incident
            </Button>
          ) : null}
          <Button size="xs" variant="ghost" icon={X} className="ml-auto" onClick={() => set("incidentId", null)}>
            Clear
          </Button>
        </div>
      ) : null}
      <div className="mb-2 flex items-center gap-2">
        <label className="relative w-full max-w-sm">
          <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onBlur={() => set("q", q.trim() || null)}
            placeholder="Search title or hypothesis…"
            className="pl-7"
            aria-label="Search investigations"
          />
        </label>
      </div>
      <InvestigationsTable
        filters={{ status: VIEW_STATUS[view], ...(incidentId ? { incidentId } : {}), ...(term.trim() ? { q: term.trim() } : {}) }}
        emptyTitle={incidentId ? "No investigation for this incident yet" : view === "closed" ? "No closed investigations" : "No active investigations"}
        onCreate={canCreate ? () => setCreating(true) : undefined}
        savedViewsKey="investigations"
      />
      {creating ? <CreateInvestigationDialog onClose={() => setCreating(false)} {...(incidentId ? { incidentId } : {})} /> : null}
    </div>
  );
}
