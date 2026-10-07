import { clsx } from "clsx";
import { Building2, Check, ChevronDown, Layers, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useSession } from "../app/session";
import { Badge } from "../components/Badge";
import { Popover } from "../components/Popover";

/** "Account / <name>" selector: switch between "All organizations" and each organization. */
export function AccountSwitcher() {
  const session = useSession();
  const [filter, setFilter] = useState("");
  const { account, organizations, organization, organizationId, canSelectAll } = session;
  const current = organization?.name ?? (organizationId === null ? (canSelectAll ? "All organizations" : account.name) : account.name);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = [...organizations].sort((a, b) => a.name.localeCompare(b.name));
    return q ? list.filter((o) => o.name.toLowerCase().includes(q) || o.slug.includes(q)) : list;
  }, [organizations, filter]);

  return (
    <Popover
      label="Switch organization"
      panelClassName="w-72 overflow-hidden"
      onOpenChange={(open) => !open && setFilter("")}
      trigger={(props) => (
        <button
          {...props}
          type="button"
          className="flex h-11 items-center gap-2 px-3 text-left text-topbar-fg hover:bg-topbar-hover"
          aria-label={`Account ${account.name}, viewing ${current}. Switch organization`}
        >
          <span className="min-w-0">
            <span className="block text-2xs leading-tight text-topbar-muted">{organization ? account.name : "Account"}</span>
            <span className="block max-w-[180px] truncate text-base font-semibold leading-tight">{organization ? organization.name : account.name}</span>
          </span>
          <ChevronDown size={14} aria-hidden className="text-topbar-muted" />
        </button>
      )}
    >
      {(close) => (
        <div>
          <div className="border-b border-line px-3 py-2">
            <div className="flex items-center gap-2">
              <span className="truncate text-base font-semibold">{account.name}</span>
              <Badge size="xs" tone={account.kind === "mssp" ? "brand" : "info"}>
                {account.kind === "mssp" ? "MSSP" : "Enterprise"}
              </Badge>
            </div>
            <div className="text-xs text-fg-subtle">
              {organizations.length} organization{organizations.length === 1 ? "" : "s"} · {session.plan} plan
            </div>
          </div>
          {organizations.length > 6 ? (
            <div className="relative border-b border-line p-2">
              <Search size={12} className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
              <input
                autoFocus
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Find organization…"
                aria-label="Find organization"
                className="h-7 w-full rounded border border-line-strong bg-surface pl-6 pr-2 text-base focus:border-primary focus:outline-none"
              />
            </div>
          ) : null}
          <ul role="listbox" aria-label="Organizations" className="scrollbar-thin max-h-72 overflow-y-auto py-1">
            {canSelectAll ? (
              <li>
                <OrgOption
                  icon={Layers}
                  label="All organizations"
                  hint={session.isMssp ? "MSSP / tenant-wide view" : "Tenant-wide view"}
                  selected={organizationId === null}
                  onSelect={() => {
                    session.setOrganizationId(null);
                    close();
                  }}
                />
              </li>
            ) : null}
            {filtered.map((o) => (
              <li key={o.id}>
                <OrgOption
                  icon={Building2}
                  label={o.name}
                  hint={o.slug}
                  selected={organizationId === o.id}
                  onSelect={() => {
                    session.setOrganizationId(o.id);
                    close();
                  }}
                />
              </li>
            ))}
            {filtered.length === 0 ? <li className="px-3 py-2 text-sm text-fg-subtle">No organizations match “{filter}”.</li> : null}
          </ul>
          <div className="flex items-center justify-between border-t border-line px-3 py-2 text-sm">
            <Link to="/organizations" className="text-primary hover:underline" onClick={close}>
              Manage organizations
            </Link>
            {session.isMssp && canSelectAll ? (
              <Link to="/mssp" className="text-primary hover:underline" onClick={close}>
                MSSP view
              </Link>
            ) : null}
          </div>
        </div>
      )}
    </Popover>
  );
}

function OrgOption({ icon: Icon, label, hint, selected, onSelect }: { icon: typeof Building2; label: string; hint: string; selected: boolean; onSelect: () => void }) {
  return (
    <button
      type="button"
      role="option"
      aria-selected={selected}
      onClick={onSelect}
      className={clsx("flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-surface-3 focus:bg-surface-3 focus:outline-none", selected && "bg-primary-soft")}
    >
      <Icon size={14} aria-hidden className="shrink-0 text-fg-muted" />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-base">{label}</span>
        <span className="block truncate text-2xs text-fg-subtle">{hint}</span>
      </span>
      {selected ? <Check size={14} aria-hidden className="text-primary" /> : null}
    </button>
  );
}
