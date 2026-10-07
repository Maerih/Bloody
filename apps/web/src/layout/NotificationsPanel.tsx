import { clsx } from "clsx";
import { Bell, CalendarClock, CircleAlert, ClipboardCheck, Siren, Webhook } from "lucide-react";
import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useNotificationFeed } from "../api/hooks";
import type { NotificationItem } from "../api/types";
import { useSession } from "../app/session";
import { IconButton } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { Popover } from "../components/Popover";
import { RelativeTime } from "../components/RelativeTime";
import { SkeletonText } from "../components/Skeleton";
import { SEVERITY_META } from "../lib/severity";
import { isString, useLocalStorageState } from "../lib/storage";

const KIND_ICON = { escalation: CircleAlert, approval: ClipboardCheck, incident: Siren } as const;

/** Bell + panel of actionable items (escalations, pending approvals, new incidents). */
export function NotificationsPanel() {
  const session = useSession();
  const feed = useNotificationFeed({
    escalations: session.canAnywhere("escalation:read"),
    approvals: session.canAnywhere("response:approve"),
    incidents: session.canAnywhere("incident:read"),
  });
  const [lastSeen, setLastSeen] = useLocalStorageState<string>(`notifications.lastSeen.${session.principal.id}`, "1970-01-01T00:00:00.000Z", isString);
  const unseen = useMemo(() => feed.items.filter((i) => new Date(i.at).getTime() > new Date(lastSeen).getTime()).length, [feed.items, lastSeen]);

  return (
    <Popover
      align="end"
      label="Notifications"
      panelClassName="w-96 overflow-hidden"
      trigger={(props) => (
        <span className="relative inline-flex">
          <IconButton {...props} icon={Bell} label={unseen > 0 ? `Notifications (${unseen} new)` : "Notifications"} tone="topbar" />
          {unseen > 0 ? (
            <span className="pointer-events-none absolute right-1 top-0.5 h-2 w-2 rounded-full bg-sev-critical ring-2 ring-topbar" data-testid="notification-dot" aria-hidden />
          ) : null}
        </span>
      )}
    >
      {(close) => (
        <div>
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <span className="text-base font-semibold">Notifications</span>
            <button
              type="button"
              className="text-sm text-primary hover:underline disabled:text-fg-subtle disabled:no-underline"
              disabled={unseen === 0}
              onClick={() => setLastSeen(new Date().toISOString())}
            >
              Mark all as read
            </button>
          </div>
          <div className="scrollbar-thin max-h-[420px] overflow-y-auto">
            {feed.isLoading ? (
              <div className="p-3">
                <SkeletonText lines={4} />
              </div>
            ) : feed.items.length === 0 ? (
              <EmptyState compact tone="success" icon={Bell} title="You're all caught up" description="No open escalations, pending approvals or new incidents." />
            ) : (
              <ul className="divide-y divide-line">
                {feed.items.map((item) => (
                  <NotificationRow key={item.id} item={item} unseen={new Date(item.at).getTime() > new Date(lastSeen).getTime()} onNavigate={close} orgName={session.organizationId === null ? session.organizationName(item.organizationId) : null} />
                ))}
              </ul>
            )}
          </div>
          <div className="flex items-center justify-between gap-2 border-t border-line bg-surface-2 px-3 py-2 text-sm">
            <Link to="/soar/channels" onClick={close} className="inline-flex items-center gap-1 text-primary hover:underline">
              <Webhook size={12} aria-hidden /> Email &amp; chat delivery
            </Link>
            <Link to="/soar/automations" onClick={close} className="inline-flex items-center gap-1 text-primary hover:underline">
              <CalendarClock size={12} aria-hidden /> Automation rules
            </Link>
          </div>
        </div>
      )}
    </Popover>
  );
}

function NotificationRow({ item, unseen, onNavigate, orgName }: { item: NotificationItem; unseen: boolean; onNavigate: () => void; orgName: string | null }) {
  const Icon = KIND_ICON[item.kind];
  const meta = SEVERITY_META[item.severity];
  return (
    <li>
      <Link to={item.href} onClick={onNavigate} className={clsx("flex gap-2.5 px-3 py-2 hover:bg-surface-2", unseen && "bg-primary-soft/40")}>
        <span className={clsx("mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full", meta.softBg, meta.text)}>
          <Icon size={13} aria-hidden />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-base font-medium text-fg">{item.title}</span>
          <span className="block truncate text-xs text-fg-muted">{item.detail}</span>
          <span className="mt-0.5 flex items-center gap-2 text-2xs text-fg-subtle">
            <RelativeTime value={item.at} />
            {orgName ? <span className="truncate">· {orgName}</span> : null}
          </span>
        </span>
        {unseen ? <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-primary" aria-label="New" /> : null}
      </Link>
    </li>
  );
}
