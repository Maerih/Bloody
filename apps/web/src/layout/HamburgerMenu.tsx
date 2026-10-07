import { ExternalLink, Menu } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useLogout } from "../api/hooks";
import { APP_CONFIG, isExternalUrl } from "../app/config";
import { HAMBURGER_SECTIONS, type MenuItem } from "../app/navigation";
import { useSession } from "../app/session";
import { IconButton } from "../components/Button";
import { Popover } from "../components/Popover";

/** External destinations come from deployment config; otherwise the in-app page is used. */
export function resolveMenuHref(item: MenuItem): { href: string; external: boolean } {
  const configured =
    item.path === "/support" ? APP_CONFIG.supportUrl : item.path === "/hub" ? APP_CONFIG.hubUrl : item.path === "/feedback" ? APP_CONFIG.feedbackUrl : null;
  if (configured) return { href: configured, external: isExternalUrl(configured) };
  return { href: item.path, external: false };
}

/** Right-hand "≡" menu: support actions, account pages, profile. */
export function HamburgerMenu() {
  const session = useSession();
  const logout = useLogout();
  const navigate = useNavigate();

  const doLogout = () => {
    logout.mutate(undefined, { onSettled: () => navigate("/login", { replace: true }) });
  };

  return (
    <Popover
      align="end"
      role="menu"
      label="Main menu"
      panelClassName="w-56 py-1"
      trigger={(props) => <IconButton {...props} icon={Menu} label="Main menu" tone="topbar" />}
    >
      {(close) => (
        <nav aria-label="Main menu">
          {HAMBURGER_SECTIONS.map((section, si) => {
            const items = section.items.filter((i) => !i.permission || session.canAnywhere(i.permission));
            if (items.length === 0) return null;
            return (
              <div key={section.title ?? si} className={si > 0 ? "mt-1 border-t border-line pt-1" : undefined}>
                {section.title ? <div className="px-3 pb-0.5 pt-1.5 text-xs font-medium text-fg-subtle">{section.title}</div> : null}
                <ul>
                  {items.map((item) => {
                    const Icon = item.icon;
                    const cls = "flex w-full items-center gap-2 px-3 py-1 text-left text-sm text-fg hover:bg-surface-3 focus:bg-surface-3 focus:outline-none";
                    if (item.action === "logout") {
                      return (
                        <li key={item.label}>
                          <button
                            type="button"
                            role="menuitem"
                            className={cls}
                            onClick={() => {
                              close();
                              doLogout();
                            }}
                          >
                            <Icon size={13} aria-hidden className="text-fg-muted" />
                            {item.label}
                          </button>
                        </li>
                      );
                    }
                    const { href, external } = resolveMenuHref(item);
                    return (
                      <li key={item.label}>
                        {external ? (
                          <a role="menuitem" href={href} target="_blank" rel="noopener noreferrer" className={cls} onClick={close}>
                            <Icon size={13} aria-hidden className="text-fg-muted" />
                            {item.label}
                            <ExternalLink size={11} aria-hidden className="text-fg-subtle" />
                          </a>
                        ) : (
                          <Link role="menuitem" to={href} className={cls} onClick={close}>
                            <Icon size={13} aria-hidden className="text-fg-muted" />
                            {item.label}
                            {item.external ? <ExternalLink size={11} aria-hidden className="text-fg-subtle" /> : null}
                          </Link>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })}
        </nav>
      )}
    </Popover>
  );
}
