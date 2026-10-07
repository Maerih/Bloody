import { clsx } from "clsx";
import { CircleHelp, Keyboard, LifeBuoy, MessageCircle, Search, Settings, Sparkles } from "lucide-react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { APP_CONFIG, isExternalUrl } from "../app/config";
import { TOP_NAV } from "../app/navigation";
import { useSession } from "../app/session";
import { useUi } from "../app/ui";
import { IconButton } from "../components/Button";
import { LogoMark } from "../components/Logo";
import { MenuList, Popover } from "../components/Popover";
import { isMac } from "../hooks/useHotkeys";
import { AccountSwitcher } from "./AccountSwitcher";
import { HamburgerMenu } from "./HamburgerMenu";
import { NotificationsPanel } from "./NotificationsPanel";

/** Dark slate top bar: logo, account/org selector, primary nav, commercial + utility actions. */
export function TopBar() {
  const session = useSession();
  const ui = useUi();
  const navigate = useNavigate();
  const nav = TOP_NAV.filter((item) => !item.permission || session.canAnywhere(item.permission)).filter(
    (item) => item.path !== "/ai" || session.isModuleEnabled("ai_soc"),
  );

  const contactSales = () => {
    const url = APP_CONFIG.salesContactUrl;
    if (url && isExternalUrl(url)) window.open(url, "_blank", "noopener,noreferrer");
    else navigate("/trials#contact");
  };

  return (
    <header className="fixed inset-x-0 top-0 z-40 flex h-11 items-center bg-topbar text-topbar-fg shadow-[0_1px_0_rgb(0_0_0/0.25)]">
      <Link to="/" className="flex h-11 w-[60px] shrink-0 items-center justify-center hover:bg-topbar-hover" aria-label="Bloody Command Center home">
        <LogoMark size={26} />
      </Link>
      <AccountSwitcher />
      <span className="mx-1 h-7 w-px shrink-0 bg-healthy/60" aria-hidden />
      <nav aria-label="Primary" className="scrollbar-none hidden min-w-0 flex-1 items-center overflow-x-auto lg:flex">
        {nav.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              clsx(
                "flex h-11 shrink-0 items-center whitespace-nowrap border-b-2 px-2.5 text-sm transition-colors",
                isActive ? "border-healthy text-white" : "border-transparent text-topbar-fg/85 hover:text-white",
              )
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="ml-auto flex shrink-0 items-center gap-1.5 pr-2">
        <button
          type="button"
          onClick={ui.openPalette}
          className="hidden h-7 items-center gap-2 rounded border border-white/15 bg-white/5 px-2 text-sm text-topbar-muted hover:bg-white/10 hover:text-topbar-fg md:inline-flex"
          aria-label="Search and commands"
          aria-keyshortcuts={isMac() ? "Meta+K" : "Control+K"}
        >
          <Search size={13} aria-hidden />
          <span>Search</span>
          <span className="rounded border border-white/15 px-1 font-mono text-2xs">{isMac() ? "⌘K" : "Ctrl K"}</span>
        </button>
        <button
          type="button"
          onClick={contactSales}
          className="inline-flex h-7 items-center gap-1 rounded bg-primary px-2.5 text-sm font-medium text-white hover:bg-primary-hover"
        >
          <MessageCircle size={13} aria-hidden />
          Contact Sales
        </button>
        <Popover
          align="end"
          role="menu"
          label="Help"
          panelClassName="w-56"
          trigger={(props) => (
            <button {...props} type="button" className="inline-flex h-7 items-center rounded bg-sev-critical px-2.5 text-sm font-medium text-white hover:brightness-95">
              Help
            </button>
          )}
        >
          {(close) => <MenuList onClose={close} items={helpMenuItems(() => ui.setShortcutsOpen(true))} />}
        </Popover>
        <NotificationsPanel />
        <IconButton icon={Settings} label="Settings" tone="topbar" onClick={() => navigate("/settings")} />
        <HamburgerMenu />
      </div>
    </header>
  );
}

export function helpMenuItems(openShortcuts: () => void) {
  const support = APP_CONFIG.supportUrl;
  const docs = APP_CONFIG.docsUrl;
  return [
    support
      ? { key: "support", label: "Support & FAQ", icon: LifeBuoy, href: support, external: isExternalUrl(support) }
      : { key: "support", label: "Support & FAQ", icon: LifeBuoy, href: "/support" },
    ...(docs ? [{ key: "docs", label: "Documentation", icon: CircleHelp, href: docs, external: isExternalUrl(docs) }] : []),
    { key: "shortcuts", label: "Keyboard shortcuts", icon: Keyboard, onSelect: openShortcuts, hint: "?" },
    { key: "ai", label: "Ask the AI SOC analyst", icon: Sparkles, href: "/ai" },
  ];
}
