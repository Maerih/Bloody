import { MessageCircle } from "lucide-react";
import { useUi } from "../app/ui";
import { MenuList, Popover } from "../components/Popover";
import { helpMenuItems } from "./TopBar";

/** Floating "Help" pill, bottom-left (always reachable, like the reference UI). */
export function HelpPill() {
  const ui = useUi();
  return (
    <div className="fixed bottom-4 left-2.5 z-40">
      <Popover
        side="top"
        role="menu"
        label="Help"
        panelClassName="w-56"
        trigger={(props) => (
          <button
            {...props}
            type="button"
            className="inline-flex h-8 items-center gap-1.5 rounded-full bg-primary px-3.5 text-base font-semibold text-white shadow-pop hover:bg-primary-hover"
          >
            <MessageCircle size={15} aria-hidden />
            Help
          </button>
        )}
      >
        {(close) => <MenuList onClose={close} items={helpMenuItems(() => ui.setShortcutsOpen(true))} />}
      </Popover>
    </div>
  );
}
