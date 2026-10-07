import { useUi } from "../app/ui";
import { Kbd } from "../components/DescriptionList";
import { Dialog } from "../components/Overlay";
import { SHORTCUTS } from "./shortcuts";

export function ShortcutList() {
  return (
    <ul className="divide-y divide-line">
      {SHORTCUTS.map((s) => (
        <li key={s.keys} className="flex items-center justify-between py-1.5 text-base">
          <span className="text-fg">{s.description}</span>
          <span className="flex items-center gap-1">
            {s.display.map((k, i) => (
              <span key={`${k}-${i}`} className="flex items-center gap-1">
                {i > 0 && s.keys.includes(" ") ? <span className="text-2xs text-fg-subtle">then</span> : null}
                <Kbd>{k}</Kbd>
              </span>
            ))}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function ShortcutHelpDialog() {
  const ui = useUi();
  return (
    <Dialog open={ui.shortcutsOpen} onClose={() => ui.setShortcutsOpen(false)} title="Keyboard shortcuts" description="Shortcuts work anywhere outside text fields." size="sm">
      <ShortcutList />
    </Dialog>
  );
}
