import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useUi } from "../app/ui";
import { useHotkeys, type Hotkey } from "../hooks/useHotkeys";
import { SHORTCUTS } from "./shortcuts";

/** Binds the SHORTCUTS catalogue to navigation and shell actions. */
export function GlobalShortcuts() {
  const navigate = useNavigate();
  const ui = useUi();
  const hotkeys = useMemo<Hotkey[]>(
    () =>
      SHORTCUTS.map((s) => ({
        keys: s.keys,
        allowInInputs: s.allowInInputs ?? false,
        handler: () => {
          if (s.path) navigate(s.path);
          else if (s.action === "palette") ui.setPaletteOpen(!ui.paletteOpen);
          else if (s.action === "search") ui.setPaletteOpen(true);
          else if (s.action === "help") ui.setShortcutsOpen(true);
        },
      })),
    [navigate, ui],
  );
  useHotkeys(hotkeys);
  return null;
}
