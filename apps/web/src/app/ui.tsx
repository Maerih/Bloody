import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

/** Shell-level UI state shared between the top bar, shortcuts and overlays. */
interface UiContextValue {
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
  openPalette: () => void;
  shortcutsOpen: boolean;
  setShortcutsOpen: (open: boolean) => void;
}

const UiContext = createContext<UiContextValue | null>(null);

export function UiProvider({ children }: { children: ReactNode }) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const openPalette = useCallback(() => setPaletteOpen(true), []);
  const value = useMemo(
    () => ({ paletteOpen, setPaletteOpen, openPalette, shortcutsOpen, setShortcutsOpen }),
    [paletteOpen, openPalette, shortcutsOpen],
  );
  return <UiContext.Provider value={value}>{children}</UiContext.Provider>;
}

export function useUi(): UiContextValue {
  const ctx = useContext(UiContext);
  if (!ctx) throw new Error("useUi must be used inside <UiProvider>");
  return ctx;
}
