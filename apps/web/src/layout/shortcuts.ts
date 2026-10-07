/** Keyboard shortcut catalogue — drives the global handler, the "?" help dialog and Preferences. */
export interface ShortcutDef {
  keys: string;
  /** Display form, e.g. ["g", "i"] or ["⌘", "K"]. */
  display: string[];
  description: string;
  /** Navigate to this path, or run a named shell action. */
  path?: string;
  action?: "palette" | "help" | "search";
  allowInInputs?: boolean;
}

export const SHORTCUTS: ShortcutDef[] = [
  { keys: "mod+k", display: ["⌘/Ctrl", "K"], description: "Open command palette & global search", action: "palette", allowInInputs: true },
  { keys: "/", display: ["/"], description: "Search", action: "search" },
  { keys: "?", display: ["?"], description: "Show keyboard shortcuts", action: "help" },
  { keys: "g h", display: ["g", "h"], description: "Go to Command Center", path: "/" },
  { keys: "g i", display: ["g", "i"], description: "Go to Incidents", path: "/incidents" },
  { keys: "g e", display: ["g", "e"], description: "Go to Escalations", path: "/escalations" },
  { keys: "g n", display: ["g", "n"], description: "Go to Investigations", path: "/investigations" },
  { keys: "g a", display: ["g", "a"], description: "Go to Assets", path: "/assets" },
  { keys: "g o", display: ["g", "o"], description: "Go to Organizations", path: "/organizations" },
  { keys: "g r", display: ["g", "r"], description: "Go to Reports", path: "/reports" },
  { keys: "g m", display: ["g", "m"], description: "Go to MSSP Command Center", path: "/mssp" },
  { keys: "g t", display: ["g", "t"], description: "Go to Trial Manager", path: "/trials" },
  { keys: "g p", display: ["g", "p"], description: "Go to Preferences", path: "/preferences" },
];
