import { useEffect, useRef } from "react";

/**
 * Global keyboard shortcuts with Gmail-style sequences ("g i") and modifier combos ("mod+k").
 * `mod` = ⌘ on macOS, Ctrl elsewhere. Shortcuts without modifiers are ignored while typing in
 * inputs, textareas, selects or contenteditable regions.
 */
export interface Hotkey {
  /** e.g. "mod+k", "g i", "?", "escape" */
  keys: string;
  handler: (event: KeyboardEvent) => void;
  /** Fire even when focus is in a text field (only sensible for modifier combos). */
  allowInInputs?: boolean;
}

const SEQUENCE_TIMEOUT_MS = 1200;

export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  if (tag === "TEXTAREA" || tag === "SELECT") return true;
  if (tag === "INPUT") {
    const type = (target as HTMLInputElement).type;
    return !["checkbox", "radio", "button", "submit", "reset", "range", "color", "file"].includes(type);
  }
  return false;
}

export function isMac(): boolean {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);
}

function normalizeKey(event: KeyboardEvent): string {
  const key = event.key.length === 1 ? event.key.toLowerCase() : event.key.toLowerCase();
  return key === " " ? "space" : key;
}

function matchesCombo(combo: string, event: KeyboardEvent): boolean {
  const parts = combo.toLowerCase().split("+");
  const key = parts[parts.length - 1];
  const wantMod = parts.includes("mod");
  const wantShift = parts.includes("shift");
  const wantAlt = parts.includes("alt");
  const mod = event.metaKey || event.ctrlKey;
  if (wantMod !== mod) return false;
  if (wantAlt !== event.altKey) return false;
  // "?" is produced with shift on most layouts; don't require/forbid shift for punctuation.
  if (key && key.length === 1 && !/[a-z0-9]/.test(key)) return normalizeKey(event) === key;
  if (wantShift !== event.shiftKey) return false;
  return normalizeKey(event) === key;
}

export function useHotkeys(hotkeys: Hotkey[], enabled = true): void {
  const ref = useRef(hotkeys);
  ref.current = hotkeys;
  const pending = useRef<{ key: string; at: number } | null>(null);

  useEffect(() => {
    if (!enabled) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.isComposing) return;
      const typing = isTypingTarget(event.target);
      const now = Date.now();
      const prefix = pending.current && now - pending.current.at < SEQUENCE_TIMEOUT_MS ? pending.current.key : null;

      for (const hk of ref.current) {
        if (typing && !hk.allowInInputs) continue;
        const seq = hk.keys.trim().split(/\s+/);
        if (seq.length === 2) {
          if (prefix === seq[0] && !event.metaKey && !event.ctrlKey && !event.altKey && normalizeKey(event) === seq[1]) {
            pending.current = null;
            event.preventDefault();
            hk.handler(event);
            return;
          }
        } else if (seq.length === 1 && seq[0] && matchesCombo(seq[0], event)) {
          pending.current = null;
          event.preventDefault();
          hk.handler(event);
          return;
        }
      }

      if (!typing && !event.metaKey && !event.ctrlKey && !event.altKey) {
        const key = normalizeKey(event);
        const startsSequence = ref.current.some((hk) => hk.keys.trim().split(/\s+/)[0] === key && hk.keys.trim().includes(" "));
        pending.current = startsSequence ? { key, at: now } : null;
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [enabled]);
}
