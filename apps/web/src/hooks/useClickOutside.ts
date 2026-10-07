import { useEffect, type RefObject } from "react";

/**
 * Calls `onDismiss` for pointer-downs outside every given element, and `onEscape`
 * (default: `onDismiss`) when Escape is pressed.
 */
export function useDismiss(refs: RefObject<HTMLElement | null>[], onDismiss: () => void, enabled = true, onEscape?: () => void): void {
  useEffect(() => {
    if (!enabled) return;
    const onPointer = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node | null;
      if (!target) return;
      if (refs.some((r) => r.current?.contains(target))) return;
      onDismiss();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") (onEscape ?? onDismiss)();
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("touchstart", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("touchstart", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [refs, onDismiss, enabled, onEscape]);
}
