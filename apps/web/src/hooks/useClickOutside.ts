import { useEffect, type RefObject } from "react";

/** Calls `onOutside` for pointer-downs outside every given element, and on Escape. */
export function useDismiss(refs: RefObject<HTMLElement | null>[], onDismiss: () => void, enabled = true): void {
  useEffect(() => {
    if (!enabled) return;
    const onPointer = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node | null;
      if (!target) return;
      if (refs.some((r) => r.current?.contains(target))) return;
      onDismiss();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onDismiss();
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("touchstart", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("touchstart", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [refs, onDismiss, enabled]);
}
