import { clsx } from "clsx";
import { useMemo } from "react";
import { CopyButton } from "./CopyButton";

/** Read-only pretty-printed JSON (raw event / API payload inspection) with copy. */
export function JsonView({ value, className, maxHeight = "28rem" }: { value: unknown; className?: string; maxHeight?: string }) {
  const text = useMemo(() => {
    try {
      return JSON.stringify(value, null, 2) ?? "null";
    } catch {
      return String(value);
    }
  }, [value]);
  return (
    <div className={clsx("relative rounded border border-line bg-surface-2", className)}>
      <CopyButton value={text} label="Copy JSON" className="absolute right-1 top-1" />
      <pre className="scrollbar-thin overflow-auto p-3 pr-9 font-mono text-xs leading-relaxed text-fg" style={{ maxHeight }} data-testid="json-view">
        {text}
      </pre>
    </div>
  );
}
