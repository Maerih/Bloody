import { clsx } from "clsx";
import { useRef, type KeyboardEvent } from "react";

/**
 * Plain-text code editor (YAML / JSON): line-number gutter, Tab inserts two spaces (YAML
 * forbids tabs), Ctrl/⌘+Enter triggers `onSubmit`. No third-party editor is bundled.
 */
export function CodeEditor({
  value,
  onChange,
  onSubmit,
  rows = 18,
  readOnly = false,
  ariaLabel,
  invalid = false,
  className,
  id,
}: {
  value: string;
  onChange: (value: string) => void;
  onSubmit?: () => void;
  rows?: number;
  readOnly?: boolean;
  ariaLabel: string;
  invalid?: boolean;
  className?: string;
  id?: string;
}) {
  const gutter = useRef<HTMLDivElement>(null);
  const lineCount = Math.max(rows, value.split("\n").length);
  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && onSubmit) {
      e.preventDefault();
      onSubmit();
      return;
    }
    if (e.key === "Tab" && !e.shiftKey && !readOnly) {
      e.preventDefault();
      const el = e.currentTarget;
      const { selectionStart: start, selectionEnd: end } = el;
      const next = `${value.slice(0, start)}  ${value.slice(end)}`;
      onChange(next);
      requestAnimationFrame(() => {
        el.selectionStart = el.selectionEnd = start + 2;
      });
    }
  };
  return (
    <div className={clsx("flex overflow-hidden rounded border bg-surface-2 font-mono text-xs leading-5", invalid ? "border-sev-critical" : "border-line-strong", className)} data-testid="code-editor">
      <div ref={gutter} className="select-none overflow-hidden border-r border-line bg-surface-3 px-2 py-2 text-right text-fg-subtle" aria-hidden style={{ maxHeight: `${rows * 1.25 + 1}rem` }}>
        {Array.from({ length: lineCount }, (_, i) => (
          <div key={i}>{i + 1}</div>
        ))}
      </div>
      <textarea
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={onKeyDown}
        onScroll={(e) => {
          if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop;
        }}
        readOnly={readOnly}
        rows={rows}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        aria-label={ariaLabel}
        aria-invalid={invalid}
        className="min-w-0 flex-1 resize-y whitespace-pre bg-transparent px-2 py-2 text-fg outline-none"
        wrap="off"
      />
    </div>
  );
}
