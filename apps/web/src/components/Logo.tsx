import { clsx } from "clsx";

/** Bloody brand mark: crimson drop with a highlight. Brand colour is used sparingly — here. */
export function LogoMark({ size = 26, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden className={className}>
      <defs>
        <linearGradient id="bloody-drop" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="rgb(var(--brand))" stopOpacity="0.85" />
          <stop offset="1" stopColor="rgb(var(--brand))" />
        </linearGradient>
      </defs>
      <path fill="url(#bloody-drop)" d="M16 2.5c-.4 0-.8.2-1 .6C11.3 9 7 14.4 7 19.6 7 24.8 11 29 16 29s9-4.2 9-9.4C25 14.4 20.7 9 17 3.1c-.2-.4-.6-.6-1-.6z" />
      <path fill="#fff" fillOpacity=".85" d="M12.2 19.4c-.6 0-1 .5-1 1 0 2.6 2.1 4.8 4.8 4.8.6 0 1-.5 1-1s-.4-1-1-1c-1.5 0-2.8-1.3-2.8-2.8 0-.5-.4-1-1-1z" />
    </svg>
  );
}

export function Logo({ className, inverse = false }: { className?: string; inverse?: boolean }) {
  return (
    <span className={clsx("inline-flex items-center gap-2", className)}>
      <LogoMark />
      <span className={clsx("font-display text-lg font-bold tracking-tight", inverse ? "text-white" : "text-fg")}>Bloody</span>
    </span>
  );
}
