import { clsx } from "clsx";
import type { RiskFactor } from "@bloody/contracts";
import { Info } from "lucide-react";
import { Link } from "react-router-dom";
import { severityMetaForScore } from "../lib/severity";
import { Popover } from "./Popover";

export interface RiskScoreProps {
  score: number | null | undefined;
  /** Explained contributions. Every score in Bloody should carry these. */
  factors?: RiskFactor[] | null;
  summary?: string | null;
  modelVersion?: string | null;
  label?: string;
  size?: "sm" | "md" | "lg";
  /** Where the full explanation lives when factors are not embedded in this response. */
  explanationHref?: string;
  className?: string;
}

const SIZES = {
  sm: "h-5 min-w-[28px] px-1 text-xs",
  md: "h-7 min-w-[38px] px-1.5 text-md",
  lg: "h-10 min-w-[54px] px-2 text-2xl",
} as const;

/** Risk score pill (0–100, coloured by severity band) with an explanation popover of RiskFactor[]. */
export function RiskScore({ score, factors, summary, modelVersion, label = "Risk score", size = "md", explanationHref, className }: RiskScoreProps) {
  if (score === null || score === undefined || !Number.isFinite(score)) {
    return (
      <span className={clsx("inline-flex items-center justify-center rounded border border-dashed border-line-strong font-semibold text-fg-subtle", SIZES[size], className)} title="Not scored yet">
        —
      </span>
    );
  }
  const meta = severityMetaForScore(score);
  const sorted = [...(factors ?? [])].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  const maxAbs = Math.max(1, ...sorted.map((f) => Math.abs(f.contribution)));
  return (
    <Popover
      className={className}
      panelClassName="w-80 p-3"
      label={`${label} explanation`}
      trigger={(props) => (
        <button
          {...props}
          type="button"
          aria-label={`${label} ${Math.round(score)} (${meta.label}). Show explanation`}
          className={clsx("inline-flex items-center justify-center gap-1 rounded font-bold tabular-nums text-white", meta.bg, SIZES[size])}
        >
          {Math.round(score)}
          {size !== "sm" ? <Info size={size === "lg" ? 14 : 11} aria-hidden className="opacity-80" /> : null}
        </button>
      )}
    >
      <div className="space-y-2">
        <div className="flex items-baseline justify-between">
          <span className="text-sm font-semibold text-fg">{label}</span>
          <span className={clsx("text-lg font-bold tabular-nums", meta.text)}>
            {Math.round(score)} <span className="text-xs font-medium">/ 100 · {meta.label}</span>
          </span>
        </div>
        {summary ? <p className="text-sm text-fg-muted">{summary}</p> : null}
        {sorted.length > 0 ? (
          <ul className="space-y-1.5" aria-label="Contributing factors">
            {sorted.map((f) => (
              <li key={f.key} className="text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium text-fg">{f.label}</span>
                  <span className={clsx("tabular-nums font-semibold", f.contribution < 0 ? "text-healthy" : "text-fg")}>
                    {f.contribution > 0 ? "+" : ""}
                    {f.contribution.toFixed(1)}
                  </span>
                </div>
                <div className="mt-0.5 h-1 rounded bg-surface-3">
                  <div
                    className={clsx("h-1 rounded", f.contribution < 0 ? "bg-healthy" : meta.bg)}
                    style={{ width: `${(Math.abs(f.contribution) / maxAbs) * 100}%` }}
                  />
                </div>
                <p className="mt-0.5 text-fg-muted">{f.explanation}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-fg-muted">
            No factor breakdown was returned with this score.
            {explanationHref ? (
              <>
                {" "}
                <Link to={explanationHref} className="text-primary hover:underline">
                  Open the full risk explanation
                </Link>
                .
              </>
            ) : null}
          </p>
        )}
        {modelVersion ? <p className="text-2xs text-fg-subtle">Risk model {modelVersion}</p> : null}
      </div>
    </Popover>
  );
}
