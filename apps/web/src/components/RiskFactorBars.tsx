import type { RiskFactor } from "@bloody/contracts";
import { clsx } from "clsx";
import { groupFactors, type DisplayFactor, type FactorGroup } from "../lib/attackPaths";
import { severityMetaForScore } from "../lib/severity";

const GROUP_LABELS: Record<FactorGroup, string> = {
  likelihood: "Likelihood drivers",
  impact: "Impact drivers",
  control: "Compensating controls",
};

function Bar({ label, value, tone, hint }: { label: string; value: number; tone: string; hint?: string }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div>
      <div className="flex items-baseline justify-between text-xs">
        <span className="font-medium text-fg">{label}</span>
        <span className="tabular-nums text-fg-muted">{pct}%</span>
      </div>
      <div className="mt-0.5 h-1.5 rounded bg-surface-3" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
        <div className={clsx("h-1.5 rounded", tone)} style={{ width: `${pct}%` }} />
      </div>
      {hint ? <p className="mt-0.5 text-2xs text-fg-subtle">{hint}</p> : null}
    </div>
  );
}

function FactorRow({ f, maxAbs, tone }: { f: DisplayFactor; maxAbs: number; tone: string }) {
  const negative = f.contribution < 0;
  return (
    <li className="text-xs" data-factor={f.key}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-medium text-fg" title={f.label}>
          {f.label}
        </span>
        <span className={clsx("shrink-0 tabular-nums font-semibold", negative ? "text-healthy" : "text-fg")}>
          {f.contribution > 0 ? "+" : ""}
          {f.contribution.toFixed(1)}
        </span>
      </div>
      <div className="mt-0.5 flex h-1.5 items-center gap-1">
        <div className="h-1.5 flex-1 rounded bg-surface-3">
          <div className={clsx("h-1.5 rounded", negative ? "bg-healthy" : tone)} style={{ width: `${(Math.abs(f.contribution) / maxAbs) * 100}%` }} />
        </div>
        <span className="w-10 shrink-0 text-right text-2xs tabular-nums text-fg-subtle" title="Signal strength (0–100%)">
          {Math.round(f.value * 100)}%
        </span>
      </div>
      <p className="mt-0.5 text-fg-muted">{f.explanation}</p>
    </li>
  );
}

/**
 * Explainable score breakdown used for attack paths, exposure and asset/identity risk:
 * likelihood × impact meters plus every factor's contribution (compensating controls negative).
 */
export function RiskFactorBars({
  factors,
  likelihood,
  impact,
  score,
  summary,
  modelVersion,
  compact = false,
}: {
  factors: RiskFactor[];
  likelihood?: number | null;
  impact?: number | null;
  score?: number | null;
  summary?: string | null;
  modelVersion?: string | null;
  compact?: boolean;
}) {
  const groups = groupFactors({ factors });
  const maxAbs = Math.max(1, ...factors.map((f) => Math.abs(f.contribution)));
  const tone = score !== null && score !== undefined ? severityMetaForScore(score).bg : "bg-primary";
  return (
    <div className="space-y-3" data-testid="risk-factors">
      {summary ? <p className="text-sm text-fg">{summary}</p> : null}
      {likelihood !== null && likelihood !== undefined && impact !== null && impact !== undefined ? (
        <div className="grid grid-cols-2 gap-3">
          <Bar label="Likelihood" value={likelihood} tone="bg-sev-high" hint="How likely compromise is" />
          <Bar label="Impact" value={impact} tone="bg-sev-critical" hint="How bad compromise would be" />
        </div>
      ) : null}
      {factors.length === 0 ? (
        <p className="text-xs text-fg-muted">No factor breakdown was returned with this score.</p>
      ) : (
        <div className={clsx("grid gap-3", compact ? "grid-cols-1" : "grid-cols-1 lg:grid-cols-3")}>
          {(Object.keys(groups) as FactorGroup[]).map((g) =>
            groups[g].length === 0 ? null : (
              <div key={g}>
                <h4 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-fg-subtle">{GROUP_LABELS[g]}</h4>
                <ul className="space-y-2" aria-label={GROUP_LABELS[g]}>
                  {groups[g].map((f) => (
                    <FactorRow key={`${g}-${f.key}`} f={f} maxAbs={maxAbs} tone={tone} />
                  ))}
                </ul>
              </div>
            ),
          )}
        </div>
      )}
      {modelVersion ? <p className="text-2xs text-fg-subtle">Risk model {modelVersion} · contributions sum to the score.</p> : null}
    </div>
  );
}
