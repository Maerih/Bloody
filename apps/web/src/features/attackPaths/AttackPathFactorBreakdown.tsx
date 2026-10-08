import type { RiskAssessment } from "@bloody/contracts";
import { clsx } from "clsx";
import { attackPathFactorRows } from "../../lib/attackPaths";
import { severityMetaForScore } from "../../lib/severity";

function Meter({ label, value, tone, hint, testId }: { label: string; value: number; tone: string; hint: string; testId?: string }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div data-testid={testId}>
      <div className="flex items-baseline justify-between text-xs">
        <span className="font-semibold text-fg">{label}</span>
        <span className="tabular-nums text-fg-muted">{pct}%</span>
      </div>
      <div className="mt-0.5 h-2 rounded bg-surface-3" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
        <div className={clsx("h-2 rounded", tone)} style={{ width: `${pct}%` }} />
      </div>
      <p className="mt-0.5 text-2xs text-fg-subtle">{hint}</p>
    </div>
  );
}

/**
 * Explainable attack-path risk: likelihood × impact, then every model factor as a bar
 * (signal strength) with its signed contribution to the score. Factors the model did not
 * observe are listed as such, so two paths can be compared factor by factor.
 */
export function AttackPathFactorBreakdown({ risk }: { risk: RiskAssessment }) {
  const rows = attackPathFactorRows(risk);
  const tone = severityMetaForScore(risk.score).bg;
  const maxAbs = Math.max(1, ...rows.map((r) => Math.abs(r.contribution)));
  return (
    <div className="space-y-3" data-testid="attack-path-factors">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Meter label="Likelihood" value={risk.likelihood} tone="bg-sev-high" hint="How likely an attacker completes this path" testId="factor-likelihood" />
        <Meter label="Impact" value={risk.impact} tone="bg-sev-critical" hint="How damaging reaching the target would be" testId="factor-impact" />
      </div>
      <ul className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-2" aria-label="Risk factors">
        {rows.map((r) => {
          const negative = r.contribution < 0;
          return (
            <li key={r.key} data-factor={r.key} className={clsx("text-xs", !r.present && "opacity-60")}>
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-medium text-fg" title={r.label}>
                  {r.label}
                </span>
                <span className={clsx("shrink-0 tabular-nums font-semibold", negative ? "text-healthy" : r.present ? "text-fg" : "text-fg-subtle")}>
                  {r.present ? `${r.contribution > 0 ? "+" : ""}${r.contribution.toFixed(1)}` : "—"}
                </span>
              </div>
              <div className="mt-0.5 flex items-center gap-1">
                <div className="h-1.5 flex-1 rounded bg-surface-3" role="meter" aria-label={`${r.label} contribution`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round((Math.abs(r.contribution) / maxAbs) * 100)}>
                  <div className={clsx("h-1.5 rounded", negative ? "bg-healthy" : tone)} style={{ width: `${(Math.abs(r.contribution) / maxAbs) * 100}%` }} />
                </div>
                <span className="w-9 shrink-0 text-right text-2xs tabular-nums text-fg-subtle" title="Signal strength">
                  {r.present ? `${Math.round(r.value * 100)}%` : ""}
                </span>
              </div>
              <p className="mt-0.5 text-fg-muted">{r.explanation}</p>
            </li>
          );
        })}
      </ul>
      <p className="text-2xs text-fg-subtle">
        {risk.modelVersion} · contributions sum to the score ({risk.score.toFixed(1)}). Compensating controls lower it.
      </p>
    </div>
  );
}
