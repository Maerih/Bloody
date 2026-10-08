import { Lightbulb } from "lucide-react";
import type { Narrative } from "../api/types";

/** Plain-language summary produced by the engines (headline, paragraphs, recommended actions). */
export function NarrativeCard({ narrative, className }: { narrative: Narrative; className?: string }) {
  return (
    <section className={`rounded border border-line bg-surface p-3 shadow-card ${className ?? ""}`} aria-label="Summary" data-testid="narrative">
      <h2 className="flex items-start gap-2 text-base font-semibold text-fg">
        <Lightbulb size={15} className="mt-0.5 shrink-0 text-sev-medium" aria-hidden />
        {narrative.headline}
      </h2>
      {narrative.paragraphs.map((p, i) => (
        <p key={i} className="mt-1 text-sm text-fg-muted">
          {p}
        </p>
      ))}
      {narrative.actions.length > 0 ? (
        <ul className="mt-2 list-disc space-y-0.5 pl-5 text-sm text-fg">
          {narrative.actions.map((a) => (
            <li key={a}>{a}</li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
