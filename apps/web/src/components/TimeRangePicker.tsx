import { CalendarRange } from "lucide-react";
import { useState } from "react";
import type { TimeRange } from "../api/types";
import { describeTimeRange, isPreset, TIME_RANGE_PRESETS } from "../lib/timeRange";
import { Button } from "./Button";
import { Input } from "./Form";
import { Popover } from "./Popover";

function toLocalInput(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Relative presets plus an absolute from/to range. */
export function TimeRangePicker({ value, onChange, size = "sm" }: { value: TimeRange; onChange: (range: TimeRange) => void; size?: "xs" | "sm" | "md" }) {
  const absolute = "from" in value ? value : null;
  const [from, setFrom] = useState(absolute ? toLocalInput(absolute.from) : "");
  const [to, setTo] = useState(absolute ? toLocalInput(absolute.to) : "");
  const fromMs = Date.parse(from);
  const toMs = Date.parse(to);
  const customValid = !Number.isNaN(fromMs) && !Number.isNaN(toMs) && fromMs < toMs;
  return (
    <Popover
      label="Time range"
      align="end"
      panelClassName="w-72 p-2"
      trigger={(props) => (
        <Button {...props} size={size} icon={CalendarRange} aria-label={`Time range: ${describeTimeRange(value)}`}>
          {describeTimeRange(value)}
        </Button>
      )}
    >
      {(close) => (
        <div className="space-y-2">
          <ul className="grid grid-cols-2 gap-1">
            {TIME_RANGE_PRESETS.map((p) => (
              <li key={p.value}>
                <button
                  type="button"
                  className={`w-full rounded px-2 py-1 text-left text-sm hover:bg-surface-3 ${"preset" in value && value.preset === p.value ? "bg-primary-soft font-medium text-primary" : ""}`}
                  onClick={() => {
                    if (isPreset(p.value)) onChange({ preset: p.value });
                    close();
                  }}
                >
                  {p.label}
                </button>
              </li>
            ))}
          </ul>
          <form
            className="space-y-1.5 border-t border-line pt-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (!customValid) return;
              onChange({ from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() });
              close();
            }}
          >
            <div className="text-xs font-semibold uppercase tracking-wide text-fg-muted">Absolute range</div>
            <label className="block text-xs text-fg-muted">
              From
              <Input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} aria-label="From" />
            </label>
            <label className="block text-xs text-fg-muted">
              To
              <Input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} aria-label="To" />
            </label>
            <Button type="submit" size="sm" variant="primary" disabled={!customValid} className="w-full">
              Apply range
            </Button>
          </form>
        </div>
      )}
    </Popover>
  );
}
