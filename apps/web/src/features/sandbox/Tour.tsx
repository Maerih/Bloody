import { ArrowLeft, ArrowRight, X } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Button } from "../../components/Button";
import { TOUR_STEPS, type TourStep } from "./tourSteps";

const STORAGE_KEY = "sciat.tour";

/** Progress is a per-browser convenience: storage can be blocked, so every access is guarded. */
function readStep(): number | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    const n = raw === null ? null : Number(raw);
    return n !== null && Number.isInteger(n) && n >= 0 && n < TOUR_STEPS.length ? n : null;
  } catch {
    return null;
  }
}
function writeStep(n: number | null) {
  try {
    if (n === null) window.localStorage.removeItem(STORAGE_KEY);
    else window.localStorage.setItem(STORAGE_KEY, String(n));
  } catch {
    // storage unavailable: the tour still runs for this page view
  }
}

/** Ask the tour to start on the next page load (used before switching into the sandbox). */
export function queueTour() {
  writeStep(0);
}

interface TourApi {
  active: boolean;
  start: () => void;
  stop: () => void;
}
const TourContext = createContext<TourApi>({ active: false, start: () => undefined, stop: () => undefined });
export const useTour = () => useContext(TourContext);

export function TourProvider({ children, steps = TOUR_STEPS }: { children: ReactNode; steps?: TourStep[] }) {
  const [step, setStep] = useState<number | null>(() => readStep());
  const go = useCallback((n: number | null) => {
    writeStep(n);
    setStep(n);
  }, []);
  const api = useMemo<TourApi>(() => ({ active: step !== null, start: () => go(0), stop: () => go(null) }), [step, go]);
  return (
    <TourContext.Provider value={api}>
      {children}
      {step !== null && steps[step] ? <TourPopover steps={steps} index={step} onGo={go} /> : null}
    </TourContext.Provider>
  );
}

type Box = { top: number; left: number; width: number; height: number };

/** Dims everything except the target: four panels around it plus an outline (no giant shadows). */
function Spotlight({ box }: { box: Box }) {
  const dim = "pointer-events-none fixed z-[80] bg-slate-900/50";
  const right = box.left + box.width;
  const bottom = box.top + box.height;
  return (
    <div aria-hidden data-testid="tour-spotlight">
      <div className={dim} style={{ top: 0, left: 0, right: 0, height: Math.max(0, box.top) }} />
      <div className={dim} style={{ top: bottom, left: 0, right: 0, bottom: 0 }} />
      <div className={dim} style={{ top: box.top, left: 0, width: Math.max(0, box.left), height: box.height }} />
      <div className={dim} style={{ top: box.top, left: right, right: 0, height: box.height }} />
      <div className="pointer-events-none fixed z-[80] rounded-md ring-2 ring-brand" style={{ top: box.top, left: box.left, width: box.width, height: box.height }} />
    </div>
  );
}

/** Below the target, else above, else to its right (tall elements such as the module rail), else centred. */
export function placement(box: Box | null, width: number, height: number, gap: number, vw = window.innerWidth, vh = window.innerHeight): React.CSSProperties {
  const center: React.CSSProperties = { top: "50%", left: "50%", width, transform: "translate(-50%, -50%)" };
  if (!box) return center;
  const left = Math.min(Math.max(16, box.left), vw - width - 16);
  if (box.top + box.height + gap + height <= vh - 16) return { top: box.top + box.height + gap, left, width };
  if (box.top - gap - height >= 16) return { top: box.top - gap - height, left, width };
  if (box.left + box.width + gap + width <= vw - 16) return { top: Math.min(Math.max(16, box.top), vh - height - 16), left: box.left + box.width + gap, width };
  return center;
}

function useTargetBox(selector: string, path: string): Box | null {
  const location = useLocation();
  const [box, setBox] = useState<Box | null>(null);
  useLayoutEffect(() => {
    setBox(null);
    if (location.pathname !== path) return;
    let el: Element | null = null;
    let tries = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const measure = () => {
      if (!el) return;
      const r = el.getBoundingClientRect();
      setBox({ top: r.top, left: r.left, width: r.width, height: r.height });
    };
    // Pages load lazily: look for the target for a few seconds before centring the step.
    const find = () => {
      el = document.querySelector(`[data-tour="${selector}"]`);
      if (el) {
        el.scrollIntoView?.({ block: "center", behavior: "smooth" });
        timer = setTimeout(measure, 250);
      } else if (tries++ < 20) timer = setTimeout(find, 150);
    };
    find();
    window.addEventListener("resize", measure);
    window.addEventListener("scroll", measure, true);
    return () => {
      if (timer) clearTimeout(timer);
      window.removeEventListener("resize", measure);
      window.removeEventListener("scroll", measure, true);
    };
  }, [selector, path, location.pathname]);
  return box;
}

function TourPopover({ steps, index, onGo }: { steps: TourStep[]; index: number; onGo: (n: number | null) => void }) {
  const s = steps[index]!;
  const navigate = useNavigate();
  const location = useLocation();
  const box = useTargetBox(s.target, s.path);
  const last = index === steps.length - 1;

  useEffect(() => {
    if (location.pathname !== s.path) navigate(s.path);
  }, [s.path, location.pathname, navigate]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onGo(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onGo]);

  const width = 360;
  const gap = 12;
  const popRef = useRef<HTMLDivElement>(null);
  const [popHeight, setPopHeight] = useState(200);
  useLayoutEffect(() => {
    if (popRef.current) setPopHeight(popRef.current.offsetHeight);
  }, [index, box]);
  const style = placement(box, width, popHeight, gap);

  return (
    <>
      {box ? (
        <Spotlight box={{ top: box.top - 6, left: box.left - 6, width: box.width + 12, height: box.height + 12 }} />
      ) : (
        <div aria-hidden className="pointer-events-none fixed inset-0 z-[80] bg-slate-900/45" />
      )}
      <div ref={popRef} role="dialog" aria-modal="false" aria-label="Product tour" className="fixed z-[90] rounded-md border border-line bg-surface p-4 text-sm shadow-pop" style={style}>
        <div className="mb-1 flex items-start justify-between gap-2">
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-brand">
              Step {index + 1} of {steps.length}
            </div>
            <h2 className="text-base font-semibold text-heading">{s.title}</h2>
          </div>
          <button type="button" aria-label="Skip tour" className="rounded p-1 text-fg-muted hover:bg-canvas" onClick={() => onGo(null)}>
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>
        <p className="text-fg-muted">{s.body}</p>
        <div className="mt-3 flex items-center justify-between gap-2">
          <button type="button" className="text-xs text-fg-muted hover:underline" onClick={() => onGo(null)}>
            Skip tour
          </button>
          <div className="flex gap-2">
            {index > 0 ? (
              <Button size="sm" variant="secondary" icon={ArrowLeft} onClick={() => onGo(index - 1)}>
                Back
              </Button>
            ) : null}
            <Button size="sm" variant="primary" iconRight={last ? undefined : ArrowRight} onClick={() => onGo(last ? null : index + 1)}>
              {last ? "Finish" : "Next"}
            </Button>
          </div>
        </div>
      </div>
    </>
  );
}
