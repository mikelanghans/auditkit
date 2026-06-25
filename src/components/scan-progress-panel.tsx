import { useEffect, useRef, useState } from "react";
import { Check, Loader2, Circle, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

export type ScanStep = { key: string; label: string };

export type ScanProgressState = "idle" | "running" | "success" | "error";

type StepEvent = {
  key: string;
  label: string;
  startedAt: number;
  completedAt: number | null;
};

const DEFAULT_SURFACE_STEPS: ScanStep[] = [
  { key: "resolve", label: "Resolving target website" },
  { key: "fetch", label: "Fetching homepage HTML" },
  { key: "headers", label: "Inspecting security headers (CSP, HSTS, XFO…)" },
  { key: "bundle", label: "Scanning bundle for secrets & debug flags" },
  { key: "probe", label: "Probing error verbosity endpoint" },
  { key: "persist", label: "Updating findings in database" },
  { key: "verify", label: "Verifying re-scan result" },
];

export function defaultSurfaceScanSteps(): ScanStep[] {
  return DEFAULT_SURFACE_STEPS.slice();
}

function fmtTime(ts: number) {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

function fmtDur(ms: number) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

/**
 * Step-by-step progress panel for scans that don't stream from the server.
 * Steps advance on a paced timer while `state === "running"`; when the caller
 * flips to "success"/"error", all remaining steps are closed out with the
 * final timestamp so the timeline reflects the real wall-clock duration.
 */
export function ScanProgressPanel({
  state,
  steps = DEFAULT_SURFACE_STEPS,
  title = "Scan progress",
  errorMessage,
  finalSummary,
  paceMs = 750,
}: {
  state: ScanProgressState;
  steps?: ScanStep[];
  title?: string;
  errorMessage?: string | null;
  finalSummary?: string | null;
  paceMs?: number;
}) {
  const [events, setEvents] = useState<StepEvent[]>([]);
  const [now, setNow] = useState<number>(() => Date.now());
  const startedRef = useRef<number | null>(null);
  const stepsRef = useRef(steps);
  stepsRef.current = steps;

  // Kick off / reset when state transitions to running.
  useEffect(() => {
    if (state !== "running") return;
    const t0 = Date.now();
    startedRef.current = t0;
    setEvents([{ key: steps[0].key, label: steps[0].label, startedAt: t0, completedAt: null }]);
  }, [state, steps]);

  // Advance steps on a timer while running.
  useEffect(() => {
    if (state !== "running") return;
    const iv = setInterval(() => {
      setNow(Date.now());
      setEvents((prev) => {
        if (prev.length >= stepsRef.current.length) return prev;
        const last = prev[prev.length - 1];
        // Hold on the final pre-completion step until the caller resolves.
        if (prev.length === stepsRef.current.length - 1) return prev;
        const t = Date.now();
        const closed = { ...last, completedAt: t };
        const next = stepsRef.current[prev.length];
        return [...prev.slice(0, -1), closed, { key: next.key, label: next.label, startedAt: t, completedAt: null }];
      });
    }, paceMs);
    return () => clearInterval(iv);
  }, [state, paceMs]);

  // On success/error: close every remaining step.
  useEffect(() => {
    if (state !== "success" && state !== "error") return;
    const t = Date.now();
    setEvents((prev) => {
      const out: StepEvent[] = [];
      const known = new Set(prev.map((e) => e.key));
      prev.forEach((e) => out.push({ ...e, completedAt: e.completedAt ?? t }));
      stepsRef.current.forEach((s) => {
        if (!known.has(s.key)) {
          out.push({ key: s.key, label: s.label, startedAt: t, completedAt: t });
        }
      });
      return out;
    });
  }, [state]);

  if (state === "idle" && events.length === 0) return null;

  const startedAt = startedRef.current ?? (events[0]?.startedAt ?? Date.now());
  const lastTs = state === "running" ? now : (events[events.length - 1]?.completedAt ?? now);
  const totalElapsed = lastTs - startedAt;

  return (
    <div className="rounded-md border bg-muted/30 p-3 text-xs space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 font-semibold text-foreground">
          {state === "running" ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
          ) : state === "error" ? (
            <AlertTriangle className="h-3.5 w-3.5 text-status-fail" />
          ) : (
            <Check className="h-3.5 w-3.5 text-status-pass" />
          )}
          {title}
        </div>
        <div className="text-[10px] tabular-nums text-muted-foreground">
          started {fmtTime(startedAt)} · {fmtDur(totalElapsed)}
        </div>
      </div>

      <ol className="space-y-1">
        {events.map((e, i) => {
          const isLast = i === events.length - 1;
          const inProgress = state === "running" && isLast && e.completedAt === null;
          const dur = e.completedAt ? e.completedAt - e.startedAt : now - e.startedAt;
          return (
            <li key={`${e.key}-${i}`} className="flex items-start gap-2 leading-snug">
              <span className="mt-0.5 shrink-0">
                {inProgress ? (
                  <Loader2 className="h-3 w-3 animate-spin text-primary" />
                ) : e.completedAt ? (
                  <Check className={cn("h-3 w-3", state === "error" && isLast ? "text-status-fail" : "text-status-pass")} />
                ) : (
                  <Circle className="h-3 w-3 text-muted-foreground/60" />
                )}
              </span>
              <span className={cn("flex-1", inProgress ? "text-foreground" : "text-muted-foreground")}>
                {e.label}
              </span>
              <span className="tabular-nums text-[10px] text-muted-foreground/80 shrink-0">
                {fmtTime(e.startedAt)}
                {e.completedAt ? <> · {fmtDur(dur)}</> : inProgress ? <> · {fmtDur(dur)}…</> : null}
              </span>
            </li>
          );
        })}
      </ol>

      {state === "error" && errorMessage ? (
        <div className="rounded border border-status-fail/40 bg-status-fail/5 p-2 text-[11px] text-status-fail">
          {errorMessage}
        </div>
      ) : null}
      {state === "success" && finalSummary ? (
        <div className="rounded border border-status-pass/40 bg-status-pass/5 p-2 text-[11px] text-foreground/80">
          {finalSummary}
        </div>
      ) : null}
    </div>
  );
}
