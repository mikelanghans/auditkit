// Pure helpers for the deep-audit progress display. No React, so tests can load it.

export type ProgressRun = {
  id: string;
  status: string;
  created_at: string;
  started_at?: string | null;
  budget_agents: number;
  progress?: {
    phase?: string;
    detail?: string | null;
    agents?: number | null;
    steps?: number | null;
    todosDone?: number | null;
    todosTotal?: number | null;
  } | null;
  progress_at?: string | null;
};

export const STEPS: { key: string; label: string }[] = [
  { key: "queued", label: "Starting machine" },
  { key: "starting", label: "Locking down" },
  { key: "cloning", label: "Cloning repo" },
  { key: "auditing", label: "Auditing" },
  { key: "validating", label: "Validating" },
  { key: "reporting", label: "Reporting" },
];

/** Minutes of silence before a run is flagged, by stage. */
export const QUIET_LIMIT_MIN = { queued: 5, running: 15 };

export function formatElapsed(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h ? `${h}h ${String(m).padStart(2, "0")}m` : `${m}m ${String(sec).padStart(2, "0")}s`;
}

/** Which step is current, and whether the runner has gone quiet. */
export function describeRun(run: ProgressRun, now: number) {
  const phase = run.status === "running" ? run.progress?.phase ?? "starting" : "queued";
  const current = Math.max(0, STEPS.findIndex((s) => s.key === phase));
  const lastSignal = Date.parse(run.progress_at ?? run.started_at ?? run.created_at);
  const quietMin = (now - lastSignal) / 60_000;
  const limit = run.status === "running" ? QUIET_LIMIT_MIN.running : QUIET_LIMIT_MIN.queued;
  return { current, quietMin, stale: quietMin > limit };
}

