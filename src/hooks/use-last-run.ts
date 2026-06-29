import { useCallback, useEffect, useState } from "react";

const PREFIX = "shield:lastrun:";

function read(key: string | null): number | null {
  if (!key || typeof window === "undefined") return null;
  try {
    const v = window.localStorage.getItem(PREFIX + key);
    const n = v ? Number(v) : NaN;
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

/**
 * Tracks the last time a named scan was run, persisted to localStorage so the
 * "already ran" indicator survives reloads. Re-renders every minute so the
 * "X ago" label stays current.
 */
export function useLastRun(key: string | null | undefined) {
  const k = key ?? null;
  const [ts, setTs] = useState<number | null>(() => read(k));

  useEffect(() => {
    setTs(read(k));
  }, [k]);

  useEffect(() => {
    const i = setInterval(() => setTs((v) => v), 60_000);
    return () => clearInterval(i);
  }, []);

  const mark = useCallback(
    (at?: number | string | Date | null) => {
      const t = at == null ? Date.now() : at instanceof Date ? at.getTime() : typeof at === "string" ? new Date(at).getTime() : at;
      const n = Number.isFinite(t) ? (t as number) : Date.now();
      setTs(n);
      if (k && typeof window !== "undefined") {
        try {
          window.localStorage.setItem(PREFIX + k, String(n));
        } catch {
          // ignore
        }
      }
    },
    [k],
  );

  return { lastRunAt: ts, mark, hasRun: ts !== null };
}

export function formatAgo(ts: number, now: number = Date.now()) {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}
