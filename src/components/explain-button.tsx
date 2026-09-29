import { useServerFn } from "@tanstack/react-start";
import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2, RefreshCw, Sparkles } from "lucide-react";
import { explainFinding } from "@/lib/explain-finding.functions";
import { cn } from "@/lib/utils";

// Explanations are generated once per finding and cached on the row, so this
// only calls the model for findings that don't have one yet. Requests are
// queued (two at a time) so opening an audit with many failures doesn't fire
// a burst of LLM calls at once.
const MAX_CONCURRENT = 2;
let active = 0;
const waiting: (() => void)[] = [];
async function queued<T>(fn: () => Promise<T>): Promise<T> {
  if (active >= MAX_CONCURRENT) await new Promise<void>((r) => waiting.push(r));
  active++;
  try {
    return await fn();
  } finally {
    active--;
    waiting.shift()?.();
  }
}

export function explanationBullets(text: string | null | undefined): string[] {
  return (text ?? "")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => l.replace(/^[-*•]\s*/, ""));
}

/**
 * Loads a finding's plain-English explanation, generating it if it isn't
 * cached. With `whenVisible`, generation waits until `ref` scrolls into view.
 */
export function useFindingExplanation({
  auditId,
  checklistItemId,
  cached,
  onCached,
  enabled = true,
  whenVisible = false,
}: {
  auditId: string;
  checklistItemId: string;
  cached: string | null;
  onCached?: (explanation: string) => void;
  enabled?: boolean;
  whenVisible?: boolean;
}) {
  const gen = useServerFn(explainFinding);
  const [text, setText] = useState<string | null>(cached);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [visible, setVisible] = useState(!whenVisible);
  const ref = useRef<HTMLDivElement | null>(null);
  const started = useRef(false);

  useEffect(() => setText(cached), [cached]);

  useEffect(() => {
    if (!whenVisible || visible || !ref.current || typeof IntersectionObserver === "undefined") {
      if (whenVisible && typeof IntersectionObserver === "undefined") setVisible(true);
      return;
    }
    const obs = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setVisible(true);
          obs.disconnect();
        }
      },
      { rootMargin: "200px" },
    );
    obs.observe(ref.current);
    return () => obs.disconnect();
  }, [whenVisible, visible]);

  const generate = useCallback(
    async (force = false) => {
      setLoading(true);
      setError(null);
      try {
        const res = await queued(() => gen({ data: { auditId, checklistItemId, force } }));
        if (!res.ok) {
          setError(res.error);
          return;
        }
        setText(res.explanation);
        onCached?.(res.explanation);
      } catch (e: any) {
        setError(e?.message ?? "Could not generate explanation");
      } finally {
        setLoading(false);
      }
    },
    [auditId, checklistItemId, gen, onCached],
  );

  useEffect(() => {
    if (!enabled || !visible || text || started.current) return;
    started.current = true;
    void generate();
  }, [enabled, visible, text, generate]);

  return {
    ref,
    text,
    loading,
    error,
    regenerate: () => generate(true),
    retry: () => generate(false),
  };
}

/** Inline "Why this matters" block shown directly on a failed finding. */
export function FindingExplanation({
  auditId,
  checklistItemId,
  cached,
  onCached,
  fallback,
  className,
}: {
  auditId: string;
  checklistItemId: string;
  cached: string | null;
  onCached?: (explanation: string) => void;
  fallback?: string | null;
  className?: string;
}) {
  const { ref, text, loading, error, regenerate, retry } = useFindingExplanation({
    auditId,
    checklistItemId,
    cached,
    onCached,
    whenVisible: true,
  });
  const bullets = explanationBullets(text);

  return (
    <div
      ref={ref}
      className={cn("rounded-md border border-amber-500/30 bg-amber-500/[0.04] p-3", className)}
    >
      <div className="flex items-center justify-between mb-1.5">
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground flex items-center gap-1">
          <Sparkles className="h-3 w-3 text-amber-500" /> Why this matters
        </div>
        {text && !loading && (
          <button
            type="button"
            onClick={regenerate}
            className="print:hidden text-[11px] text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
            title="Write a new explanation from the current notes"
          >
            <RefreshCw className="h-3 w-3" /> Regenerate
          </button>
        )}
      </div>
      {loading ? (
        <div className="flex items-center gap-2 text-xs text-muted-foreground py-1">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Writing a plain-English explanation…
        </div>
      ) : bullets.length ? (
        <ul className="space-y-1.5 text-sm leading-snug list-disc pl-4">
          {bullets.map((b, i) => (
            <li key={i}>{b}</li>
          ))}
        </ul>
      ) : error ? (
        <p className="text-xs text-muted-foreground">
          {fallback ? `${fallback} ` : ""}
          <span className="print:hidden">
            (Couldn&apos;t write an explanation: {error}.{" "}
            <button type="button" onClick={retry} className="underline underline-offset-2">
              Try again
            </button>
            )
          </span>
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">
          {fallback ?? "Explanation will appear here."}
        </p>
      )}
    </div>
  );
}
