// Live progress for a queued or running deep code audit: phase stepper,
// elapsed time, what the agent is doing, budget use, and a warning when the
// runner goes quiet.
import { useEffect, useState } from "react";
import { AlertTriangle, Check, Loader2, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { STEPS, describeRun, formatElapsed, type ProgressRun } from "@/lib/code-audit-progress";

export type { ProgressRun };

function useNow(ms = 1000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

export function CodeAuditProgress({
  run,
  onStop,
  stopping,
}: {
  run: ProgressRun;
  onStop: () => void;
  stopping: boolean;
}) {
  const now = useNow();
  const [confirm, setConfirm] = useState(false);
  const { current, quietMin, stale } = describeRun(run, now);
  const p = run.progress ?? {};
  const since = Date.parse(run.started_at ?? run.created_at);
  const todoPct = p.todosTotal ? Math.round(((p.todosDone ?? 0) / p.todosTotal) * 100) : null;
  const agentPct = p.agents != null && run.budget_agents ? Math.min(100, Math.round((p.agents / run.budget_agents) * 100)) : null;

  return (
    <div className="space-y-3">
      <ol className="flex flex-wrap items-center gap-x-1 gap-y-2 text-xs">
        {STEPS.map((s, i) => (
          <li key={s.key} className="flex items-center gap-1">
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-full px-2 py-0.5",
                i < current && "bg-status-pass/15 text-status-pass",
                i === current && "bg-primary/15 text-primary font-medium",
                i > current && "bg-muted text-muted-foreground",
              )}
            >
              {i < current ? <Check className="h-3 w-3" /> : i === current ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
              {s.label}
            </span>
            {i < STEPS.length - 1 && <span className="text-muted-foreground">›</span>}
          </li>
        ))}
      </ol>

      <div className="text-sm">
        <span className="font-medium tabular-nums">{formatElapsed(now - since)}</span>
        <span className="text-muted-foreground"> elapsed</span>
        {p.detail && run.status === "running" && <span className="text-muted-foreground"> · {p.detail}</span>}
      </div>

      {run.status === "running" && current === 3 && (
        <div className="grid gap-2 sm:grid-cols-2">
          {todoPct != null && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Audit plan</span>
                <span className="tabular-nums">{p.todosDone ?? 0} / {p.todosTotal} steps</span>
              </div>
              <Progress value={todoPct} className="h-1.5" />
            </div>
          )}
          {agentPct != null && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Agent budget</span>
                <span className="tabular-nums">{p.agents} / {run.budget_agents} agents{p.steps ? ` · ${p.steps} tool calls` : ""}</span>
              </div>
              <Progress value={agentPct} className="h-1.5" />
            </div>
          )}
        </div>
      )}

      {stale && (
        <div className="flex items-start gap-2 rounded-md border border-status-warn/40 bg-status-warn/10 p-2 text-xs">
          <AlertTriangle className="h-4 w-4 shrink-0 text-status-warn" />
          <span>
            {run.status === "running"
              ? `No update from the runner for ${Math.floor(quietMin)} minutes.`
              : `The runner hasn't checked in after ${Math.floor(quietMin)} minutes.`}{" "}
            It may have crashed; check <code>fly logs -a auditkit-code-audit-runner</code>, then stop this run.
          </span>
        </div>
      )}

      <div>
        <Button
          type="button"
          size="sm"
          variant={confirm ? "destructive" : "outline"}
          disabled={stopping}
          onClick={() => (confirm ? onStop() : setConfirm(true))}
          onBlur={() => setConfirm(false)}
        >
          {stopping ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Square className="h-3.5 w-3.5 mr-1" />}
          {confirm ? "Click again to stop" : "Stop run"}
        </Button>
      </div>
    </div>
  );
}
