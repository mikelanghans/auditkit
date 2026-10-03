// Every scanner run for an audit, newest first, with what changed since the
// previous run (build plan, phase 1b).
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { format } from "date-fns";
import { ChevronRight, Loader2, Radar } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type Run = {
  id: string;
  scanner: string;
  trigger: string;
  target: string | null;
  status: string;
  started_at: string;
  finished_at: string | null;
  parent_run_id: string | null;
  summary: { counts?: Record<string, number>; changes?: Record<string, number>; evidence?: number; error?: string } | null;
};

type Result = {
  id: string;
  status: string;
  change: string | null;
  previous_status: string | null;
  checklist_key: string | null;
  notes: string | null;
  stored: boolean;
  item: { title: string; severity: string } | null;
};

const SCANNER_LABEL: Record<string, string> = {
  website: "Website",
  surface: "Attack surface",
  supabase: "Supabase",
  repo: "Repo",
  dependencies: "Dependencies",
  ai_endpoint: "AI endpoint",
  code_audit: "Deep code audit",
  full: "Full audit",
};

const CHANGE_TONE: Record<string, string> = {
  new: "bg-status-fail/15 text-status-fail border-status-fail/30",
  regressed: "bg-status-fail/15 text-status-fail border-status-fail/30",
  fixed: "bg-status-pass/15 text-status-pass border-status-pass/30",
  unverified: "bg-status-warn/15 text-status-warn border-status-warn/30",
  unchanged: "bg-muted text-muted-foreground border-border",
};

const STATUS_TONE: Record<string, string> = {
  pass: "text-status-pass",
  fail: "text-status-fail",
  warn: "text-status-warn",
  inconclusive: "text-status-warn",
  not_run: "text-muted-foreground",
  na: "text-muted-foreground",
};

const CHANGE_ORDER = ["regressed", "new", "fixed", "unverified", "unchanged"];

export function ScanHistoryPanel({ auditId }: { auditId: string }) {
  const runs = useQuery({
    queryKey: ["scan-runs", auditId],
    queryFn: async (): Promise<Run[]> => {
      const { data, error } = await supabase
        .from("scan_runs")
        .select("id, scanner, trigger, target, status, started_at, finished_at, parent_run_id, summary")
        .eq("audit_id", auditId)
        .order("started_at", { ascending: false })
        .limit(50);
      if (error) throw new Error(error.message);
      return (data ?? []) as Run[];
    },
  });

  return (
    <Card className="p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Radar className="h-4 w-4 text-primary" />
        <h2 className="text-sm font-semibold">Scan history</h2>
        <span className="text-xs text-muted-foreground">Every run, compared with the one before it</span>
      </div>
      {runs.isLoading ? (
        <div className="text-xs text-muted-foreground flex items-center gap-2"><Loader2 className="h-3 w-3 animate-spin" /> Loading…</div>
      ) : runs.error ? (
        <div className="text-xs text-destructive">Couldn't load scan history: {(runs.error as Error).message}</div>
      ) : !runs.data?.length ? (
        <div className="text-xs text-muted-foreground">No runs recorded yet. Runs are kept from the next scan on.</div>
      ) : (
        <ul className="divide-y divide-border/60">
          {runs.data.map((r) => <RunRow key={r.id} run={r} />)}
        </ul>
      )}
    </Card>
  );
}

function RunRow({ run }: { run: Run }) {
  const [open, setOpen] = useState(false);
  const changes = run.summary?.changes ?? {};
  const counts = run.summary?.counts ?? {};
  const results = useQuery({
    queryKey: ["scan-results", run.id],
    enabled: open,
    queryFn: async (): Promise<Result[]> => {
      const { data, error } = await supabase
        .from("scan_results")
        .select("id, status, change, previous_status, checklist_key, notes, stored, item:checklist_items(title, severity)")
        .eq("run_id", run.id);
      if (error) throw new Error(error.message);
      const rows = (data ?? []) as Result[];
      return rows.sort(
        (a, b) => CHANGE_ORDER.indexOf(a.change ?? "unchanged") - CHANGE_ORDER.indexOf(b.change ?? "unchanged"),
      );
    },
  });

  return (
    <li className="py-2">
      <button type="button" onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 text-left">
        <ChevronRight className={cn("h-3.5 w-3.5 text-muted-foreground transition-transform", open && "rotate-90")} />
        {run.parent_run_id && <span className="text-xs text-muted-foreground" title="Step of a full audit">↳</span>}
        <span className={cn("text-sm", run.scanner === "full" ? "font-semibold" : "font-medium")}>{SCANNER_LABEL[run.scanner] ?? run.scanner}</span>
        {run.target && <span className="text-xs font-mono text-muted-foreground truncate max-w-[280px]">{run.target}</span>}
        {run.status !== "done" && (
          <Badge variant="outline" className={run.status === "failed" ? "text-destructive" : "text-status-warn"}>{run.status}</Badge>
        )}
        <span className="ml-auto flex items-center gap-1.5">
          {CHANGE_ORDER.filter((c) => c !== "unchanged" && changes[c]).map((c) => (
            <Badge key={c} variant="outline" className={cn("text-[11px]", CHANGE_TONE[c])}>{changes[c]} {c}</Badge>
          ))}
          <span className="text-xs text-muted-foreground tabular-nums">
            {counts.pass ?? 0}✓ {counts.fail ?? 0}✗{counts.not_run ? ` · ${counts.not_run} not run` : ""}
            {run.summary?.evidence ? ` · ${run.summary.evidence} evidence` : ""}
          </span>
          <span className="text-xs text-muted-foreground whitespace-nowrap">{format(new Date(run.started_at), "MMM d, HH:mm")}</span>
        </span>
      </button>
      {open && (
        <div className="mt-2 ml-5 space-y-1">
          {run.summary?.error && <div className="text-xs text-destructive">History incomplete: {run.summary.error}</div>}
          {results.isLoading ? (
            <div className="text-xs text-muted-foreground flex items-center gap-2"><Loader2 className="h-3 w-3 animate-spin" /> Loading…</div>
          ) : (
            (results.data ?? []).map((res) => (
              <details key={res.id} className="rounded border border-border/50 px-2 py-1">
                <summary className="flex items-center gap-2 cursor-pointer text-xs list-none">
                  {res.change && (
                    <Badge variant="outline" className={cn("text-[10px] px-1.5", CHANGE_TONE[res.change])}>{res.change}</Badge>
                  )}
                  <span className={cn("font-medium uppercase text-[10px]", STATUS_TONE[res.status])}>{res.status.replace("_", " ")}</span>
                  <span className="truncate">{res.item?.title ?? res.checklist_key ?? "(unknown check)"}</span>
                  {!res.item && <span className="text-[10px] text-status-warn">no checklist item</span>}
                  {res.previous_status && res.change !== "unchanged" && (
                    <span className="ml-auto text-[10px] text-muted-foreground">was {res.previous_status}</span>
                  )}
                </summary>
                {res.notes && <pre className="mt-1 whitespace-pre-wrap text-[11px] text-muted-foreground font-mono">{res.notes}</pre>}
              </details>
            ))
          )}
        </div>
      )}
    </li>
  );
}
