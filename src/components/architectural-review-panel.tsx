import { useServerFn } from "@tanstack/react-start";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Brain, Loader2, Trash2, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { RepoLauncher, type SavedRepo } from "@/components/repo-launcher";
import {
  runArchitecturalReview,
  setArchitecturalFindingInclude,
  deleteArchitecturalFinding,
  type ArchitecturalFindingRow,
} from "@/lib/architectural-review.functions";

const SEV_TONE: Record<string, string> = {
  critical: "border-status-fail/60 text-status-fail",
  high: "border-orange-500/60 text-orange-500",
  medium: "border-status-na/60 text-status-na",
  low: "border-status-pass/60 text-status-pass",
};

export function ArchitecturalReviewSection({
  auditId,
  clientId,
  savedRepos,
  enabled,
}: {
  auditId: string;
  clientId: string | null;
  savedRepos: SavedRepo[];
  /** Only show this section once an AI Assist / auto-scan pass has produced findings. */
  enabled: boolean;
}) {
  const qc = useQueryClient();
  const run = useServerFn(runArchitecturalReview);
  const setInclude = useServerFn(setArchitecturalFindingInclude);
  const removeFinding = useServerFn(deleteArchitecturalFinding);

  const findings = useQuery({
    queryKey: ["architectural-findings", auditId],
    enabled,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("architectural_findings")
        .select("id, audit_id, title, severity, affected_files, explanation, recommendation, include_in_report, created_at")
        .eq("audit_id", auditId)
        .order("created_at", { ascending: true });
      if (error) throw error;
      return (data ?? []) as ArchitecturalFindingRow[];
    },
  });

  const [busyId, setBusyId] = useState<string | null>(null);

  if (!enabled) return null;

  const hasFindings = (findings.data?.length ?? 0) > 0;

  return (
    <Card className="p-4 border-l-4 border-l-slate-700 bg-slate-900 text-slate-100 dark:bg-slate-950">
      <div className="flex items-start justify-between gap-3 flex-wrap mb-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="rounded-md bg-slate-800 p-2 shrink-0">
            <Brain className="h-5 w-5 text-cyan-300" />
          </div>
          <div className="min-w-0">
            <h3 className="font-semibold leading-tight text-slate-50">Architectural Review</h3>
            <p className="text-xs text-slate-300/80 mt-0.5 max-w-xl">
              A holistic, cross-file pass that surfaces duplicated systems, inconsistent enforcement,
              and privilege concentration that line-level scans miss.
            </p>
          </div>
        </div>
        <RepoLauncher
          trigger={{
            label: hasFindings ? "Re-run Architectural Review" : "Run Architectural Review",
            icon: <Sparkles className="h-4 w-4 mr-1" />,
            className: "bg-cyan-500/15 border-cyan-400/40 text-cyan-100 hover:bg-cyan-500/25 hover:text-white",
          }}
          clientId={clientId}
          savedRepos={savedRepos}
          title="Run Architectural Review"
          description="Sends the repo's most security-relevant files plus your existing audit findings to Claude for a cross-cutting structural review."
          submitLabel="Run review"
          runningLabel="Reviewing…"
          loadingToast="Architectural review running…"
          onRun={async ({ repoUrl, token, loadingToastId }) => {
            try {
              const res = await run({ data: { auditId, repoUrl, token } });
              if (!res.ok) { toast.error(res.error, { id: loadingToastId }); return false; }
              toast.success(
                `Architectural review complete — ${res.findings.length} finding${res.findings.length === 1 ? "" : "s"}`,
                { id: loadingToastId, description: `${res.repo} · ${res.filesScanned} files reviewed` },
              );
              qc.invalidateQueries({ queryKey: ["architectural-findings", auditId] });
              return true;
            } catch (err: any) {
              toast.error(err?.message ?? "Architectural review failed", { id: loadingToastId });
              return false;
            }
          }}
        />
      </div>

      {findings.isLoading ? (
        <div className="text-xs text-slate-400 italic">Loading…</div>
      ) : !hasFindings ? (
        <div className="text-xs text-slate-400 italic">
          No architectural findings yet. Run the review to surface cross-cutting risks.
        </div>
      ) : (
        <ul className="space-y-2">
          {findings.data!.map((f) => {
            const sevCls = SEV_TONE[f.severity] ?? SEV_TONE.medium;
            return (
              <li
                key={f.id}
                className="rounded-md border border-slate-700/70 bg-slate-800/60 p-3 text-xs text-slate-100"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant="outline" className={`text-[10px] uppercase ${sevCls}`}>{f.severity}</Badge>
                      <span className="font-semibold text-sm text-slate-50">{f.title}</span>
                    </div>
                    {f.explanation && (
                      <p className="mt-1.5 text-slate-200/90 leading-relaxed">{f.explanation}</p>
                    )}
                    {f.recommendation && (
                      <p className="mt-1.5 text-slate-300/90 leading-relaxed">
                        <span className="font-semibold text-slate-100">Recommendation: </span>{f.recommendation}
                      </p>
                    )}
                    {f.affected_files.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {f.affected_files.map((p) => (
                          <code
                            key={p}
                            className="rounded bg-slate-900/70 border border-slate-700 px-1.5 py-0.5 text-[10px] font-mono text-slate-200"
                          >
                            {p}
                          </code>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <div className="flex items-center gap-2">
                      <Label htmlFor={`include-${f.id}`} className="text-[10px] uppercase tracking-wide text-slate-300">
                        Add to report
                      </Label>
                      <Switch
                        id={`include-${f.id}`}
                        checked={f.include_in_report}
                        disabled={busyId === f.id}
                        onCheckedChange={async (next) => {
                          setBusyId(f.id);
                          // optimistic
                          qc.setQueryData<ArchitecturalFindingRow[]>(
                            ["architectural-findings", auditId],
                            (prev) => (prev ?? []).map((x) => x.id === f.id ? { ...x, include_in_report: next } : x),
                          );
                          try {
                            const res = await setInclude({ data: { id: f.id, include: next } });
                            if (!res.ok) {
                              toast.error(res.error);
                              qc.invalidateQueries({ queryKey: ["architectural-findings", auditId] });
                            }
                          } finally { setBusyId(null); }
                        }}
                      />
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2 text-slate-300 hover:text-status-fail hover:bg-status-fail/10"
                      disabled={busyId === f.id}
                      onClick={async () => {
                        setBusyId(f.id);
                        try {
                          const res = await removeFinding({ data: { id: f.id } });
                          if (!res.ok) { toast.error(res.error); return; }
                          qc.invalidateQueries({ queryKey: ["architectural-findings", auditId] });
                        } finally { setBusyId(null); }
                      }}
                    >
                      {busyId === f.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                    </Button>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
