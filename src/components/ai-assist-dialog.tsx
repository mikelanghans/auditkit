import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Brain, Check, Loader2, X } from "lucide-react";
import { toast } from "sonner";
import { RepoLauncher, type SavedRepo } from "@/components/repo-launcher";
import { runAIAssist, applyAIAssistFinding, type AIAssistFinding } from "@/lib/ai-assist.functions";
import { FixPromptButton } from "@/components/fix-prompt-dialog";

export type AIAssistSummary = {
  repo: string;
  filesScanned: number;
  highApplied: number;
  mediumPending: AIAssistFinding[];
  at: string;
};

export function AIAssistDialog({
  auditId,
  clientId,
  savedRepos,
  onDone,
  onResult,
  onSaved,
}: {
  auditId: string;
  clientId?: string | null;
  savedRepos: SavedRepo[];
  onDone: () => void;
  onResult: (s: AIAssistSummary) => void;
  onSaved?: () => void;
}) {
  const scan = useServerFn(runAIAssist);

  return (
    <RepoLauncher
      trigger={{
        label: "AI Assist",
        icon: <Brain className="h-4 w-4 mr-1" />,
        className: "border-purple-500/40 text-purple-600 hover:bg-purple-500/5 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300",
      }}
      clientId={clientId ?? null}
      savedRepos={savedRepos}
      title="AI Assist code review"
      description="Sends the most security-relevant files from the repo to Claude. High-confidence findings auto-apply; medium-confidence ones await your review."
      submitLabel="Run AI Assist"
      runningLabel="Analyzing…"
      loadingToast="AI Assist analyzing repository…"
      onSaved={onSaved}
      onRun={async ({ repoUrl, token, loadingToastId }) => {
        try {
          const res = await scan({ data: { auditId, repoUrl, token } });
          if (!res.ok) { toast.error(res.error, { id: loadingToastId }); return false; }
          toast.success(
            `AI Assist found ${res.highApplied} high-confidence finding${res.highApplied === 1 ? "" : "s"} (auto-applied) and ${res.mediumPending.length} suggestion${res.mediumPending.length === 1 ? "" : "s"} awaiting your review`,
            { id: loadingToastId, description: `${res.repo} · ${res.filesScanned} files reviewed` },
          );
          onResult({
            repo: res.repo,
            filesScanned: res.filesScanned,
            highApplied: res.highApplied,
            mediumPending: res.mediumPending,
            at: new Date().toISOString(),
          });
          onDone();
          return true;
        } catch (err: any) {
          toast.error(err?.message ?? "AI Assist failed", { id: loadingToastId });
          return false;
        }
      }}
    />
  );
}

export function AIAssistReviewPanel({
  auditId,
  summary,
  onChange,
  onRefresh,
}: {
  auditId: string;
  summary: AIAssistSummary;
  onChange: (next: AIAssistSummary) => void;
  onRefresh: () => void;
}) {
  const apply = useServerFn(applyAIAssistFinding);
  const [busy, setBusy] = useState<string | null>(null);

  const remove = (idx: number) => {
    const next = { ...summary, mediumPending: summary.mediumPending.filter((_, i) => i !== idx) };
    onChange(next);
  };

  const accept = async (f: AIAssistFinding, idx: number) => {
    setBusy(f.checklist_item_id);
    try {
      const res = await apply({ data: { auditId, finding: f } });
      if (!res.ok) { toast.error(res.error); return; }
      toast.success(`Applied: ${f.checklist_title}`);
      remove(idx);
      onRefresh();
    } catch (e: any) {
      toast.error(e?.message ?? "Could not apply finding");
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card className="p-4 border-l-4 border-l-purple-500 bg-purple-500/[0.03]">
      <div className="flex items-center gap-2 mb-3">
        <Brain className="h-4 w-4 text-purple-500 shrink-0" />
        <div className="font-medium text-sm">AI Assist results</div>
        <div className="ml-auto text-xs text-muted-foreground">
          <span className="font-medium text-purple-600 dark:text-purple-400">{summary.highApplied}</span> auto-applied ·{" "}
          <span className="font-medium">{summary.mediumPending.length}</span> awaiting review
        </div>
      </div>
      <p className="text-xs text-muted-foreground mb-3 truncate">
        {summary.repo} · {summary.filesScanned} files reviewed
      </p>

      {summary.mediumPending.length === 0 ? (
        <div className="text-xs text-muted-foreground italic">No medium-confidence suggestions to review.</div>
      ) : (
        <ul className="space-y-2">
          {summary.mediumPending.map((f, i) => (
            <li key={`${f.checklist_item_id}-${i}`} className="rounded-md border border-border bg-card p-3 text-xs">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-foreground">{f.checklist_title}</span>
                    <Badge variant="outline" className="text-[10px] uppercase">{f.category}</Badge>
                    <Badge
                      variant="outline"
                      className={`text-[10px] uppercase ${f.suggested_status === "fail" ? "border-status-fail/50 text-status-fail" : "border-status-pass/50 text-status-pass"}`}
                    >
                      Suggest: {f.suggested_status}
                    </Badge>
                    <Badge variant="outline" className="text-[10px] uppercase border-status-na/50 text-status-na">medium</Badge>
                  </div>
                  <p className="mt-1.5 text-foreground/80">{f.reasoning}</p>
                  {f.evidence && (
                    <pre className="mt-1.5 whitespace-pre-wrap break-words font-mono text-[11px] bg-muted/60 rounded p-2 max-h-32 overflow-auto">
{f.evidence}
                    </pre>
                  )}
                </div>
                <div className="flex flex-col gap-1 shrink-0">
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 px-2 border-status-pass/50 text-status-pass hover:bg-status-pass/10"
                    disabled={busy === f.checklist_item_id}
                    onClick={() => accept(f, i)}
                  >
                    {busy === f.checklist_item_id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
                    <span className="ml-1">Accept</span>
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 px-2"
                    disabled={busy === f.checklist_item_id}
                    onClick={() => remove(i)}
                  >
                    <X className="h-3 w-3" />
                    <span className="ml-1">Dismiss</span>
                  </Button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
