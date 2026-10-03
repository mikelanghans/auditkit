// "Run full audit": every scanner that has a target, in order, as one run
// (build plan, phase 1c). Credentials are asked for once, used for this run
// only, and never stored.
import { useEffect, useMemo, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CircleDashed, Loader2, MinusCircle, PlayCircle, XCircle, Zap } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useAuditScope, useAuditTargets } from "@/hooks/use-audit-targets";
import { getCachedRepoToken } from "@/lib/repo-token-cache";
import type { SavedRepo } from "@/components/repo-launcher";
import { startFullAudit, finishFullAudit, type FullAuditStep, type FullAuditStepScanner } from "@/lib/full-audit.functions";
import { runAutoScan } from "@/lib/scan.functions";
import { runSupabaseScan } from "@/lib/supabase-scan.functions";
import { runRepoScan } from "@/lib/repo-scan.functions";
import { runAIScan } from "@/lib/ai-scan.functions";
import { startCodeAudit } from "@/lib/code-audit.functions";
import type { CodeAuditProfile } from "@/lib/code-audit-contract";

type PlannedStep = { key: string; scanner: FullAuditStepScanner; label: string; target: string | null; meta?: Record<string, unknown> };
type StepState = { outcome: FullAuditStep["outcome"] | "pending" | "running"; reason?: string | null; detail?: string | null };

const LABEL: Record<FullAuditStepScanner, string> = {
  website: "Website",
  supabase: "Supabase",
  repo: "Repo + dependencies",
  ai_endpoint: "AI endpoint",
  code_audit: "Deep code audit (runner)",
};

export function FullAuditDialog({
  auditId,
  websiteUrl,
  savedRepos,
  onDone,
}: {
  auditId: string;
  websiteUrl: string | null;
  savedRepos: SavedRepo[];
  onDone: () => void;
}) {
  const qc = useQueryClient();
  const targets = useAuditTargets(auditId);
  const scope = useAuditScope(auditId);
  const start = useServerFn(startFullAudit);
  const finish = useServerFn(finishFullAudit);
  const website = useServerFn(runAutoScan);
  const supa = useServerFn(runSupabaseScan);
  const repo = useServerFn(runRepoScan);
  const ai = useServerFn(runAIScan);
  const deep = useServerFn(startCodeAudit);

  const [open, setOpen] = useState(false);
  const [running, setRunning] = useState(false);
  const [states, setStates] = useState<Record<string, StepState>>({});
  // Credentials for this run only.
  const [anonKey, setAnonKey] = useState("");
  const [serviceKey, setServiceKey] = useState("");
  const [pat, setPat] = useState("");
  const [ghToken, setGhToken] = useState("");
  const [aiToken, setAiToken] = useState("");
  const [deepOn, setDeepOn] = useState(false);
  const [deepConsent, setDeepConsent] = useState(false);
  const [profile, setProfile] = useState<CodeAuditProfile>("standard");

  const list = (targets.data ?? []).filter((t) => t.in_scope);
  const supabaseTargets = list.filter((t) => t.kind === "supabase");
  const repoTargets = list.filter((t) => t.kind === "repo");
  const aiTargets = list.filter((t) => t.kind === "ai_endpoint");

  const plan: PlannedStep[] = useMemo(() => {
    const steps: PlannedStep[] = [{ key: "website", scanner: "website", label: LABEL.website, target: websiteUrl }];
    supabaseTargets.forEach((t, i) => steps.push({ key: `supabase:${t.id}`, scanner: "supabase", label: LABEL.supabase, target: t.value, meta: { first: i === 0 } }));
    if (!supabaseTargets.length) steps.push({ key: "supabase", scanner: "supabase", label: LABEL.supabase, target: null });
    repoTargets.forEach((t) => steps.push({ key: `repo:${t.id}`, scanner: "repo", label: LABEL.repo, target: t.value }));
    if (!repoTargets.length) steps.push({ key: "repo", scanner: "repo", label: LABEL.repo, target: null });
    aiTargets.forEach((t) => steps.push({ key: `ai:${t.id}`, scanner: "ai_endpoint", label: LABEL.ai_endpoint, target: t.value, meta: t.meta }));
    if (!aiTargets.length) steps.push({ key: "ai", scanner: "ai_endpoint", label: LABEL.ai_endpoint, target: null });
    if (repoTargets.length) steps.push({ key: "deep", scanner: "code_audit", label: LABEL.code_audit, target: repoTargets[0].value });
    return steps;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [websiteUrl, targets.data]);

  // Pre-fill the GitHub token from this tab's cache when a saved repo matches.
  useEffect(() => {
    if (!open || ghToken) return;
    for (const t of repoTargets) {
      const saved = savedRepos.find((r) => r.repo_url.replace(/\.git$|\/+$/g, "").toLowerCase() === t.value.toLowerCase());
      const tok = saved ? getCachedRepoToken(saved.id) : null;
      if (tok) { setGhToken(tok); break; }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, targets.data]);

  const set = (key: string, s: StepState) => setStates((prev) => ({ ...prev, [key]: s }));

  const runStep = async (step: PlannedStep, parentRunId: string): Promise<FullAuditStep> => {
    const base = { scanner: step.scanner, target: step.target };
    const notRun = (reason: string): FullAuditStep => ({ ...base, outcome: "not_run", reason });
    const failed = (reason: string): FullAuditStep => ({ ...base, outcome: "failed", reason });
    try {
      switch (step.scanner) {
        case "website": {
          if (!websiteUrl) return notRun("This audit has no website set.");
          const r: any = await website({ data: { auditId, parentRunId } });
          return { ...base, outcome: "done", reason: `${r.passes} pass · ${r.fails} fail${r.inconclusive ? ` · ${r.inconclusive} unverified` : ""}` };
        }
        case "supabase": {
          if (!step.target) return notRun("No Supabase target in Targets & scope.");
          if (!step.meta?.first) return notRun("Only the first Supabase project runs in a full audit; scan the others from the Supabase dialog with their own keys.");
          if (!anonKey.trim() || !serviceKey.trim()) return notRun("Anon and service-role keys weren't given for this run.");
          const r: any = await supa({
            data: { auditId, projectUrl: step.target, anonKey: anonKey.trim(), serviceRoleKey: serviceKey.trim(), managementPat: pat.trim() || null, appUrl: websiteUrl, parentRunId },
          });
          if (!r.ok) return failed(r.error);
          return { ...base, outcome: "done", reason: `${r.passes} pass · ${r.fails} fail${r.patUsed ? "" : " · no PAT, so database checks were limited"}` };
        }
        case "repo": {
          if (!step.target) return notRun("No repo target in Targets & scope.");
          if (!ghToken.trim()) return notRun("No GitHub token given for this run.");
          const r: any = await repo({ data: { auditId, repoUrl: step.target, token: ghToken.trim(), appUrl: websiteUrl, parentRunId } });
          if (!r.ok) return failed(r.error);
          return { ...base, outcome: "done", reason: `${r.findings?.length ?? 0} secret hit(s) · deps ${r.dep?.status ?? "not checked"}` };
        }
        case "ai_endpoint": {
          if (!step.target) return notRun("No AI endpoint target in Targets & scope.");
          const field = typeof step.meta?.prompt_field === "string" && step.meta.prompt_field ? (step.meta.prompt_field as string) : "prompt";
          const r: any = await ai({ data: { auditId, endpointUrl: step.target, promptField: field, authToken: aiToken.trim() || null, parentRunId } });
          if (!r.ok) return failed(r.error);
          return { ...base, outcome: "done", reason: `${r.counts.passes} pass · ${r.counts.fails} fail · ${r.counts.inconclusive} unverified` };
        }
        case "code_audit": {
          if (!deepOn) return notRun("Deep code audit not selected for this run.");
          if (!deepConsent) return notRun("Client consent to send code to the runner wasn't confirmed.");
          const r: any = await deep({ data: { auditId, repoUrl: step.target!, token: ghToken.trim() || undefined, profile, clientConsent: true } });
          if (!r.ok) return failed(r.error);
          // Runs on its own machine; results arrive on the Deep code audit page.
          return { ...base, outcome: "started", reason: "Started on the runner; results arrive on the Deep code audit page." };
        }
      }
    } catch (e: any) {
      return failed(e?.message ?? String(e));
    }
  };

  const runAll = async () => {
    setRunning(true);
    setStates(Object.fromEntries(plan.map((p) => [p.key, { outcome: "pending" }])));
    const tid = toast.loading("Full audit running…");
    try {
      const s: any = await start({ data: { auditId } });
      if (!s.ok) throw new Error(s.error);
      const results: FullAuditStep[] = [];
      for (const step of plan) {
        set(step.key, { outcome: "running" });
        const out = await runStep(step, s.runId);
        results.push(out);
        set(step.key, { outcome: out.outcome, reason: out.reason });
      }
      const f: any = await finish({ data: { auditId, runId: s.runId, steps: results } });
      if (!f.ok) throw new Error(f.error);
      const c = f.summary.counts ?? {};
      toast.success(`Full audit ${f.status === "done" ? "complete" : "finished with gaps"}`, {
        id: tid,
        description: `${c.pass ?? 0} pass · ${c.fail ?? 0} fail · ${c.inconclusive ?? 0} unverified · ${c.not_run ?? 0} not run`,
      });
      qc.invalidateQueries({ queryKey: ["findings", auditId] });
      qc.invalidateQueries({ queryKey: ["scan-runs", auditId] });
      onDone();
    } catch (e: any) {
      toast.error(e?.message ?? "Full audit failed", { id: tid });
    } finally {
      setRunning(false);
      // Credentials are for this run only.
      setAnonKey(""); setServiceKey(""); setPat(""); setAiToken("");
    }
  };

  const writeOk = !!scope.data?.write_tests_allowed;

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!running) setOpen(o); }}>
      <DialogTrigger asChild>
        <Button className="gap-1"><Zap className="h-4 w-4" /> Run full audit</Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Zap className="h-4 w-4" /> Run full audit</DialogTitle>
          <DialogDescription>
            Every scanner with a target, one after another, saved as one run with its evidence. Anything that can&rsquo;t run is recorded as not run. Keep this tab open until it finishes.
          </DialogDescription>
        </DialogHeader>

        <ol className="space-y-1.5">
          {plan.map((p) => {
            const st = states[p.key];
            return (
              <li key={p.key} className="flex items-start gap-2 text-sm">
                <StepIcon state={st?.outcome} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{p.label}</span>
                    <span className="text-xs font-mono text-muted-foreground truncate">{p.target ?? "no target"}</span>
                  </div>
                  {st?.reason && <div className="text-xs text-muted-foreground">{st.reason}</div>}
                </div>
              </li>
            );
          })}
        </ol>

        {!running && (
          <div className="grid gap-3 rounded-md border border-border/60 bg-muted/30 p-3 text-xs">
            {supabaseTargets.length > 0 && (
              <div className="grid grid-cols-3 gap-2">
                <div className="space-y-1"><Label className="text-xs">Supabase anon key</Label><Input type="password" className="h-8 text-xs" value={anonKey} onChange={(e) => setAnonKey(e.target.value)} /></div>
                <div className="space-y-1"><Label className="text-xs">Service-role key</Label><Input type="password" className="h-8 text-xs" value={serviceKey} onChange={(e) => setServiceKey(e.target.value)} /></div>
                <div className="space-y-1"><Label className="text-xs">Management PAT (optional)</Label><Input type="password" className="h-8 text-xs" value={pat} onChange={(e) => setPat(e.target.value)} /></div>
              </div>
            )}
            {repoTargets.length > 0 && (
              <div className="space-y-1"><Label className="text-xs">GitHub token (read access to the repo)</Label><Input type="password" className="h-8 text-xs" value={ghToken} onChange={(e) => setGhToken(e.target.value)} /></div>
            )}
            {aiTargets.length > 0 && (
              <div className="space-y-1"><Label className="text-xs">AI endpoint auth token (optional)</Label><Input type="password" className="h-8 text-xs" value={aiToken} onChange={(e) => setAiToken(e.target.value)} /></div>
            )}
            {repoTargets.length > 0 && (
              <div className="space-y-2">
                <label className="flex items-center gap-2"><Checkbox checked={deepOn} onCheckedChange={(v) => setDeepOn(!!v)} /> Also start a deep code audit on the runner</label>
                {deepOn && (
                  <div className="flex items-center gap-3 pl-6">
                    <Select value={profile} onValueChange={(v) => setProfile(v as CodeAuditProfile)}>
                      <SelectTrigger className="h-8 w-[130px] text-xs"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="quick">Quick</SelectItem>
                        <SelectItem value="standard">Standard</SelectItem>
                        <SelectItem value="deep">Deep</SelectItem>
                      </SelectContent>
                    </Select>
                    <label className="flex items-center gap-2"><Checkbox checked={deepConsent} onCheckedChange={(v) => setDeepConsent(!!v)} /> Client agreed to their code being analyzed by the runner</label>
                  </div>
                )}
              </div>
            )}
            <p className="text-muted-foreground">
              Passive checks only{writeOk ? "" : " (write and stress tests aren't authorized in scope)"}. Keys and tokens are used for this run and not saved.
            </p>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={running}>Close</Button>
          <Button onClick={runAll} disabled={running || targets.isLoading}>
            {running ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <PlayCircle className="h-4 w-4 mr-1" />}
            {running ? "Running…" : "Start"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function StepIcon({ state }: { state?: StepState["outcome"] }) {
  if (state === "running") return <Loader2 className="h-4 w-4 mt-0.5 animate-spin text-primary shrink-0" />;
  if (state === "done" || state === "started") return <CheckCircle2 className="h-4 w-4 mt-0.5 text-status-pass shrink-0" />;
  if (state === "failed") return <XCircle className="h-4 w-4 mt-0.5 text-status-fail shrink-0" />;
  if (state === "not_run") return <MinusCircle className="h-4 w-4 mt-0.5 text-muted-foreground shrink-0" />;
  return <CircleDashed className="h-4 w-4 mt-0.5 text-muted-foreground shrink-0" />;
}
