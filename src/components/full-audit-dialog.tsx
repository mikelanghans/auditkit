// "Run full audit": enter every key and token once, check them all up front,
// then run the pipeline (recon → config → code → AI → deep → synthesis).
// When the server Workflow is configured the run continues with this dialog
// closed; otherwise this tab drives it and keys stay in the tab.
import { useEffect, useMemo, useRef, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Clock,
  Layers,
  Loader2,
  MinusCircle,
  PlayCircle,
  RotateCcw,
  ShieldCheck,
  XCircle,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { supabase } from "@/integrations/supabase/client";
import { useAuditScope, useAuditTargets } from "@/hooks/use-audit-targets";
import { getCachedRepoToken } from "@/lib/repo-token-cache";
import type { SavedRepo } from "@/components/repo-launcher";
import {
  preflightFullAudit,
  startPipeline,
  advanceFullAudit,
  retryPipelineStage,
  type PipelineCredsInput,
} from "@/lib/full-audit-pipeline.functions";
import { STAGE_GROUPS, SCANNER_LABEL, type StageRow } from "@/lib/pipeline";
import type { Synthesis, SynthIssue } from "@/lib/pipeline-synthesis";
import type { PreflightCheck } from "@/lib/pipeline-preflight";
import type { CodeAuditProfile } from "@/lib/code-audit-contract";

type RunRow = { id: string; status: string; pipeline_driver: string | null; started_at: string; finished_at: string | null };

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
  const preflight = useServerFn(preflightFullAudit);
  const start = useServerFn(startPipeline);
  const advance = useServerFn(advanceFullAudit);
  const retry = useServerFn(retryPipelineStage);

  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<null | "checking" | "starting" | "driving">(null);
  const [checks, setChecks] = useState<PreflightCheck[] | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(true);
  // Credentials: in this tab only.
  const [anonKey, setAnonKey] = useState("");
  const [serviceKey, setServiceKey] = useState("");
  const [pat, setPat] = useState("");
  const [ghToken, setGhToken] = useState("");
  const [aiToken, setAiToken] = useState("");
  const [deepOn, setDeepOn] = useState(false);
  const [aiDeepOn, setAiDeepOn] = useState(false);
  const [deepConsent, setDeepConsent] = useState(false);
  const [profile, setProfile] = useState<CodeAuditProfile>("standard");
  const driving = useRef(false);

  const list = (targets.data ?? []).filter((t) => t.in_scope);
  const supabaseTargets = list.filter((t) => t.kind === "supabase");
  const repoTargets = list.filter((t) => t.kind === "repo");
  const aiTargets = list.filter((t) => t.kind === "ai_endpoint");
  const writeOk = !!scope.data?.write_tests_allowed;

  const creds = (): PipelineCredsInput => ({
    githubToken: ghToken,
    anonKey,
    serviceRoleKey: serviceKey,
    managementPat: pat,
    aiToken,
  });
  const options = () => ({ auditId, creds: creds(), deepAudit: deepOn, aiDeep: aiDeepOn && writeOk, profile, clientConsent: deepConsent });

  // Pre-fill the GitHub token from this tab's cache when a saved repo matches.
  useEffect(() => {
    if (!open || ghToken) return;
    for (const t of repoTargets) {
      const saved = savedRepos.find((r) => r.repo_url.replace(/\.git$|\/+$/g, "").toLowerCase() === t.value.toLowerCase());
      const tok = saved ? getCachedRepoToken(saved.id) : null;
      if (tok) {
        setGhToken(tok);
        break;
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, targets.data]);

  // The latest pipeline run for this audit, so the dialog reattaches to a run
  // that's still going (e.g. on the server after the tab was closed).
  const latest = useQuery({
    queryKey: ["pipeline-latest", auditId],
    enabled: open,
    queryFn: async (): Promise<RunRow | null> => {
      const { data, error } = await supabase
        .from("scan_runs")
        .select("id, status, pipeline_driver, started_at, finished_at")
        .eq("audit_id", auditId)
        .eq("scanner", "full")
        .not("pipeline_driver", "is", null)
        .order("started_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (error) return null;
      return (data ?? null) as RunRow | null;
    },
  });
  useEffect(() => {
    if (open && !runId && latest.data) {
      setRunId(latest.data.id);
      setShowForm(latest.data.status !== "running" ? true : false);
    }
  }, [open, latest.data, runId]);

  const run = useQuery({
    queryKey: ["pipeline-run", runId],
    enabled: open && !!runId,
    refetchInterval: (q) => ((q.state.data as any)?.run?.status === "running" ? 2500 : false),
    queryFn: async () => {
      const [{ data: r }, { data: stages }] = await Promise.all([
        supabase.from("scan_runs").select("id, status, pipeline_driver, started_at, finished_at").eq("id", runId!).maybeSingle(),
        supabase.from("pipeline_stages").select("*").eq("run_id", runId!).order("position"),
      ]);
      return { run: (r ?? null) as RunRow | null, stages: (stages ?? []) as unknown as StageRow[] };
    },
  });
  const stages = run.data?.stages ?? [];
  const runRow = run.data?.run ?? null;
  const live = runRow?.status === "running";

  // When the run closes, refresh the audit page.
  const wasLive = useRef(false);
  useEffect(() => {
    if (wasLive.current && runRow && !live) {
      qc.invalidateQueries({ queryKey: ["findings", auditId] });
      qc.invalidateQueries({ queryKey: ["scan-runs", auditId] });
      qc.invalidateQueries({ queryKey: ["audit-targets", auditId] });
      onDone();
    }
    wasLive.current = !!live;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const refresh = () => qc.invalidateQueries({ queryKey: ["pipeline-run", runId] });

  /** Browser driver: run stages one request at a time until none are left. */
  const drive = async (id: string) => {
    if (driving.current) return;
    driving.current = true;
    setBusy("driving");
    try {
      for (let i = 0; i < 80; i++) {
        const r: any = await advance({ data: { runId: id, creds: creds(), profile } });
        refresh();
        if (!r.ok) {
          toast.error(r.error);
          break;
        }
        if (!r.more) break;
      }
    } catch (e: any) {
      toast.error(e?.message ?? "The run stopped");
    } finally {
      driving.current = false;
      setBusy(null);
      refresh();
    }
  };

  const check = async () => {
    setBusy("checking");
    try {
      const r: any = await preflight({ data: options() });
      setChecks(r.checks ?? []);
      if (!r.ok) toast.error(r.error ?? "Some keys or tokens didn't check out.");
      else toast.success(r.checks.length ? "Every key and token checks out." : "Nothing to check: no keys or tokens entered.");
    } catch (e: any) {
      toast.error(e?.message ?? "Check failed");
    } finally {
      setBusy(null);
    }
  };

  const begin = async () => {
    setBusy("starting");
    try {
      const r: any = await start({ data: options() });
      if (r.checks) setChecks(r.checks);
      if (!r.ok) {
        toast.error(r.error);
        setBusy(null);
        return;
      }
      setRunId(r.runId);
      setShowForm(false);
      qc.invalidateQueries({ queryKey: ["pipeline-latest", auditId] });
      if (r.driver === "workflow") {
        toast.success("Full audit started on the server. You can close this dialog.");
        setBusy(null);
        clearCreds();
      } else {
        setBusy(null);
        await drive(r.runId);
        clearCreds();
      }
    } catch (e: any) {
      toast.error(e?.message ?? "Couldn't start the run");
      setBusy(null);
    }
  };

  const retryStage = async (s: StageRow) => {
    if (!runId) return;
    setBusy("driving");
    try {
      const r: any = await retry({ data: { runId, key: s.key, creds: creds(), profile, clientConsent: deepConsent } });
      if (r.checks) setChecks(r.checks);
      if (!r.ok) {
        toast.error(r.error);
        setBusy(null);
        return;
      }
      refresh();
      setBusy(null);
      if (r.more) await drive(runId);
    } catch (e: any) {
      toast.error(e?.message ?? "Retry failed");
      setBusy(null);
    }
  };

  const clearCreds = () => {
    setAnonKey("");
    setServiceKey("");
    setPat("");
    setAiToken("");
  };

  const browserDriven = runRow?.pipeline_driver === "browser";
  const lockOpen = busy === "driving" || busy === "starting";
  const synthesis = stages.find((s) => s.scanner === "synthesis" && s.status === "done")?.output as Synthesis | undefined;

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!lockOpen) setOpen(o); }}>
      <DialogTrigger asChild>
        <Button className="gap-1"><Zap className="h-4 w-4" /> Run full audit</Button>
      </DialogTrigger>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Zap className="h-4 w-4" /> Run full audit</DialogTitle>
          <DialogDescription>
            Enter every key and token once. They&rsquo;re all checked before anything runs, then the scanners run as a pipeline:
            later stages use what earlier ones found, and the last stage merges every finding into one list.
          </DialogDescription>
        </DialogHeader>

        {runId && stages.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Layers className="h-3.5 w-3.5" />
              {live
                ? browserDriven
                  ? "Running from this tab. Keep it open until the scanners finish."
                  : "Running on the server. You can close this dialog and come back."
                : `Finished ${runRow?.finished_at ? new Date(runRow.finished_at).toLocaleString() : ""}`}
              {!showForm && !lockOpen && (
                <Button variant="link" size="sm" className="h-auto p-0 text-xs ml-auto" onClick={() => setShowForm(true)}>
                  New run…
                </Button>
              )}
            </div>
            <StageView stages={stages} onRetry={live ? undefined : retryStage} busy={!!busy} />
            {synthesis && <SynthesisView s={synthesis} />}
          </div>
        )}

        {showForm && !lockOpen && (
          <div className="grid gap-3 rounded-md border border-border/60 bg-muted/30 p-3 text-xs">
            {supabaseTargets.length > 0 && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <div className="space-y-1"><Label className="text-xs">Supabase anon key</Label><Input type="password" className="h-8 text-xs" value={anonKey} onChange={(e) => setAnonKey(e.target.value)} /></div>
                <div className="space-y-1"><Label className="text-xs">Service-role key</Label><Input type="password" className="h-8 text-xs" value={serviceKey} onChange={(e) => setServiceKey(e.target.value)} /></div>
                <div className="space-y-1"><Label className="text-xs">Management PAT (optional)</Label><Input type="password" className="h-8 text-xs" value={pat} onChange={(e) => setPat(e.target.value)} /></div>
              </div>
            )}
            {repoTargets.length > 0 && (
              <div className="space-y-1">
                <Label className="text-xs">GitHub token (fine-grained, Contents: Read-only on the repo)</Label>
                <Input type="password" className="h-8 text-xs" value={ghToken} onChange={(e) => setGhToken(e.target.value)} />
              </div>
            )}
            {aiTargets.length > 0 && (
              <div className="space-y-1"><Label className="text-xs">AI endpoint auth token (optional)</Label><Input type="password" className="h-8 text-xs" value={aiToken} onChange={(e) => setAiToken(e.target.value)} /></div>
            )}
            {aiTargets.length > 0 && (
              <label className={`flex items-center gap-2 ${writeOk ? "" : "opacity-60"}`}>
                <Checkbox checked={aiDeepOn && writeOk} disabled={!writeOk} onCheckedChange={(v) => setAiDeepOn(!!v)} />
                Also run the deeper AI tests (up to 40 requests per endpoint, including a short burst; costs the client tokens){writeOk ? "" : " — needs active tests allowed in scope"}
              </label>
            )}
            {repoTargets.length > 0 && (
              <div className="space-y-2">
                <label className="flex items-center gap-2"><Checkbox checked={deepOn} onCheckedChange={(v) => setDeepOn(!!v)} /> Also run a deep code audit on the runner, after the repo scan</label>
                {deepOn && (
                  <div className="flex flex-wrap items-center gap-3 pl-6">
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
            {checks && checks.length > 0 && <PreflightList checks={checks} />}
            <p className="text-muted-foreground">
              {aiDeepOn && writeOk ? "Passive checks, plus the deeper AI tests you selected" : `Passive checks only${writeOk ? "" : " (write and stress tests aren't authorized in scope)"}`}.
              {" "}Keys and tokens aren&rsquo;t saved. A server-side run keeps them encrypted until its last scanner has run, then deletes them.
            </p>
          </div>
        )}

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={() => setOpen(false)} disabled={lockOpen}>Close</Button>
          {showForm && (
            <>
              <Button variant="outline" onClick={check} disabled={!!busy || targets.isLoading}>
                {busy === "checking" ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <ShieldCheck className="h-4 w-4 mr-1" />}
                Check keys
              </Button>
              <Button onClick={begin} disabled={!!busy || targets.isLoading || (deepOn && !deepConsent)}>
                {busy === "starting" ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <PlayCircle className="h-4 w-4 mr-1" />}
                {busy === "starting" ? "Checking and starting…" : "Start"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PreflightList({ checks }: { checks: PreflightCheck[] }) {
  return (
    <ul className="space-y-1">
      {checks.map((c) => (
        <li key={c.key} className="flex items-start gap-2">
          {c.status === "pass" ? (
            <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 text-status-pass shrink-0" />
          ) : (
            <XCircle className="h-3.5 w-3.5 mt-0.5 text-status-fail shrink-0" />
          )}
          <span>
            <span className="font-medium">{c.label}:</span> {c.detail}
          </span>
        </li>
      ))}
    </ul>
  );
}

function duration(s: StageRow): string | null {
  if (!s.started_at) return null;
  const end = s.finished_at ? Date.parse(s.finished_at) : s.status === "running" || s.status === "waiting" ? Date.now() : null;
  if (!end) return null;
  const sec = Math.max(0, Math.round((end - Date.parse(s.started_at)) / 1000));
  if (sec < 1) return null;
  return sec < 90 ? `${sec}s` : sec < 5400 ? `${Math.round(sec / 60)}m` : `${(sec / 3600).toFixed(1)}h`;
}

function StageView({ stages, onRetry, busy }: { stages: StageRow[]; onRetry?: (s: StageRow) => void; busy: boolean }) {
  return (
    <ol className="space-y-2">
      {STAGE_GROUPS.map(({ group, label }) => {
        const rows = stages.filter((s) => s.stage === group);
        if (!rows.length) return null;
        const st = groupStatus(rows);
        return (
          <li key={group} className="rounded-md border border-border/60">
            <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border/60 bg-muted/30">
              <StatusIcon status={st} />
              <span className="text-xs font-semibold uppercase tracking-wide">{label}</span>
            </div>
            <ul className="divide-y divide-border/40">
              {rows.map((s) => (
                <li key={s.key} className="flex items-start gap-2 px-3 py-2 text-sm">
                  <StatusIcon status={s.status} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-x-2">
                      <span className="font-medium">{SCANNER_LABEL[s.scanner]}</span>
                      {s.target && <span className="text-xs font-mono text-muted-foreground truncate max-w-[22rem]">{s.target}</span>}
                      {duration(s) && (
                        <span className="text-xs text-muted-foreground inline-flex items-center gap-0.5"><Clock className="h-3 w-3" />{duration(s)}</span>
                      )}
                    </div>
                    {s.reason && <div className="text-xs text-muted-foreground">{s.reason}</div>}
                  </div>
                  {onRetry && s.scanner !== "synthesis" && (s.status === "failed" || s.status === "skipped") && (
                    <Button variant="ghost" size="sm" className="h-7 text-xs shrink-0" disabled={busy} onClick={() => onRetry(s)} title="Re-run just this stage with the keys entered below">
                      <RotateCcw className="h-3 w-3 mr-1" /> Retry
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          </li>
        );
      })}
    </ol>
  );
}

function groupStatus(rows: StageRow[]): StageRow["status"] {
  if (rows.some((r) => r.status === "running")) return "running";
  if (rows.some((r) => r.status === "waiting")) return "waiting";
  if (rows.some((r) => r.status === "pending")) return "pending";
  if (rows.some((r) => r.status === "failed")) return "failed";
  if (rows.every((r) => r.status === "skipped")) return "skipped";
  return "done";
}

function StatusIcon({ status }: { status: StageRow["status"] }) {
  const c = "h-4 w-4 mt-0.5 shrink-0";
  if (status === "running") return <Loader2 className={`${c} animate-spin text-primary`} />;
  if (status === "waiting") return <Clock className={`${c} text-primary`} />;
  if (status === "done") return <CheckCircle2 className={`${c} text-status-pass`} />;
  if (status === "failed") return <XCircle className={`${c} text-status-fail`} />;
  if (status === "skipped") return <MinusCircle className={`${c} text-muted-foreground`} />;
  return <CircleDashed className={`${c} text-muted-foreground`} />;
}

const SEV_CLASS: Record<string, string> = {
  critical: "bg-sev-critical text-white",
  high: "bg-sev-high text-black",
  medium: "bg-sev-medium text-black",
  low: "bg-sev-low text-black",
  informational: "bg-muted text-foreground",
};
const SOURCE_LABEL: Record<string, string> = {
  website: "Website",
  surface: "Attack surface",
  supabase: "Supabase",
  repo: "Repo scan",
  dependencies: "Dependencies",
  ai_endpoint: "AI probe",
  ai_deep: "Deeper AI tests",
  code_audit: "Deep audit",
};

function SynthesisView({ s }: { s: Synthesis }) {
  const [all, setAll] = useState(false);
  const issues = useMemo(() => (all ? s.issues : s.issues.slice(0, 8)), [all, s.issues]);
  return (
    <section className="rounded-md border border-border/60 p-3 space-y-2">
      <div className="flex flex-wrap items-baseline gap-x-3">
        <h3 className="text-sm font-semibold">Findings, merged</h3>
        <span className="text-xs text-muted-foreground">
          {s.issues.length} issue{s.issues.length === 1 ? "" : "s"}
          {(["critical", "high", "medium", "low"] as const).filter((k) => s.counts[k]).map((k) => ` · ${s.counts[k]} ${k}`).join("")}
          {s.corroborated ? ` · ${s.corroborated} found by more than one method` : ""}
        </span>
      </div>
      {s.issues.length === 0 && <p className="text-xs text-muted-foreground">No failing checks in this run.</p>}
      <ul className="space-y-1.5">
        {issues.map((i) => <IssueRow key={i.key} i={i} />)}
      </ul>
      {s.issues.length > 8 && (
        <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => setAll(!all)}>
          {all ? "Show fewer" : `Show all ${s.issues.length}`}
        </Button>
      )}
      {s.gaps.length > 0 && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground inline-flex items-center gap-1">
            <AlertTriangle className="h-3 w-3" /> {s.gaps.length} not tested in this run
          </summary>
          <ul className="mt-1 space-y-0.5 pl-4 list-disc text-muted-foreground">
            {s.gaps.map((g, n) => <li key={n}><span className="text-foreground">{g.label}:</span> {g.reason ?? g.status}</li>)}
          </ul>
        </details>
      )}
    </section>
  );
}

function IssueRow({ i }: { i: SynthIssue }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      <span className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${SEV_CLASS[i.severity] ?? SEV_CLASS.informational}`}>
        {i.severity}
      </span>
      <div className="min-w-0">
        <div className="font-medium">
          {i.title}
          {i.change && <span className="ml-2 text-xs font-normal text-status-fail">{i.change}</span>}
        </div>
        <div className="text-xs text-muted-foreground">
          {i.sources.map((x) => SOURCE_LABEL[x] ?? x).join(" + ")}
          {i.corroborated && <span className="ml-1 text-status-pass">· corroborated</span>}
          {i.deepVerdict === "needs_validation" && <span className="ml-1">· needs validation</span>}
          {i.files.length > 0 && <span className="ml-1 font-mono">· {i.files.slice(0, 2).join(", ")}{i.files.length > 2 ? ` +${i.files.length - 2}` : ""}</span>}
        </div>
      </div>
    </li>
  );
}
