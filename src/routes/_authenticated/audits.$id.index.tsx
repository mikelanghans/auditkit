import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useMemo, useState, useRef, useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ArrowLeft, FileText, Check, X, Minus, CheckCircle2, CircleHelp, Shield, Radar, Loader2, Github, Filter, Circle, Sparkles, GitBranch, Package, ExternalLink, Brain, Bot, RefreshCw, ChevronDown, ClipboardCheck, History, RotateCcw, FileSearch } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { runAutoScan } from "@/lib/scan.functions";

import { runRepoScan } from "@/lib/repo-scan.functions";
import { recheckAIAssistItem } from "@/lib/ai-assist.functions";
import { DeleteAuditButton } from "@/components/delete-audit-button";
import { SupabaseScanDialog } from "@/components/supabase-scan-dialog";
import { AIScanDialog, type AIScanPreset } from "@/components/ai-scan-dialog";
import { AIAssistDialog, AIAssistReviewPanel, type AIAssistSummary } from "@/components/ai-assist-dialog";
import { RepoLauncher, type SavedRepo } from "@/components/repo-launcher";
import { ArchitecturalReviewSection } from "@/components/architectural-review-panel";
import { FixPromptButton } from "@/components/fix-prompt-dialog";
import { FindingExplanation } from "@/components/explain-button";
import type { DepFinding } from "@/lib/dep-scan-core";
import type { DetectedEndpoint } from "@/lib/ai-endpoint-detect.functions";
import { clearAllCachedRepoTokens } from "@/lib/repo-token-cache";
import { resolveFinding, listFindingHistory } from "@/lib/finding-resolution.functions";
import { ScanProgressPanel, defaultSurfaceScanSteps, type ScanProgressState } from "@/components/scan-progress-panel";
import { useLastRun } from "@/hooks/use-last-run";
import { LastRunBadge } from "@/components/last-run-badge";
import { format } from "date-fns";
import { BUILT_WITH_OPTIONS, builtWithLabel, type BuiltWith } from "@/lib/built-with";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";


export const Route = createFileRoute("/_authenticated/audits/$id/")({
  head: () => ({ meta: [{ title: "Audit — AuditKit" }] }),
  component: AuditView,
});

type Item = {
  id: string;
  category: string;
  title: string;
  description: string | null;
  severity: string;
  sort_order: number;
  what_to_look_for: string | null;
};
type Finding = { id?: string; checklist_item_id: string; status: "pass" | "fail" | "na" | "resolved" | "inconclusive" | null; notes: string | null; auto_scanned?: boolean | null; ai_assisted?: boolean | null; lovable_prompt?: string | null; cursor_prompt?: string | null; claude_prompt?: string | null; explanation?: string | null; resolved_at?: string | null; resolved_via?: "automated_rescan" | "manual_evidence" | null; evidence_text?: string | null; evidence_url?: string | null };

function AuditView() {
  const { id } = Route.useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const audit = useQuery({
    queryKey: ["audit", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, status, started_at, completed_at, summary, website_url, built_with, client:clients(id, name, websites, has_agentic_features, uses_ai_features)")
        .eq("id", id).single();
      if (error) throw error;
      return data;
    },
  });

  const clientId = (audit.data as any)?.client?.id ?? null;
  const clientRepos = useQuery({
    queryKey: ["client-repos", clientId],
    enabled: !!clientId,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("client_repos")
        .select("id, label, repo_url, website_url")
        .eq("client_id", clientId)
        .order("created_at", { ascending: true });
      if (error) throw error;
      return data ?? [];
    },
  });
  const auditWebsite = (audit.data as any)?.website_url as string | null | undefined;
  const allRepos = clientRepos.data ?? [];
  // Repos linked to this audit's website + any unassigned repos (legacy / shared).
  const savedRepos = auditWebsite
    ? allRepos.filter((r: any) => !r.website_url || r.website_url === auditWebsite)
    : allRepos;



  const hasAgentic = !!(audit.data as any)?.client?.has_agentic_features;
  const usesAi = !!(audit.data as any)?.client?.uses_ai_features;

  const items = useQuery({
    queryKey: ["checklist-items", { hasAgentic, usesAi }],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("checklist_items")
        .select("id, category, title, description, severity, sort_order, what_to_look_for").eq("is_active", true)
        .order("sort_order");
      if (error) throw error;
      const all = (data ?? []) as Item[];
      return all.filter((it) => {
        if (it.category === "Agentic AI Security" && !hasAgentic) return false;
        if (it.category === "AI Service Continuity" && !usesAi) return false;
        return true;
      });
    },
  });


  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audit_findings")
        .select("id, checklist_item_id, status, notes, auto_scanned, ai_assisted, lovable_prompt, cursor_prompt, claude_prompt, explanation, resolved_at, resolved_via, evidence_text, evidence_url")
        .eq("audit_id", id);
      if (error) throw error;
      return (data ?? []) as Finding[];
    },
  });

  const hasAutoScanned = useMemo(() => (findings.data ?? []).some((f) => f.auto_scanned), [findings.data]);
  const hasArchEligible = useMemo(
    () => (findings.data ?? []).some((f) => f.auto_scanned || f.ai_assisted),
    [findings.data],
  );

  type SurfaceSummary = { passes: number; fails: number; warnings: number; target: string; at: string };
  type RepoSummary = {
    passes: number; fails: number; findings: number; repo: string; at: string;
    dep?: {
      ok: boolean;
      error?: string;
      path?: string;
      packagesScanned?: number;
      counts?: { critical: number; high: number; medium: number; low: number };
      status?: "pass" | "fail" | "inconclusive";
      findings?: DepFinding[];
    };
    aiEndpoints?: DetectedEndpoint[];
    aiDetectError?: string | null;
  };

  type SupabaseSummary = { passes: number; fails: number; project: string; leaks: number; publicBuckets: string[]; bundleMatches: number; at: string };
  type AISummary = { passes: number; fails: number; endpoint: string; critical: number; high: number; medium: number; at: string };
  const [surfaceSummary, setSurfaceSummary] = useState<SurfaceSummary | null>(null);
  const [repoSummary, setRepoSummary] = useState<RepoSummary | null>(null);
  const [supabaseSummary, setSupabaseSummary] = useState<SupabaseSummary | null>(null);
  const [aiSummary, setAISummary] = useState<AISummary | null>(null);
  const [aiAssistSummary, setAIAssistSummary] = useState<AIAssistSummary | null>(null);
  const [aiScanPreset, setAIScanPreset] = useState<AIScanPreset | null>(null);

  const combinedSummary = useMemo(() => {
    if (!surfaceSummary && !repoSummary && !supabaseSummary && !aiSummary) return null;
    return {
      passes: (surfaceSummary?.passes ?? 0) + (repoSummary?.passes ?? 0) + (supabaseSummary?.passes ?? 0) + (aiSummary?.passes ?? 0),
      fails: (surfaceSummary?.fails ?? 0) + (repoSummary?.fails ?? 0) + (supabaseSummary?.fails ?? 0) + (aiSummary?.fails ?? 0),
      warnings: surfaceSummary?.warnings ?? 0,
      sources: [surfaceSummary && "Surface", repoSummary && "Repo", supabaseSummary && "Supabase", aiSummary && "AI"].filter(Boolean).join(" + "),
    };
  }, [surfaceSummary, repoSummary, supabaseSummary, aiSummary]);

  const findingsMap = useMemo(() => {
    const m = new Map<string, Finding>();
    findings.data?.forEach((f) => m.set(f.checklist_item_id, f));
    return m;
  }, [findings.data]);

  const categories = useMemo(() => {
    if (!items.data) return [];
    const seen = new Map<string, Item[]>();
    items.data.forEach((it) => {
      const arr = seen.get(it.category) ?? [];
      arr.push(it);
      seen.set(it.category, arr);
    });
    return Array.from(seen.entries()).map(([name, list]) => {
      const statuses = list.map((it) => findingsMap.get(it.id)?.status);
      // "inconclusive" means a scanner couldn't verify it — still to do.
      const done = statuses.filter((s) => s && s !== "inconclusive").length;
      const pass = statuses.filter((s) => s === "pass").length;
      const fail = statuses.filter((s) => s === "fail").length;
      const na = statuses.filter((s) => s === "na").length;
      return { name, items: list, done, total: list.length, pass, fail, na };
    });
  }, [items.data, findingsMap]);

  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const currentCat = activeCategory ?? categories[0]?.name ?? null;

  const allSeverities = useMemo(() => {
    if (!items.data) return [] as string[];
    const set = new Set<string>();
    items.data.forEach((it) => set.add(it.severity));
    return Array.from(set).sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order as any)[a] - (order as any)[b];
    });
  }, [items.data]);

  const [selectedSeverities, setSelectedSeverities] = useState<string[]>(["critical", "high", "medium", "low"]);
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>(["pass", "fail", "na", "inconclusive", "unrated"]);

  const setFinding = useMutation({
    mutationFn: async (payload: { checklist_item_id: string; status: "pass" | "fail" | "na"; notes?: string | null }) => {
      const { error } = await supabase
        .from("audit_findings")
        .upsert(
          {
            audit_id: id,
            checklist_item_id: payload.checklist_item_id,
            status: payload.status,
            notes: payload.notes ?? null,
          },
          { onConflict: "audit_id,checklist_item_id" },
        );
      if (error) throw error;
    },
    onMutate: async (payload) => {
      await qc.cancelQueries({ queryKey: ["findings", id] });
      const prev = qc.getQueryData<Finding[]>(["findings", id]) ?? [];
      const next = prev.filter((f) => f.checklist_item_id !== payload.checklist_item_id);
      next.push({ checklist_item_id: payload.checklist_item_id, status: payload.status, notes: payload.notes ?? null });
      qc.setQueryData(["findings", id], next);
      return { prev };
    },
    onError: (_e, _p, ctx) => {
      if (ctx?.prev) qc.setQueryData(["findings", id], ctx.prev);
      toast.error("Could not save");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["findings", id] }),
  });

  const totalDone = categories.reduce((s, c) => s + c.done, 0);
  const totalItems = categories.reduce((s, c) => s + c.total, 0);
  const pct = totalItems ? Math.round((totalDone / totalItems) * 100) : 0;

  const complete = useMutation({
    mutationFn: async () => {
      const { error } = await supabase
        .from("audits")
        .update({ status: "completed", completed_at: new Date().toISOString() })
        .eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      clearAllCachedRepoTokens();
      qc.invalidateQueries({ queryKey: ["audit", id] });
      qc.invalidateQueries({ queryKey: ["audits"] });
      toast.success("Audit marked complete — session GitHub tokens cleared");
      navigate({ to: "/audits/$id/report", params: { id } });
    },
  });

  const rawCatItems = categories.find((c) => c.name === currentCat)?.items ?? [];
  const catItems = rawCatItems.filter((it) => {
    const matchesSeverity = selectedSeverities.includes(it.severity);
    const status = findingsMap.get(it.id)?.status ?? "unrated";
    const matchesStatus = selectedStatuses.includes(status);
    return matchesSeverity && matchesStatus;
  });

  if (items.data && items.data.length === 0) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Card className="p-10 text-center">
          <h2 className="text-lg font-semibold">No checklist items yet</h2>
          <p className="text-sm text-muted-foreground mt-2">
            Seed the <code className="bg-muted px-1 rounded">checklist_items</code> table with your 35 items to begin auditing.
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <BackLink />
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{audit.data?.title}</h1>
          <p className="text-sm text-muted-foreground inline-flex items-center gap-2">
            <span>
              {(audit.data as any)?.client?.name} · <span className="capitalize">{audit.data?.status.replace("_", " ")}</span>
            </span>
            {savedRepos.length > 0 && (
              <span
                title={`${savedRepos.length} GitHub repo${savedRepos.length === 1 ? "" : "s"} connected:\n${savedRepos.map((r) => `• ${r.label} — ${r.repo_url}`).join("\n")}`}
                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-border bg-muted/40 text-xs"
              >
                <Github className="h-3 w-3" />
                <span className="h-1.5 w-1.5 rounded-full bg-status-pass" />
                <span className="text-[10px] uppercase tracking-wide">
                  GitHub{savedRepos.length > 1 ? ` ×${savedRepos.length}` : ""}
                </span>
              </span>
            )}
            <BuiltWithChip auditId={id} value={(audit.data as any)?.built_with ?? null} onChanged={() => audit.refetch()} />
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Link to="/audits/$id/activity" params={{ id }}>
            <Button variant="outline"><History className="h-4 w-4 mr-1" /> Activity</Button>
          </Link>
          <Link to="/audits/$id/code-audit" params={{ id }}>
            <Button variant="outline"><FileSearch className="h-4 w-4 mr-1" /> Code audit</Button>
          </Link>
          <Link to="/audits/$id/report" params={{ id }}>
            <Button variant="outline"><FileText className="h-4 w-4 mr-1" /> Report</Button>
          </Link>
          <DeleteAuditButton auditId={id} title={audit.data?.title} redirectTo="/dashboard" />
          {audit.data?.status !== "completed" && (
            <Button
              className="bg-navy text-navy-foreground hover:bg-navy/90"
              onClick={() => complete.mutate()}
              disabled={complete.isPending}
            >
              <CheckCircle2 className="h-4 w-4 mr-1" /> Mark complete
            </Button>
          )}
        </div>
      </div>

      <Card className="p-4">
        <div className="flex items-center justify-between text-sm mb-2">
          <span className="font-medium">Overall progress</span>
          <span className="text-muted-foreground">{totalDone}/{totalItems} · {pct}%</span>
        </div>
        <Progress value={pct} />
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-6">
        <aside className="bg-sidebar border border-sidebar-border rounded-lg p-2 h-fit sticky top-4">
          {categories.map((c) => {
            const p = c.total ? Math.round((c.done / c.total) * 100) : 0;
            const active = c.name === currentCat;
            return (
              <button
                key={c.name}
                onClick={() => setActiveCategory(c.name)}
                className={cn(
                  "w-full text-left px-3 py-2.5 rounded-md transition-colors",
                  active ? "bg-sidebar-accent text-sidebar-accent-foreground" : "hover:bg-sidebar-accent/50",
                )}
              >
                <div className="flex items-center justify-between text-sm font-medium gap-2">
                  <span className="truncate">{c.name}</span>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {c.fail > 0 && (
                      <span className="inline-flex items-center gap-0.5 text-xs font-medium text-status-fail">
                        <X className="h-3 w-3" />{c.fail}
                      </span>
                    )}
                    {c.pass > 0 && (
                      <span className="inline-flex items-center gap-0.5 text-xs font-medium text-status-pass">
                        <Check className="h-3 w-3" />{c.pass}
                      </span>
                    )}
                    {c.na > 0 && (
                      <span className="inline-flex items-center gap-0.5 text-xs font-medium text-muted-foreground">
                        <Minus className="h-3 w-3" />{c.na}
                      </span>
                    )}
                    <span className={cn("text-xs ml-1", active ? "text-sidebar-accent-foreground" : "text-muted-foreground")}>{p}%</span>
                  </div>
                </div>
                <Progress value={p} className="h-1 mt-2" />
              </button>
            );
          })}
        </aside>

        <div className="space-y-3">
          <Collapsible defaultOpen>
            <Card className="overflow-hidden">
              <CollapsibleTrigger className="group flex w-full items-center gap-2 px-4 py-3 text-left hover:bg-muted/40 transition-colors">
                <Radar className="h-4 w-4 text-primary shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-semibold">Automated Scan Results</div>
                  <div className="text-xs text-muted-foreground">SHIELD Surface, Repo, Supabase, AI Endpoints, AI Assist</div>
                </div>
                {combinedSummary && (
                  <div className="text-xs text-muted-foreground hidden sm:block">
                    <span className="text-status-pass font-medium">{combinedSummary.passes}</span> pass ·{" "}
                    <span className="text-status-fail font-medium">{combinedSummary.fails}</span> fail
                  </div>
                )}
                <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform group-data-[state=closed]:-rotate-90" />
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="space-y-3 p-4 pt-0 border-t border-border/60">
                  <ShieldScanBanner
                    auditId={id}
                    appUrl={(audit.data as any)?.website_url ?? null}
                    clientId={clientId}
                    savedRepos={savedRepos}
                    hasScanned={hasAutoScanned}
                    onDone={() => qc.invalidateQueries({ queryKey: ["findings", id] })}
                    onSurfaceResult={setSurfaceSummary}
                    onRepoResult={setRepoSummary}
                    onSupabaseResult={setSupabaseSummary}
                    onAIResult={setAISummary}
                    onAIAssistResult={setAIAssistSummary}
                    aiScanPreset={aiScanPreset}
                    onAIScanPresetConsumed={() => setAIScanPreset(null)}
                  />

                  {aiAssistSummary && (
                    <AIAssistReviewPanel
                      auditId={id}
                      summary={aiAssistSummary}
                      onChange={setAIAssistSummary}
                      onRefresh={() => qc.invalidateQueries({ queryKey: ["findings", id] })}
                    />
                  )}


                  {combinedSummary && (() => {
                    const failedItems = (items.data ?? []).filter((it) => {
                      const f = findingsMap.get(it.id);
                      return f?.auto_scanned && f.status === "fail";
                    });
                    const jumpTo = (it: Item) => {
                      setActiveCategory(it.category);
                      if (!selectedStatuses.includes("fail")) setSelectedStatuses((s) => [...s, "fail"]);
                      setTimeout(() => {
                        const el = document.getElementById(`item-${it.id}`);
                        el?.scrollIntoView({ behavior: "smooth", block: "center" });
                        el?.classList.add("ring-2", "ring-status-fail");
                        setTimeout(() => el?.classList.remove("ring-2", "ring-status-fail"), 1600);
                      }, 50);
                    };
                    return (
                      <Card className="p-4 border-l-4 border-l-primary/60 bg-primary/[0.02]">
                        <div className="flex items-center gap-2 mb-3">
                          <CheckCircle2 className="h-4 w-4 text-status-pass shrink-0" />
                          <div className="font-medium text-sm">Automated scan results</div>
                          <div className="ml-auto text-xs text-muted-foreground">
                            <span className="text-status-pass font-medium">{combinedSummary.passes}</span> passed ·{" "}
                            <span className="text-status-fail font-medium">{combinedSummary.fails}</span> failed
                            {combinedSummary.warnings > 0 && (
                              <> · <span className="text-status-na font-medium">{combinedSummary.warnings}</span> warnings</>
                            )}
                          </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
                          {surfaceSummary && (
                            <div className="rounded-md border border-border bg-card p-2">
                              <div className="font-medium text-foreground">Surface</div>
                              <div className="text-muted-foreground truncate">{surfaceSummary.target}</div>
                              <div className="mt-1">
                                <span className="text-status-pass">{surfaceSummary.passes} pass</span> ·{" "}
                                <span className="text-status-fail">{surfaceSummary.fails} fail</span>
                              </div>
                            </div>
                          )}
                          {repoSummary && (
                            <div className="rounded-md border border-border bg-card p-2">
                              <div className="font-medium text-foreground">Repo</div>
                              <div className="text-muted-foreground truncate">{repoSummary.repo}</div>
                              <div className="mt-1">
                                <span className="text-status-pass">{repoSummary.passes} pass</span> ·{" "}
                                <span className="text-status-fail">{repoSummary.fails} fail</span>
                                {repoSummary.findings > 0 && <> · {repoSummary.findings} hit{repoSummary.findings === 1 ? "" : "s"}</>}
                                {repoSummary.dep?.ok && repoSummary.dep.packagesScanned !== undefined && (
                                  <> · {repoSummary.dep.packagesScanned} pkgs / {(repoSummary.dep.findings?.length ?? 0)} flagged</>
                                )}
                              </div>
                            </div>
                          )}
                          {supabaseSummary && (
                            <div className="rounded-md border border-border bg-card p-2">
                              <div className="font-medium text-foreground">Supabase</div>
                              <div className="text-muted-foreground truncate">{supabaseSummary.project}</div>
                              <div className="mt-1 space-x-1">
                                <span className="text-status-pass">{supabaseSummary.passes} pass</span> ·{" "}
                                <span className="text-status-fail">{supabaseSummary.fails} fail</span>
                                {supabaseSummary.leaks > 0 && <span className="text-status-fail"> · {supabaseSummary.leaks} leak{supabaseSummary.leaks === 1 ? "" : "s"}</span>}
                                {supabaseSummary.publicBuckets.length > 0 && <span className="text-status-na"> · {supabaseSummary.publicBuckets.length} public bucket{supabaseSummary.publicBuckets.length === 1 ? "" : "s"}</span>}
                                {supabaseSummary.bundleMatches > 0 && <span className="text-status-fail"> · ⚠ key in bundle</span>}
                              </div>
                            </div>
                          )}
                          {aiSummary && (
                            <div className="rounded-md border border-border bg-card p-2">
                              <div className="font-medium text-foreground">AI Endpoint</div>
                              <div className="text-muted-foreground truncate">{aiSummary.endpoint}</div>
                              <div className="mt-1 space-x-1">
                                <span className="text-status-pass">{aiSummary.passes} pass</span> ·{" "}
                                <span className="text-status-fail">{aiSummary.fails} fail</span>
                                {aiSummary.critical > 0 && <span className="text-status-fail"> · {aiSummary.critical} critical</span>}
                                {aiSummary.high > 0 && <span className="text-status-fail"> · {aiSummary.high} high</span>}
                                {aiSummary.medium > 0 && <span className="text-status-na"> · {aiSummary.medium} medium</span>}
                              </div>
                            </div>
                          )}
                        </div>

                        {failedItems.length > 0 && (
                          <div className="mt-4 pt-3 border-t border-border/60">
                            <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">
                              Jump to failure ({failedItems.length} across all scans)
                            </div>
                            <ul className="space-y-1">
                              {failedItems.map((it) => (
                                <li key={it.id}>
                                  <button
                                    onClick={() => jumpTo(it)}
                                    className="w-full text-left text-sm flex items-start gap-2 px-2 py-1.5 rounded-md hover:bg-status-fail/5 group"
                                  >
                                    <X className="h-3.5 w-3.5 text-status-fail mt-0.5 shrink-0" />
                                    <span className="flex-1 min-w-0">
                                      <span className="font-medium group-hover:text-status-fail truncate block">{it.title}</span>
                                      <span className="text-xs text-muted-foreground">{it.category}</span>
                                    </span>
                                  </button>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </Card>
                    );
                  })()}
                  {repoSummary?.dep && <RepoDepPanel dep={repoSummary.dep} />}
                  {repoSummary?.aiEndpoints && repoSummary.aiEndpoints.length > 0 && (
                    <AIEndpointsDiscoveredPanel
                      endpoints={repoSummary.aiEndpoints}
                      onTest={(ep) => setAIScanPreset({ url: ep.url, promptField: ep.promptField, source: ep.source })}
                    />
                  )}
                </div>
              </CollapsibleContent>
            </Card>
          </Collapsible>

          <section className="space-y-3">
            <div className="flex items-center gap-2 pt-2">
              <ClipboardCheck className="h-4 w-4 text-primary shrink-0" />
              <div>
                <h2 className="text-sm font-semibold">Manual Review &amp; Auditor Workspace</h2>
                <p className="text-xs text-muted-foreground">Architectural review and the 43-item checklist requiring auditor judgement.</p>
              </div>
            </div>

            <ArchitecturalReviewSection
              auditId={id}
              clientId={clientId}
              savedRepos={savedRepos}
              enabled={hasArchEligible}
            />


          <div className="flex items-center gap-3 flex-wrap">
            <Filter className="h-4 w-4 text-muted-foreground shrink-0" />
            <ToggleGroup
              type="multiple"
              value={selectedSeverities}
              onValueChange={setSelectedSeverities}
              className="flex-wrap"
            >
              {allSeverities.map((sev) => (
                <ToggleGroupItem key={sev} value={sev} aria-label={sev} className="text-xs capitalize">
                  {sev}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-xs text-muted-foreground font-medium shrink-0">Status</span>
            <ToggleGroup
              type="multiple"
              value={selectedStatuses}
              onValueChange={setSelectedStatuses}
              className="flex-wrap"
            >
              <ToggleGroupItem value="pass" aria-label="Pass" className="text-xs">
                <Check className="h-3.5 w-3.5 mr-1 text-status-pass" /> Pass
              </ToggleGroupItem>
              <ToggleGroupItem value="fail" aria-label="Fail" className="text-xs">
                <X className="h-3.5 w-3.5 mr-1 text-status-fail" /> Fail
              </ToggleGroupItem>
              <ToggleGroupItem value="na" aria-label="N/A" className="text-xs">
                <Minus className="h-3.5 w-3.5 mr-1 text-status-na" /> N/A
              </ToggleGroupItem>
              <ToggleGroupItem value="inconclusive" aria-label="Couldn't verify" className="text-xs">
                <CircleHelp className="h-3.5 w-3.5 mr-1 text-amber-600" /> Couldn't verify
              </ToggleGroupItem>
              <ToggleGroupItem value="resolved" aria-label="Resolved" className="text-xs">
                <CheckCircle2 className="h-3.5 w-3.5 mr-1 text-status-pass" /> Resolved
              </ToggleGroupItem>
              <ToggleGroupItem value="unrated" aria-label="Unrated" className="text-xs">
                <Circle className="h-3.5 w-3.5 mr-1 text-muted-foreground" /> Unrated
              </ToggleGroupItem>
            </ToggleGroup>
          </div>
          {catItems.map((it) => {
            const f = findingsMap.get(it.id);
            return (
              <ItemRow
                key={it.id}
                auditId={id}
                item={it}
                finding={f}
                autoScanned={!!f?.auto_scanned}
                aiAssisted={!!f?.ai_assisted}
                savedRepos={savedRepos}
                onSet={(status, notes) => {
                  // Block changing another item while a Fail in this category has no notes
                  const blocker = rawCatItems.find((other) => {
                    if (other.id === it.id) return false;
                    const of = findingsMap.get(other.id);
                    return of?.status === "fail" && !(of.notes && of.notes.trim());
                  });
                  if (blocker) {
                    toast.error(`Add findings for "${blocker.title}" before continuing`);
                    document.getElementById(`item-${blocker.id}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
                    document.getElementById(`notes-${blocker.id}`)?.focus();
                    return;
                  }
                  setFinding.mutate({ checklist_item_id: it.id, status, notes });
                }}
              />
            );
          })}
          </section>
        </div>

      </div>
    </div>
  );
}

function BackLink() {
  return (
    <Link to="/dashboard" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
      <ArrowLeft className="h-4 w-4 mr-1" /> Dashboard
    </Link>
  );
}

function ShieldScanBanner({
  auditId, appUrl, clientId, savedRepos, hasScanned, onDone, onSurfaceResult, onRepoResult, onSupabaseResult, onAIResult, onAIAssistResult, aiScanPreset, onAIScanPresetConsumed,
}: {
  auditId: string;
  appUrl: string | null;
  clientId: string | null;
  savedRepos: SavedRepo[];
  hasScanned: boolean;
  onDone: () => void;
  onSurfaceResult: (s: { passes: number; fails: number; warnings: number; target: string; at: string }) => void;
  onRepoResult: (s: {
    passes: number; fails: number; findings: number; repo: string; at: string;
    dep?: { ok: boolean; error?: string; path?: string; packagesScanned?: number; counts?: { critical: number; high: number; medium: number; low: number }; status?: "pass" | "fail" | "inconclusive"; findings?: DepFinding[] };
    aiEndpoints?: DetectedEndpoint[];
    aiDetectError?: string | null;
  }) => void;
  onSupabaseResult: (s: { passes: number; fails: number; project: string; leaks: number; publicBuckets: string[]; bundleMatches: number; at: string }) => void;
  onAIResult: (s: { passes: number; fails: number; endpoint: string; critical: number; high: number; medium: number; at: string }) => void;
  onAIAssistResult: (s: AIAssistSummary) => void;
  aiScanPreset: AIScanPreset | null;
  onAIScanPresetConsumed: () => void;
}) {

  const scan = useServerFn(runAutoScan);
  const [pending, setPending] = useState(false);
  const [progress, setProgress] = useState(0);

  // Animated indeterminate-ish progress while pending
  useEffect(() => {
    if (!pending) { setProgress(0); return; }
    setProgress(8);
    const iv = setInterval(() => {
      setProgress((p) => (p < 90 ? p + Math.max(1, (90 - p) * 0.08) : p));
    }, 250);
    return () => clearInterval(iv);
  }, [pending]);

  const surfaceLR = useLastRun(`surface:${auditId}`);
  const repoLR = useLastRun(`repo:${auditId}`);
  const supabaseLR = useLastRun(`supabase:${auditId}`);
  const aiLR = useLastRun(`ai:${auditId}`);
  const aiAssistLR = useLastRun(`aiassist:${auditId}`);

  const run = async () => {
    setPending(true);
    const tid = toast.loading("Running SHIELD Surface Scan…");
    try {
      const res = await scan({ data: { auditId } });
      setProgress(100);
      toast.success(
        `Surface scan complete — ${res.passes} passed, ${res.fails} failed, ${res.warnings} warnings`,
        { id: tid, description: res.target },
      );
      const at = new Date().toISOString();
      onSurfaceResult({ passes: res.passes, fails: res.fails, warnings: res.warnings, target: res.target, at });
      surfaceLR.mark();
      onDone();
    } catch (e: any) {
      toast.error(e?.message ?? "Scan failed", { id: tid });
    } finally {
      setTimeout(() => setPending(false), 400);
    }
  };

  const surfaceHasRun = hasScanned || surfaceLR.hasRun;

  return (
    <Card className="p-4 border-l-4 border-l-primary bg-primary/[0.03]">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-start gap-3 min-w-0">
          <div className="rounded-md bg-primary/10 p-2 shrink-0">
            <Shield className="h-5 w-5 text-primary" />
          </div>
          <div className="min-w-0">
            <h3 className="font-semibold leading-tight">SHIELD Surface Scan</h3>
            <p className="text-sm text-muted-foreground mt-0.5">
              Automatically probes the client&apos;s live site for SSL, security headers, CSP, error verbosity, exposed secrets, and debug mode.
            </p>
          </div>
        </div>
        <div className="flex items-start gap-2 flex-wrap min-w-0">
          <div className="inline-flex flex-col items-start gap-1">
            <Button
              onClick={run}
              disabled={pending}
              variant={surfaceHasRun ? "outline" : "default"}
            >
              {pending ? (
                <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Running SHIELD Surface Scan…</>
              ) : surfaceHasRun ? (
                <><Radar className="h-4 w-4 mr-1" /> Re-scan Surface</>
              ) : (
                <><Sparkles className="h-4 w-4 mr-1" /> Run Surface Scan</>
              )}
            </Button>
            <LastRunBadge ts={surfaceLR.lastRunAt} />
          </div>
          <div className="inline-flex flex-col items-start gap-1">
            <RepoScanDialog auditId={auditId} appUrl={appUrl} clientId={clientId} savedRepos={savedRepos} onDone={onDone} onRepoResult={(s) => { repoLR.mark(); onRepoResult(s); }} hasRun={repoLR.hasRun} />
            <LastRunBadge ts={repoLR.lastRunAt} />
          </div>
          <div className="inline-flex flex-col items-start gap-1">
            <SupabaseScanDialog auditId={auditId} appUrl={appUrl} onDone={onDone} onResult={(s) => { supabaseLR.mark(); onSupabaseResult(s); }} hasRun={supabaseLR.hasRun} />
            <LastRunBadge ts={supabaseLR.lastRunAt} />
          </div>
          <div className="inline-flex flex-col items-start gap-1">
            <AIScanDialog auditId={auditId} appUrl={appUrl} savedRepos={savedRepos} onDone={onDone} onResult={(s) => { aiLR.mark(); onAIResult(s); }} preset={aiScanPreset} onPresetConsumed={onAIScanPresetConsumed} hasRun={aiLR.hasRun} />
            <LastRunBadge ts={aiLR.lastRunAt} />
          </div>
          <div className="inline-flex flex-col items-start gap-1">
            <AIAssistDialog auditId={auditId} clientId={clientId} savedRepos={savedRepos} onDone={onDone} onResult={(s) => { aiAssistLR.mark(); onAIAssistResult(s); }} hasRun={aiAssistLR.hasRun} />
            <LastRunBadge ts={aiAssistLR.lastRunAt} />
          </div>
        </div>
      </div>
      {pending && (
        <div className="mt-3">
          <Progress value={progress} />
        </div>
      )}
      {hasScanned && !pending && (
        <p className="text-xs text-muted-foreground mt-3 flex items-center gap-1.5">
          <CheckCircle2 className="h-3.5 w-3.5 text-status-pass" /> Scan complete — items marked with the “Auto-detected” badge were populated by the scanner.
        </p>
      )}
    </Card>
  );
}


function ItemRow({
  auditId, item, finding, autoScanned, aiAssisted, savedRepos, onSet,
}: { auditId: string; item: Item; finding: Finding | undefined; autoScanned: boolean; aiAssisted: boolean; savedRepos: SavedRepo[]; onSet: (status: "pass" | "fail" | "na", notes: string | null) => void }) {
  const qc = useQueryClient();
  const [notes, setNotes] = useState(finding?.notes ?? "");
  const status = finding?.status ?? null;
  const showNotes = status === "fail";
  const notesRef = useRef<HTMLTextAreaElement>(null);
  const wasFail = useRef(status === "fail");

  useEffect(() => {
    if (status === "fail" && !wasFail.current) {
      // Just transitioned into fail — autofocus the textarea
      requestAnimationFrame(() => notesRef.current?.focus());
    }
    wasFail.current = status === "fail";
  }, [status]);

  useEffect(() => {
    setNotes(finding?.notes ?? "");
  }, [finding?.notes]);

  const missingNotes = status === "fail" && !notes.trim();

  const statusBorder =
    status === "pass" ? "border-l-status-pass" :
    status === "fail" ? "border-l-status-fail" :
    status === "na" ? "border-l-status-na" :
    status === "resolved" ? "border-l-status-pass" :
    status === "inconclusive" ? "border-l-amber-500" :
    "border-l-transparent";

  const statusBg =
    status === "pass" ? "bg-status-pass/[0.04]" :
    status === "fail" ? "bg-status-fail/[0.04]" :
    status === "na" ? "bg-status-na/[0.04]" :
    status === "resolved" ? "bg-status-pass/[0.06]" :
    status === "inconclusive" ? "bg-amber-500/[0.05]" :
    "";

  return (
    <Card id={`item-${item.id}`} className={cn("p-4 border-l-4", statusBorder, statusBg, missingNotes && "ring-2 ring-status-fail/60")}>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h3 className="font-medium">{item.title}</h3>
          <div className="flex items-center gap-2 flex-wrap mt-0.5">
            {item.description && <p className="text-sm text-muted-foreground">{item.description}</p>}
            <SeverityBadge severity={item.severity} />
            {status === "inconclusive" && (
              <Badge variant="outline" className="gap-1 text-[10px] uppercase tracking-wide border-amber-500/50 text-amber-700 dark:text-amber-300">
                <CircleHelp className="h-3 w-3" /> Couldn't verify
              </Badge>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {autoScanned && (
            <>
              <Badge variant="secondary" className="gap-1 text-[10px] uppercase tracking-wide">
                <Sparkles className="h-3 w-3" /> Auto-detected
              </Badge>
              {finding?.notes?.startsWith("[Auto-scan ") && (
                <SurfaceRecheckButton auditId={auditId} checklistItemId={item.id} />
              )}
            </>
          )}
          {aiAssisted && (
            <>
              <Badge variant="secondary" className="gap-1 text-[10px] uppercase tracking-wide bg-purple-500/15 text-purple-700 dark:text-purple-300 hover:bg-purple-500/20">
                <Brain className="h-3 w-3" /> AI Assisted
              </Badge>
              <RecheckItemButton auditId={auditId} checklistItemId={item.id} savedRepos={savedRepos} />
            </>
          )}
          {finding?.id && <HistoryButton findingId={finding.id} itemTitle={item.title} />}
          <div className="flex items-center gap-1">
            <StatusBtn label="Pass" icon={<Check className="h-4 w-4" />} active={status === "pass"} color="pass" onClick={() => onSet("pass", null)} />
            <StatusBtn label="Fail" icon={<X className="h-4 w-4" />} active={status === "fail"} color="fail" onClick={() => onSet("fail", notes || null)} />
            <StatusBtn label="N/A" icon={<Minus className="h-4 w-4" />} active={status === "na"} color="na" onClick={() => onSet("na", null)} />
          </div>
        </div>
      </div>

      {status === "resolved" && (
        <div className="mt-3 rounded-md border border-status-pass/40 bg-status-pass/[0.06] p-3 flex items-start justify-between gap-3 flex-wrap">
          <div className="text-sm">
            <div className="flex items-center gap-2 font-medium text-status-pass">
              <CheckCircle2 className="h-4 w-4" /> Resolved
              <span className="text-xs text-muted-foreground font-normal">
                {finding?.resolved_at ? `· ${format(new Date(finding.resolved_at), "MMM d, yyyy")}` : ""}
                {finding?.resolved_via === "automated_rescan" ? " · Auto re-scan" : finding?.resolved_via === "manual_evidence" ? " · Manual evidence" : ""}
              </span>
            </div>
            {finding?.evidence_text && (
              <p className="text-sm text-muted-foreground mt-1 whitespace-pre-wrap">{finding.evidence_text}</p>
            )}
            {finding?.evidence_url && (
              <a href={finding.evidence_url} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1 mt-1">
                <ExternalLink className="h-3 w-3" /> Evidence link
              </a>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            className="gap-1"
            onClick={() => onSet("fail", notes || finding?.evidence_text || null)}
          >
            <RotateCcw className="h-3.5 w-3.5" /> Reopen
          </Button>
        </div>
      )}

      {item.what_to_look_for && (
        <div className="mt-3 rounded-md border border-border bg-muted/40 p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">
            How to test
          </div>
          <pre className="text-sm whitespace-pre-wrap font-sans leading-relaxed text-foreground/90">
{item.what_to_look_for}
          </pre>
        </div>
      )}

      {status === "inconclusive" && (
        <div className="mt-3 rounded-md border border-amber-500/40 bg-amber-500/[0.06] p-3 space-y-1.5">
          <div className="text-xs font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-300">
            Scanner couldn't verify this — check it manually, then mark Pass, Fail or N/A
          </div>
          {finding?.notes && (
            <pre className="text-xs whitespace-pre-wrap font-sans leading-relaxed text-foreground/80 max-h-64 overflow-auto">{finding.notes}</pre>
          )}
        </div>
      )}

      {showNotes && (
        <div className="mt-3 space-y-1.5">
          <label htmlFor={`notes-${item.id}`} className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Findings & evidence <span className="text-status-fail">*required</span>
          </label>
          <Textarea
            id={`notes-${item.id}`}
            ref={notesRef}
            placeholder="Describe the failure, evidence, remediation…"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            onBlur={() => {
              if ((notes || "") !== (finding?.notes || "")) onSet("fail", notes || null);
            }}
            rows={3}
            className={cn(missingNotes && "border-status-fail focus-visible:ring-status-fail")}
            aria-required="true"
          />
          {missingNotes && (
            <p className="text-xs text-status-fail">Findings are required before moving on.</p>
          )}
        </div>
      )}
      {status === "fail" && !missingNotes && (
        <FindingExplanation
          className="mt-3"
          auditId={auditId}
          checklistItemId={item.id}
          cached={finding?.explanation ?? null}
          fallback={item.description ?? null}
          onCached={(text) => {
            qc.setQueryData<Finding[]>(["findings", auditId], (prev) =>
              (prev ?? []).map((f) => (f.checklist_item_id === item.id ? { ...f, explanation: text } : f)),
            );
          }}
        />
      )}
      {status === "fail" && !missingNotes && (
        <div className="mt-3 flex items-start gap-3 flex-wrap">
          <FixPromptButton
            auditId={auditId}
            checklistItemId={item.id}
            cached={{
              lovable: finding?.lovable_prompt ?? null,
              cursor: finding?.cursor_prompt ?? null,
              claude: finding?.claude_prompt ?? null,
            }}
            onCached={(target, p) => {
              const col = target === "lovable" ? "lovable_prompt" : target === "cursor" ? "cursor_prompt" : "claude_prompt";
              qc.setQueryData<Finding[]>(["findings", auditId], (prev) =>
                (prev ?? []).map((f) =>
                  f.checklist_item_id === item.id ? { ...f, [col]: p } : f,
                ),
              );
            }}
          />
          <ResolveButton
            auditId={auditId}
            checklistItemId={item.id}
            isAutomated={!!finding?.auto_scanned}
            checklistKey={null}
          />
        </div>
      )}
    </Card>
  );
}

function SurfaceRecheckButton({
  auditId, checklistItemId,
}: { auditId: string; checklistItemId: string }) {
  const qc = useQueryClient();
  const scan = useServerFn(runAutoScan);
  const [pending, setPending] = useState(false);
  const [open, setOpen] = useState(false);
  const [scanState, setScanState] = useState<ScanProgressState>("idle");
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanSummary, setScanSummary] = useState<string | null>(null);

  const run = async () => {
    setPending(true);
    setOpen(true);
    setScanError(null);
    setScanSummary(null);
    setScanState("running");
    try {
      const res = await scan({ data: { auditId } });
      await qc.invalidateQueries({ queryKey: ["findings", auditId] });
      const updated = qc.getQueryData<Finding[]>(["findings", auditId])?.find((f) => f.checklist_item_id === checklistItemId);
      setScanState("success");
      setScanSummary(
        `${updated?.status === "pass" ? "Re-scan cleared this finding. " : ""}${res.passes} passed · ${res.fails} failed · ${res.warnings} warnings${res.inconclusive ? ` · ${res.inconclusive} couldn't verify` : ""}`,
      );
    } catch (e: any) {
      setScanState("error");
      setScanError(e?.message ?? "Re-scan failed");
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      <Button
        size="sm"
        variant="ghost"
        className="h-7 px-2 text-xs gap-1 text-muted-foreground hover:text-foreground hover:bg-muted"
        onClick={run}
        disabled={pending}
        title="Re-run the surface scan and update this finding"
      >
        {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
        Re-scan
      </Button>
      <Dialog open={open} onOpenChange={(o) => { if (pending) return; setOpen(o); if (!o) { setScanState("idle"); setScanError(null); setScanSummary(null); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Surface re-scan</DialogTitle>
            <DialogDescription>Re-running the automated scanner against this audit's target.</DialogDescription>
          </DialogHeader>
          <ScanProgressPanel
            state={scanState}
            steps={defaultSurfaceScanSteps()}
            title="Scan progress"
            errorMessage={scanError}
            finalSummary={scanSummary}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={pending}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function RecheckItemButton({
  auditId, checklistItemId, savedRepos,
}: { auditId: string; checklistItemId: string; savedRepos: SavedRepo[] }) {
  const qc = useQueryClient();
  const recheck = useServerFn(recheckAIAssistItem);
  const [pending, setPending] = useState(false);

  const repo = savedRepos.find((r) => r.repo_url) ?? null;
  const cachedToken = repo ? (typeof window !== "undefined" ? window.sessionStorage.getItem("repo-pat:" + repo.id) : null) : null;
  const disabled = pending || !repo || !cachedToken;

  const run = async () => {
    if (!repo?.repo_url) {
      toast.error("Connect a GitHub repo to re-check this item.");
      return;
    }
    if (!cachedToken) {
      toast.error("Run a repo scan first to provide a GitHub token for this session.");
      return;
    }
    setPending(true);
    const tid = toast.loading(`Re-checking with ${repo.label}…`);
    try {
      const res = await recheck({
        data: { auditId, checklistItemId, repoUrl: repo.repo_url, token: cachedToken },
      });
      if (!res.ok) {
        toast.error(res.error ?? "Re-check failed", { id: tid });
        return;
      }
      if (!res.applied) {
        toast.message(res.message ?? "No evidence found.", { id: tid });
      } else {
        toast.success(`Re-check: ${res.status?.toUpperCase()} (${res.confidence} confidence)`, { id: tid });
        qc.invalidateQueries({ queryKey: ["findings", auditId] });
      }
    } catch (e: any) {
      toast.error(e?.message ?? "Re-check failed", { id: tid });
    } finally {
      setPending(false);
    }
  };

  return (
    <Button
      size="sm"
      variant="ghost"
      className="h-7 px-2 text-xs gap-1 text-purple-700 dark:text-purple-300 hover:bg-purple-500/10"
      onClick={run}
      disabled={disabled}
      title={repo ? `Re-scan repo for this item using ${repo.label}` : "Connect a GitHub repo with a token to enable re-check"}
    >
      {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
      Re-check
    </Button>
  );
}



function StatusBtn({
  label, icon, active, color, onClick,
}: { label: string; icon: React.ReactNode; active: boolean; color: "pass" | "fail" | "na"; onClick: () => void }) {
  const palette = {
    pass: "border-status-pass/50 text-status-pass bg-status-pass/10",
    fail: "border-status-fail/50 text-status-fail bg-status-fail/10",
    na: "border-status-na/50 text-status-na bg-status-na/10",
  } as const;
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border text-xs font-medium transition-colors",
        active ? palette[color] : "border-border text-muted-foreground hover:bg-muted",
      )}
    >
      {icon}
      {label}
    </button>
  );
}

function RepoScanDialog({ auditId, appUrl, clientId, savedRepos, onDone, onRepoResult, hasRun }: {
  auditId: string;
  appUrl: string | null;
  clientId: string | null;
  savedRepos: SavedRepo[];
  onDone: () => void;
  onRepoResult: (s: {
    passes: number; fails: number; findings: number; repo: string; at: string;
    dep?: { ok: boolean; error?: string; path?: string; packagesScanned?: number; counts?: { critical: number; high: number; medium: number; low: number }; status?: "pass" | "fail" | "inconclusive"; findings?: DepFinding[] };
    aiEndpoints?: DetectedEndpoint[];
    aiDetectError?: string | null;
  }) => void;
  hasRun?: boolean;
}) {

  const scan = useServerFn(runRepoScan);
  const qc = useQueryClient();

  return (
    <RepoLauncher
      trigger={{ label: hasRun ? "Re-scan Repo" : "Scan Repo", icon: <GitBranch className="h-4 w-4 mr-1" /> }}
      clientId={clientId}
      savedRepos={savedRepos}
      title="Scan GitHub repo"
      description={<>Two-phase scan: (1) last 100 commits on the default branch for committed <code>.env</code> files and known secret patterns; (2) <code>package.json</code> dependencies checked against the npm advisory database.</>}
      submitLabel="Start scan"
      runningLabel="Scanning commits + dependencies…"
      loadingToast="Scanning repo commits & dependencies…"
      onSaved={() => qc.invalidateQueries({ queryKey: ["client-repos", clientId] })}
      onRun={async ({ repoUrl, token, loadingToastId }) => {
        try {
          const res = await scan({ data: { auditId, repoUrl, token, appUrl } });
          if (!res.ok) { toast.error(res.error, { id: loadingToastId }); return false; }
          const fails = res.results.filter((r) => r.status === "fail").length;
          const passes = res.results.filter((r) => r.status === "pass").length;
          const dep = res.dep;
          const depDesc = dep?.ok
            ? ` · ${dep.packagesScanned} pkgs / ${dep.findings?.length ?? 0} vulnerable`
            : dep && !dep.ok ? ` · deps: ${dep.error}` : "";
          const aiDesc = (res.aiEndpoints?.length ?? 0) > 0 ? ` · ${res.aiEndpoints!.length} AI endpoint(s)` : "";
          toast.success(
            `Repo scan complete — ${passes} pass, ${fails} fail`,
            { id: loadingToastId, description: `${res.repo} · ${res.commitsScanned} commits · ${res.findings.length} hit(s)${depDesc}${aiDesc}` },
          );
          onRepoResult({
            passes, fails, findings: res.findings.length, repo: res.repo, at: new Date().toISOString(),
            dep: dep
              ? (dep.ok
                  ? { ok: true, path: dep.path, packagesScanned: dep.packagesScanned, counts: dep.counts, status: dep.status, findings: dep.findings }
                  : { ok: false, error: dep.error })
              : undefined,
            aiEndpoints: res.aiEndpoints ?? [],
            aiDetectError: res.aiDetectError ?? null,
          });
          onDone();
          return true;
        } catch (err: any) {
          toast.error(err?.message ?? "Repo scan failed", { id: loadingToastId });
          return false;
        }

      }}
    />
  );
}

type RepoDep = NonNullable<Parameters<Parameters<typeof RepoScanDialog>[0]["onRepoResult"]>[0]["dep"]>;

function RepoDepPanel({ dep }: { dep: RepoDep }) {
  if (!dep.ok) {
    return (
      <Card className="p-4 border-l-4 border-l-status-na/60">
        <div className="flex items-center gap-2">
          <Package className="h-4 w-4 text-muted-foreground shrink-0" />
          <div className="font-medium text-sm">Dependency scan skipped</div>
        </div>
        <p className="text-xs text-muted-foreground mt-1">{dep.error}</p>
      </Card>
    );
  }
  const findings = dep.findings ?? [];
  const counts = dep.counts ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const total = dep.packagesScanned ?? 0;

  const sevClass = (s: DepFinding["severity"]) => {
    if (s === "critical") return "bg-status-fail/10 text-status-fail border-status-fail/40";
    if (s === "high") return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/40";
    if (s === "medium") return "bg-status-na/10 text-status-na border-status-na/40";
    return "bg-muted text-muted-foreground border-border";
  };
  const rowClass = (s: DepFinding["severity"]) => {
    if (s === "critical") return "bg-status-fail/5";
    if (s === "high") return "bg-amber-500/5";
    return "";
  };

  return (
    <Card className="p-4 border-l-4 border-l-amber-500/60">
      <div className="flex items-center gap-2 mb-1">
        <Package className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
        <div className="font-medium text-sm">Repo scan — dependencies</div>
        <div className="ml-auto text-xs text-muted-foreground">{dep.path}</div>
      </div>
      <p className="text-sm text-foreground mb-3">
        <span className="font-medium">{total} packages scanned, {findings.length} vulnerable</span>
        {findings.length > 0 && (
          <span className="text-muted-foreground">
            {" "}— {counts.critical} critical · {counts.high} high · {counts.medium} medium · {counts.low} low
          </span>
        )}
      </p>

      {findings.length === 0 ? (
        <p className="text-xs text-muted-foreground">No critical/high CVEs, no packages 2+ majors behind, no &gt;6-month-old pins.</p>
      ) : (
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2 font-medium">Package</th>
                <th className="text-left px-3 py-2 font-medium">Current Version</th>
                <th className="text-left px-3 py-2 font-medium">Latest Version</th>
                <th className="text-left px-3 py-2 font-medium">Severity</th>
                <th className="text-left px-3 py-2 font-medium">CVE ID</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f: DepFinding, i: number) => (
                <tr key={`${f.name}-${i}`} className={cn("border-t border-border", rowClass(f.severity))}>
                  <td className="px-3 py-2 font-mono text-xs">{f.name}</td>
                  <td className="px-3 py-2 font-mono text-xs">{f.current}</td>
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{f.latest ?? "—"}</td>
                  <td className="px-3 py-2">
                    <span className={cn("inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-medium uppercase", sevClass(f.severity))}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {f.cve ? (
                      <a
                        href={f.advisoryUrl ?? `https://nvd.nist.gov/vuln/detail/${f.cve}`}
                        target="_blank" rel="noreferrer"
                        className="inline-flex items-center gap-1 font-mono text-primary hover:underline"
                      >
                        {f.cve} <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                    <div className="text-muted-foreground">{f.reason}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function AIEndpointsDiscoveredPanel({
  endpoints,
  onTest,
}: {
  endpoints: DetectedEndpoint[];
  onTest: (ep: DetectedEndpoint) => void;
}) {
  return (
    <Card className="p-4 border-l-4 border-l-purple-500/60">
      <div className="flex items-center gap-2 mb-1">
        <Bot className="h-4 w-4 text-purple-600 dark:text-purple-400 shrink-0" />
        <div className="font-medium text-sm">AI Endpoints Discovered</div>
        <div className="ml-auto text-xs text-muted-foreground">
          {endpoints.length} endpoint{endpoints.length === 1 ? "" : "s"}
        </div>
      </div>
      <p className="text-xs text-muted-foreground mb-3">
        Detected from repo source. Click <span className="font-medium text-foreground">Test for Injection</span> to pre-fill the AI scan with the URL and prompt field.
      </p>
      <ul className="space-y-2">
        {endpoints.map((ep, i) => (
          <li key={`${ep.filePath}-${i}`} className="rounded-md border border-border bg-card p-2.5">
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-sm">{ep.source}</span>
                  {ep.partialUrl && (
                    <Badge variant="outline" className="text-[10px] uppercase border-status-na/50 text-status-na">partial URL</Badge>
                  )}
                  {ep.requiresAuth && (
                    <Badge variant="outline" className="text-[10px] uppercase">auth</Badge>
                  )}
                  <Badge variant="secondary" className="text-[10px] font-mono lowercase">field: {ep.promptField}</Badge>
                </div>
                <div className="text-xs text-muted-foreground font-mono truncate mt-0.5">
                  {ep.url || "(URL needs completion)"}
                </div>
                <div className="text-[11px] text-muted-foreground/80 italic truncate mt-0.5">{ep.filePath}</div>
              </div>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => onTest(ep)}
                disabled={!ep.url}
                title={!ep.url ? "URL could not be resolved — open the AI scan dialog manually to complete it." : undefined}
              >
                <Bot className="h-3.5 w-3.5 mr-1" /> Test for Injection
              </Button>
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}


const EVENT_LABEL: Record<string, string> = {
  flagged: "Flagged",
  fix_submitted: "Fix submitted",
  rescanned: "Re-scanned",
  resolved: "Resolved",
  reopened: "Reopened",
};

function HistoryButton({ findingId, itemTitle }: { findingId: string; itemTitle: string }) {
  const [open, setOpen] = useState(false);
  const fetchHistory = useServerFn(listFindingHistory);
  const { data, isLoading } = useQuery({
    queryKey: ["finding-history", findingId],
    queryFn: () => fetchHistory({ data: { findingId } }),
    enabled: open,
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1 h-8">
          <History className="h-3.5 w-3.5" /> History
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><History className="h-4 w-4" /> Finding history</DialogTitle>
          <DialogDescription className="line-clamp-2">{itemTitle}</DialogDescription>
        </DialogHeader>
        <div className="max-h-[60vh] overflow-y-auto">
          {isLoading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground py-6 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading timeline…
            </div>
          )}
          {!isLoading && (!data || data.length === 0) && (
            <p className="text-sm text-muted-foreground py-6 text-center">No history yet.</p>
          )}
          {!isLoading && data && data.length > 0 && (
            <ol className="relative border-l border-border ml-3 space-y-4 py-2">
              {data.map((row: any) => (
                <li key={row.id} className="ml-4">
                  <span className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full bg-primary border-2 border-background" />
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs uppercase tracking-wide font-semibold text-foreground">
                      {EVENT_LABEL[row.event_type] ?? row.event_type}
                    </span>
                    <time className="text-xs text-muted-foreground">
                      {format(new Date(row.created_at), "MMM d, yyyy · h:mm a")}
                    </time>
                  </div>
                  {row.evidence_text && (
                    <p className="text-sm text-muted-foreground mt-1 whitespace-pre-wrap">{row.evidence_text}</p>
                  )}
                  {row.evidence_url && (
                    <a href={row.evidence_url} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1 mt-1">
                      <ExternalLink className="h-3 w-3" /> {row.evidence_url}
                    </a>
                  )}
                </li>
              ))}
            </ol>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function ResolveButton({
  auditId, checklistItemId, isAutomated,
}: { auditId: string; checklistItemId: string; isAutomated: boolean; checklistKey: string | null }) {
  const qc = useQueryClient();
  const resolve = useServerFn(resolveFinding);
  const [open, setOpen] = useState(false);
  const [evidenceText, setEvidenceText] = useState("");
  const [evidenceUrl, setEvidenceUrl] = useState("");
  const [pending, setPending] = useState(false);
  const [scanState, setScanState] = useState<ScanProgressState>("idle");
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanSummary, setScanSummary] = useState<string | null>(null);

  const submit = async (mode: "automated" | "manual") => {
    setPending(true);
    if (mode === "automated") {
      setScanError(null);
      setScanSummary(null);
      setScanState("running");
    }
    const tid = toast.loading(mode === "automated" ? "Re-running scanner…" : "Submitting evidence…");
    try {
      const res: any = await resolve({
        data: {
          auditId,
          checklistItemId,
          mode,
          evidenceText: mode === "manual" ? evidenceText.trim() : null,
          evidenceUrl: mode === "manual" && evidenceUrl.trim() ? evidenceUrl.trim() : null,
        },
      });
      await qc.invalidateQueries({ queryKey: ["findings", auditId] });
      if (res?.ok === false) {
        const msg = res?.reason === "rescan_still_failing"
          ? "Re-scan still failing — cannot mark resolved"
          : (res?.reason ?? "Re-scan did not verify the fix");
        if (mode === "automated") {
          setScanState("error");
          setScanError(msg);
        }
        toast.error(msg, { id: tid });
      } else {
        if (mode === "automated") {
          setScanState("success");
          setScanSummary("Scanner returned pass — finding marked resolved.");
        }
        toast.success("Finding marked resolved", { id: tid });
        // For manual path, close immediately. For automated, let user see the timeline.
        if (mode === "manual") {
          setOpen(false);
        }
        setEvidenceText("");
        setEvidenceUrl("");
      }
    } catch (e: any) {
      if (mode === "automated") {
        setScanState("error");
        setScanError(e?.message ?? "Could not resolve finding");
      }
      toast.error(e?.message ?? "Could not resolve finding", { id: tid });
    } finally {
      setPending(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (pending) return; setOpen(o); if (!o) { setScanState("idle"); setScanError(null); setScanSummary(null); } }}>

      <DialogTrigger asChild>
        <Button variant="default" size="sm" className="gap-1 h-8 bg-status-pass hover:bg-status-pass/90 text-white">
          <CheckCircle2 className="h-3.5 w-3.5" /> Mark resolved
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Mark finding as resolved</DialogTitle>
          <DialogDescription>
            {isAutomated
              ? "This finding came from an automated scanner. Re-run the scan to verify the fix — the status will only flip to resolved if the scanner returns pass."
              : "Describe the fix you applied. A short evidence note is required; an optional link can be a PR, screenshot, or ticket."}
          </DialogDescription>
        </DialogHeader>

        {isAutomated ? (
          <div className="space-y-3">
            <div className="rounded-md border bg-muted/40 p-3 text-sm text-muted-foreground">
              Clicking <span className="font-semibold text-foreground">Re-scan & verify</span> will re-run the relevant surface
              scanner against this audit. A timeline entry will be written with the before/after result.
            </div>
            <ScanProgressPanel
              state={scanState}
              steps={defaultSurfaceScanSteps()}
              title="Re-scan progress"
              errorMessage={scanError}
              finalSummary={scanSummary}
            />
          </div>
        ) : (
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="evidence-text">Evidence / description of the fix <span className="text-status-fail">*</span></Label>
              <Textarea
                id="evidence-text"
                value={evidenceText}
                onChange={(e) => setEvidenceText(e.target.value)}
                placeholder="What did you change, where, and how was it verified?"
                rows={4}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="evidence-url">Evidence link (optional)</Label>
              <Input
                id="evidence-url"
                value={evidenceUrl}
                onChange={(e) => setEvidenceUrl(e.target.value)}
                placeholder="https://github.com/org/repo/pull/123 or screenshot URL"
              />
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => setOpen(false)} disabled={pending}>Cancel</Button>
          {isAutomated ? (
            <Button onClick={() => submit("automated")} disabled={pending} className="gap-1">
              {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              Re-scan & verify
            </Button>
          ) : (
            <Button onClick={() => submit("manual")} disabled={pending || !evidenceText.trim()} className="gap-1">
              {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
              Submit & resolve
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function BuiltWithChip({ auditId, value, onChanged }: { auditId: string; value: string | null; onChanged: () => void }) {
  const [saving, setSaving] = useState(false);
  const label = builtWithLabel(value);
  const update = async (v: BuiltWith | null) => {
    setSaving(true);
    const { error } = await supabase.from("audits").update({ built_with: v } as any).eq("id", auditId);
    setSaving(false);
    if (error) { toast.error(error.message); return; }
    toast.success(v ? `Marked as built with ${builtWithLabel(v)}` : "Built with cleared");
    onChanged();
  };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          disabled={saving}
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-border bg-muted/40 text-xs hover:bg-muted transition-colors"
          title="Which tool built this app"
        >
          <Sparkles className="h-3 w-3" />
          <span className="text-[10px] uppercase tracking-wide">
            {label ? `Built with ${label}` : "Built with…"}
          </span>
          <ChevronDown className="h-3 w-3 opacity-60" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-56">
        {BUILT_WITH_OPTIONS.map((o) => (
          <DropdownMenuItem key={o.value} onSelect={() => update(o.value)}>
            {o.label}
            {value === o.value && <Check className="h-3.5 w-3.5 ml-auto" />}
          </DropdownMenuItem>
        ))}
        {value && (
          <DropdownMenuItem onSelect={() => update(null)} className="text-muted-foreground">
            Clear
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
