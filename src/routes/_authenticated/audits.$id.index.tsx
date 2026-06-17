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
import { ArrowLeft, FileText, Check, X, Minus, CheckCircle2, Shield, Radar, Loader2, Github, Filter, Circle, Sparkles, GitBranch, Package, ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { runAutoScan } from "@/lib/scan.functions";

import { runRepoScan } from "@/lib/repo-scan.functions";
import { DeleteAuditButton } from "@/components/delete-audit-button";
import { SupabaseScanDialog } from "@/components/supabase-scan-dialog";
import { AIScanDialog } from "@/components/ai-scan-dialog";
import type { DepFinding } from "@/lib/dep-scan-core";

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
type Finding = { checklist_item_id: string; status: "pass" | "fail" | "na" | null; notes: string | null; auto_scanned?: boolean | null };

function AuditView() {
  const { id } = Route.useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const audit = useQuery({
    queryKey: ["audit", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, status, started_at, completed_at, summary, client:clients(id, name, app_url)")
        .eq("id", id).single();
      if (error) throw error;
      return data;
    },
  });

  const items = useQuery({
    queryKey: ["checklist-items"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("checklist_items")
        .select("id, category, title, description, severity, sort_order, what_to_look_for").eq("is_active", true)
        .order("sort_order");
      if (error) throw error;
      return (data ?? []) as Item[];
    },
  });

  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audit_findings")
        .select("checklist_item_id, status, notes, auto_scanned")
        .eq("audit_id", id);
      if (error) throw error;
      return (data ?? []) as Finding[];
    },
  });

  const hasAutoScanned = useMemo(() => (findings.data ?? []).some((f) => f.auto_scanned), [findings.data]);

  type SurfaceSummary = { passes: number; fails: number; warnings: number; target: string; at: string };
  type RepoSummary = {
    passes: number; fails: number; findings: number; repo: string; at: string;
    dep?: {
      ok: boolean;
      error?: string;
      path?: string;
      packagesScanned?: number;
      counts?: { critical: number; high: number; medium: number; low: number };
      status?: "pass" | "fail";
      findings?: DepFinding[];
    };
  };
  type SupabaseSummary = { passes: number; fails: number; project: string; leaks: number; publicBuckets: string[]; bundleMatches: number; at: string };
  type AISummary = { passes: number; fails: number; endpoint: string; critical: number; high: number; medium: number; at: string };
  const [surfaceSummary, setSurfaceSummary] = useState<SurfaceSummary | null>(null);
  const [repoSummary, setRepoSummary] = useState<RepoSummary | null>(null);
  const [supabaseSummary, setSupabaseSummary] = useState<SupabaseSummary | null>(null);
  const [aiSummary, setAISummary] = useState<AISummary | null>(null);
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
      const done = statuses.filter((s) => s).length;
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
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>(["pass", "fail", "na", "unrated"]);

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
      qc.invalidateQueries({ queryKey: ["audit", id] });
      qc.invalidateQueries({ queryKey: ["audits"] });
      toast.success("Audit marked complete");
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
          <p className="text-sm text-muted-foreground">
            {(audit.data as any)?.client?.name} · <span className="capitalize">{audit.data?.status.replace("_", " ")}</span>
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
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
          <ShieldScanBanner
            auditId={id}
            appUrl={(audit.data as any)?.client?.app_url ?? null}
            hasScanned={hasAutoScanned}
            onDone={() => qc.invalidateQueries({ queryKey: ["findings", id] })}
            onSurfaceResult={setSurfaceSummary}
            onRepoResult={setRepoSummary}
            onSupabaseResult={setSupabaseSummary}
            onAIResult={setAISummary}
            onDepResult={setDepResult}
          />
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

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2 text-xs">
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
                  {depResult && (
                    <div className="rounded-md border border-border bg-card p-2">
                      <div className="font-medium text-foreground">Dependencies</div>
                      <div className="text-muted-foreground truncate">{depResult.repo} · {depResult.packagesScanned} pkgs</div>
                      <div className="mt-1 space-x-1">
                        {depResult.counts.critical > 0 && <span className="text-status-fail">{depResult.counts.critical} critical</span>}
                        {depResult.counts.high > 0 && <span className="text-status-fail"> · {depResult.counts.high} high</span>}
                        {depResult.counts.medium > 0 && <span className="text-status-na"> · {depResult.counts.medium} medium</span>}
                        {depResult.counts.low > 0 && <span className="text-muted-foreground"> · {depResult.counts.low} low</span>}
                        {depResult.findings.length === 0 && <span className="text-status-pass">all clean</span>}
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
          {depResult && depResult.findings.length > 0 && <DependencyResultsPanel result={depResult} />}
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
                item={it}
                finding={f}
                autoScanned={!!f?.auto_scanned}
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
  auditId, appUrl, hasScanned, onDone, onSurfaceResult, onRepoResult, onSupabaseResult, onAIResult, onDepResult,
}: {
  auditId: string;
  appUrl: string | null;
  hasScanned: boolean;
  onDone: () => void;
  onSurfaceResult: (s: { passes: number; fails: number; warnings: number; target: string; at: string }) => void;
  onRepoResult: (s: { passes: number; fails: number; findings: number; repo: string; at: string }) => void;
  onSupabaseResult: (s: { passes: number; fails: number; project: string; leaks: number; publicBuckets: string[]; bundleMatches: number; at: string }) => void;
  onAIResult: (s: { passes: number; fails: number; endpoint: string; critical: number; high: number; medium: number; at: string }) => void;
  onDepResult: (r: DepScanResult) => void;
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
      onSurfaceResult({ passes: res.passes, fails: res.fails, warnings: res.warnings, target: res.target, at: new Date().toISOString() });
      onDone();
    } catch (e: any) {
      toast.error(e?.message ?? "Scan failed", { id: tid });
    } finally {
      setTimeout(() => setPending(false), 400);
    }
  };

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
        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          <Button
            onClick={run}
            disabled={pending}
            variant={hasScanned ? "outline" : "default"}
          >
            {pending ? (
              <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Running SHIELD Surface Scan…</>
            ) : hasScanned ? (
              <><Radar className="h-4 w-4 mr-1" /> Re-scan</>
            ) : (
              <><Sparkles className="h-4 w-4 mr-1" /> Run Surface Scan</>
            )}
          </Button>
          <RepoScanDialog auditId={auditId} onDone={onDone} onRepoResult={onRepoResult} />
          <SupabaseScanDialog auditId={auditId} appUrl={appUrl} onDone={onDone} onResult={onSupabaseResult} />
          <AIScanDialog auditId={auditId} onDone={onDone} onResult={onAIResult} />
          <DependencyScanDialog auditId={auditId} onDone={onDone} onResult={onDepResult} />
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
  item, finding, autoScanned, onSet,
}: { item: Item; finding: Finding | undefined; autoScanned: boolean; onSet: (status: "pass" | "fail" | "na", notes: string | null) => void }) {
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
    "border-l-transparent";

  const statusBg =
    status === "pass" ? "bg-status-pass/[0.04]" :
    status === "fail" ? "bg-status-fail/[0.04]" :
    status === "na" ? "bg-status-na/[0.04]" :
    "";

  return (
    <Card id={`item-${item.id}`} className={cn("p-4 border-l-4", statusBorder, statusBg, missingNotes && "ring-2 ring-status-fail/60")}>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h3 className="font-medium">{item.title}</h3>
          <div className="flex items-center gap-2 flex-wrap mt-0.5">
            {item.description && <p className="text-sm text-muted-foreground">{item.description}</p>}
            <SeverityBadge severity={item.severity} />
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {autoScanned && (
            <Badge variant="secondary" className="gap-1 text-[10px] uppercase tracking-wide">
              <Sparkles className="h-3 w-3" /> Auto-detected
            </Badge>
          )}
          <div className="flex items-center gap-1">
            <StatusBtn label="Pass" icon={<Check className="h-4 w-4" />} active={status === "pass"} color="pass" onClick={() => onSet("pass", null)} />
            <StatusBtn label="Fail" icon={<X className="h-4 w-4" />} active={status === "fail"} color="fail" onClick={() => onSet("fail", notes || null)} />
            <StatusBtn label="N/A" icon={<Minus className="h-4 w-4" />} active={status === "na"} color="na" onClick={() => onSet("na", null)} />
          </div>
        </div>
      </div>

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
    </Card>
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

function RepoScanDialog({ auditId, onDone, onRepoResult }: {
  auditId: string;
  onDone: () => void;
  onRepoResult: (s: { passes: number; fails: number; findings: number; repo: string; at: string }) => void;
}) {
  const scan = useServerFn(runRepoScan);
  const [open, setOpen] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [token, setToken] = useState("");
  const [pending, setPending] = useState(false);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (!pending) { setProgress(0); return; }
    setProgress(6);
    const iv = setInterval(() => {
      setProgress((p) => (p < 92 ? p + Math.max(0.5, (92 - p) * 0.04) : p));
    }, 250);
    return () => clearInterval(iv);
  }, [pending]);

  const reset = () => { setRepoUrl(""); setToken(""); };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim() || !token.trim()) {
      toast.error("Enter both the repo URL and a personal access token.");
      return;
    }
    setPending(true);
    const tid = toast.loading("Scanning repo commits…");
    try {
      const res = await scan({ data: { auditId, repoUrl: repoUrl.trim(), token: token.trim() } });
      setProgress(100);
      if (!res.ok) {
        toast.error(res.error, { id: tid });
        return;
      }
      const fails = res.results.filter((r) => r.status === "fail").length;
      const passes = res.results.filter((r) => r.status === "pass").length;
      toast.success(
        `Repo scan complete — ${passes} pass, ${fails} fail`,
        { id: tid, description: `${res.repo} · ${res.commitsScanned} commits · ${res.findings.length} hit(s)` },
      );
      onRepoResult({ passes, fails, findings: res.findings.length, repo: res.repo, at: new Date().toISOString() });
      onDone();
      reset();
      setOpen(false);
    } catch (err: any) {
      toast.error(err?.message ?? "Repo scan failed", { id: tid });
    } finally {
      setTimeout(() => setPending(false), 400);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!pending) setOpen(o); }}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <GitBranch className="h-4 w-4 mr-1" /> Scan Repo
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Github className="h-4 w-4" /> Scan GitHub repo
            </DialogTitle>
            <DialogDescription>
              Scans the last 100 commits on the default branch for committed <code>.env</code> files and known
              secret patterns (Supabase service role, Stripe, OpenAI, Anthropic, AWS, PEM keys, GitHub tokens).
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-1.5">
            <Label htmlFor="repo-url">Repository URL</Label>
            <Input
              id="repo-url"
              placeholder="https://github.com/owner/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              disabled={pending}
              autoFocus
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="pat">GitHub personal access token</Label>
            <Input
              id="pat"
              type="password"
              placeholder="ghp_… or github_pat_…"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              disabled={pending}
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground leading-relaxed">
              Needs <strong>read-only repo scope</strong> (Fine-grained PAT: <em>Contents: Read</em> + <em>Metadata: Read</em>, or a classic PAT with <code>repo</code> for private repos / <code>public_repo</code> for public). The token is <strong>never stored</strong> — it is used only for this scan and discarded afterward.
            </p>
          </div>

          {pending && (
            <div className="space-y-1.5">
              <Progress value={progress} />
              <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                <Loader2 className="h-3 w-3 animate-spin" /> Fetching commits and scanning patches… this usually takes 10–15s.
              </p>
            </div>
          )}

          <DialogFooter>
            <Button type="button" variant="ghost" disabled={pending} onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" disabled={pending}>
              {pending ? <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Scanning…</> : <><GitBranch className="h-4 w-4 mr-1" /> Start scan</>}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

type DepFindingSev = DepScanResult["findings"][number]["severity"];

function DependencyResultsPanel({ result }: { result: DepScanResult }) {
  const sevClass = (s: DepFindingSev) => {
    if (s === "critical") return "bg-status-fail/10 text-status-fail border-status-fail/40";
    if (s === "high") return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/40";
    if (s === "medium") return "bg-status-na/10 text-status-na border-status-na/40";
    return "bg-muted text-muted-foreground border-border";
  };
  const rowClass = (s: DepFindingSev) => {
    if (s === "critical") return "bg-status-fail/5";
    if (s === "high") return "bg-amber-500/5";
    return "";
  };
  return (
    <Card className="p-4 border-l-4 border-l-amber-500/60">
      <div className="flex items-center gap-2 mb-3">
        <Package className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
        <div className="font-medium text-sm">Dependency scan — {result.repo}</div>
        <div className="ml-auto text-xs text-muted-foreground">
          {result.packagesScanned} scanned · {result.findings.length} flagged
        </div>
      </div>
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="text-left px-3 py-2 font-medium">Package</th>
              <th className="text-left px-3 py-2 font-medium">Current</th>
              <th className="text-left px-3 py-2 font-medium">Latest</th>
              <th className="text-left px-3 py-2 font-medium">Severity</th>
              <th className="text-left px-3 py-2 font-medium">CVE / Reason</th>
            </tr>
          </thead>
          <tbody>
            {result.findings.map((f, i) => (
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
                  {f.cve && (
                    <a
                      href={f.advisoryUrl ?? `https://nvd.nist.gov/vuln/detail/${f.cve}`}
                      target="_blank" rel="noreferrer"
                      className="inline-flex items-center gap-1 font-mono text-primary hover:underline"
                    >
                      {f.cve} <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                  <div className="text-muted-foreground">{f.reason}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
