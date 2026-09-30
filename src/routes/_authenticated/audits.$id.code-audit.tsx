import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useMemo, useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { ArrowLeft, Download, FileSearch, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { startCodeAudit, mapCodeAuditFinding, stopCodeAudit } from "@/lib/code-audit.functions";
import { CodeAuditProgress } from "@/components/code-audit-progress";
import { PROFILE_BUDGETS, type CodeAuditProfile } from "@/lib/code-audit-contract";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/audits/$id/code-audit")({
  head: () => ({ meta: [{ title: "Deep code audit — AuditKit" }] }),
  component: CodeAuditPage,
});

const PROFILE_HELP: Record<CodeAuditProfile, string> = {
  quick: "One hunting wave. Small repos, re-checks, retainer months.",
  standard: "Full workflow. The default for a SHIELD audit.",
  deep: "Per-subsystem coverage for high-stakes clients.",
};

const SEV_STYLE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-slate-200 text-slate-800",
  informational: "bg-slate-100 text-slate-700",
};

const RUN_TONE: Record<string, string> = {
  queued: "bg-muted text-foreground",
  dispatching: "bg-muted text-foreground",
  running: "bg-primary/15 text-primary",
  done: "bg-status-pass/15 text-status-pass",
  incomplete: "bg-status-warn/15 text-status-warn",
  failed: "bg-status-fail/15 text-status-fail",
  cancelled: "bg-muted text-muted-foreground",
};

type ReviewPatch = {
  review_state?: string;
  include_in_report?: boolean;
  reviewer_note?: string | null;
};

type Run = {
  id: string;
  created_at: string;
  repo_url: string;
  git_ref: string | null;
  profile: string;
  budget_agents: number;
  status: string;
  error: string | null;
  started_at: string | null;
  progress: any;
  progress_at: string | null;
  source_commit: string | null;
  agents_used: number | null;
  incomplete_reason: string | null;
  coverage: any;
  report_md: string | null;
  findings_detail_md: string | null;
  needs_validation_md: string | null;
  confirmed_count: number;
  needs_validation_count: number;
  rejected_count: number;
};

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function CodeAuditPage() {
  const { id } = Route.useParams();
  const qc = useQueryClient();
  const start = useServerFn(startCodeAudit);

  const runs = useQuery({
    queryKey: ["code-audit-runs", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("code_audit_runs")
        .select("*")
        .eq("audit_id", id)
        .order("created_at", { ascending: false })
        .limit(20);
      if (error) throw error;
      return (data ?? []) as Run[];
    },
    // Poll while a run is in flight.
    refetchInterval: (q) =>
      ((q.state.data as Run[] | undefined) ?? []).some((r) =>
        ["queued", "dispatching", "running"].includes(r.status),
      )
        ? 10_000
        : false,
  });

  const stop = useServerFn(stopCodeAudit);
  const [stoppingId, setStoppingId] = useState<string | null>(null);
  async function onStop(runId: string) {
    setStoppingId(runId);
    try {
      const res = await stop({ data: { runId } });
      if (!res.ok) toast.error(res.error);
      else toast.success("Run stopped.");
      await qc.invalidateQueries({ queryKey: ["code-audit-runs", id] });
    } catch (e: any) {
      toast.error(e?.message ?? "Could not stop the run.");
    } finally {
      setStoppingId(null);
    }
  }

  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const finishedRuns = (runs.data ?? []).filter(
    (r) => r.status === "done" || r.status === "incomplete",
  );
  const run = (runs.data ?? []).find((r) => r.id === selectedRunId) ?? finishedRuns[0] ?? null;

  const [repoUrl, setRepoUrl] = useState("");
  const [gitRef, setGitRef] = useState("");
  const [token, setToken] = useState("");
  const [profile, setProfile] = useState<CodeAuditProfile>("standard");
  const [consent, setConsent] = useState(false);
  const [starting, setStarting] = useState(false);

  async function onStart(e: React.FormEvent) {
    e.preventDefault();
    setStarting(true);
    try {
      const res = await start({
        data: { auditId: id, repoUrl, gitRef, token, profile, clientConsent: consent },
      });
      if (!res.ok) return toast.error(res.error);
      toast.success(
        "Deep code audit queued. It usually takes 30–90 minutes; this page updates on its own.",
      );
      setToken("");
      qc.invalidateQueries({ queryKey: ["code-audit-runs", id] });
    } catch (err: any) {
      toast.error(err?.message ?? "Could not start the audit.");
    } finally {
      setStarting(false);
    }
  }

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">
      <div>
        <Link
          to="/audits/$id"
          params={{ id }}
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4 mr-1" /> Back to audit
        </Link>
        <h1 className="mt-2 text-2xl font-bold flex items-center gap-2">
          <FileSearch className="h-6 w-6" /> Deep code audit
        </h1>
        <p className="text-sm text-muted-foreground max-w-3xl">
          Runs Cloudflare&apos;s security-audit workflow over the client&apos;s repository in an
          isolated runner: dozens of Claude agents hunt, then independent verifiers confirm or
          reject each candidate. Confirmed findings can mark checklist items as failing. Finding
          nothing never marks anything as passing.
        </p>
      </div>

      <Card className="p-5">
        <form onSubmit={onStart} className="grid gap-4 md:grid-cols-2">
          <div className="space-y-1.5 md:col-span-2">
            <Label htmlFor="repo">GitHub repository</Label>
            <Input
              id="repo"
              placeholder="https://github.com/owner/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ref">Branch, tag or commit (optional)</Label>
            <Input
              id="ref"
              placeholder="default branch"
              value={gitRef}
              onChange={(e) => setGitRef(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="tok">GitHub token (private repos)</Label>
            <Input
              id="tok"
              type="password"
              autoComplete="off"
              placeholder="read-only fine-grained token"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
            <p className="text-[11px] text-muted-foreground">
              Used once to clone, encrypted in transit to the runner, never stored.
            </p>
          </div>
          <div className="space-y-1.5 md:col-span-2">
            <Label>Profile</Label>
            <div className="grid gap-2 sm:grid-cols-3">
              {(Object.keys(PROFILE_BUDGETS) as CodeAuditProfile[]).map((p) => (
                <button
                  type="button"
                  key={p}
                  onClick={() => setProfile(p)}
                  className={cn(
                    "text-left rounded-md border p-3 text-sm transition-colors",
                    profile === p ? "border-primary bg-primary/5" : "hover:bg-muted/50",
                  )}
                >
                  <div className="font-medium capitalize">{p}</div>
                  <div className="text-xs text-muted-foreground">
                    Up to {PROFILE_BUDGETS[p]} agents
                  </div>
                  <div className="text-xs mt-1">{PROFILE_HELP[p]}</div>
                </button>
              ))}
            </div>
          </div>
          <label className="flex items-start gap-2 text-sm md:col-span-2">
            <Checkbox
              checked={consent}
              onCheckedChange={(v) => setConsent(v === true)}
              className="mt-0.5"
            />
            <span>
              The client has agreed, in the engagement letter, to their source code being analysed
              with Anthropic&apos;s API.
            </span>
          </label>
          <div className="md:col-span-2">
            <Button
              type="submit"
              disabled={starting || !repoUrl || !consent}
              className="bg-navy text-navy-foreground hover:bg-navy/90"
            >
              {starting ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null} Start deep audit
            </Button>
          </div>
        </form>
      </Card>

      {(runs.data ?? []).length > 0 && (
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-2 border-b text-xs uppercase tracking-wide text-muted-foreground">
            Runs
          </div>
          <ul className="divide-y">
            {(runs.data ?? []).map((r) => (
              <li key={r.id}>
                <button
                  type="button"
                  onClick={() => setSelectedRunId(r.id)}
                  className={cn(
                    "w-full text-left px-4 py-3 text-sm flex flex-wrap items-center gap-3 hover:bg-muted/40",
                    run?.id === r.id && "bg-muted/60",
                  )}
                >
                  <span
                    className={cn(
                      "rounded px-2 py-0.5 text-xs font-medium capitalize",
                      RUN_TONE[r.status],
                    )}
                  >
                    {r.status}
                  </span>
                  <span className="font-mono text-xs">
                    {r.repo_url.replace("https://github.com/", "")}
                  </span>
                  <span className="text-xs text-muted-foreground capitalize">{r.profile}</span>
                  <span className="text-xs text-muted-foreground">
                    {formatDistanceToNow(new Date(r.created_at), { addSuffix: true })}
                  </span>
                  {(r.status === "done" || r.status === "incomplete") && (
                    <span className="text-xs ml-auto">
                      {r.confirmed_count} confirmed · {r.needs_validation_count} to validate
                    </span>
                  )}
                  {r.status === "failed" && r.error && (
                    <span className="text-xs text-status-fail basis-full whitespace-pre-wrap break-words select-text">
                      {r.error}
                    </span>
                  )}
                </button>
                {["queued", "dispatching", "running"].includes(r.status) && (
                  <div className="px-4 pb-4">
                    <CodeAuditProgress run={r} onStop={() => onStop(r.id)} stopping={stoppingId === r.id} />
                  </div>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {run && <RunDetail run={run} auditId={id} />}
    </div>
  );
}

function RunDetail({ run, auditId }: { run: Run; auditId: string }) {
  const qc = useQueryClient();
  const mapFn = useServerFn(mapCodeAuditFinding);

  const findings = useQuery({
    queryKey: ["code-audit-findings", run.id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("code_audit_findings")
        .select("*")
        .eq("run_id", run.id)
        .order("created_at", { ascending: true });
      if (error) throw error;
      return data ?? [];
    },
  });

  const checklist = useQuery({
    queryKey: ["checklist-items-all"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("checklist_items")
        .select("id, title, category")
        .eq("is_active", true)
        .order("category");
      if (error) throw error;
      return data ?? [];
    },
  });

  const groups = useMemo(() => {
    const rows = findings.data ?? [];
    const sevRank: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      informational: 4,
    };
    const sorted = [...rows].sort(
      (a, b) => (sevRank[a.severity ?? ""] ?? 9) - (sevRank[b.severity ?? ""] ?? 9),
    );
    return {
      confirmed: sorted.filter((f) => f.verdict === "confirmed"),
      needs_validation: sorted.filter((f) => f.verdict === "needs_validation"),
      rejected: sorted.filter((f) => f.verdict === "rejected"),
    };
  }, [findings.data]);

  async function update(fid: string, patch: ReviewPatch) {
    const { error } = await supabase.from("code_audit_findings").update(patch).eq("id", fid);
    if (error) return toast.error(error.message);
    qc.invalidateQueries({ queryKey: ["code-audit-findings", run.id] });
  }

  async function mapTo(fid: string, checklistItemId: string) {
    if (!checklistItemId) return;
    const res = await mapFn({ data: { findingId: fid, checklistItemId } });
    if (!res.ok) return toast.error(res.error);
    toast.success(res.message);
    qc.invalidateQueries({ queryKey: ["code-audit-findings", run.id] });
    qc.invalidateQueries({ queryKey: ["findings", auditId] });
  }

  const cov = run.coverage as {
    total?: number;
    byStatus?: Record<string, number>;
    units?: any[];
  } | null;

  return (
    <div className="space-y-4">
      <Card className="p-4 space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-medium">
            Run on{" "}
            {run.source_commit ? <code>{run.source_commit.slice(0, 10)}</code> : "unknown commit"}
          </span>
          <span className="text-muted-foreground">
            · {run.agents_used ?? "?"} of {run.budget_agents} agents used
          </span>
          <div className="ml-auto flex gap-2">
            {run.report_md && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => download("REPORT.md", run.report_md!)}
              >
                <Download className="h-3.5 w-3.5 mr-1" /> REPORT.md
              </Button>
            )}
            {run.findings_detail_md && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => download("FINDINGS-DETAIL.md", run.findings_detail_md!)}
              >
                <Download className="h-3.5 w-3.5 mr-1" /> FINDINGS-DETAIL.md
              </Button>
            )}
          </div>
        </div>
        {run.status === "incomplete" && (
          <div className="rounded-md border border-status-warn/40 bg-status-warn/10 p-2 text-sm">
            This run is incomplete ({run.incomplete_reason}). It is partial coverage, not a clean
            result.
          </div>
        )}
        {cov && (
          <Collapsible>
            <CollapsibleTrigger className="text-sm text-muted-foreground hover:text-foreground">
              What was reviewed: {cov.total} coverage unit(s)
              {cov.byStatus
                ? ` (${Object.entries(cov.byStatus)
                    .map(([k, v]) => `${v} ${k}`)
                    .join(", ")})`
                : ""}{" "}
              ▾
            </CollapsibleTrigger>
            <CollapsibleContent>
              <ul className="mt-2 space-y-1 text-xs">
                {(cov.units ?? []).map((u, i) => (
                  <li key={i} className="flex gap-2">
                    <Badge variant="outline" className="text-[10px] capitalize">
                      {u.status}
                    </Badge>
                    <span>
                      <span className="font-medium">{u.surface}</span> — {u.attack_class}
                    </span>
                  </li>
                ))}
              </ul>
            </CollapsibleContent>
          </Collapsible>
        )}
      </Card>

      <FindingGroup
        title="Confirmed"
        hint="Verified by independent agents. Map each to a checklist item to record it as a failure."
        rows={groups.confirmed}
        checklist={checklist.data ?? []}
        onUpdate={update}
        onMap={mapTo}
        defaultOpen
      />
      <FindingGroup
        title="Needs validation"
        hint="Real in source, but blocked on a fact the runner couldn't establish (deployment settings, provider behaviour). Run the owner check with the client."
        rows={groups.needs_validation}
        checklist={checklist.data ?? []}
        onUpdate={update}
        defaultOpen
      />
      {groups.rejected.length > 0 && (
        <FindingGroup
          title="Rejected"
          hint="Candidates the verifiers disproved."
          rows={groups.rejected}
          checklist={[]}
          onUpdate={update}
        />
      )}
    </div>
  );
}

function Pre({ value }: { value: unknown }) {
  if (value == null) return null;
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return (
    <pre className="text-xs whitespace-pre-wrap bg-muted rounded p-2 max-h-72 overflow-auto">
      {text}
    </pre>
  );
}

function FindingGroup({
  title,
  hint,
  rows,
  checklist,
  onUpdate,
  onMap,
  defaultOpen,
}: {
  title: string;
  hint: string;
  rows: any[];
  checklist: { id: string; title: string; category: string }[];
  onUpdate: (id: string, patch: ReviewPatch) => void;
  onMap?: (id: string, checklistItemId: string) => void;
  defaultOpen?: boolean;
}) {
  return (
    <Collapsible defaultOpen={defaultOpen}>
      <CollapsibleTrigger className="w-full text-left">
        <h2 className="text-lg font-semibold">
          {title} <span className="text-muted-foreground font-normal">({rows.length})</span>
        </h2>
        <p className="text-xs text-muted-foreground">{hint}</p>
      </CollapsibleTrigger>
      <CollapsibleContent className="mt-3 space-y-3">
        {rows.length === 0 && <p className="text-sm text-muted-foreground">None.</p>}
        {rows.map((f) => (
          <Card
            key={f.id}
            className={cn("p-4 space-y-2", f.review_state === "dismissed" && "opacity-60")}
          >
            <div className="flex items-start gap-2 flex-wrap">
              {f.severity && (
                <span
                  className={cn(
                    "rounded px-2 py-0.5 text-xs font-semibold capitalize",
                    SEV_STYLE[f.severity] ?? "",
                  )}
                >
                  {f.severity}
                </span>
              )}
              <span className="font-medium flex-1 min-w-[240px]">{f.title}</span>
            </div>
            {f.description && <p className="text-sm whitespace-pre-wrap">{f.description}</p>}
            <Collapsible>
              <CollapsibleTrigger className="text-xs text-primary hover:underline">
                Root cause, trace, evidence and fix ▾
              </CollapsibleTrigger>
              <CollapsibleContent className="mt-2 space-y-2">
                {f.root_cause && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                      Root cause
                    </div>
                    <p className="text-sm whitespace-pre-wrap">{f.root_cause}</p>
                  </div>
                )}
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    Trace
                  </div>
                  <Pre value={f.trace} />
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    Evidence
                  </div>
                  <Pre value={f.evidence} />
                </div>
                {f.remediation && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                      Fix
                    </div>
                    <Pre value={f.remediation} />
                  </div>
                )}
                {f.blockers && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                      Blocked on
                    </div>
                    <Pre value={f.blockers} />
                  </div>
                )}
                {f.validation_plan && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                      Validation plan (owner check)
                    </div>
                    <Pre value={f.validation_plan} />
                  </div>
                )}
              </CollapsibleContent>
            </Collapsible>
            <div className="flex flex-wrap items-center gap-3 pt-1 text-sm">
              <label className="flex items-center gap-1.5">
                <Checkbox
                  checked={f.include_in_report}
                  onCheckedChange={(v) => onUpdate(f.id, { include_in_report: v === true })}
                />
                Include in report
              </label>
              {onMap && (
                <select
                  className="rounded-md border bg-background px-2 py-1 text-sm max-w-xs"
                  value={f.checklist_item_id ?? ""}
                  onChange={(e) => onMap(f.id, e.target.value)}
                >
                  <option value="">Map to checklist item (marks it failing)…</option>
                  {checklist.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.category} — {c.title}
                    </option>
                  ))}
                </select>
              )}
              <select
                className="rounded-md border bg-background px-2 py-1 text-sm"
                value={f.review_state}
                onChange={(e) => onUpdate(f.id, { review_state: e.target.value })}
              >
                <option value="pending">Pending review</option>
                <option value="accepted">Accepted</option>
                <option value="dismissed">Dismissed</option>
              </select>
            </div>
          </Card>
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
}
