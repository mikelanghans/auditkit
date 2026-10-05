import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useMemo, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Download, Copy, Check, RefreshCw, Wand2, Loader2, ListChecks } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { generateRemediationSteps } from "@/lib/remediation-steps.functions";
import { SeverityBadge } from "@/components/severity-badge";
import { FixPromptButton } from "@/components/fix-prompt-dialog";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { resolveFinding } from "@/lib/finding-resolution.functions";
import { generateFixPrompt } from "@/lib/fix-prompt.functions";
import { todayLocal, REMEDIATION_LABEL } from "@/lib/finding-lifecycle";
import { buildFixPlan, fixPlanMarkdown, TOOL_LABEL, type FixTool } from "@/lib/fix-plan";

export const Route = createFileRoute("/_authenticated/audits/$id/fixes")({
  head: () => ({ meta: [{ title: "Fix plan — AuditKit" }] }),
  component: FixPlanPage,
});

const PROMPT_COL: Record<FixTool, "lovable_prompt" | "cursor_prompt" | "claude_prompt"> = {
  lovable: "lovable_prompt",
  cursor: "cursor_prompt",
  claude: "claude_prompt",
};

function FixPlanPage() {
  const { id } = Route.useParams();
  const qc = useQueryClient();
  const resolve = useServerFn(resolveFinding);
  const gen = useServerFn(generateFixPrompt);
  const genSteps = useServerFn(generateRemediationSteps);
  const [tool, setTool] = useState<FixTool>("lovable");
  const [retesting, setRetesting] = useState<string | null>(null);
  const [filling, setFilling] = useState<{ done: number; total: number } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [generatingSteps, setGeneratingSteps] = useState(false);
  const [steps, setSteps] = useState<Record<string, { ok: boolean; text: string }>>({});

  const audit = useQuery({
    queryKey: ["audit", id, "fixes"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, client:clients(name, has_agentic_features, uses_ai_features)")
        .eq("id", id).single();
      if (error) throw error;
      return data as any;
    },
  });
  const hasAgentic = !!audit.data?.client?.has_agentic_features;
  const usesAi = !!audit.data?.client?.uses_ai_features;

  const items = useQuery({
    queryKey: ["checklist-items", { hasAgentic, usesAi }, "fixes"],
    enabled: !!audit.data,
    queryFn: async () => {
      const { data } = await supabase
        .from("checklist_items")
        .select("id, category, title, description, severity, sort_order").eq("is_active", true)
        .order("sort_order");
      return (data ?? []).filter((it: any) =>
        !(it.category === "Agentic AI Security" && !hasAgentic) && !(it.category === "AI Service Continuity" && !usesAi));
    },
  });

  const findingsKey = ["findings", id, "fixes"];
  const findings = useQuery({
    queryKey: findingsKey,
    queryFn: async () => {
      const { data } = await supabase
        .from("audit_findings")
        .select("checklist_item_id, status, explanation, auto_scanned, lovable_prompt, cursor_prompt, claude_prompt, risk_accepted_reason, risk_accepted_by, risk_accepted_at, risk_accepted_until, severity_override, severity_override_reason, remediation_owner, remediation_due, remediation_status")
        .eq("audit_id", id);
      return data ?? [];
    },
  });

  const map = useMemo(() => new Map((findings.data ?? []).map((f: any) => [f.checklist_item_id as string, f])), [findings.data]);
  const today = todayLocal();
  const plan = useMemo(() => buildFixPlan((items.data ?? []) as any, map as any, tool, today), [items.data, map, tool, today]);
  const missing = plan.filter((p) => !p.prompt).length;

  const setPrompt = (itemId: string, target: FixTool, prompt: string) => {
    qc.setQueryData<any[]>(findingsKey, (prev) =>
      (prev ?? []).map((f) => (f.checklist_item_id === itemId ? { ...f, [PROMPT_COL[target]]: prompt } : f)));
  };

  const fillMissing = async () => {
    const todo = plan.filter((p) => !p.prompt);
    setFilling({ done: 0, total: todo.length });
    let failed = 0;
    for (const [i, p] of todo.entries()) {
      try {
        const res: any = await gen({ data: { auditId: id, checklistItemId: p.id, target: tool } as any });
        if (res.ok) setPrompt(p.id, tool, res.prompt);
        else failed++;
      } catch {
        failed++;
      }
      setFilling({ done: i + 1, total: todo.length });
    }
    setFilling(null);
    if (failed) toast.error(`${failed} prompt(s) couldn't be generated. Try those one at a time.`);
    else toast.success("All prompts ready");
  };

  const toggle = (itemId: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(itemId)) next.delete(itemId);
      else if (next.size >= 10) toast.error("Select up to 10 findings at a time.");
      else next.add(itemId);
      return next;
    });

  const runSteps = async () => {
    setGeneratingSteps(true);
    try {
      const res: any = await genSteps({ data: { auditId: id, checklistItemIds: [...selected] } });
      if (!res.ok) { toast.error(res.error); return; }
      const next: Record<string, { ok: boolean; text: string }> = {};
      for (const r of res.results) next[r.checklistItemId] = r.ok ? { ok: true, text: r.steps } : { ok: false, text: r.error };
      setSteps((prev) => ({ ...prev, ...next }));
      const failed = res.results.filter((r: any) => !r.ok).length;
      if (failed) toast.error(`${failed} finding(s) couldn't get steps.`);
      else toast.success("Remediation steps ready");
      setSelected(new Set());
    } catch (e: any) {
      toast.error(e?.message ?? "Could not generate remediation steps");
    } finally {
      setGeneratingSteps(false);
    }
  };

  const retest = async (itemId: string) => {
    setRetesting(itemId);
    try {
      const res: any = await resolve({ data: { auditId: id, checklistItemId: itemId, mode: "automated" } });
      if (res.ok) toast.success(res.alreadyResolved ? "Already resolved" : "Fixed — re-scan passed");
      else toast.error(res.reason ?? "Still failing");
      await qc.invalidateQueries({ queryKey: findingsKey });
      await qc.invalidateQueries({ queryKey: ["findings", id] });
    } catch (e: any) {
      toast.error(e?.message ?? "Re-test failed");
    } finally {
      setRetesting(null);
    }
  };

  const markdown = () =>
    fixPlanMarkdown(plan, {
      audit: audit.data?.title ?? "Audit",
      client: audit.data?.client?.name ?? null,
      tool,
      generatedAt: new Date().toISOString(),
    });

  const download = () => {
    const blob = new Blob([markdown()], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    const slug = (audit.data?.title ?? "audit").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 50);
    a.download = `fix-plan-${slug}-${tool}.md`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };

  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      toast.error("Couldn't copy");
    }
  };

  const loading = audit.isLoading || items.isLoading || findings.isLoading;

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <Link to="/audits/$id/report" params={{ id }} className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4 mr-1" /> Back to report
        </Link>
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="outline" disabled={!plan.length} onClick={() => copy("all", markdown())}>
            {copied === "all" ? <Check className="h-4 w-4 mr-1" /> : <Copy className="h-4 w-4 mr-1" />} Copy Markdown
          </Button>
          <Button disabled={!plan.length} onClick={download}>
            <Download className="h-4 w-4 mr-1" /> Download .md
          </Button>
        </div>
      </div>

      <div>
        <h1 className="text-2xl font-semibold">Fix plan</h1>
        <p className="text-sm text-muted-foreground">
          {audit.data?.title}{audit.data?.client?.name ? ` · ${audit.data.client.name}` : ""}. Open issues, most urgent first, each with a prompt for the client's coding tool. Prompts are AI-written starting points; an issue is only fixed when its re-test passes. Accepted risks are left out.
        </p>
      </div>

      <Card className="p-4 flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Client builds with</span>
          <div className="inline-flex rounded-md border p-0.5" role="radiogroup" aria-label="Coding tool">
            {(Object.keys(TOOL_LABEL) as FixTool[]).map((t) => (
              <button
                key={t}
                role="radio"
                aria-checked={tool === t}
                onClick={() => setTool(t)}
                className={cn("px-3 py-1 text-sm rounded", tool === t ? "bg-primary text-primary-foreground" : "hover:bg-muted")}
              >
                {TOOL_LABEL[t]}
              </button>
            ))}
          </div>
        </div>
        {missing > 0 && (
          <Button variant="outline" size="sm" disabled={!!filling} onClick={fillMissing}>
            {filling ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Wand2 className="h-4 w-4 mr-1" />}
            {filling ? `Generating ${filling.done}/${filling.total}…` : `Generate ${missing} missing prompt${missing === 1 ? "" : "s"}`}
          </Button>
        )}
      </Card>

      {plan.length > 0 && (
        <Card className="p-4 flex items-center justify-between flex-wrap gap-3">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={selected.size > 0 && selected.size === plan.length ? true : selected.size > 0 ? "indeterminate" : false}
              onCheckedChange={(v) => setSelected(v === true ? new Set(plan.slice(0, 10).map((p) => p.id)) : new Set())}
              aria-label="Select all findings"
            />
            {selected.size ? `${selected.size} selected` : "Select findings for AI remediation steps (up to 10)"}
          </label>
          <Button size="sm" disabled={!selected.size || generatingSteps} onClick={runSteps}>
            {generatingSteps ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <ListChecks className="h-4 w-4 mr-1" />}
            {generatingSteps ? "Writing steps…" : "Generate remediation steps"}
          </Button>
        </Card>
      )}

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : !plan.length ? (
        <Card className="p-6 text-sm text-muted-foreground">No open issues. Nothing to hand off.</Card>
      ) : (
        <ol className="space-y-3">
          {plan.map((p, i) => (
            <li key={p.id}>
              <Card className="p-4 space-y-3">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Checkbox
                        checked={selected.has(p.id)}
                        onCheckedChange={() => toggle(p.id)}
                        aria-label={`Select ${p.title}`}
                      />
                      <span className="text-sm font-mono text-muted-foreground">{i + 1}.</span>
                      <span className="font-medium">{p.title}</span>
                      <SeverityBadge severity={p.severity} />
                    </div>
                    <div className="text-xs text-muted-foreground flex items-center gap-2 flex-wrap">
                      <span>{p.category}</span>
                      {p.owner && <span>· Owner: {p.owner}</span>}
                      {p.due && <span className={cn(p.overdue && "text-destructive font-medium")}>· Due {p.due}{p.overdue ? " (overdue)" : ""}</span>}
                      {p.remediation && <Badge variant="outline" className="text-xs">{REMEDIATION_LABEL[p.remediation] ?? p.remediation}</Badge>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <FixPromptButton
                      auditId={id}
                      checklistItemId={p.id}
                      cached={{
                        lovable: (map.get(p.id) as any)?.lovable_prompt ?? null,
                        cursor: (map.get(p.id) as any)?.cursor_prompt ?? null,
                        claude: (map.get(p.id) as any)?.claude_prompt ?? null,
                      }}
                      onCached={(target, prompt) => setPrompt(p.id, target as FixTool, prompt)}
                    />
                    {p.autoChecked && (
                      <Button size="sm" variant="outline" disabled={retesting === p.id} onClick={() => retest(p.id)}>
                        {retesting === p.id ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-1" />} Re-test
                      </Button>
                    )}
                  </div>
                </div>
                {p.why && <p className="text-sm text-muted-foreground whitespace-pre-line">{p.why}</p>}
                {steps[p.id] && (
                  <div className="rounded-md border border-primary/30 bg-primary/5 p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium uppercase tracking-wide text-primary flex items-center gap-1">
                        <ListChecks className="h-3.5 w-3.5" /> AI remediation steps
                      </span>
                      {steps[p.id].ok && (
                        <Button size="icon" variant="ghost" className="h-7 w-7" aria-label="Copy steps" onClick={() => copy(`s-${p.id}`, steps[p.id].text)}>
                          {copied === `s-${p.id}` ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                        </Button>
                      )}
                    </div>
                    <div className={cn("text-sm whitespace-pre-wrap", !steps[p.id].ok && "text-destructive")}>{steps[p.id].text}</div>
                  </div>
                )}
                {p.prompt ? (
                  <div className="relative">
                    <pre className="text-xs bg-muted rounded p-3 pr-12 whitespace-pre-wrap max-h-48 overflow-auto">{p.prompt}</pre>
                    <Button size="icon" variant="ghost" className="absolute top-1 right-1 h-8 w-8" aria-label="Copy prompt" onClick={() => copy(p.id, p.prompt!)}>
                      {copied === p.id ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                    </Button>
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground italic">No {TOOL_LABEL[tool]} prompt yet.</p>
                )}
              </Card>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
