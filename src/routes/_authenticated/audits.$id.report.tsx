import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ArrowLeft, Printer, ChevronDown, Siren, ShieldCheck, ShieldAlert, AlertOctagon, Check, X, AlertTriangle, Minus } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { EvidenceBlocks } from "@/components/evidence-blocks";
import { ExplainButton } from "@/components/explain-button";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import {
  computeSecurityScore,
  gradeTone,
  failuresBySeverity,
  estimateRemediationHours,
  launchRecommendation,
  type RiskBreakdown,
} from "@/lib/security-score";

export const Route = createFileRoute("/_authenticated/audits/$id/report")({
  head: () => ({ meta: [{ title: "Report — AuditKit" }] }),
  component: ReportPage,
});

function ReportPage() {
  const { id } = Route.useParams();

  const audit = useQuery({
    queryKey: ["audit", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, status, started_at, completed_at, summary, client:clients(name, contact_name, contact_email)")
        .eq("id", id).single();
      if (error) throw error;
      return data as any;
    },
  });

  const items = useQuery({
    queryKey: ["checklist-items"],
    queryFn: async () => {
      const { data } = await supabase
        .from("checklist_items")
        .select("id, category, title, description, severity, sort_order").eq("is_active", true)
        .order("sort_order");
      return data ?? [];
    },
  });

  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: async () => {
      const { data } = await supabase
        .from("audit_findings")
        .select("checklist_item_id, status, notes, explanation")
        .eq("audit_id", id);
      return data ?? [];
    },
  });

  const map = useMemo(() => {
    const m = new Map<string, { status: string | null; notes: string | null; explanation: string | null }>();
    findings.data?.forEach((f: any) => m.set(f.checklist_item_id, f));
    return m;
  }, [findings.data]);

  const grouped = useMemo(() => {
    if (!items.data) return [];
    const m = new Map<string, any[]>();
    items.data.forEach((it: any) => {
      const arr = m.get(it.category) ?? [];
      arr.push(it);
      m.set(it.category, arr);
    });
    return Array.from(m.entries());
  }, [items.data]);

  const totals = useMemo(() => {
    const t = { pass: 0, fail: 0, na: 0, unanswered: 0, total: items.data?.length ?? 0 };
    items.data?.forEach((it: any) => {
      const s = map.get(it.id)?.status;
      if (s === "pass") t.pass++;
      else if (s === "fail") t.fail++;
      else if (s === "na") t.na++;
      else t.unanswered++;
    });
    return t;
  }, [items.data, map]);

  const statusMap = useMemo(() => {
    const m = new Map<string, string | null | undefined>();
    map.forEach((v, k) => m.set(k, v.status));
    return m;
  }, [map]);

  const security = useMemo(
    () => computeSecurityScore((items.data ?? []) as any, statusMap as any),
    [items.data, statusMap],
  );
  const risk = useMemo(
    () => failuresBySeverity((items.data ?? []) as any, statusMap as any),
    [items.data, statusMap],
  );
  const effort = useMemo(() => estimateRemediationHours(risk), [risk]);
  const verdict = useMemo(() => launchRecommendation(security.score, risk), [security.score, risk]);

  const scopeSnapshot = useMemo(() => {
    return grouped.map(([cat, list]) => {
      let pass = 0, fail = 0, na = 0, unanswered = 0;
      list.forEach((it: any) => {
        const s = map.get(it.id)?.status;
        if (s === "pass") pass++;
        else if (s === "fail") fail++;
        else if (s === "na") na++;
        else unanswered++;
      });
      const status: "pass" | "warn" | "fail" =
        fail > 0 ? "fail" : unanswered > 0 ? "warn" : "pass";
      return { cat, status, pass, fail, na, unanswered, total: list.length };
    });
  }, [grouped, map]);

  return (
    <div className="space-y-6 print:space-y-4">
      <div className="flex items-center justify-between print:hidden">
        <Link to="/audits/$id" params={{ id }} className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4 mr-1" /> Back to audit
        </Link>
        <Button onClick={() => window.print()} className="bg-navy text-navy-foreground hover:bg-navy/90">
          <Printer className="h-4 w-4 mr-1" /> Print / Save PDF
        </Button>
      </div>

      <div className="bg-card border rounded-xl p-8 print:border-0 print:p-0">
        <header className="border-b pb-6 mb-6">
          <p className="text-xs uppercase tracking-widest text-muted-foreground">Security Audit Report</p>
          <h1 className="text-3xl font-semibold tracking-tight mt-1">{audit.data?.title}</h1>
          <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <Meta label="Client" value={audit.data?.client?.name} />
            <Meta label="Contact" value={audit.data?.client?.contact_name} />
            <Meta label="Started" value={audit.data?.started_at ? format(new Date(audit.data.started_at), "PP") : "—"} />
            <Meta label="Status" value={<span className="capitalize">{audit.data?.status?.replace("_", " ")}</span>} />
          </div>
        </header>

        <ExecutiveSummary
          score={security.score}
          grade={security.grade}
          risk={risk}
          effort={effort}
          verdict={verdict}
          totals={totals}
        />

        {grouped.map(([cat, list]) => (
          <section key={cat} className="mb-6 break-inside-avoid">
            <h2 className="text-lg font-semibold border-b pb-2 mb-3">{cat}</h2>
            <div className="space-y-3">
              {list.map((it: any) => {
                const f = map.get(it.id);
                if (f?.status === "fail") {
                  return (
                    <FailedFindingCard
                      key={it.id}
                      auditId={id}
                      item={it}
                      notes={f.notes}
                      explanation={f.explanation}
                    />
                  );
                }
                return (
                  <div key={it.id} className="border rounded-lg p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium">{it.title}</span>
                          <SeverityBadge severity={it.severity} />
                        </div>
                        {it.description && <p className="text-sm text-muted-foreground mt-1">{it.description}</p>}
                      </div>
                      <StatusPill status={f?.status} />
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        ))}
      </div>

      <style>{`
        @media print {
          header.bg-navy, nav, button { display: none !important; }
          body { background: white; }
        }
      `}</style>
    </div>
  );
}

function ExecutiveSummary({
  score, grade, risk, effort, verdict, totals,
}: {
  score: number | null;
  grade: "A" | "B" | "C" | "D" | "F" | "—";
  risk: RiskBreakdown;
  effort: { min: number; max: number };
  verdict: ReturnType<typeof launchRecommendation>;
  totals: { pass: number; fail: number; na: number; unanswered: number; total: number };
}) {
  const tone = gradeTone(grade);
  const scoreCls = {
    pass: "text-status-pass",
    warn: "text-status-na",
    fail: "text-status-fail",
    muted: "text-foreground",
  }[tone];
  const ringCls = {
    pass: "ring-status-pass/30 bg-status-pass/[0.06]",
    warn: "ring-status-na/30 bg-status-na/[0.06]",
    fail: "ring-status-fail/30 bg-status-fail/[0.06]",
    muted: "ring-border bg-muted/30",
  }[tone];
  const verdictTone =
    verdict.verdict === "go" ? "border-status-pass/50 bg-status-pass/[0.08] text-status-pass" :
    verdict.verdict === "fix-first" ? "border-status-na/50 bg-status-na/[0.08] text-status-na" :
    "border-status-fail/60 bg-status-fail/[0.08] text-status-fail";

  return (
    <section className="mb-8 space-y-4">
      <div className="flex items-baseline justify-between">
        <h2 className="text-lg font-semibold">Executive Security Summary</h2>
        <div className="text-xs text-muted-foreground">
          {totals.pass} pass · {totals.fail} fail · {totals.na} N/A · {totals.unanswered} unanswered
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1.4fr_2fr] gap-4">
        <div className={cn("rounded-xl ring-1 p-5 flex items-center gap-4", ringCls)}>
          <div className="flex flex-col items-center">
            <div className={cn("text-5xl font-semibold tabular-nums leading-none", scoreCls)}>
              {score ?? "—"}
            </div>
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-1">/ 100</div>
          </div>
          <div className="h-12 w-px bg-border" />
          <div>
            <div className={cn("font-mono text-3xl font-semibold leading-none", scoreCls)}>{grade}</div>
            <div className="text-xs uppercase tracking-wide text-muted-foreground mt-1">Overall grade</div>
          </div>
        </div>

        <div className={cn("rounded-xl border p-4 flex items-start gap-3", verdictTone)}>
          {verdict.verdict === "go" && <ShieldCheck className="h-6 w-6 shrink-0 mt-0.5" />}
          {verdict.verdict === "fix-first" && <ShieldAlert className="h-6 w-6 shrink-0 mt-0.5" />}
          {verdict.verdict === "block" && <AlertOctagon className="h-6 w-6 shrink-0 mt-0.5" />}
          <div>
            <div className="text-[10px] uppercase tracking-widest opacity-80">Launch Recommendation</div>
            <div className="font-semibold text-base mt-0.5">{verdict.label}</div>
            <div className="text-xs text-muted-foreground mt-1">{verdict.reason}</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <RiskTile label="Critical" count={risk.critical} cls="bg-status-fail/[0.08] border-status-fail/40 text-status-fail" />
        <RiskTile label="High" count={risk.high} cls="bg-orange-500/[0.08] border-orange-500/40 text-orange-600 dark:text-orange-400" />
        <RiskTile label="Medium" count={risk.medium} cls="bg-status-na/[0.08] border-status-na/40 text-status-na" />
        <RiskTile label="Low" count={risk.low} cls="bg-status-pass/[0.08] border-status-pass/40 text-status-pass" />
      </div>

      <div className="text-xs text-muted-foreground flex flex-wrap gap-x-4 gap-y-1">
        <span><span className="font-medium text-foreground">Estimated remediation effort:</span>{" "}
          {effort.max === 0 ? "—" : `${effort.min}–${effort.max} hours`}
        </span>
        <span className="opacity-70">Score is severity-weighted across rated items (Pass / Pass + Fail). N/A and unanswered items are excluded.</span>
      </div>
    </section>
  );
}

function RiskTile({ label, count, cls }: { label: string; count: number; cls: string }) {
  return (
    <div className={cn("rounded-lg border px-3 py-2 flex items-baseline justify-between", cls)}>
      <span className="text-xs font-semibold uppercase tracking-wide">{label}</span>
      <span className="text-xl font-semibold tabular-nums">{count}</span>
    </div>
  );
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: "Critical Risk",
  high: "High Risk",
  medium: "Medium Risk",
  low: "Low Risk",
};
const SEVERITY_BANNER: Record<string, string> = {
  critical: "bg-status-fail/15 text-status-fail border-status-fail/40",
  high: "bg-orange-500/15 text-orange-600 dark:text-orange-300 border-orange-500/40",
  medium: "bg-status-na/15 text-status-na border-status-na/40",
  low: "bg-status-pass/15 text-status-pass border-status-pass/40",
};
const SEVERITY_LIKELIHOOD: Record<string, string> = {
  critical: "High",
  high: "High",
  medium: "Medium",
  low: "Low",
};
const SEVERITY_IMPACT: Record<string, string> = {
  critical: "Severe",
  high: "High",
  medium: "Medium",
  low: "Low",
};

function FailedFindingCard({
  auditId, item, notes, explanation,
}: {
  auditId: string;
  item: any;
  notes: string | null;
  explanation: string | null;
}) {
  const [open, setOpen] = useState(false);
  const [exp, setExp] = useState<string | null>(explanation);
  const sev = (item.severity ?? "medium").toLowerCase();
  const bannerCls = SEVERITY_BANNER[sev] ?? SEVERITY_BANNER.medium;
  const label = SEVERITY_LABEL[sev] ?? "Risk";

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <Card className={cn("border-l-4 overflow-hidden", "border-l-status-fail")}>
        <CollapsibleTrigger asChild>
          <button
            type="button"
            className={cn(
              "w-full text-left px-4 py-3 flex items-center gap-3 border-b transition-colors",
              bannerCls,
              "hover:brightness-105",
            )}
          >
            <Siren className="h-5 w-5 shrink-0" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] font-bold uppercase tracking-widest">{label}</span>
                <span className="text-[10px] uppercase tracking-widest opacity-70">· Auto detected</span>
              </div>
              <div className="font-semibold text-foreground mt-0.5 truncate">{item.title}</div>
            </div>
            <ChevronDown className={cn("h-4 w-4 shrink-0 transition-transform text-foreground/70", open && "rotate-180")} />
          </button>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <div className="p-4 space-y-4">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={item.severity} />
              <span className="text-xs text-muted-foreground">{item.category}</span>
              <div className="ml-auto print:hidden">
                <ExplainButton
                  auditId={auditId}
                  checklistItemId={item.id}
                  cached={exp}
                  onCached={setExp}
                />
              </div>
            </div>

            <DetailRow label="Why should I care?">
              {exp ? (
                <ul className="border-l-2 border-amber-500/40 pl-3 space-y-1.5 text-sm">
                  {exp.split("\n").map((l) => l.trim()).filter(Boolean).map((l, i) => (
                    <li key={i}>{l.replace(/^[-*•]\s*/, "")}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">
                  {item.description ?? "Click Explain to generate a plain-English summary."}
                </p>
              )}
            </DetailRow>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <Stat label="Risk" value={label.replace(" Risk", "")} />
              <Stat label="Likelihood" value={SEVERITY_LIKELIHOOD[sev] ?? "Medium"} />
              <Stat label="Business Impact" value={SEVERITY_IMPACT[sev] ?? "Medium"} />
            </div>

            {notes && (
              <DetailRow label="Evidence">
                <EvidenceBlocks notes={notes} />
              </DetailRow>
            )}
          </div>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground mb-1.5">{label}</div>
      {children}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border bg-muted/30 px-3 py-2">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="font-semibold mt-0.5">{value}</div>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="font-medium">{value || "—"}</div>
    </div>
  );
}

function StatusPill({ status }: { status: string | null | undefined }) {
  if (!status) return <span className="text-xs text-muted-foreground">—</span>;
  const cls = {
    pass: "bg-status-pass/15 text-status-pass border-status-pass/40",
    fail: "bg-status-fail/15 text-status-fail border-status-fail/40",
    na: "bg-status-na/15 text-status-na border-status-na/40",
  }[status] ?? "";
  return (
    <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold uppercase", cls)}>
      {status}
    </span>
  );
}
