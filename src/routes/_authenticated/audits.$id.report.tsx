import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useMemo, useRef, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ArrowLeft, Printer, Download, ChevronDown, ShieldCheck, ShieldAlert, AlertOctagon, Check, X, AlertTriangle, Minus, Brain, CheckCircle2, RefreshCw, ExternalLink, Wrench } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { EvidenceBlocks } from "@/components/evidence-blocks";
import { explanationBullets, useFindingExplanation } from "@/components/explain-button";
import { format } from "date-fns";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { listResolvedFindings } from "@/lib/finding-resolution.functions";
import {
  useReportExtras,
  SummarySection,
  ScopeMethodSection,
  RetestSection,
  EvidenceRefs,
  ReportAppendix,
  ExportButtons,
  FrameworkSection,
  ControlTags,
  LinkedCodeFindings,
} from "@/components/report-extras";
import {
  summarizeMethod,
  retestComparison,
  buildEvidenceIndex,
  summarizeFrameworks,
  controlLabel,
  type EvidenceRef,
  type ReportModel,
} from "@/lib/report-model";
import { logReportExport } from "@/hooks/use-audit-trail";
import { lifecycleOf, todayLocal, REMEDIATION_LABEL, type Lifecycle, type LifecycleFields } from "@/lib/finding-lifecycle";
import {
  computeSecurityScore,
  gradeTone,
  failuresBySeverity,
  estimateRemediationHours,
  launchRecommendation,
  computeCoverage,
  type Coverage,
  type RiskBreakdown,
} from "@/lib/security-score";


export const Route = createFileRoute("/_authenticated/audits/$id/report")({
  head: () => ({ meta: [{ title: "Report — AuditKit" }] }),
  component: ReportPage,
});

async function downloadReportPdf(el: HTMLElement | null, filename: string, win?: Window | null) {
  if (!el) return;
  const [{ default: html2canvas }, { default: jsPDF }] = await Promise.all([
    import("html2canvas-pro"),
    import("jspdf"),
  ]);
  const pdf = new jsPDF({ orientation: "portrait", unit: "pt", format: "letter" });
  const margin = 24;
  const pageW = pdf.internal.pageSize.getWidth() - margin * 2;
  const pageH = pdf.internal.pageSize.getHeight() - margin * 2;

  // Render one page-sized strip at a time. A single canvas of the whole report is
  // far larger than Safari/iOS allow, which makes the download silently fail.
  // html2canvas-pro treats x/y as offsets relative to the element itself.
  const elW = el.scrollWidth;
  const elH = el.scrollHeight;
  const cssPxPerPt = elW / pageW;
  const chunkH = Math.floor(pageH * cssPxPerPt);
  const scale = Math.min(2, Math.sqrt(12_000_000 / (elW * chunkH)));

  let offset = 0;
  let first = true;
  while (offset < elH) {
    const h = Math.min(chunkH, elH - offset);
    const canvas = await html2canvas(el, {
      scale,
      useCORS: true,
      backgroundColor: "#ffffff",
      x: 0,
      y: offset,
      width: elW,
      height: h,
      logging: false,
      ignoreElements: (node) => node.classList?.contains("print:hidden"),
    });
    if (!first) pdf.addPage();
    pdf.addImage(canvas.toDataURL("image/jpeg", 0.9), "JPEG", margin, margin, pageW, h / cssPxPerPt);
    canvas.width = 0;
    canvas.height = 0;
    first = false;
    offset += h;
  }
  const blob = pdf.output("blob");
  const url = URL.createObjectURL(blob);
  if (win && !win.closed) {
    // Embedded previews block downloads — show the PDF in the pre-opened tab.
    win.location.href = url;
  } else {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  setTimeout(() => URL.revokeObjectURL(url), 120_000);
}

function ReportPage() {
  const { id } = Route.useParams();
  const reportRef = useRef<HTMLDivElement>(null);
  const [downloading, setDownloading] = useState(false);

  const audit = useQuery({
    queryKey: ["audit", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, status, started_at, completed_at, summary, summary_approved_at, checklist_version, checklist_frozen_at, website_url, client:clients(name, contact_name, contact_email, has_agentic_features, uses_ai_features)")
        .eq("id", id).single();
      if (error) throw error;
      return data as any;
    },
  });

  const hasAgentic = !!audit.data?.client?.has_agentic_features;
  const usesAi = !!audit.data?.client?.uses_ai_features;

  const items = useQuery({
    queryKey: ["checklist-items", { hasAgentic, usesAi }],
    queryFn: async () => {
      const { data } = await supabase
        .from("checklist_items")
        .select("id, category, title, description, severity, sort_order").eq("is_active", true)
        .order("sort_order");
      const all = data ?? [];
      return all.filter((it: any) => {
        if (it.category === "Agentic AI Security" && !hasAgentic) return false;
        if (it.category === "AI Service Continuity" && !usesAi) return false;
        return true;
      });
    },
  });


  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: async () => {
      const { data } = await supabase
        .from("audit_findings")
        .select("checklist_item_id, status, notes, explanation, risk_accepted_reason, risk_accepted_by, risk_accepted_at, risk_accepted_until, severity_override, severity_override_reason, remediation_owner, remediation_due, remediation_status")
        .eq("audit_id", id);
      return data ?? [];
    },
  });

  const archFindings = useQuery({
    queryKey: ["architectural-findings", id, "report"],
    queryFn: async () => {
      const { data } = await supabase
        .from("architectural_findings")
        .select("id, title, severity, affected_files, explanation, recommendation, fix_steps, include_in_report")
        .eq("audit_id", id)
        .eq("include_in_report", true)
        .order("created_at", { ascending: true });
      return data ?? [];
    },
  });


  const map = useMemo(() => {
    const m = new Map<string, { status: string | null; notes: string | null; explanation: string | null } & LifecycleFields>();
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
    const t = { pass: 0, fail: 0, na: 0, resolved: 0, inconclusive: 0, unanswered: 0, total: items.data?.length ?? 0 };
    items.data?.forEach((it: any) => {
      const s = map.get(it.id)?.status;
      if (s === "pass") t.pass++;
      else if (s === "fail") t.fail++;
      else if (s === "na") t.na++;
      else if (s === "resolved") t.resolved++;
      else if (s === "inconclusive") t.inconclusive++;
      else t.unanswered++;
    });
    return t;
  }, [items.data, map]);

  const statusMap = useMemo(() => {
    const m = new Map<string, string | null | undefined>();
    map.forEach((v, k) => m.set(k, v.status));
    return m;
  }, [map]);

  // Severity overrides and accepted risks for this audit.
  const today = todayLocal();
  const lifecycle = useMemo(() => {
    const m = new Map<string, Lifecycle>();
    (items.data ?? []).forEach((it: any) => m.set(it.id, lifecycleOf(map.get(it.id), it.severity, today)));
    return m;
  }, [items.data, map, today]);
  const scoredItems = useMemo(
    () => (items.data ?? []).map((it: any) => ({ ...it, severity: lifecycle.get(it.id)?.severity ?? it.severity })),
    [items.data, lifecycle],
  );
  const acceptedItems = useMemo(
    () => (items.data ?? []).filter((it: any) => lifecycle.get(it.id)?.acceptedActive),
    [items.data, lifecycle],
  );

  const security = useMemo(
    () => computeSecurityScore(scoredItems as any, statusMap as any),
    [scoredItems, statusMap],
  );
  const risk = useMemo(
    () => failuresBySeverity(scoredItems as any, statusMap as any),
    [scoredItems, statusMap],
  );
  const effort = useMemo(() => estimateRemediationHours(risk), [risk]);
  const coverage = useMemo(
    () => computeCoverage((items.data ?? []) as any, statusMap as any),
    [items.data, statusMap],
  );
  const verdict = useMemo(
    () => launchRecommendation(security.score, risk, coverage),
    [security.score, risk, coverage],
  );

  const failedItems = useMemo(() => {
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    // Accepted risks are listed separately; overrides change the order.
    return scoredItems
      .filter((it: any) => map.get(it.id)?.status === "fail" && !lifecycle.get(it.id)?.acceptedActive)
      .sort((a: any, b: any) => {
        const sevDiff =
          (order[(a.severity ?? "medium").toLowerCase()] ?? 2) -
          (order[(b.severity ?? "medium").toLowerCase()] ?? 2);
        if (sevDiff !== 0) return sevDiff;
        // Same severity: keep checklist order so numbering is stable.
        return (a.sort_order ?? 0) - (b.sort_order ?? 0);
      });
  }, [scoredItems, map, lifecycle]);

  const scopeSnapshot = useMemo(() => {
    return grouped.map(([cat, list]) => {
      let pass = 0, fail = 0, na = 0, unanswered = 0;
      list.forEach((it: any) => {
        const s = map.get(it.id)?.status;
        if (s === "pass" || s === "resolved") pass++;
        else if (s === "fail") fail++;
        else if (s === "na") na++;
        else unanswered++;
      });
      const status: "pass" | "warn" | "fail" =
        fail > 0 ? "fail" : unanswered > 0 ? "warn" : "pass";
      return { cat, status, pass, fail, na, unanswered, total: list.length };
    });
  }, [grouped, map]);

  // ---- Built from audit data (phase 2c)
  const extras = useReportExtras(id);
  const [baselineId, setBaselineId] = useState<string | null>(null);
  const titleById = useMemo(() => new Map((items.data ?? []).map((it: any) => [it.id, it.title as string])), [items.data]);
  const method = useMemo(() => summarizeMethod(extras.data?.runs ?? []), [extras.data]);
  const untested = useMemo(
    () =>
      (items.data ?? [])
        .filter((it: any) => {
          const st = map.get(it.id)?.status;
          return st === "inconclusive" || !st;
        })
        .map((it: any) => ({ title: it.title, category: it.category, status: map.get(it.id)?.status ?? "unanswered" })),
    [items.data, map],
  );
  const evidence = useMemo(() => {
    const ordered = [...failedItems.map((it: any) => it.id), ...grouped.flatMap(([, list]) => list.map((it: any) => it.id))];
    return buildEvidenceIndex([...new Set(ordered)], extras.data?.results ?? [], extras.data?.evidence ?? []);
  }, [failedItems, grouped, extras.data]);
  const retestRows = useMemo(() => {
    const runs = extras.data?.runs ?? [];
    const baseline = runs.find((r) => r.id === baselineId);
    return baseline ? retestComparison(baseline, runs, extras.data?.results ?? [], statusMap) : [];
  }, [baselineId, extras.data, statusMap]);
  const controlsByItem = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const c of extras.data?.controls ?? []) {
      const list = m.get(c.checklist_item_id) ?? [];
      list.push(controlLabel(c));
      m.set(c.checklist_item_id, list);
    }
    return m;
  }, [extras.data]);
  const frameworks = useMemo(
    () => summarizeFrameworks(extras.data?.controls ?? [], statusMap, (itemId) => titleById.get(itemId)),
    [extras.data, statusMap, titleById],
  );
  const model: ReportModel | null = useMemo(() => {
    if (!audit.data || !items.data || !extras.data) return null;
    const approved = audit.data.summary && audit.data.summary_approved_at ? audit.data.summary : null;
    const baseline = extras.data.runs.find((r) => r.id === baselineId);
    return {
      audit: {
        title: audit.data.title,
        client: audit.data.client?.name ?? null,
        website: audit.data.website_url ?? null,
        started_at: audit.data.started_at ?? null,
        completed_at: audit.data.completed_at ?? null,
        status: audit.data.status ?? null,
      },
      summary: approved,
      score: { score: security.score ?? null, grade: String(security.grade) },
      counts: totals,
      scope: extras.data.scope
        ? {
            environment: extras.data.scope.environment,
            authorized_by: extras.data.scope.authorized_by,
            authorized_at: extras.data.scope.authorized_at,
            authorization_ref: extras.data.scope.authorization_ref,
            testing_window: extras.data.scope.testing_window,
            out_of_scope: extras.data.scope.out_of_scope,
            write_tests_allowed: extras.data.scope.write_tests_allowed,
          }
        : null,
      targets: extras.data.targets.map((t) => ({ kind: t.kind, value: t.value, in_scope: t.in_scope, label: t.label })),
      method,
      untested,
      failed: failedItems.map((it: any) => ({ item: it, notes: map.get(it.id)?.notes ?? null, evidence: evidence.byItem.get(it.id) ?? [], controls: controlsByItem.get(it.id) ?? [] })),
      frameworks,
      accepted: acceptedItems.map((it: any) => ({
        title: it.title,
        severity: lifecycle.get(it.id)?.severity ?? it.severity,
        by: map.get(it.id)?.risk_accepted_by ?? null,
        until: map.get(it.id)?.risk_accepted_until ?? null,
        reason: map.get(it.id)?.risk_accepted_reason ?? null,
      })),
      checklistVersion: audit.data.checklist_version ?? null,
      retest: baseline
        ? { baselineLabel: `${baseline.scanner} run of ${baseline.started_at.slice(0, 16).replace("T", " ")} UTC`, rows: retestRows.map((r) => ({ ...r, title: titleById.get(r.itemId) ?? r.itemId })) }
        : null,
      evidenceIndex: evidence.index,
      chain: extras.data.chain,
      generatedAt: new Date().toISOString(),
    };
  }, [audit.data, items.data, extras.data, baselineId, security, totals, method, untested, failedItems, map, evidence, retestRows, titleById, controlsByItem, frameworks, acceptedItems, lifecycle]);
  const fileBase = (() => {
    const dateStr = (audit.data?.completed_at || audit.data?.started_at || new Date().toISOString()).slice(0, 10);
    const raw = audit.data?.website_url || audit.data?.title || "report";
    const host = (() => {
      try { return new URL(raw.includes("://") ? raw : `https://${raw}`).hostname.replace(/^www\./, ""); } catch { return raw; }
    })();
    return `security-audit-${dateStr}-${host.replace(/[^a-z0-9.-]/gi, "-")}`;
  })();

  return (
    <div className="space-y-6 print:space-y-4">
      <div className="flex items-center justify-between print:hidden">
        <Link to="/audits/$id" params={{ id }} className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4 mr-1" /> Back to audit
        </Link>
        <div className="flex items-center gap-2">
          <Button variant="outline" asChild>
            <Link to="/audits/$id/fixes" params={{ id }}>
              <Wrench className="h-4 w-4 mr-1" /> Fix plan
            </Link>
          </Button>
          <Button variant="outline" onClick={() => { void logReportExport(id, "print", null, extras.data?.chain?.head_hash ?? null); window.print(); }}>
            <Printer className="h-4 w-4 mr-1" /> Print
          </Button>
          <ExportButtons auditId={id} model={model} fileBase={fileBase} />
          <Button
            disabled={downloading}
            onClick={async () => {
              const inIframe = (() => { try { return window.self !== window.top; } catch { return true; } })();
              // Open the tab immediately while the click still counts, so popup blockers allow it.
              const win = inIframe ? window.open("", "_blank") : null;
              if (win) win.document.write("<p style='font-family:sans-serif;padding:24px'>Preparing PDF…</p>");
              setDownloading(true);
              try {
                const dateStr = (audit.data?.completed_at || audit.data?.started_at || new Date().toISOString()).slice(0, 10);
                const rawUrl = audit.data?.website_url || "";
                const domain = (() => {
                  try {
                    return new URL(rawUrl.includes("://") ? rawUrl : `https://${rawUrl}`).hostname.replace(/^www\./, "");
                  } catch {
                    return rawUrl.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0] || "report";
                  }
                })();
                const safeDomain = domain.replace(/[^a-z0-9.-]/gi, "-");
                await downloadReportPdf(reportRef.current, `security-audit-${dateStr}-${safeDomain}.pdf`, win);
                void logReportExport(id, "pdf", null, extras.data?.chain?.head_hash ?? null);
              } catch (e: any) {
                win?.close();
                toast.error(e?.message ? `Could not create PDF: ${e.message}` : "Could not create PDF");
              } finally {
                setDownloading(false);
              }
            }}
            className="bg-navy text-navy-foreground hover:bg-navy/90"
          >
            <Download className="h-4 w-4 mr-1" /> {downloading ? "Preparing…" : "Download PDF"}
          </Button>
        </div>
      </div>

      <div ref={reportRef} className="bg-card border rounded-xl p-8 print:border-0 print:p-0">
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

        <SummarySection
          auditId={id}
          summary={audit.data?.summary ?? null}
          approvedAt={audit.data?.summary_approved_at ?? null}
        />

        <ExecutiveSummary
          score={security.score}
          grade={security.grade}
          risk={risk}
          effort={effort}
          verdict={verdict}
          totals={totals}
          coverage={coverage}
        />

        <ScopeMethodSection
          scope={extras.data?.scope ?? null}
          targets={extras.data?.targets ?? []}
          method={method}
          untested={untested}
        />

        {failedItems.length > 0 && (
          <section className="mb-8">
            <h2 className="text-lg font-semibold border-b pb-2 mb-3">
              Issues ({failedItems.length})
            </h2>
            <div className="space-y-3">
              {failedItems.map((it: any, idx: number) => {
                const f = map.get(it.id);
                return (
                  <FailedFindingCard
                    key={it.id}
                    auditId={id}
                    item={it}
                    notes={f?.notes ?? null}
                    explanation={f?.explanation ?? null}
                    priority={idx + 1}
                    evidenceRefs={evidence.byItem.get(it.id)}
                    controls={controlsByItem.get(it.id)}
                    lifecycle={lifecycle.get(it.id)}
                    finding={f}
                    linkedCode={(extras.data?.linkedCode ?? []).filter((c) => c.checklist_item_id === it.id)}
                  />
                );
              })}
            </div>
          </section>
        )}

        {acceptedItems.length > 0 && (
          <section className="mb-8 break-inside-avoid">
            <h2 className="text-lg font-semibold border-b pb-2 mb-3">Accepted risks ({acceptedItems.length})</h2>
            <p className="text-xs text-muted-foreground mb-2">Failed checks the client has chosen to accept for now. They count as failures in the score and reopen on the date shown.</p>
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-muted-foreground"><th className="py-1">Check</th><th>Severity</th><th>Accepted by</th><th>Until</th><th>Reason</th></tr></thead>
              <tbody>
                {acceptedItems.map((it: any) => {
                  const f = map.get(it.id);
                  return (
                    <tr key={it.id} className="border-t border-border/50 align-top">
                      <td className="py-1">{it.title}</td>
                      <td className="text-xs">{lifecycle.get(it.id)?.severity}</td>
                      <td className="text-xs">{f?.risk_accepted_by}</td>
                      <td className="text-xs whitespace-nowrap">{f?.risk_accepted_until}</td>
                      <td className="text-xs">{f?.risk_accepted_reason}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>
        )}

        <RetestSection
          runs={extras.data?.runs ?? []}
          baselineId={baselineId}
          onBaseline={setBaselineId}
          rows={retestRows}
          titleOf={(itemId) => titleById.get(itemId) ?? itemId}
        />

        <FrameworkSection frameworks={frameworks} />

        <ScopeSnapshot items={scopeSnapshot} score={security.score} />

        {grouped.map(([cat, list]) => (
          <section key={cat} className="mb-6 break-inside-avoid">
            <h2 className="text-lg font-semibold border-b pb-2 mb-3">{cat}</h2>
            <div className="space-y-3">
              {list.map((it: any) => {
                const f = map.get(it.id);
                return (
                  <PassFindingCard
                    key={it.id}
                    item={it}
                    status={f?.status}
                    notes={f?.notes ?? null}
                  />
                );
              })}
            </div>
          </section>
        ))}

        <ArchitecturalRiskSection findings={archFindings.data ?? []} />

        <CodeAuditSection auditId={id} titleOf={(itemId) => titleById.get(itemId)} />

        <ResolvedFindingsAppendix auditId={id} />

        <ReportAppendix
          index={evidence.index}
          chain={extras.data?.chain ?? null}
          auditId={id}
          checklistVersion={audit.data?.checklist_version ?? null}
          checklistFrozenAt={audit.data?.checklist_frozen_at ?? null}
        />
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
  score, grade, risk, effort, verdict, totals, coverage,
}: {
  score: number | null;
  grade: "A" | "B" | "C" | "D" | "F" | "—";
  risk: RiskBreakdown;
  effort: { min: number; max: number };
  verdict: ReturnType<typeof launchRecommendation>;
  totals: { pass: number; fail: number; na: number; resolved: number; inconclusive: number; unanswered: number; total: number };
  coverage: Coverage;
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
    verdict.verdict === "insufficient" ? "border-status-na/50 bg-muted/40 text-status-na" :
    "border-status-fail/60 bg-status-fail/[0.08] text-status-fail";

  return (
    <section className="mb-8 space-y-4">
      <div className="flex items-baseline justify-between">
        <h2 className="text-lg font-semibold">Executive Security Summary</h2>
        <div className="text-xs text-muted-foreground">
          {totals.pass} pass · {totals.fail} fail · {totals.resolved} resolved · {totals.na} N/A · {totals.inconclusive} couldn't verify · {totals.unanswered} unanswered
        </div>
      </div>

      <div className="rounded-xl border p-5">
        <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Assessment coverage</div>
        <div className="text-3xl font-semibold tracking-tight mt-1">
          Assessment {Math.round(coverage.ratio * 100)}% complete — {coverage.assessed} of {coverage.total} checks run.
        </div>
        <div className="mt-3 h-2 w-full rounded-full bg-muted overflow-hidden">
          <div
            className={cn("h-full rounded-full", coverage.sufficient ? "bg-status-pass" : "bg-status-na")}
            style={{ width: `${Math.round(coverage.ratio * 100)}%` }}
          />
        </div>
        {coverage.underCoveredCategories.length > 0 && (
          <div className="text-xs text-muted-foreground mt-2">
            Not sufficiently assessed: {coverage.underCoveredCategories.map((c) => `${c.category} (${c.assessed}/${c.total})`).join(", ")}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1.4fr_2fr] gap-4">
        <div className={cn("rounded-xl ring-1 p-5 flex items-center gap-4", ringCls)}>
          <div className="flex flex-col items-center">
            <div className={cn("text-4xl font-semibold tabular-nums leading-none", scoreCls)}>
              {score ?? "—"}
            </div>
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-1">/ 100</div>
          </div>
          <div className="h-12 w-px bg-border" />
          <div>
            <div className={cn("font-mono text-2xl font-semibold leading-none", scoreCls)}>{grade}</div>
            <div className="text-[11px] text-muted-foreground mt-1 max-w-[16rem]">
              Score among items assessed so far — not a whole-app grade.
            </div>
          </div>
        </div>

        <div className={cn("rounded-xl border p-4 flex items-start gap-3", verdictTone)}>
          {verdict.verdict === "go" && <ShieldCheck className="h-6 w-6 shrink-0 mt-0.5" />}
          {(verdict.verdict === "fix-first" || verdict.verdict === "insufficient") && <ShieldAlert className="h-6 w-6 shrink-0 mt-0.5" />}
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
        <RiskTile label="Low" count={risk.low} cls="bg-blue-500/[0.08] border-blue-500/40 text-blue-600 dark:text-blue-400" />
      </div>

      <div className="text-xs text-muted-foreground flex flex-wrap gap-x-4 gap-y-1">
        <span><span className="font-medium text-foreground">Estimated remediation effort:</span>{" "}
          {effort.max === 0 ? "—" : `${effort.min}–${effort.max} hours`}
        </span>
        <span className="opacity-70">Score reflects only assessed items (severity-weighted Pass / Pass + Fail); unanswered items are tracked separately and prevent a launch recommendation until run.</span>
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
  low: "bg-blue-500/15 text-blue-600 dark:text-blue-300 border-blue-500/40",
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
  auditId, item, notes, explanation, priority, evidenceRefs, controls, lifecycle, finding, linkedCode,
}: {
  auditId: string;
  item: any;
  notes: string | null;
  explanation: string | null;
  priority: number;
  evidenceRefs?: EvidenceRef[];
  controls?: string[];
  lifecycle?: Lifecycle;
  finding?: LifecycleFields;
  linkedCode?: { id: string; title: string; severity: string | null; verdict: string; checklist_item_id: string }[];
}) {
  const [open, setOpen] = useState(true);
  // Generated as the card scrolls into view, so it's ready before it's opened
  // and appears in the printed report.
  const { ref, text: exp, loading: expLoading } = useFindingExplanation({
    auditId,
    checklistItemId: item.id,
    cached: explanation,
    whenVisible: true,
  });
  const sev = (item.severity ?? "medium").toLowerCase();
  const bannerCls = SEVERITY_BANNER[sev] ?? SEVERITY_BANNER.medium;
  const label = SEVERITY_LABEL[sev] ?? "Risk";

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <Card ref={ref} className={cn("border-l-4 overflow-hidden", "border-l-status-fail")}>
        <CollapsibleTrigger asChild>
          <button
            type="button"
            className={cn(
              "w-full text-left px-4 py-3 flex items-center gap-3 border-b transition-colors",
              bannerCls,
              "hover:brightness-105",
            )}
          >
            <span
              className="shrink-0 inline-flex items-center justify-center h-7 w-7 rounded-full bg-foreground/10 border border-current/40 text-xs font-bold"
              title={`Priority ${priority}`}
            >
              {priority}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] font-bold uppercase tracking-widest">Priority {priority}</span>
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
            </div>
            <ControlTags tags={controls} />
            {lifecycle?.overridden && (
              <p className="text-xs text-muted-foreground">
                Severity set to <strong>{lifecycle.severity}</strong> for this audit (checklist default {lifecycle.defaultSeverity}): {finding?.severity_override_reason}
              </p>
            )}
            {lifecycle?.acceptedExpired && (
              <p className="text-xs text-status-fail">
                Risk acceptance by {finding?.risk_accepted_by} expired on {finding?.risk_accepted_until}; this issue is open again.
              </p>
            )}
            {(finding?.remediation_owner || finding?.remediation_due || finding?.remediation_status) && (
              <p className="text-xs">
                <span className="text-muted-foreground">Remediation: </span>
                {[finding?.remediation_status ? REMEDIATION_LABEL[finding.remediation_status] ?? finding.remediation_status : null,
                  finding?.remediation_owner ? `owner ${finding.remediation_owner}` : null,
                  finding?.remediation_due ? `due ${finding.remediation_due}${lifecycle?.overdue ? " (overdue)" : ""}` : null]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
            )}

            <DetailRow label="Why should I care?">
              {exp ? (
                <ul className="border-l-2 border-amber-500/40 pl-3 space-y-1.5 text-sm">
                  {explanationBullets(exp).map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">
                  {expLoading ? "Writing a plain-English explanation…" : (item.description ?? "")}
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

            {linkedCode && linkedCode.length > 0 && (
              <DetailRow label="Also found in the code review">
                <LinkedCodeFindings rows={linkedCode} />
              </DetailRow>
            )}

            {evidenceRefs && evidenceRefs.length > 0 && (
              <DetailRow label="Evidence references (see appendix)">
                <EvidenceRefs refs={evidenceRefs} />
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

function ScopeSnapshot({
  items,
  score,
}: {
  items: { cat: string; status: "pass" | "warn" | "fail"; pass: number; fail: number; na: number; unanswered: number; total: number }[];
  score: number | null;
}) {
  if (items.length === 0) return null;
  return (
    <section className="mb-8 rounded-xl border bg-muted/20 p-5 break-inside-avoid">
      <div className="flex items-baseline justify-between mb-4">
        <h2 className="text-lg font-semibold">Audit Scope Snapshot</h2>
        <div className="font-mono text-xs text-muted-foreground">
          Security Score: <span className="text-foreground font-semibold">{score ?? "—"}</span> / 100
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {items.map((it) => {
          const Icon = it.status === "pass" ? Check : it.status === "warn" ? AlertTriangle : X;
          const tone =
            it.status === "pass" ? "text-status-pass border-status-pass/40 bg-status-pass/[0.06]" :
            it.status === "warn" ? "text-status-na border-status-na/40 bg-status-na/[0.06]" :
            "text-status-fail border-status-fail/40 bg-status-fail/[0.06]";
          return (
            <div key={it.cat} className={cn("rounded-lg border p-3 flex flex-col gap-2", tone)}>
              <div className="text-sm font-semibold text-foreground truncate" title={it.cat}>{it.cat}</div>
              <div className="flex items-center justify-between">
                <Icon className="h-5 w-5" />
                <span className="text-[10px] uppercase tracking-widest text-muted-foreground">
                  {it.pass}/{it.total}
                </span>
              </div>
            </div>
          );
        })}
      </div>
      <p className="text-xs text-muted-foreground mt-3">
        Snapshot of each audit area. A category is marked failing if any check failed, or pending if any check is unanswered.
      </p>
    </section>
  );
}

function PassFindingCard({
  item,
  status,
  notes,
}: {
  item: any;
  status: string | null | undefined;
  notes: string | null;
}) {
  const isPass = status === "pass" || status === "resolved";
  const isResolved = status === "resolved";
  const isNa = status === "na";
  const isInconclusive = status === "inconclusive";
  const isUnanswered = !status || isInconclusive;
  const Icon = isPass ? Check : isNa ? Minus : AlertTriangle;
  const tone = isPass
    ? "border-l-status-pass"
    : isNa
    ? "border-l-muted-foreground/40"
    : "border-l-status-na";

  return (
    <Card className={cn("border-l-4 p-4 space-y-3", tone)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold">{item.title}</span>
            <SeverityBadge severity={item.severity} />
            <span className="text-xs text-muted-foreground">· {item.category}</span>
          </div>
        </div>
        <div className={cn(
          "inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-semibold uppercase tracking-wide shrink-0",
          isPass && "bg-status-pass/15 text-status-pass",
          isNa && "bg-muted text-muted-foreground",
          isUnanswered && "bg-status-na/15 text-status-na",
        )}>
          <Icon className="h-3.5 w-3.5" />
          {isResolved ? "Resolved" : isPass ? "Passed" : isNa ? "N/A" : isInconclusive ? "Not verified" : "Unanswered"}
        </div>
      </div>

      <DetailRow label="Evidence">
        {notes ? (
          <EvidenceBlocks notes={notes} />
        ) : (
          <p className="text-sm text-muted-foreground">
            {isPass
              ? "Verified during this audit."
              : isNa
              ? "Not applicable to this project."
              : isInconclusive
              ? "The automated scan could not verify this check."
              : "Not yet reviewed."}
          </p>
        )}
      </DetailRow>

      <DetailRow label="Recommendation">
        <p className="text-sm text-muted-foreground">
          {isPass
            ? "No action required — keep this control in place and re-verify on the next audit."
            : isNa
            ? "No action required. Re-evaluate if scope changes."
            : isInconclusive
            ? "The scanner could not verify this. Check it manually and record a pass / fail / N/A before finalizing the report."
            : "Review this check and record a pass / fail / N/A before finalizing the report."}
        </p>
      </DetailRow>
    </Card>
  );
}

type ArchFinding = {
  id: string;
  title: string;
  severity: string;
  affected_files: string[] | any;
  explanation: string | null;
  recommendation: string | null;
  fix_steps?: string[] | any;
};

const ARCH_SEV_BANNER: Record<string, string> = {
  critical: "bg-status-fail/15 text-status-fail border-status-fail/40",
  high: "bg-orange-500/15 text-orange-600 dark:text-orange-300 border-orange-500/40",
  medium: "bg-status-na/15 text-status-na border-status-na/40",
  low: "bg-blue-500/15 text-blue-600 dark:text-blue-300 border-blue-500/40",
};

function ArchitecturalRiskSection({ findings }: { findings: ArchFinding[] }) {
  if (!findings || findings.length === 0) return null;
  return (
    <section className="mb-6 break-inside-avoid">
      <h2 className="text-lg font-semibold border-b pb-2 mb-3 flex items-center gap-2">
        <Brain className="h-5 w-5 text-cyan-600" />
        Architectural Risk Assessment
      </h2>
      <p className="text-sm text-muted-foreground mb-3">
        Cross-cutting structural observations that span multiple files — duplicated systems,
        inconsistent enforcement, and privilege concentration that line-level scans cannot see.
      </p>
      <div className="space-y-3">
        {findings.map((f) => {
          const sev = (f.severity ?? "medium").toLowerCase();
          const bannerCls = ARCH_SEV_BANNER[sev] ?? ARCH_SEV_BANNER.medium;
          const files: string[] = Array.isArray(f.affected_files) ? f.affected_files : [];
          return (
            <Card key={f.id} className="border-l-4 border-l-slate-700 overflow-hidden">
              <div className={cn("px-4 py-3 flex items-center gap-3 border-b", bannerCls)}>
                <Brain className="h-5 w-5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="text-[10px] font-bold uppercase tracking-widest">
                    {sev} · Architectural
                  </div>
                  <div className="font-semibold text-foreground mt-0.5">{f.title}</div>
                </div>
              </div>
              <div className="p-4 space-y-3">
                {f.explanation && (
                  <p className="text-sm text-foreground/90 leading-relaxed">{f.explanation}</p>
                )}
                {f.recommendation && (
                  <div className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
                    <span className="font-semibold">Recommendation: </span>
                    {f.recommendation}
                  </div>
                )}
                {Array.isArray(f.fix_steps) && f.fix_steps.length > 0 && (
                  <div className="rounded-md border border-cyan-500/30 bg-cyan-500/5 px-3 py-2 text-sm">
                    <div className="text-[10px] font-semibold uppercase tracking-widest text-cyan-700 dark:text-cyan-300 mb-1.5">
                      Project-specific fix steps
                    </div>
                    <ol className="list-decimal pl-5 space-y-1 text-foreground/90 leading-relaxed">
                      {(f.fix_steps as string[]).map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  </div>
                )}
                {files.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground mb-1.5">
                      Affected files
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {files.map((p) => (
                        <code
                          key={p}
                          className="rounded bg-muted px-1.5 py-0.5 text-[11px] font-mono"
                        >
                          {p}
                        </code>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Card>
          );
        })}
      </div>
    </section>
  );
}


function ResolvedFindingsAppendix({ auditId }: { auditId: string }) {
  const fetchResolved = useServerFn(listResolvedFindings);
  const { data, isLoading } = useQuery({
    queryKey: ["resolved-findings", auditId],
    queryFn: () => fetchResolved({ data: { auditId } }),
  });

  if (isLoading) return null;
  const rows = data ?? [];
  if (rows.length === 0) return null;

  return (
    <section className="mt-10 pt-6 border-t-2 border-dashed border-border break-inside-avoid">
      <h2 className="text-lg font-semibold flex items-center gap-2 mb-1">
        <CheckCircle2 className="h-5 w-5 text-status-pass" />
        Appendix · Resolved Findings
      </h2>
      <p className="text-xs text-muted-foreground mb-4">
        Findings that were verified as fixed during this audit. Each entry shows the date verified and
        whether verification came from an automated re-scan or manually submitted evidence.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-sm border border-border rounded-md">
          <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="text-left p-2 font-medium">Finding</th>
              <th className="text-left p-2 font-medium">Category</th>
              <th className="text-left p-2 font-medium">Verified</th>
              <th className="text-left p-2 font-medium">Method</th>
              <th className="text-left p-2 font-medium">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.finding_id} className="border-t border-border align-top">
                <td className="p-2 font-medium">{r.title}</td>
                <td className="p-2 text-muted-foreground">{r.category}</td>
                <td className="p-2 whitespace-nowrap text-muted-foreground">
                  {r.resolved_at ? format(new Date(r.resolved_at), "MMM d, yyyy") : "—"}
                </td>
                <td className="p-2">
                  <span className={cn(
                    "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                    r.resolved_via === "automated_rescan"
                      ? "bg-status-pass/15 text-status-pass"
                      : "bg-primary/10 text-primary",
                  )}>
                    {r.resolved_via === "automated_rescan" ? (
                      <><RefreshCw className="h-3 w-3" /> Auto re-scan</>
                    ) : (
                      <><Check className="h-3 w-3" /> Manual evidence</>
                    )}
                  </span>
                </td>
                <td className="p-2 text-xs text-muted-foreground max-w-[28ch]">
                  {r.evidence_text ? (
                    <span title={r.evidence_text}>{r.evidence_text.length > 80 ? r.evidence_text.slice(0, 80) + "…" : r.evidence_text}</span>
                  ) : r.resolved_via === "automated_rescan" ? (
                    <span className="italic">Re-scan returned pass</span>
                  ) : (
                    <span>—</span>
                  )}
                  {r.evidence_url && (
                    <a href={r.evidence_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 ml-1 text-primary hover:underline">
                      <ExternalLink className="h-3 w-3" /> link
                    </a>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}


// Code-level findings from the deep code audit that the auditor chose to
// include. Only confirmed and needs-validation records are shown.
function CodeAuditSection({ auditId, titleOf }: { auditId: string; titleOf?: (itemId: string) => string | undefined }) {
  const { data } = useQuery({
    queryKey: ["code-audit-report", auditId],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("code_audit_findings")
        .select("id, verdict, severity, title, description, root_cause, remediation, validation_plan, checklist_item_id")
        .eq("audit_id", auditId)
        .eq("include_in_report", true)
        .neq("verdict", "rejected")
        .neq("review_state", "dismissed");
      if (error) throw error;
      return data ?? [];
    },
  });
  const rows = data ?? [];
  if (rows.length === 0) return null;
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const sorted = [...rows].sort(
    (a, b) =>
      (a.verdict === "confirmed" ? 0 : 1) - (b.verdict === "confirmed" ? 0 : 1) ||
      (rank[a.severity ?? ""] ?? 9) - (rank[b.severity ?? ""] ?? 9),
  );
  const fixText = (r: unknown): string | null => {
    if (!r) return null;
    if (typeof r === "string") return r;
    const o = r as Record<string, unknown>;
    const v = o.strategy ?? o.summary ?? o.fix ?? o.description;
    return typeof v === "string" ? v : null;
  };
  return (
    <section className="mb-8 break-inside-avoid">
      <h2 className="text-lg font-semibold border-b pb-2 mb-1">Code-level findings</h2>
      <p className="text-xs text-muted-foreground mb-3">
        From a source-code review of the application. Confirmed findings were verified independently; findings that need
        validation depend on a deployment fact to be checked with your team.
      </p>
      <div className="space-y-3">
        {sorted.map((r) => (
          <Card key={r.id} className="p-4 space-y-1.5 break-inside-avoid">
            <div className="flex items-center gap-2 flex-wrap text-xs">
              <span className="font-semibold uppercase tracking-wide">
                {r.verdict === "confirmed" ? r.severity ?? "confirmed" : "needs validation"}
              </span>
            </div>
            <div className="font-semibold">{r.title}</div>
            {r.checklist_item_id && titleOf?.(r.checklist_item_id) && (
              <div className="text-xs text-muted-foreground">Linked to the issue “{titleOf(r.checklist_item_id)}”</div>
            )}
            {r.description && <p className="text-sm whitespace-pre-wrap">{r.description}</p>}
            {fixText(r.remediation) && (
              <p className="text-sm">
                <span className="font-medium">Fix: </span>
                {fixText(r.remediation)}
              </p>
            )}
          </Card>
        ))}
      </div>
    </section>
  );
}
