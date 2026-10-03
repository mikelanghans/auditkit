// Report sections built from audit data (build plan, phase 2c): approved
// executive summary, scope and method, re-test comparison, evidence refs and
// appendix, plus Markdown and evidence-bundle exports.
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { format } from "date-fns";
import { CheckCircle2, FileArchive, FileText, Loader2, PenLine, ShieldAlert, ShieldCheck, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { draftExecutiveSummary } from "@/lib/report-summary.functions";
import { fetchAuditEvents, logReportExport, type ChainStatus } from "@/hooks/use-audit-trail";
import { sha256Hex } from "@/lib/evidence";
import { buildZip, type ZipEntry } from "@/lib/zip-store";
import {
  SCANNER_LABEL,
  buildReportMarkdown,
  type ControlRow,
  type EvidenceMeta,
  type FrameworkSummary,
  type EvidenceRef,
  type MethodSummary,
  type ReportModel,
  type ResultRow,
  type RetestRow,
  type RunRow,
} from "@/lib/report-model";
import type { AuditScope, AuditTarget } from "@/lib/audit-targets";

export type ReportExtras = {
  targets: AuditTarget[];
  scope: AuditScope | null;
  runs: RunRow[];
  results: ResultRow[];
  evidence: EvidenceMeta[];
  controls: ControlRow[];
  /** Deep-audit findings linked to a checklist item and kept for the report. */
  linkedCode: { id: string; title: string; severity: string | null; verdict: string; checklist_item_id: string }[];
  chain: ChainStatus | null;
};

/** Everything the data-built sections need. Tables that don't exist yet (migrations not pushed) come back empty. */
export function useReportExtras(auditId: string) {
  return useQuery({
    queryKey: ["report-extras", auditId],
    queryFn: async (): Promise<ReportExtras> => {
      const soft = <T,>(r: { data: T | null; error: { message: string } | null }, fallback: T): T => {
        if (r.error) console.warn("[report]", r.error.message);
        return (r.data ?? fallback) as T;
      };
      const [targets, scope, runs, results, evidence, chain, controls, linkedCode] = await Promise.all([
        supabase.from("audit_targets").select("id, audit_id, kind, value, label, meta, in_scope").eq("audit_id", auditId).order("created_at"),
        supabase.from("audit_scope").select("*").eq("audit_id", auditId).maybeSingle(),
        supabase.from("scan_runs").select("id, scanner, trigger, target, status, started_at, finished_at, parent_run_id, summary").eq("audit_id", auditId).order("started_at"),
        supabase.from("scan_results").select("run_id, checklist_item_id, checklist_key, scanner, status, evidence_ids, created_at").eq("audit_id", auditId).limit(20000),
        supabase.from("evidence").select("id, kind, title, sha256, size_bytes, source, captured_at, checklist_item_id, storage_path, purged_at").eq("audit_id", auditId).limit(5000),
        supabase.rpc("verify_audit_chain", { p_audit: auditId }),
        (supabase as any).from("checklist_item_controls").select("checklist_item_id, framework, control_id, control_title").limit(5000),
        supabase
          .from("code_audit_findings")
          .select("id, title, severity, verdict, checklist_item_id")
          .eq("audit_id", auditId)
          .eq("include_in_report", true)
          .neq("verdict", "rejected")
          .neq("review_state", "dismissed")
          .not("checklist_item_id", "is", null),
      ]);
      return {
        targets: soft(targets as any, []),
        scope: soft(scope as any, null),
        runs: soft(runs as any, []),
        results: soft(results as any, []),
        evidence: soft(evidence as any, []),
        controls: soft(controls as any, []),
        linkedCode: soft(linkedCode as any, []),
        chain: (soft(chain as any, []) as ChainStatus[])[0] ?? null,
      };
    },
  });
}

// ---------------------------------------------------------------- summary

export function SummarySection({
  auditId,
  summary,
  approvedAt,
}: {
  auditId: string;
  summary: string | null;
  approvedAt: string | null;
}) {
  const qc = useQueryClient();
  const draft = useServerFn(draftExecutiveSummary);
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(summary ?? "");
  const [busy, setBusy] = useState<null | "draft" | "save">(null);

  const refresh = () => qc.invalidateQueries({ queryKey: ["audit", auditId] });
  const runDraft = async () => {
    setBusy("draft");
    try {
      const r: any = await draft({ data: { auditId } });
      if (!r.ok) throw new Error(r.error);
      setText(r.text);
      setEditing(true);
      await refresh();
    } catch (e: any) {
      toast.error(e?.message ?? "Couldn't draft the summary.");
    } finally {
      setBusy(null);
    }
  };
  const save = async (approve: boolean) => {
    setBusy("save");
    const { error } = await supabase
      .from("audits")
      .update({ summary: text.trim() || null, summary_approved_at: approve && text.trim() ? new Date().toISOString() : null })
      .eq("id", auditId);
    setBusy(null);
    if (error) return toast.error(error.message);
    setEditing(false);
    toast.success(approve ? "Summary approved." : "Draft saved.");
    refresh();
  };

  const approved = !!(summary && approvedAt);
  return (
    <section className="mb-8">
      {approved && !editing && (
        <div className="prose prose-sm max-w-none dark:prose-invert">
          {summary!.split(/\n{2,}/).map((p, i) => <p key={i}>{p}</p>)}
        </div>
      )}
      <div className="print:hidden mt-2 rounded-md border border-dashed border-border p-3 space-y-2">
        <div className="flex items-center gap-2 text-xs">
          <PenLine className="h-3.5 w-3.5" />
          <span className="font-medium">Executive summary</span>
          <span className="text-muted-foreground">
            {approved ? `approved ${format(new Date(approvedAt!), "PP")}` : summary ? "draft, not printed until approved" : "none yet"}
          </span>
          <div className="ml-auto flex gap-1.5">
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={runDraft} disabled={!!busy}>
              {busy === "draft" ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Sparkles className="h-3 w-3 mr-1" />}
              {summary ? "Redraft with Claude" : "Draft with Claude"}
            </Button>
            {!editing && (
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => { setText(summary ?? ""); setEditing(true); }}>
                Edit
              </Button>
            )}
          </div>
        </div>
        {(editing || (summary && !approved)) && (
          <>
            <Textarea rows={7} className="text-sm" value={editing ? text : summary ?? ""} onChange={(e) => { setEditing(true); setText(e.target.value); }} />
            <div className="flex justify-end gap-1.5">
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => save(false)} disabled={!!busy}>Save draft</Button>
              <Button size="sm" className="h-7 text-xs" onClick={() => save(true)} disabled={!!busy || !(editing ? text : summary)?.trim()}>
                <CheckCircle2 className="h-3 w-3 mr-1" /> Approve for the report
              </Button>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- scope & method

const day = (iso: string | null | undefined) => (iso ? format(new Date(iso), "PP") : "—");

export function ScopeMethodSection({
  scope,
  targets,
  method,
  untested,
}: {
  scope: AuditScope | null;
  targets: AuditTarget[];
  method: MethodSummary;
  untested: { title: string; category: string; status: string }[];
}) {
  return (
    <section className="mb-8 break-inside-avoid">
      <h2 className="text-lg font-semibold border-b pb-2 mb-3">Scope and method</h2>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
        <Field label="Environment" value={scope?.environment ?? "not recorded"} />
        <Field
          label="Authorized by"
          value={scope?.authorized_by ? `${scope.authorized_by}${scope.authorized_at ? ` on ${day(scope.authorized_at)}` : ""}${scope.authorization_ref ? ` (${scope.authorization_ref})` : ""}` : "not recorded"}
        />
        {scope?.testing_window && <Field label="Testing window" value={scope.testing_window} />}
        <Field label="Write and stress tests" value={scope?.write_tests_allowed ? "allowed" : "not performed (not authorized)"} />
        {scope?.out_of_scope && <Field label="Out of scope" value={scope.out_of_scope} />}
      </dl>
      {targets.length > 0 && (
        <table className="w-full text-sm mt-3">
          <thead><tr className="text-left text-xs text-muted-foreground"><th className="py-1">Target</th><th>Type</th><th>In scope</th></tr></thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} className="border-t border-border/50">
                <td className="py-1 font-mono text-xs">{t.value}{t.label ? <span className="font-sans text-muted-foreground"> · {t.label}</span> : null}</td>
                <td className="text-xs">{t.kind.replace("_", " ")}</td>
                <td className="text-xs">{t.in_scope ? "yes" : "no"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {method.scanners.length > 0 && (
        <>
          <p className="text-sm mt-4">Automated testing ran between {day(method.firstActivity)} and {day(method.lastActivity)}.</p>
          <table className="w-full text-sm mt-2">
            <thead><tr className="text-left text-xs text-muted-foreground"><th className="py-1">Check</th><th>Runs</th><th>Targets</th><th>Last run</th></tr></thead>
            <tbody>
              {method.scanners.map((s) => (
                <tr key={s.scanner} className="border-t border-border/50">
                  <td className="py-1">{s.label}</td>
                  <td className="tabular-nums">{s.runs}</td>
                  <td className="font-mono text-xs">{s.targets.join(", ") || "—"}</td>
                  <td className="text-xs">{day(s.last)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {(method.notRun.length > 0 || untested.length > 0) && (
        <div className="mt-4">
          <h3 className="text-sm font-semibold mb-1">Not tested, and why</h3>
          <ul className="text-sm list-disc pl-5 space-y-0.5">
            {method.notRun.map((n, i) => (
              <li key={`n${i}`}>{SCANNER_LABEL[n.scanner] ?? n.scanner}{n.target ? ` (${n.target})` : ""}: {n.reason}</li>
            ))}
            {untested.map((u) => (
              <li key={u.title}>{u.title} <span className="text-muted-foreground">({u.category})</span>: {u.status === "inconclusive" ? "could not be verified" : "not assessed"}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <dt className="text-muted-foreground w-44 shrink-0">{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

// ---------------------------------------------------------------- re-test

const CHANGE_TONE: Record<string, string> = {
  fixed: "text-status-pass",
  regressed: "text-status-fail",
  new: "text-status-fail",
  still_failing: "text-status-warn",
};

export function RetestSection({
  runs,
  baselineId,
  onBaseline,
  rows,
  titleOf,
}: {
  runs: RunRow[];
  baselineId: string | null;
  onBaseline: (id: string | null) => void;
  rows: RetestRow[];
  titleOf: (id: string) => string;
}) {
  const choices = runs.filter((r) => !r.parent_run_id && r.status !== "running").slice().reverse();
  if (!choices.length) return null;
  const baseline = runs.find((r) => r.id === baselineId);
  return (
    <section className={baseline ? "mb-8 break-inside-avoid" : "mb-8 print:hidden"}>
      <div className="flex items-center gap-3 border-b pb-2 mb-3">
        <h2 className="text-lg font-semibold">Re-test</h2>
        <div className="print:hidden ml-auto">
          <Select value={baselineId ?? "none"} onValueChange={(v) => onBaseline(v === "none" ? null : v)}>
            <SelectTrigger className="h-8 w-[300px] text-xs"><SelectValue placeholder="Compare with…" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="none">No re-test section</SelectItem>
              {choices.map((r) => (
                <SelectItem key={r.id} value={r.id}>
                  {SCANNER_LABEL[r.scanner] ?? r.scanner} · {format(new Date(r.started_at), "MMM d, HH:mm")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      {baseline && (
        <>
          <p className="text-sm text-muted-foreground mb-2">
            Compared with the {SCANNER_LABEL[baseline.scanner]?.toLowerCase() ?? baseline.scanner} of {format(new Date(baseline.started_at), "PPp")}.
          </p>
          {!rows.length ? (
            <p className="text-sm">No changes.</p>
          ) : (
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-muted-foreground"><th className="py-1">Check</th><th>Before</th><th>Now</th><th>Change</th></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.itemId} className="border-t border-border/50">
                    <td className="py-1">{titleOf(r.itemId)}</td>
                    <td className="text-xs">{r.before ?? "—"}</td>
                    <td className="text-xs">{r.now}</td>
                    <td className={`text-xs font-medium ${CHANGE_TONE[r.change]}`}>{r.change.replace("_", " ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}

// ---------------------------------------------------------------- evidence refs & appendix

export function EvidenceRefs({ refs }: { refs: EvidenceRef[] | undefined }) {
  if (!refs?.length) return null;
  return (
    <ul className="text-xs space-y-0.5">
      {refs.map((e) => (
        <li key={e.id} className="flex gap-2">
          <span className="font-semibold w-8 shrink-0">{e.label}</span>
          <span className="flex-1">{e.title} <span className="text-muted-foreground">({e.kind.replace("_", " ")}, {format(new Date(e.captured_at), "PP")})</span></span>
          <span className="font-mono text-muted-foreground">{e.sha256.slice(0, 12)}…</span>
        </li>
      ))}
    </ul>
  );
}

export function ReportAppendix({
  index,
  chain,
  auditId,
  checklistVersion,
  checklistFrozenAt,
}: {
  index: EvidenceRef[];
  chain: ChainStatus | null;
  auditId: string;
  checklistVersion: string | null;
  checklistFrozenAt: string | null;
}) {
  const qc = useQueryClient();
  const [freezing, setFreezing] = useState(false);
  const freeze = async () => {
    setFreezing(true);
    const { error } = await supabase.rpc("freeze_audit_checklist", { p_audit: auditId });
    setFreezing(false);
    if (error) return toast.error(error.message);
    toast.success("Checklist frozen for this audit.");
    qc.invalidateQueries({ queryKey: ["audit", auditId] });
  };
  return (
    <section className="mt-8 break-before-page">
      <h2 className="text-lg font-semibold border-b pb-2 mb-3">Appendix: evidence index</h2>
      {!index.length ? (
        <p className="text-sm text-muted-foreground">No evidence recorded.</p>
      ) : (
        <table className="w-full text-xs">
          <thead><tr className="text-left text-muted-foreground"><th className="py-1">Ref</th><th>Evidence</th><th>Type</th><th>Captured</th><th>SHA-256</th></tr></thead>
          <tbody>
            {index.map((e) => (
              <tr key={e.id} className="border-t border-border/50 align-top">
                <td className="py-1 font-semibold">{e.label}</td>
                <td>{e.title}</td>
                <td>{e.kind.replace("_", " ")}</td>
                <td className="whitespace-nowrap">{format(new Date(e.captured_at), "PP p")}</td>
                <td className="font-mono break-all">{e.sha256}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h2 className="text-lg font-semibold border-b pb-2 mb-3 mt-6">Appendix: checklist version</h2>
      <div className="text-sm flex items-center gap-3 flex-wrap">
        {checklistVersion ? (
          <span>
            Assessed against checklist <span className="font-mono text-xs break-all">{checklistVersion}</span>
            {checklistFrozenAt ? <span className="text-muted-foreground"> (frozen {format(new Date(checklistFrozenAt), "PP")})</span> : null}
          </span>
        ) : (
          <span className="text-muted-foreground">Not frozen yet. It freezes automatically when the audit is marked complete.</span>
        )}
        <Button size="sm" variant="outline" className="h-7 text-xs print:hidden" onClick={freeze} disabled={freezing}>
          {freezing && <Loader2 className="h-3 w-3 mr-1 animate-spin" />} {checklistVersion ? "Re-freeze now" : "Freeze now"}
        </Button>
      </div>
      <h2 className="text-lg font-semibold border-b pb-2 mb-3 mt-6">Appendix: audit trail</h2>
      {chain ? (
        <div className="text-sm space-y-1">
          <p className="flex items-center gap-1.5">
            {chain.ok ? <ShieldCheck className="h-4 w-4 text-status-pass" /> : <ShieldAlert className="h-4 w-4 text-destructive" />}
            {chain.ok
              ? `Verified: ${chain.events} recorded events, each chained to the one before it.`
              : `Not verified: ${chain.problem} (event #${chain.first_bad_seq}).`}
          </p>
          {chain.head_hash && <p className="font-mono text-xs break-all text-muted-foreground">Chain head: {chain.head_hash}</p>}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">Audit trail not available.</p>
      )}
    </section>
  );
}

// ---------------------------------------------------------------- exports

function slug(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 50) || "item";
}

function save(bytes: Uint8Array | string, name: string, type: string) {
  const blob = new Blob([bytes as BlobPart], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

export function ExportButtons({ auditId, model, fileBase }: { auditId: string; model: ReportModel | null; fileBase: string }) {
  const [busy, setBusy] = useState<null | "md" | "zip">(null);

  const markdown = async () => {
    if (!model) return;
    setBusy("md");
    try {
      const md = buildReportMarkdown(model);
      save(md, `${fileBase}.md`, "text/markdown");
      await logReportExport(auditId, "markdown", await sha256Hex(md), model.chain?.head_hash ?? null);
    } finally {
      setBusy(null);
    }
  };

  const bundle = async () => {
    if (!model) return;
    setBusy("zip");
    const tid = toast.loading("Building evidence bundle…");
    try {
      const md = buildReportMarkdown(model);
      const entries: ZipEntry[] = [{ name: "report.md", data: md }];
      const manifest: any[] = [];
      // Text evidence in batches; files from storage.
      const ids = model.evidenceIndex.map((e) => e.id);
      const texts = new Map<string, string>();
      for (let i = 0; i < ids.length; i += 100) {
        const { data, error } = await supabase.from("evidence").select("id, content_text").in("id", ids.slice(i, i + 100));
        if (error) throw new Error(error.message);
        for (const r of data ?? []) if (r.content_text != null) texts.set(r.id, r.content_text);
      }
      for (const e of model.evidenceIndex) {
        const base = `evidence/${e.label}-${slug(e.title)}`;
        if (e.purged_at) {
          manifest.push({ ...e, file: null, purged: true });
          continue;
        }
        if (e.storage_path) {
          const { data, error } = await supabase.storage.from("evidence").download(e.storage_path);
          if (error || !data) {
            manifest.push({ ...e, file: null, error: error?.message ?? "download failed" });
            continue;
          }
          const bytes = new Uint8Array(await data.arrayBuffer());
          const ext = e.storage_path.includes(".") ? e.storage_path.slice(e.storage_path.lastIndexOf(".")) : "";
          const name = `${base}${ext}`;
          entries.push({ name, data: bytes });
          const got = await sha256Hex(bytes);
          manifest.push({ ...e, file: name, hash_matches: got === e.sha256 });
          if (texts.has(e.id)) entries.push({ name: `${base}.note.txt`, data: texts.get(e.id)! });
        } else {
          const text = texts.get(e.id) ?? "";
          const name = `${base}.${text.trimStart().startsWith("{") ? "json" : "txt"}`;
          entries.push({ name, data: text });
          manifest.push({ ...e, file: name, hash_matches: (await sha256Hex(text)) === e.sha256 });
        }
      }
      const events = await fetchAuditEvents(auditId).catch(() => []);
      entries.push({ name: "audit-trail.json", data: JSON.stringify({ chain: model.chain, events }, null, 2) });
      entries.push({
        name: "manifest.json",
        data: JSON.stringify({ audit: model.audit.title, generated_at: model.generatedAt, chain_head: model.chain?.head_hash ?? null, evidence: manifest }, null, 2),
      });
      entries.push({
        name: "README.txt",
        data: [
          `Evidence bundle for "${model.audit.title}", generated ${model.generatedAt}.`,
          "",
          "report.md          the report",
          "evidence/          one file per evidence item, named by its reference (E1, E2…) in the report",
          "manifest.json      each item's SHA-256 as recorded when it was captured",
          "audit-trail.json   the audit's hash-chained event log",
          "",
          "To check a file hasn't changed since capture:  shasum -a 256 evidence/<file>",
          "and compare with its sha256 in manifest.json (and in the report's appendix).",
          `Audit trail chain head at export: ${model.chain?.head_hash ?? "n/a"}`,
        ].join("\n"),
      });
      const zip = buildZip(entries);
      save(zip, `${fileBase}-evidence.zip`, "application/zip");
      await logReportExport(auditId, "evidence_bundle", await sha256Hex(zip), model.chain?.head_hash ?? null);
      const bad = manifest.filter((m) => m.hash_matches === false || m.error);
      if (bad.length) toast.warning(`Bundle saved, but ${bad.length} item(s) didn't match their recorded hash or couldn't be downloaded. See manifest.json.`, { id: tid });
      else toast.success(`Bundle saved: ${model.evidenceIndex.length} evidence item(s), all hashes match.`, { id: tid });
    } catch (e: any) {
      toast.error(e?.message ?? "Couldn't build the bundle.", { id: tid });
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <Button variant="outline" onClick={markdown} disabled={!model || !!busy}>
        {busy === "md" ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <FileText className="h-4 w-4 mr-1" />} Markdown
      </Button>
      <Button variant="outline" onClick={bundle} disabled={!model || !!busy}>
        {busy === "zip" ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <FileArchive className="h-4 w-4 mr-1" />} Evidence bundle
      </Button>
    </>
  );
}

// ---------------------------------------------------------------- frameworks

export function FrameworkSection({ frameworks }: { frameworks: FrameworkSummary[] }) {
  const [shown, setShown] = useState<string | null>(null);
  if (!frameworks.length) return null;
  const active = frameworks.find((f) => f.framework === shown) ?? frameworks[0];
  return (
    <section className="mb-8">
      <div className="flex items-center gap-3 border-b pb-2 mb-3 flex-wrap">
        <h2 className="text-lg font-semibold">Findings by framework</h2>
        <div className="flex gap-1 print:hidden ml-auto">
          {frameworks.map((f) => (
            <Button key={f.framework} size="sm" variant={f.framework === active.framework ? "default" : "outline"} className="h-7 text-xs" onClick={() => setShown(f.framework)}>
              {f.framework.replace("OWASP ", "").replace(" (2025)", "")}
            </Button>
          ))}
        </div>
      </div>
      <p className="text-xs text-muted-foreground mb-2">
        Each check is tagged with the controls it gives evidence for. A tag means evidence toward a control, not that the control is satisfied.
      </p>
      {frameworks.map((fw) => (
        <div key={fw.framework} className={fw.framework === active.framework ? "" : "hidden print:block"}>
          <h3 className="text-sm font-semibold mt-3 mb-1">{fw.framework}</h3>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-muted-foreground"><th className="py-1">Control</th><th>Checks</th><th>Pass</th><th>Fail</th><th>Not assessed</th><th>Failing checks</th></tr>
            </thead>
            <tbody>
              {fw.controls.map((c) => (
                <tr key={c.control_id} className="border-t border-border/50 align-top">
                  <td className="py-1"><span className="font-mono">{c.control_id}</span> <span className="text-muted-foreground">{c.control_title}</span></td>
                  <td className="tabular-nums">{c.checks}</td>
                  <td className="tabular-nums text-status-pass">{c.pass}</td>
                  <td className={`tabular-nums ${c.fail ? "text-status-fail font-semibold" : ""}`}>{c.fail}</td>
                  <td className="tabular-nums text-muted-foreground">{c.other}</td>
                  <td>{c.failing.join("; ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </section>
  );
}

export function ControlTags({ tags }: { tags: string[] | undefined }) {
  if (!tags?.length) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map((t) => (
        <span key={t} className="rounded border border-border px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">{t}</span>
      ))}
    </div>
  );
}

export function LinkedCodeFindings({ rows }: { rows: ReportExtras["linkedCode"] | undefined }) {
  if (!rows?.length) return null;
  return (
    <ul className="text-xs space-y-0.5">
      {rows.map((r) => (
        <li key={r.id}>
          <span className="font-semibold uppercase">{r.verdict === "confirmed" ? r.severity ?? "confirmed" : "needs validation"}</span> {r.title}
          <span className="text-muted-foreground"> (details under Code-level findings)</span>
        </li>
      ))}
    </ul>
  );
}
