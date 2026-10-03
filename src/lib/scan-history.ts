// Run history for every scanner (build plan, phase 1b).
//
// A scanner opens a run once it has its results, records each result, then
// finishes the run. Three database calls per scan: load the previous decisive
// results for the audit, insert the run, insert all results in one batch and
// close the run. Workers have a subrequest budget, so nothing here is per-item.
//
// History is a record, not a gate: if it can't be written (for example the
// migration hasn't been pushed yet) the scan still writes audit_findings and
// the failure is logged and reported back in the run summary instead.
import type { SupabaseClient } from "@supabase/supabase-js";
import { prepareEvidenceRows, type EvidenceInput } from "./evidence";

export type ScannerName = "website" | "supabase" | "repo" | "dependencies" | "ai_endpoint" | "code_audit" | "full";
export type RunTrigger = "manual" | "full" | "schedule" | "retest";
export type ResultStatus = "pass" | "fail" | "warn" | "na" | "inconclusive" | "not_run";
export type ResultChange = "new" | "regressed" | "unchanged" | "fixed" | "unverified";

export type PreviousResult = { status: "pass" | "fail"; run_id: string | null };

export type RecordedResult = {
  checklist_item_id: string | null;
  checklist_key: string | null;
  status: ResultStatus;
  notes?: string | null;
  /** Whether the result was written to audit_findings. */
  stored: boolean;
  /** Refs of the EvidenceInput items this result rests on. */
  evidence?: string[];
};

export type RunOptions = {
  auditId: string;
  scanner: ScannerName;
  target?: string | null;
  trigger?: RunTrigger;
  parentRunId?: string | null;
};

export type HistorySummary = {
  run_id: string | null;
  counts: Partial<Record<ResultStatus, number>>;
  changes: Partial<Record<ResultChange, number>>;
  evidence_count?: number;
  /** Set when history could not be saved; the scan itself still completed. */
  history_error?: string;
};

const MAX_NOTES = 20_000;

/**
 * How a result compares with the latest earlier pass/fail for the same item.
 * Exported for tests.
 */
export function classifyChange(status: ResultStatus, prev: PreviousResult | null | undefined): ResultChange | null {
  if (status === "fail") {
    if (!prev) return "new";
    return prev.status === "pass" ? "regressed" : "unchanged";
  }
  if (status === "pass") {
    if (!prev) return null;
    return prev.status === "fail" ? "fixed" : "unchanged";
  }
  if (status === "inconclusive" || status === "not_run") return prev ? "unverified" : null;
  return null; // warn / na: no pass/fail claim either way
}

function itemKey(r: { checklist_item_id: string | null; checklist_key: string | null }): string | null {
  if (r.checklist_item_id) return `id:${r.checklist_item_id}`;
  if (r.checklist_key) return `key:${r.checklist_key}`;
  return null;
}

async function loadPrevious(
  supabase: SupabaseClient<any>,
  auditId: string,
): Promise<Map<string, PreviousResult>> {
  const { data, error } = await supabase
    .from("scan_results")
    .select("checklist_item_id, checklist_key, status, run_id, created_at")
    .eq("audit_id", auditId)
    .in("status", ["pass", "fail"])
    .order("created_at", { ascending: false })
    .limit(5000);
  if (error) throw new Error(error.message);
  const latest = new Map<string, PreviousResult & { at: string }>();
  for (const r of (data ?? []) as any[]) {
    const k = itemKey(r);
    if (!k) continue;
    const at = String(r.created_at ?? "");
    const cur = latest.get(k);
    // Don't rely on the database order alone; keep the newest per item.
    if (!cur || at > cur.at) latest.set(k, { status: r.status, run_id: r.run_id ?? null, at });
  }
  return new Map([...latest].map(([k, v]) => [k, { status: v.status, run_id: v.run_id }]));
}

/**
 * Save one scanner run and its results. Never throws: history problems are
 * returned in `history_error` so the scan's own response still goes back.
 */
export async function saveScanRun(
  supabase: SupabaseClient<any>,
  opts: RunOptions,
  results: RecordedResult[],
  extras: { summary?: Record<string, unknown>; evidence?: EvidenceInput[] } = {},
): Promise<HistorySummary> {
  const extraSummary = extras.summary ?? {};
  const counts: HistorySummary["counts"] = {};
  const changes: HistorySummary["changes"] = {};
  let runId: string | null = null;
  try {
    const previous = await loadPrevious(supabase, opts.auditId);

    const rows = results.map((r) => {
      const k = itemKey(r);
      const prev = k ? previous.get(k) : undefined;
      const change = classifyChange(r.status, prev);
      counts[r.status] = (counts[r.status] ?? 0) + 1;
      if (change) changes[change] = (changes[change] ?? 0) + 1;
      return {
        audit_id: opts.auditId,
        checklist_item_id: r.checklist_item_id,
        checklist_key: r.checklist_key,
        scanner: opts.scanner,
        status: r.status,
        change,
        previous_status: prev?.status ?? null,
        previous_run_id: prev?.run_id ?? null,
        stored: r.stored,
        notes: r.notes ? String(r.notes).slice(0, MAX_NOTES) : null,
      };
    });

    const { data: run, error: runErr } = await supabase
      .from("scan_runs")
      .insert({
        audit_id: opts.auditId,
        scanner: opts.scanner,
        trigger: opts.trigger ?? "manual",
        parent_run_id: opts.parentRunId ?? null,
        target: opts.target ? String(opts.target).slice(0, 2048) : null,
      })
      .select("id")
      .single();
    if (runErr || !run) throw new Error(runErr?.message ?? "could not create scan run");
    runId = (run as { id: string }).id;

    // Evidence first, so each result can carry the ids of what it rests on.
    let idByRef = new Map<string, string>();
    let evidenceCount = 0;
    const wanted = (extras.evidence ?? []).filter((e) => results.some((r) => r.evidence?.includes(e.ref)));
    if (wanted.length) {
      const prepared = await prepareEvidenceRows(opts.auditId, runId!, wanted);
      const { error: evErr } = await supabase.from("evidence").insert(prepared.rows);
      if (evErr) throw new Error(`evidence: ${evErr.message}`);
      idByRef = prepared.idByRef;
      evidenceCount = prepared.rows.length;
    }

    let status: "done" | "partial" = "done";
    if (rows.length) {
      const { error: resErr } = await supabase.from("scan_results").insert(
        rows.map((r, i) => ({
          ...r,
          run_id: runId,
          evidence_ids: (results[i].evidence ?? []).map((ref) => idByRef.get(ref)).filter(Boolean),
        })),
      );
      if (resErr) throw new Error(resErr.message);
    }
    if (counts.inconclusive || counts.not_run) status = "partial";

    const { error: closeErr } = await supabase
      .from("scan_runs")
      .update({ status, finished_at: new Date().toISOString(), summary: { counts, changes, evidence: evidenceCount, ...extraSummary } })
      .eq("id", runId);
    if (closeErr) throw new Error(closeErr.message);

    return { run_id: runId, counts, changes, evidence_count: evidenceCount };
  } catch (e: any) {
    const msg = e?.message ?? String(e);
    console.error(`[scan-history] ${opts.scanner} run for audit ${opts.auditId} not saved:`, msg);
    if (runId) {
      // Best effort: don't leave a run stuck in "running".
      await supabase
        .from("scan_runs")
        .update({ status: "failed", finished_at: new Date().toISOString(), summary: { counts, changes, error: msg } })
        .eq("id", runId)
        .then(() => undefined, () => undefined);
    }
    return { run_id: runId, counts, changes, history_error: msg };
  }
}
