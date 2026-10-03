// "Run full audit" (build plan, phase 1c).
//
// A full audit is a parent scan_run. The browser opens it, runs each scanner
// in turn with parentRunId set (each scanner saves its own child run, results
// and evidence), then closes it with the list of steps. Steps that could not
// run are recorded as `not_run` results on the parent, so the gap shows up in
// history and in the report instead of disappearing.
//
// Why the browser drives it: each scanner is already a server function sized
// for a Worker request. Running them one request at a time keeps every step
// inside Worker limits. Scheduled runs (phase 4) will need a server-side
// driver (Cloudflare Workflows), and can reuse the same open/close functions.
import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export type FullAuditStepScanner = "website" | "supabase" | "repo" | "ai_endpoint" | "code_audit";

export type FullAuditStep = {
  scanner: FullAuditStepScanner;
  target: string | null;
  outcome: "done" | "failed" | "not_run" | "started";
  /** Why it failed or didn't run. */
  reason?: string | null;
};

const SCANNERS: FullAuditStepScanner[] = ["website", "supabase", "repo", "ai_endpoint", "code_audit"];

async function ownAudit(supabase: any, auditId: string, userId: string) {
  const { data } = await supabase.from("audits").select("id, created_by, title").eq("id", auditId).maybeSingle();
  return data && data.created_by === userId ? data : null;
}

export const startFullAudit = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string }) => {
    if (!input || typeof input.auditId !== "string") throw new Error("auditId required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const audit = await ownAudit(supabase, data.auditId, userId);
    if (!audit) return { ok: false as const, error: "Audit not found or access denied." };
    const { data: run, error } = await supabase
      .from("scan_runs")
      .insert({ audit_id: data.auditId, scanner: "full", trigger: "manual", status: "running", target: audit.title })
      .select("id")
      .single();
    if (error || !run) {
      return {
        ok: false as const,
        error: `Couldn't start the run: ${error?.message ?? "unknown error"}. If this is a new install, push the latest database migrations.`,
      };
    }
    return { ok: true as const, runId: (run as { id: string }).id };
  });

/** Pure: the parent run's summary from its steps and its child runs. Exported for tests. */
export function summarizeFullAudit(
  steps: FullAuditStep[],
  children: { scanner: string; status: string; summary: any }[],
) {
  const counts: Record<string, number> = {};
  const changes: Record<string, number> = {};
  let evidence = 0;
  for (const c of children) {
    for (const [k, v] of Object.entries((c.summary?.counts ?? {}) as Record<string, number>)) counts[k] = (counts[k] ?? 0) + v;
    for (const [k, v] of Object.entries((c.summary?.changes ?? {}) as Record<string, number>)) changes[k] = (changes[k] ?? 0) + v;
    evidence += Number(c.summary?.evidence ?? 0);
  }
  const notRun = steps.filter((s) => s.outcome === "not_run" || s.outcome === "failed");
  if (notRun.length) counts.not_run = (counts.not_run ?? 0) + notRun.length;
  const status: "done" | "partial" = notRun.length || counts.inconclusive ? "partial" : "done";
  return { status, summary: { counts, changes, evidence, steps, child_runs: children.length } };
}

export const finishFullAudit = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string; runId: string; steps: FullAuditStep[] }) => {
    if (!input || typeof input.auditId !== "string" || typeof input.runId !== "string") throw new Error("Invalid input");
    if (!Array.isArray(input.steps) || input.steps.length > 50) throw new Error("Invalid steps");
    const steps = input.steps.map((s) => {
      if (!SCANNERS.includes(s?.scanner)) throw new Error("Invalid step scanner");
      if (!["done", "failed", "not_run", "started"].includes(s?.outcome)) throw new Error("Invalid step outcome");
      return {
        scanner: s.scanner,
        target: typeof s.target === "string" ? s.target.slice(0, 2048) : null,
        outcome: s.outcome,
        reason: typeof s.reason === "string" ? s.reason.slice(0, 1000) : null,
      } as FullAuditStep;
    });
    return { ...input, steps };
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const audit = await ownAudit(supabase, data.auditId, userId);
    if (!audit) return { ok: false as const, error: "Audit not found or access denied." };

    const { data: parent } = await supabase
      .from("scan_runs")
      .select("id, scanner, status")
      .eq("id", data.runId)
      .eq("audit_id", data.auditId)
      .maybeSingle();
    if (!parent || parent.scanner !== "full") return { ok: false as const, error: "Run not found." };
    if (parent.status !== "running") return { ok: false as const, error: "This run is already closed." };

    const { data: children, error: cErr } = await supabase
      .from("scan_runs")
      .select("scanner, status, summary")
      .eq("parent_run_id", data.runId);
    if (cErr) return { ok: false as const, error: cErr.message };

    // Steps that didn't run become visible gaps on the parent run.
    const gaps = data.steps.filter((s) => s.outcome === "not_run" || s.outcome === "failed");
    if (gaps.length) {
      const { error } = await supabase.from("scan_results").insert(
        gaps.map((s) => ({
          run_id: data.runId,
          audit_id: data.auditId,
          checklist_key: `step:${s.scanner}`,
          scanner: s.scanner,
          status: "not_run",
          stored: false,
          notes: `${s.outcome === "failed" ? "Failed" : "Not run"}${s.target ? ` (${s.target})` : ""}: ${s.reason ?? "no reason given"}`,
        })),
      );
      if (error) return { ok: false as const, error: error.message };
    }

    const { status, summary } = summarizeFullAudit(data.steps, (children ?? []) as any[]);
    const { error: uErr } = await supabase
      .from("scan_runs")
      .update({ status, finished_at: new Date().toISOString(), summary })
      .eq("id", data.runId);
    if (uErr) return { ok: false as const, error: uErr.message };
    return { ok: true as const, status, summary };
  });
