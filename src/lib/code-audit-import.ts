// Apply a verified runner callback to the database. The route has already
// checked the HMAC signature; this module re-validates the payload shape and
// enforces run state transitions, so a replayed or out-of-order callback
// can't rewrite a finished run.

type Db = { from: (table: string) => any };

const RUN_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VERDICTS = new Set(["confirmed", "needs_validation", "rejected"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "informational"]);
const MAX_FINDINGS = 500;
const MAX_LEDGER_UNITS = 5000;
const MAX_MD = 400_000;
const MAX_RAW_JSON = 60_000;

export type ImportResult =
  { ok: true; status: number; message: string } | { ok: false; status: number; error: string };

function str(v: unknown, max: number): string | null {
  if (typeof v !== "string") return null;
  const s = v.replace(/\u0000/g, "");
  return s.length > max ? s.slice(0, max) + "…" : s;
}

function jsonCapped(v: unknown, max: number): unknown {
  if (v === undefined) return null;
  const s = JSON.stringify(v);
  if (s.length <= max) return v;
  return { truncated: true, preview: s.slice(0, max) };
}

export type NormalizedFinding = {
  fingerprint: string;
  verdict: "confirmed" | "needs_validation" | "rejected";
  severity: string | null;
  title: string;
  description: string | null;
  root_cause: string | null;
  trace: unknown;
  evidence: unknown;
  remediation: unknown;
  blockers: unknown;
  validation_plan: unknown;
  raw: unknown;
};

/** Validate and normalise the skill's findings.json records. */
export function normalizeFindings(records: unknown): {
  findings: NormalizedFinding[];
  errors: string[];
} {
  const errors: string[] = [];
  const findings: NormalizedFinding[] = [];
  if (!Array.isArray(records)) return { findings, errors: ["findings must be an array"] };
  if (records.length > MAX_FINDINGS)
    return { findings, errors: [`more than ${MAX_FINDINGS} findings`] };
  const seen = new Set<string>();
  records.forEach((r: any, i) => {
    if (!r || typeof r !== "object" || Array.isArray(r)) return errors.push(`[${i}] not an object`);
    const fingerprint = str(r.fingerprint, 300);
    const title = str(r.title, 500);
    const verdict = String(r.verdict ?? "");
    if (!fingerprint) return errors.push(`[${i}] missing fingerprint`);
    if (!title) return errors.push(`[${i}] missing title`);
    if (!VERDICTS.has(verdict))
      return errors.push(`[${i}] invalid verdict "${verdict.slice(0, 40)}"`);
    if (seen.has(fingerprint)) return errors.push(`[${i}] duplicate fingerprint`);
    seen.add(fingerprint);
    const sevRaw = String(r?.severity?.overall_severity ?? "").toLowerCase();
    findings.push({
      fingerprint,
      verdict: verdict as NormalizedFinding["verdict"],
      severity: verdict === "confirmed" && SEVERITIES.has(sevRaw) ? sevRaw : null,
      title,
      description: str(r.description, 20_000),
      root_cause: str(r.root_cause ?? r.claimed_root_cause, 10_000),
      trace: jsonCapped(r.trace, 30_000),
      evidence: jsonCapped(r.evidence, 30_000),
      remediation: jsonCapped(r.remediation, 20_000),
      blockers: jsonCapped(r.blockers, 10_000),
      validation_plan: jsonCapped(r.validation_plan, 20_000),
      raw: jsonCapped(r, MAX_RAW_JSON),
    });
  });
  return { findings, errors };
}

/** What the auditor sees as "what was reviewed". Keeps the ledger small. */
export function summarizeLedger(units: unknown): { ok: boolean; summary: any; error?: string } {
  if (!Array.isArray(units))
    return { ok: false, summary: null, error: "coverage ledger must be an array" };
  if (units.length > MAX_LEDGER_UNITS)
    return { ok: false, summary: null, error: "coverage ledger too large" };
  const byStatus: Record<string, number> = {};
  const unitsOut = units.slice(0, 500).map((u: any) => {
    const status = String(u?.status ?? "unknown").slice(0, 40);
    byStatus[status] = (byStatus[status] ?? 0) + 1;
    return {
      surface: str(u?.surface, 300),
      boundary: str(u?.boundary, 300),
      attack_class: str(u?.attack_class, 200),
      status,
      reviewed_paths: Array.isArray(u?.reviewed_paths)
        ? u.reviewed_paths.slice(0, 50).map((p: unknown) => str(p, 300))
        : [],
      unresolved: jsonCapped(u?.unresolved, 2_000),
    };
  });
  for (const u of units.slice(500) as any[]) {
    const status = String(u?.status ?? "unknown").slice(0, 40);
    byStatus[status] = (byStatus[status] ?? 0) + 1;
  }
  return { ok: true, summary: { total: units.length, byStatus, units: unitsOut } };
}

const PHASES = new Set(["starting", "cloning", "auditing", "validating", "reporting"]);
const count = (v: unknown) => (Number.isInteger(v) && (v as number) >= 0 && (v as number) < 1_000_000 ? (v as number) : null);

/**
 * Progress text comes from the audit agent, which reads hostile code, so it's
 * treated as untrusted: known phases only, short plain-text detail, numbers only.
 */
export function sanitizeProgress(p: any): Record<string, unknown> | null {
  if (!p || !PHASES.has(p.phase)) return null;
  const detail =
    typeof p.detail === "string"
      ? p.detail.replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, 160) || null
      : null;
  return {
    phase: p.phase,
    detail,
    agents: count(p.agents),
    steps: count(p.steps),
    todosDone: count(p.todosDone),
    todosTotal: count(p.todosTotal),
  };
}

export async function applyCallback(
  payload: any,
  deps: { db: Db; now?: () => Date },
): Promise<ImportResult> {
  const now = (deps.now ?? (() => new Date()))().toISOString();
  if (!payload || typeof payload !== "object")
    return { ok: false, status: 400, error: "invalid body" };
  const runId = String(payload.runId ?? "");
  if (!RUN_ID_RE.test(runId)) return { ok: false, status: 400, error: "invalid runId" };

  const { data: run, error } = await deps.db
    .from("code_audit_runs")
    .select("id, audit_id, status")
    .eq("id", runId)
    .maybeSingle();
  if (error) return { ok: false, status: 500, error: "lookup failed" };
  if (!run) return { ok: false, status: 404, error: "unknown run" };
  const open = run.status === "queued" || run.status === "dispatching" || run.status === "running";

  if (payload.event === "started") {
    if (!open) return { ok: true, status: 200, message: "ignored: run already finished" };
    await deps.db
      .from("code_audit_runs")
      .update({
        status: "running",
        started_at: now,
        runner_machine_id: str(payload.machineId, 100),
      })
      .eq("id", runId);
    return { ok: true, status: 200, message: "started" };
  }

  if (payload.event === "progress") {
    if (!open) return { ok: true, status: 200, message: "ignored: run already finished" };
    const progress = sanitizeProgress(payload);
    if (!progress) return { ok: false, status: 400, error: "invalid progress" };
    await deps.db
      .from("code_audit_runs")
      .update({
        progress,
        progress_at: now,
        ...(run.status === "running" ? {} : { status: "running", started_at: now }),
      })
      .eq("id", runId);
    return { ok: true, status: 200, message: "progress" };
  }

  if (payload.event === "failed") {
    if (!open) return { ok: true, status: 200, message: "ignored: run already finished" };
    await deps.db
      .from("code_audit_runs")
      .update({
        status: "failed",
        finished_at: now,
        error: str(payload.error, 2_000) ?? "runner reported a failure",
        agents_used: Number.isInteger(payload.agentsUsed) ? payload.agentsUsed : null,
      })
      .eq("id", runId);
    return { ok: true, status: 200, message: "failed recorded" };
  }

  if (payload.event !== "completed") return { ok: false, status: 400, error: "unknown event" };
  // Idempotent: a completed run is never re-imported (replay protection).
  if (!open) return { ok: true, status: 200, message: "ignored: run already finished" };

  const v = payload.validators ?? {};
  const validatorsPassed =
    /^PASS\b/.test(String(v.findings ?? "")) && /^PASS\b/.test(String(v.ledger ?? ""));
  const { findings, errors } = normalizeFindings(payload.findings);
  const ledger = summarizeLedger(payload.coverageLedger);

  if (!validatorsPassed || errors.length > 0 || !ledger.ok) {
    const why = [
      !validatorsPassed
        ? `skill validators did not pass (findings: ${String(v.findings ?? "missing").slice(0, 200)}; ledger: ${String(v.ledger ?? "missing").slice(0, 200)})`
        : null,
      errors.length ? `findings rejected: ${errors.slice(0, 5).join("; ")}` : null,
      !ledger.ok ? ledger.error : null,
    ]
      .filter(Boolean)
      .join(" | ");
    await deps.db
      .from("code_audit_runs")
      .update({ status: "failed", finished_at: now, error: why.slice(0, 2_000) })
      .eq("id", runId);
    return { ok: false, status: 422, error: why };
  }

  if (findings.length > 0) {
    const rows = findings.map((f) => ({ ...f, run_id: runId, audit_id: run.audit_id }));
    const { error: insErr } = await deps.db
      .from("code_audit_findings")
      .upsert(rows, { onConflict: "run_id,fingerprint" });
    if (insErr) return { ok: false, status: 500, error: "could not store findings" };
  }

  const count = (verdict: string) => findings.filter((f) => f.verdict === verdict).length;
  const incomplete = payload.runStatus !== "complete";
  await deps.db
    .from("code_audit_runs")
    .update({
      status: incomplete ? "incomplete" : "done",
      finished_at: now,
      incomplete_reason: incomplete
        ? (str(payload.incompleteReason, 500) ?? "runner reported an incomplete run")
        : null,
      source_commit: str(payload.sourceCommit, 64),
      agents_used: Number.isInteger(payload.agentsUsed) ? payload.agentsUsed : null,
      coverage: ledger.summary,
      report_md: str(payload.reportMd, MAX_MD),
      findings_detail_md: str(payload.findingsDetailMd, MAX_MD),
      needs_validation_md: str(payload.needsValidationMd, MAX_MD),
      confirmed_count: count("confirmed"),
      needs_validation_count: count("needs_validation"),
      rejected_count: count("rejected"),
    })
    .eq("id", runId);

  return { ok: true, status: 200, message: `imported ${findings.length} finding(s)` };
}
