// Full-audit pipeline engine. Server only (service-role client).
//
// One call to advancePipeline() runs exactly one stage, so every call fits in
// a Worker request or a Workflow step. Two drivers call it:
//   - FullAuditWorkflow (exports.cloudflare.ts): durable, runs with the tab
//     closed. Credentials are sealed in pipeline_secrets for the run.
//   - The browser (advanceFullAudit server function), when the Workflow
//     binding isn't configured (local dev, Lovable preview). Credentials stay
//     in the tab and come with each call.
// The deep audit runs on its own machine: its stage waits, and the runner's
// callback (onCodeAuditFinished) settles it and closes the run.
import {
  gateStage,
  nextStage,
  pipelineSettled,
  onlyWaiting,
  stagesToSteps,
  deepAuditFocus,
  suggestTargets,
  SCANNER_LABEL,
  type CredPresence,
  type StageRow,
} from "./pipeline";
import { summarizeFullAudit } from "./full-audit.functions";
import { websiteScanCore } from "./scan.functions";
import { surfaceScanCore } from "./attack-surface.functions";
import { supabaseScanCore } from "./supabase-scan.functions";
import { repoScanCore } from "./repo-scan.functions";
import { aiScanCore } from "./ai-scan.functions";
import { aiDeepCore } from "./ai-deep.functions";
import { startCodeAuditCore } from "./code-audit.functions";
import { draftSummaryCore } from "./report-summary.functions";
import {
  synthesize,
  synthesisFacts,
  type SynthGap,
  type SynthResult,
  type SynthItem,
  type SynthCodeFinding,
  type RepoLeads,
} from "./pipeline-synthesis";
import { sealJson, openJson, type CodeAuditProfile } from "./code-audit-contract";

export type PipelineCreds = {
  githubToken?: string | null;
  anonKey?: string | null;
  serviceRoleKey?: string | null;
  managementPat?: string | null;
  aiToken?: string | null;
};

export type PipelineRunOptions = { profile: CodeAuditProfile };

const SECRETS_LABEL = "pipeline-secrets";
const SECRETS_TTL_MS = 6 * 3600_000;

export function credPresence(c: PipelineCreds | null | undefined): CredPresence {
  const has = (v?: string | null) => !!v && v.trim().length > 0;
  return {
    github: has(c?.githubToken),
    supabaseKeys: has(c?.anonKey) && has(c?.serviceRoleKey),
    supabasePat: has(c?.managementPat),
    aiToken: has(c?.aiToken),
  };
}

export function secretsKey(): string | null {
  const k = process.env.FULL_AUDIT_SECRETS_KEY;
  return k && k.length >= 32 ? k : null;
}

export async function storeRunSecrets(admin: any, runId: string, creds: PipelineCreds) {
  const key = secretsKey();
  if (!key) throw new Error("FULL_AUDIT_SECRETS_KEY isn't set.");
  const sealed = await sealJson(creds, key, SECRETS_LABEL);
  const { error } = await admin
    .from("pipeline_secrets")
    .upsert({ run_id: runId, sealed, expires_at: new Date(Date.now() + SECRETS_TTL_MS).toISOString() });
  if (error) throw new Error(error.message);
}

export async function loadRunSecrets(admin: any, runId: string): Promise<PipelineCreds> {
  const key = secretsKey();
  if (!key) return {};
  const { data } = await admin.from("pipeline_secrets").select("sealed, expires_at").eq("run_id", runId).maybeSingle();
  if (!data || Date.parse(data.expires_at) < Date.now()) return {};
  try {
    return await openJson<PipelineCreds>(data.sealed, key, SECRETS_LABEL);
  } catch {
    return {};
  }
}

export async function dropRunSecrets(admin: any, runId: string) {
  await admin.from("pipeline_secrets").delete().eq("run_id", runId);
}

type RunCtx = {
  run: { id: string; audit_id: string; created_by: string; status: string; pipeline_driver: string | null; summary: any };
  audit: { id: string; website_url: string | null; created_by: string };
  stages: StageRow[];
};

export async function loadRun(admin: any, runId: string): Promise<RunCtx | null> {
  const { data: run } = await admin
    .from("scan_runs")
    .select("id, audit_id, created_by, status, pipeline_driver, summary")
    .eq("id", runId)
    .maybeSingle();
  if (!run) return null;
  const { data: audit } = await admin.from("audits").select("id, website_url, created_by").eq("id", run.audit_id).maybeSingle();
  if (!audit) return null;
  const { data: stages } = await admin.from("pipeline_stages").select("*").eq("run_id", runId).order("position");
  return { run, audit, stages: (stages ?? []) as StageRow[] };
}

async function setStage(admin: any, runId: string, key: string, patch: Partial<StageRow> & Record<string, unknown>) {
  await admin.from("pipeline_stages").update(patch).eq("run_id", runId).eq("key", key);
}

type Outcome = { status: "done" | "failed" | "waiting"; reason: string | null; output?: Record<string, unknown> };

/** Run one scanner for a stage. Never throws: errors become a failed stage. */
async function execute(admin: any, ctx: RunCtx, stage: StageRow, creds: PipelineCreds, opts: PipelineRunOptions): Promise<Outcome> {
  const owner = ctx.audit.created_by;
  const auditId = ctx.audit.id;
  const parentRunId = ctx.run.id;
  const core = { checkQuota: false };
  const meta = stage.meta ?? {};
  try {
    switch (stage.scanner) {
      case "website": {
        const r: any = await websiteScanCore(admin, { auditId, parentRunId }, { checkQuota: false, trigger: "full", createdBy: owner });
        return { status: "done", reason: `${r.passes} pass · ${r.fails} fail${r.inconclusive ? ` · ${r.inconclusive} unverified` : ""}` };
      }
      case "surface": {
        const r: any = await surfaceScanCore(admin, { auditId, parentRunId }, { checkQuota: false, trigger: "full", createdBy: owner });
        if (!r.ok) return { status: "failed", reason: r.error };
        return {
          status: "done",
          reason: `${r.subdomains.length} host(s) in certificate logs${r.subdomainError ? ` (${r.subdomainError})` : ""}`,
          output: { domain: r.domain, hosts: (r.subdomains as string[]).slice(0, 200) },
        };
      }
      case "supabase": {
        const r: any = await supabaseScanCore(
          admin,
          owner,
          {
            auditId,
            projectUrl: stage.target!,
            anonKey: creds.anonKey!.trim(),
            serviceRoleKey: creds.serviceRoleKey!.trim(),
            managementPat: creds.managementPat?.trim() || null,
            appUrl: ctx.audit.website_url,
            parentRunId,
          } as any,
          core,
        );
        if (!r.ok) return { status: "failed", reason: r.error };
        return { status: "done", reason: `${r.passes} pass · ${r.fails} fail${r.patUsed ? "" : " · no access token, so database checks were limited"}` };
      }
      case "repo": {
        const r: any = await repoScanCore(
          admin,
          owner,
          { auditId, repoUrl: stage.target!, token: creds.githubToken!.trim(), appUrl: ctx.audit.website_url, parentRunId },
          core,
        );
        if (!r.ok) return { status: "failed", reason: r.error };
        const codeReadable = !!r.codeAccess?.treeRead && (r.codeAccess?.filesRead ?? 0) > 0;
        const reason = codeReadable
          ? `${r.findings?.length ?? 0} secret hit(s) · deps ${r.dep?.status ?? "not checked"} · ${r.codeAccess.filesRead} file(s) read`
          : "Commit history checked, but no source files could be read. The token needs Contents: Read-only.";
        return {
          status: "done",
          reason,
          output: {
            codeReadable,
            leads: r.leads ?? null,
            aiEndpoints: ((r.aiEndpoints ?? []) as any[]).slice(0, 20).map((e) => ({ url: e.url, promptField: e.promptField })),
          },
        };
      }
      case "ai_endpoint": {
        const field = typeof meta.prompt_field === "string" && meta.prompt_field ? (meta.prompt_field as string) : "prompt";
        const r: any = await aiScanCore(
          admin,
          owner,
          { auditId, endpointUrl: stage.target!, promptField: field, authToken: creds.aiToken?.trim() || null, parentRunId },
          core,
        );
        if (!r.ok) return { status: "failed", reason: r.error };
        const c = r.counts;
        const total = (r.results ?? []).length;
        return {
          status: "done",
          reason: `${c.passes} pass · ${c.fails} fail · ${c.inconclusive} unverified`,
          output: { reachable: !(total > 0 && c.errors === total) },
        };
      }
      case "ai_deep": {
        const field = typeof meta.prompt_field === "string" && meta.prompt_field ? (meta.prompt_field as string) : "prompt";
        const msgs = typeof meta.messages_field === "string" ? (meta.messages_field as string) : null;
        const r: any = await aiDeepCore(
          admin,
          owner,
          { auditId, endpointUrl: stage.target!, promptField: field, messagesField: msgs, authToken: creds.aiToken?.trim() || null, parentRunId },
          core,
        );
        if (!r.ok) return { status: "failed", reason: r.error };
        return {
          status: "done",
          reason: `${r.counts.pass} pass · ${r.counts.fail} fail · ${r.counts.inconclusive} unverified · ${r.requestsUsed} requests`,
        };
      }
      case "synthesis":
        return await runSynthesis(admin, ctx);
      case "code_audit": {
        const repoStage = ctx.stages.find((s) => s.key === stage.depends_on[0]);
        const focus = deepAuditFocus(repoStage?.output);
        const r: any = await startCodeAuditCore(
          admin,
          owner,
          {
            auditId,
            repoUrl: stage.target!,
            token: creds.githubToken?.trim() || undefined,
            profile: opts.profile,
            clientConsent: true,
            focus,
          },
          core,
        );
        if (!r.ok) return { status: "failed", reason: r.error };
        return {
          status: "waiting",
          reason: `Running on the runner${focus.length ? ` with ${focus.length} lead(s) from the repo scan` : ""}. This run closes when it reports back.`,
          output: { codeAuditRunId: r.runId, focus: focus.length },
        };
      }
    }
  } catch (e: any) {
    return { status: "failed", reason: String(e?.message ?? e).slice(0, 1000) };
  }
}

/**
 * The last stage: merge every scanner's results (and the deep audit's
 * findings) into one ranked list, then draft the executive summary from it.
 * An approved summary is never overwritten.
 */
async function runSynthesis(admin: any, ctx: RunCtx): Promise<Outcome> {
  const runId = ctx.run.id;
  const { data: children } = await admin.from("scan_runs").select("id").eq("parent_run_id", runId);
  const childIds = ((children ?? []) as { id: string }[]).map((c) => c.id);
  const [{ data: results }, { data: items }] = await Promise.all([
    childIds.length
      ? admin.from("scan_results").select("scanner, status, checklist_item_id, checklist_key, change").in("run_id", childIds)
      : Promise.resolve({ data: [] }),
    admin.from("checklist_items").select("id, title, category, severity").eq("is_active", true),
  ]);
  const deep = ctx.stages.find((s) => s.scanner === "code_audit" && s.status === "done" && s.output?.codeAuditRunId);
  const { data: codeFindings } = deep
    ? await admin
        .from("code_audit_findings")
        .select("id, title, severity, verdict, checklist_item_id, trace, evidence")
        .eq("run_id", deep.output.codeAuditRunId)
        .neq("review_state", "dismissed")
    : { data: [] };
  const repo = ctx.stages.find((s) => s.scanner === "repo" && s.status === "done");
  const gaps: SynthGap[] = ctx.stages
    .filter((s) => s.scanner !== "synthesis" && (s.status === "failed" || s.status === "skipped"))
    .map((s) => ({ scanner: s.scanner, label: SCANNER_LABEL[s.scanner], status: s.status as "failed" | "skipped", reason: s.reason }));

  const syn = synthesize({
    results: (results ?? []) as SynthResult[],
    items: (items ?? []) as SynthItem[],
    codeFindings: (codeFindings ?? []) as SynthCodeFinding[],
    repoLeads: (repo?.output?.leads ?? null) as RepoLeads,
    gaps,
  });

  let summaryNote = "";
  const { data: audit } = await admin.from("audits").select("summary_approved_at").eq("id", ctx.audit.id).maybeSingle();
  if (audit?.summary_approved_at) {
    summaryNote = " · kept your approved summary";
  } else if (process.env.ANTHROPIC_API_KEY) {
    const r: any = await draftSummaryCore(
      admin,
      ctx.audit.created_by,
      { auditId: ctx.audit.id, extraFacts: synthesisFacts(syn, (s) => SCANNER_LABEL[s as keyof typeof SCANNER_LABEL] ?? s) },
      { checkQuota: false },
    ).catch((e: any) => ({ ok: false, error: e?.message ?? "failed" }));
    summaryNote = r.ok ? " · summary drafted for your review" : ` · summary not drafted (${r.error})`;
  }

  const n = syn.issues.length;
  return {
    status: "done",
    reason: `${n} issue${n === 1 ? "" : "s"}${syn.corroborated ? `, ${syn.corroborated} found by more than one method` : ""} · ${gaps.length} not tested${summaryNote}`,
    output: { ...syn, issues: syn.issues.slice(0, 100) },
  };
}

export type AdvanceResult = {
  /** The stage this call settled, if any. */
  stage: { key: string; status: string; reason: string | null } | null;
  /** True while there are stages left for a driver to run. */
  more: boolean;
  /** The run's own state after this call. */
  runStatus: string;
};

/**
 * Settle the next stage: skip it if a gate says so, otherwise run it. When
 * nothing is left but the deep audit, drop the run's sealed credentials; when
 * everything has settled, close the run.
 */
export async function advancePipeline(
  admin: any,
  runId: string,
  creds: PipelineCreds,
  opts: PipelineRunOptions,
): Promise<AdvanceResult> {
  const ctx = await loadRun(admin, runId);
  if (!ctx) throw new Error("Run not found.");
  if (ctx.run.status !== "running") return { stage: null, more: false, runStatus: ctx.run.status };

  const next = nextStage(ctx.stages);
  if (!next) return await afterStage(admin, ctx, null);

  const skip = gateStage(next, ctx.stages, credPresence(creds));
  if (skip) {
    const now = new Date().toISOString();
    await setStage(admin, runId, next.key, { status: "skipped", reason: skip, started_at: now, finished_at: now });
    next.status = "skipped";
    next.reason = skip;
    return await afterStage(admin, ctx, next);
  }

  // Claim it, so two drivers can't run the same stage.
  const { data: claimed } = await admin
    .from("pipeline_stages")
    .update({ status: "running", started_at: new Date().toISOString(), attempts: (next.attempts ?? 0) + 1 })
    .eq("run_id", runId)
    .eq("key", next.key)
    .eq("status", "pending")
    .select("key");
  if (!claimed?.length) return { stage: null, more: true, runStatus: "running" };

  const out = await execute(admin, ctx, next, creds, opts);
  await setStage(admin, runId, next.key, {
    status: out.status,
    reason: out.reason?.slice(0, 2000) ?? null,
    output: out.output ?? {},
    finished_at: out.status === "waiting" ? null : new Date().toISOString(),
  });
  Object.assign(next, { status: out.status, reason: out.reason, output: out.output ?? {} });
  return await afterStage(admin, ctx, next);
}

async function afterStage(admin: any, ctx: RunCtx, settled: StageRow | null): Promise<AdvanceResult> {
  const stage = settled ? { key: settled.key, status: settled.status, reason: settled.reason } : null;
  const fresh = (await loadRun(admin, ctx.run.id)) ?? ctx;
  if (pipelineSettled(fresh.stages)) {
    const status = await finalizeRun(admin, ctx.run.id);
    return { stage, more: false, runStatus: status };
  }
  if (onlyWaiting(fresh.stages)) {
    // Every scanner that needs a credential has run.
    await dropRunSecrets(admin, ctx.run.id);
    await addSuggestions(admin, fresh);
    return { stage, more: false, runStatus: "running" };
  }
  return { stage, more: true, runStatus: "running" };
}

/** Out-of-scope target suggestions from what the stages turned up. */
async function addSuggestions(admin: any, ctx: RunCtx) {
  const { data: existing } = await admin.from("audit_targets").select("kind, value").eq("audit_id", ctx.audit.id);
  const rows = suggestTargets(ctx.stages, existing ?? [], ctx.audit.website_url).map((t) => ({
    audit_id: ctx.audit.id,
    kind: t.kind,
    value: t.value,
    label: t.label,
    meta: { ...t.meta, suggested_run: ctx.run.id },
    in_scope: false,
  }));
  if (rows.length) await admin.from("audit_targets").upsert(rows, { onConflict: "audit_id,kind,value", ignoreDuplicates: true });
  return rows.length;
}

/** Close the parent run from its stages. Idempotent: only an open run closes. */
export async function finalizeRun(admin: any, runId: string): Promise<string> {
  const ctx = await loadRun(admin, runId);
  if (!ctx) return "failed";
  await dropRunSecrets(admin, runId);
  if (ctx.run.status !== "running") return ctx.run.status;

  const suggested = await addSuggestions(admin, ctx).catch(() => 0);
  const synth = ctx.stages.find((s) => s.scanner === "synthesis" && s.status === "done")?.output as any;
  const steps = stagesToSteps(ctx.stages);
  const { data: children } = await admin.from("scan_runs").select("scanner, status, summary").eq("parent_run_id", runId);
  const gaps = ctx.stages.filter((s) => s.scanner !== "synthesis" && (s.status === "failed" || s.status === "skipped"));
  // A retried run closes again: replace its earlier gap rows.
  await admin.from("scan_results").delete().eq("run_id", runId).like("checklist_key", "step:%");
  if (gaps.length) {
    await admin.from("scan_results").insert(
      gaps.map((s) => ({
        run_id: runId,
        audit_id: ctx.audit.id,
        checklist_key: `step:${s.scanner}`,
        scanner: s.scanner,
        status: "not_run",
        stored: false,
        notes: `${s.status === "failed" ? "Failed" : "Not run"}${s.target ? ` (${s.target})` : ""}: ${s.reason ?? "no reason given"}`,
      })),
    );
  }
  // The deep audit's own results live on its page; count it as done here.
  const { status, summary } = summarizeFullAudit(
    steps.map((s) => (s.outcome === "started" ? { ...s, outcome: "done" as const } : s)),
    (children ?? []) as any[],
  );
  const { data: closed } = await admin
    .from("scan_runs")
    .update({
      status,
      finished_at: new Date().toISOString(),
      summary: {
        ...summary,
        pipeline: true,
        suggested_targets: suggested,
        ...(synth ? { synthesis: { counts: synth.counts, corroborated: synth.corroborated, issues: (synth.issues ?? []).length } } : {}),
      },
    })
    .eq("id", runId)
    .eq("status", "running")
    .select("id");
  return closed?.length ? status : ctx.run.status;
}

/** The runner reported back (or was stopped): settle the waiting stage. */
export async function onCodeAuditFinished(admin: any, codeAuditRunId: string) {
  const { data: car } = await admin.from("code_audit_runs").select("id, status, error, incomplete_reason").eq("id", codeAuditRunId).maybeSingle();
  if (!car || ["queued", "dispatching", "running"].includes(car.status)) return;
  const { data: waiting } = await admin
    .from("pipeline_stages")
    .select("run_id, key")
    .eq("status", "waiting")
    .eq("output->>codeAuditRunId", codeAuditRunId);
  for (const w of (waiting ?? []) as { run_id: string; key: string }[]) {
    const done = car.status === "done" || car.status === "incomplete";
    await setStage(admin, w.run_id, w.key, {
      status: done ? "done" : "failed",
      reason:
        car.status === "done"
          ? "Finished. Review its findings on the Deep code audit page."
          : car.status === "incomplete"
            ? `Finished incomplete${car.incomplete_reason ? `: ${car.incomplete_reason}` : ""}. Review its findings on the Deep code audit page.`
            : `The runner ${car.status === "cancelled" ? "was stopped" : "failed"}${car.error ? `: ${String(car.error).slice(0, 500)}` : ""}.`,
      finished_at: new Date().toISOString(),
    });
    await drive(admin, w.run_id);
  }
}

/** Run whatever is left that needs no credentials (synthesis), then close. */
async function drive(admin: any, runId: string) {
  for (let i = 0; i < 5; i++) {
    const r = await advancePipeline(admin, runId, {}, { profile: "standard" });
    if (!r.more) break;
  }
}

/**
 * Close out runs nobody is driving any more: a browser run whose tab was
 * closed, or a deep audit whose runner never reported back. Called from the
 * scheduled-scans hook.
 */
export async function sweepStalePipelines(admin: any, now = Date.now()) {
  const maxDeepMs = (Number(process.env.CODE_AUDIT_MAX_HOURS ?? 3) + 1) * 3600_000;
  const idleMs = 2 * 3600_000;
  const swept: string[] = [];
  const { data: runs } = await admin.from("scan_runs").select("id").eq("scanner", "full").eq("status", "running").not("pipeline_driver", "is", null).limit(50);
  for (const { id } of (runs ?? []) as { id: string }[]) {
    const ctx = await loadRun(admin, id);
    if (!ctx) continue;
    const ts = (s: StageRow) => Date.parse(s.finished_at ?? s.started_at ?? "") || 0;
    const lastActivity = Math.max(Date.parse((ctx.run as any).started_at ?? "") || 0, ...ctx.stages.map(ts));
    let changed = false;
    for (const s of ctx.stages) {
      if (s.status === "waiting" && now - (Date.parse(s.started_at ?? "") || now) > maxDeepMs) {
        const runIdOfDeep = s.output?.codeAuditRunId as string | undefined;
        if (runIdOfDeep) await onCodeAuditFinished(admin, runIdOfDeep);
        const after = await admin.from("pipeline_stages").select("status").eq("run_id", id).eq("key", s.key).maybeSingle();
        if (after.data?.status === "waiting") {
          await setStage(admin, id, s.key, { status: "failed", reason: "The runner never reported back.", finished_at: new Date(now).toISOString() });
        }
        changed = true;
      } else if (s.scanner !== "synthesis" && (s.status === "pending" || s.status === "running") && now - lastActivity > idleMs) {
        await setStage(admin, id, s.key, {
          status: s.status === "running" ? "failed" : "skipped",
          reason:
            s.status === "running"
              ? "Stopped partway (the run stopped responding)."
              : "The run stopped before this stage (the browser tab was probably closed). Retry it from the full audit.",
          finished_at: new Date(now).toISOString(),
        });
        changed = true;
      }
    }
    if (changed) {
      await drive(admin, id);
      swept.push(id);
    }
  }
  // Credentials past their expiry, whatever happened to their run.
  await admin.from("pipeline_secrets").delete().lt("expires_at", new Date(now).toISOString());
  return { swept };
}

/** Label for messages, e.g. "Repo + dependencies". */
export const stageLabel = (s: StageRow) => SCANNER_LABEL[s.scanner];
