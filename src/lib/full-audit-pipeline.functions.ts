// "Run full audit" as a pipeline: the server functions the dialog calls.
//
//   preflightFullAudit  check every key and token against its target; no run,
//                       no quota spent.
//   startPipeline       preflight again, spend the quota for the whole run,
//                       open the parent run, write its stages, and start the
//                       Workflow (server driver) when it's configured.
//   advanceFullAudit    browser driver: run the next stage. Credentials come
//                       with each call and are never stored.
//   retryPipelineStage  re-run one failed or skipped stage (reopens the run,
//                       then synthesis runs again).
import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { consumeQuota } from "./quota";
import { planPipeline, gateStage, type StageRow } from "./pipeline";
import { runPreflight, type PreflightCheck } from "./pipeline-preflight";
import type { CodeAuditProfile } from "./code-audit-contract";

export type PipelineCredsInput = {
  githubToken?: string | null;
  anonKey?: string | null;
  serviceRoleKey?: string | null;
  managementPat?: string | null;
  aiToken?: string | null;
};

const PROFILES: CodeAuditProfile[] = ["quick", "standard", "deep"];

function cleanCreds(c: PipelineCredsInput | null | undefined): PipelineCredsInput {
  const one = (v: unknown) => {
    if (typeof v !== "string") return null;
    const t = v.trim();
    if (!t) return null;
    if (t.length > 4000 || /\s/.test(t.replace(/^Bearer /, ""))) throw new Error("A key or token doesn't look right (spaces or too long).");
    return t;
  };
  return {
    githubToken: one(c?.githubToken),
    anonKey: one(c?.anonKey),
    serviceRoleKey: one(c?.serviceRoleKey),
    managementPat: one(c?.managementPat),
    aiToken: one(c?.aiToken),
  };
}

async function ownAudit(supabase: any, auditId: string, userId: string) {
  const { data } = await supabase.from("audits").select("id, created_by, title, website_url").eq("id", auditId).maybeSingle();
  return data && data.created_by === userId ? data : null;
}

async function loadScope(supabase: any, auditId: string) {
  const [{ data: targets }, { data: scope }] = await Promise.all([
    supabase.from("audit_targets").select("id, kind, value, meta, in_scope").eq("audit_id", auditId).order("created_at"),
    supabase.from("audit_scope").select("write_tests_allowed").eq("audit_id", auditId).maybeSingle(),
  ]);
  return { targets: (targets ?? []) as any[], writeTestsAllowed: !!scope?.write_tests_allowed };
}

function preflightInput(audit: any, targets: any[], creds: PipelineCredsInput, deepAudit: boolean) {
  const inScope = targets.filter((t) => t.in_scope);
  return {
    websiteUrl: audit.website_url ?? null,
    repos: inScope.filter((t) => t.kind === "repo").map((t) => t.value),
    supabase: inScope.find((t) => t.kind === "supabase")?.value ?? null,
    aiEndpoints: inScope.filter((t) => t.kind === "ai_endpoint").map((t) => t.value),
    creds,
    deepAudit,
  };
}

type StartInput = {
  auditId: string;
  creds?: PipelineCredsInput | null;
  deepAudit?: boolean;
  aiDeep?: boolean;
  profile?: CodeAuditProfile;
  clientConsent?: boolean;
  /** Run from the tab even when the Workflow is configured. */
  forceBrowser?: boolean;
};

function validateStart(input: StartInput) {
  if (!input || typeof input.auditId !== "string") throw new Error("auditId required");
  const profile = input.profile ?? "standard";
  if (!PROFILES.includes(profile)) throw new Error("Choose a profile.");
  return {
    auditId: input.auditId,
    creds: cleanCreds(input.creds),
    deepAudit: input.deepAudit === true,
    aiDeep: input.aiDeep === true,
    profile,
    clientConsent: input.clientConsent === true,
    forceBrowser: input.forceBrowser === true,
  };
}

export const preflightFullAudit = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator(validateStart)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const audit = await ownAudit(supabase, data.auditId, userId);
    if (!audit) return { ok: false as const, error: "Audit not found or access denied.", checks: [] as PreflightCheck[] };
    const { targets } = await loadScope(supabase, data.auditId);
    const r = await runPreflight(preflightInput(audit, targets, data.creds, data.deepAudit));
    return { ok: r.ok, error: r.ok ? null : "Some keys or tokens didn't check out.", checks: r.checks };
  });

/** Whether this deployment can run the pipeline on the server. */
function workflowBinding(): { create: (o: { id?: string; params: unknown }) => Promise<{ id: string }> } | null {
  const env = (globalThis as any).__env__;
  const b = env?.FULL_AUDIT_WORKFLOW;
  const key = process.env.FULL_AUDIT_SECRETS_KEY;
  return b && typeof b.create === "function" && key && key.length >= 32 && env?.SELF ? b : null;
}

export const startPipeline = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator(validateStart)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const audit = await ownAudit(supabase, data.auditId, userId);
    if (!audit) return { ok: false as const, error: "Audit not found or access denied." };
    if (data.deepAudit && !data.clientConsent)
      return { ok: false as const, error: "Confirm the client has agreed to their source code being analysed by Anthropic's API." };

    const { targets, writeTestsAllowed } = await loadScope(supabase, data.auditId);

    // 1. Fail fast: every credential given is checked before anything runs.
    const pre = await runPreflight(preflightInput(audit, targets, data.creds, data.deepAudit));
    if (!pre.ok) return { ok: false as const, error: "Some keys or tokens didn't check out. Nothing was run.", checks: pre.checks };

    // 2. Plan, and spend the quota for the stages that will run.
    const planned = planPipeline(targets, {
      websiteUrl: audit.website_url ?? null,
      deepAudit: data.deepAudit,
      aiDeep: data.aiDeep,
      writeTestsAllowed,
    });
    const { credPresence } = await import("./pipeline-engine.server");
    const presence = credPresence(data.creds);
    const rows: StageRow[] = planned.map((p) => ({ ...p, status: "pending", reason: null, output: {} }));
    const willRun = rows.filter((s) => !gateStage(s, rows, presence));
    const scans = willRun.filter((s) => s.scanner !== "code_audit" && s.scanner !== "synthesis").length;
    if (scans) {
      const q = await consumeQuota(supabase, "scan", scans);
      if (!q.ok) return { ok: false as const, error: q.error };
    }
    if (willRun.some((s) => s.scanner === "code_audit")) {
      const q = await consumeQuota(supabase, "code_audit", 1);
      if (!q.ok) return { ok: false as const, error: q.error };
    }
    if (process.env.ANTHROPIC_API_KEY) {
      const q = await consumeQuota(supabase, "llm", 1);
      if (!q.ok) return { ok: false as const, error: q.error };
    }

    // 3. Open the run and write its stages.
    const { data: run, error } = await supabase
      .from("scan_runs")
      .insert({ audit_id: data.auditId, scanner: "full", trigger: "manual", status: "running", target: audit.title })
      .select("id")
      .single();
    if (error || !run) {
      return { ok: false as const, error: `Couldn't start the run: ${error?.message ?? "unknown error"}. If this is a new install, push the latest database migrations.` };
    }
    const runId = (run as { id: string }).id;
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const admin = supabaseAdmin as any;
    const { error: sErr } = await admin.from("pipeline_stages").insert(
      planned.map((p) => ({ ...p, run_id: runId, audit_id: data.auditId })),
    );
    if (sErr) {
      await admin.from("scan_runs").update({ status: "failed", finished_at: new Date().toISOString(), summary: { error: sErr.message } }).eq("id", runId);
      return { ok: false as const, error: `Couldn't write the run's stages: ${sErr.message}` };
    }

    // 4. Server driver when configured; otherwise the tab drives.
    const wf = data.forceBrowser ? null : workflowBinding();
    if (wf) {
      try {
        const eng = await import("./pipeline-engine.server");
        await eng.storeRunSecrets(admin, runId, data.creds);
        const inst = await wf.create({ id: runId, params: { runId, profile: data.profile } });
        await admin.from("scan_runs").update({ pipeline_driver: "workflow", workflow_instance: inst.id }).eq("id", runId);
        return { ok: true as const, runId, driver: "workflow" as const, checks: pre.checks };
      } catch (e: any) {
        console.error("[startPipeline] workflow start failed, falling back to the browser", e?.message ?? e);
        const eng = await import("./pipeline-engine.server");
        await eng.dropRunSecrets(admin, runId);
      }
    }
    await admin.from("scan_runs").update({ pipeline_driver: "browser" }).eq("id", runId);
    return { ok: true as const, runId, driver: "browser" as const, checks: pre.checks };
  });

async function ownRun(supabase: any, runId: string, userId: string) {
  const { data } = await supabase.from("scan_runs").select("id, audit_id, created_by, scanner, status, pipeline_driver").eq("id", runId).maybeSingle();
  return data && data.created_by === userId && data.scanner === "full" && data.pipeline_driver ? data : null;
}

export const advanceFullAudit = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { runId: string; creds?: PipelineCredsInput | null; profile?: CodeAuditProfile }) => {
    if (!input || typeof input.runId !== "string") throw new Error("runId required");
    const profile = input.profile ?? "standard";
    if (!PROFILES.includes(profile)) throw new Error("Choose a profile.");
    return { runId: input.runId, creds: cleanCreds(input.creds), profile };
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const run = await ownRun(supabase, data.runId, userId);
    if (!run) return { ok: false as const, error: "Run not found." };
    if (run.pipeline_driver !== "browser") return { ok: false as const, error: "This run is driven on the server." };
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const eng = await import("./pipeline-engine.server");
    const res = await eng.advancePipeline(supabaseAdmin as any, data.runId, data.creds, { profile: data.profile });
    return { ok: true as const, ...res };
  });

export const retryPipelineStage = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { runId: string; key: string; creds?: PipelineCredsInput | null; profile?: CodeAuditProfile; clientConsent?: boolean }) => {
    if (!input || typeof input.runId !== "string" || typeof input.key !== "string" || input.key.length > 200) throw new Error("Invalid input");
    const profile = input.profile ?? "standard";
    if (!PROFILES.includes(profile)) throw new Error("Choose a profile.");
    return { runId: input.runId, key: input.key, creds: cleanCreds(input.creds), profile, clientConsent: input.clientConsent === true };
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const run = await ownRun(supabase, data.runId, userId);
    if (!run) return { ok: false as const, error: "Run not found." };
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const admin = supabaseAdmin as any;
    const { data: stage } = await admin.from("pipeline_stages").select("*").eq("run_id", data.runId).eq("key", data.key).maybeSingle();
    if (!stage || stage.scanner === "synthesis") return { ok: false as const, error: "Stage not found." };
    if (stage.status !== "failed" && stage.status !== "skipped") return { ok: false as const, error: "Only a failed or skipped stage can be retried." };
    if (stage.scanner === "code_audit" && !data.clientConsent)
      return { ok: false as const, error: "Confirm the client has agreed to their source code being analysed by Anthropic's API." };
    const { data: others } = await admin.from("pipeline_stages").select("status").eq("run_id", data.runId).in("status", ["pending", "running"]);
    if (others?.length) return { ok: false as const, error: "Wait for the run to finish before retrying a stage." };

    // The retried stage's own credentials, checked first.
    const { data: audit } = await admin.from("audits").select("id, website_url").eq("id", run.audit_id).maybeSingle();
    const pre = await runPreflight({
      websiteUrl: ["website", "surface"].includes(stage.scanner) ? (audit?.website_url ?? null) : null,
      repos: stage.scanner === "repo" || stage.scanner === "code_audit" ? [stage.target] : [],
      supabase: stage.scanner === "supabase" ? stage.target : null,
      aiEndpoints: stage.scanner === "ai_endpoint" || stage.scanner === "ai_deep" ? [stage.target] : [],
      creds: data.creds,
      deepAudit: stage.scanner === "code_audit",
    });
    if (!pre.ok) return { ok: false as const, error: "That key or token didn't check out.", checks: pre.checks };
    const quota = await consumeQuota(supabase, stage.scanner === "code_audit" ? "code_audit" : "scan", 1);
    if (!quota.ok) return { ok: false as const, error: quota.error };

    // Reopen: this stage and the synthesis run again; the run closes again after.
    // Retrying the deeper AI tests is the opt-in for them.
    const meta = stage.scanner === "ai_deep" ? { ...(stage.meta ?? {}), selected: true } : stage.meta;
    await admin.from("pipeline_stages").update({ status: "pending", reason: null, finished_at: null, meta }).eq("run_id", data.runId).eq("key", data.key);
    await admin.from("pipeline_stages").update({ status: "pending", reason: null, finished_at: null, output: {} }).eq("run_id", data.runId).eq("scanner", "synthesis");
    await admin.from("scan_runs").update({ status: "running", finished_at: null }).eq("id", data.runId);
    // A retry always runs from the tab: credentials stay in the browser.
    await admin.from("scan_runs").update({ pipeline_driver: "browser" }).eq("id", data.runId);

    const eng = await import("./pipeline-engine.server");
    const res = await eng.advancePipeline(admin, data.runId, data.creds, { profile: data.profile });
    return { ok: true as const, ...res };
  });
