// Deep code audit (Cloudflare security-audit skill on a Fly.io runner).
// See docs/security-audit/INTEGRATION-PLAN.md and runner/README.md.
import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { consumeQuota } from "./quota";
import { PROFILE_BUDGETS, type CodeAuditProfile } from "./code-audit-contract";
import { GITHUB_HOSTS, safeFetch } from "./ssrf-guard";

export type StartCodeAuditInput = {
  auditId: string;
  repoUrl: string;
  gitRef?: string;
  token?: string;
  profile: CodeAuditProfile;
  clientConsent: boolean;
};

/** Accept only plain https GitHub repo URLs; the runner clones exactly this. */
export function normalizeGithubRepo(raw: string): string | null {
  try {
    const u = new URL(String(raw ?? "").trim());
    if (
      u.protocol !== "https:" ||
      u.hostname.toLowerCase() !== "github.com" ||
      u.username ||
      u.password
    )
      return null;
    const [owner, repo, ...rest] = u.pathname.replace(/^\/+|\/+$/g, "").split("/");
    if (!owner || !repo || rest.length > 0) return null;
    const name = repo.replace(/\.git$/, "");
    if (!/^[A-Za-z0-9_.-]{1,100}$/.test(owner) || !/^[A-Za-z0-9_.-]{1,100}$/.test(name))
      return null;
    return `https://github.com/${owner}/${name}`;
  } catch {
    return null;
  }
}

/** Branch, tag or commit names the runner may pass to `git fetch`. */
export function isSafeGitRef(ref: string): boolean {
  return (
    /^[A-Za-z0-9._/-]{1,200}$/.test(ref) &&
    !ref.startsWith("-") &&
    !ref.startsWith("/") &&
    !ref.includes("..") &&
    !ref.includes("//")
  );
}

/**
 * Check, before paying for a machine, that the runner will be able to clone
 * the repo: public without a token, or readable with the token given.
 */
export async function checkRepoAccess(
  repoUrl: string,
  token: string | null,
): Promise<{ ok: true; private: boolean } | { ok: false; error: string }> {
  const [owner, repo] = new URL(repoUrl).pathname.replace(/^\/+/, "").split("/");
  const headers: Record<string, string> = {
    accept: "application/vnd.github+json",
    "user-agent": "AuditKit-CodeAudit/1.0",
    "x-github-api-version": "2022-11-28",
  };
  if (token) headers.authorization = `Bearer ${token}`;
  let res: Response;
  try {
    res = await safeFetch(`https://api.github.com/repos/${owner}/${repo}`, { headers }, { timeoutMs: 10_000, allowHosts: GITHUB_HOSTS });
  } catch (e: any) {
    return { ok: false, error: `Couldn't reach GitHub to check access to ${owner}/${repo}: ${e?.message ?? "request failed"}. Try again.` };
  }
  if (res.status === 401) return { ok: false, error: "GitHub rejected that token (expired, revoked or mistyped)." };
  if (res.status === 404 || res.status === 403) {
    await res.body?.cancel().catch(() => {});
    return {
      ok: false,
      error: token
        ? `That token can't see ${owner}/${repo}. Give it access to this repository with Contents: Read-only.`
        : `${owner}/${repo} is private (or doesn't exist). Add a GitHub token with read access to it.`,
    };
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    return { ok: false, error: `GitHub returned HTTP ${res.status} when checking ${owner}/${repo}. Try again.` };
  }
  const meta = (await res.json().catch(() => ({}))) as { private?: boolean; permissions?: { pull?: boolean } };
  if (token && meta.permissions && meta.permissions.pull === false)
    return { ok: false, error: `That token can't read ${owner}/${repo}'s code. Give it Contents: Read-only.` };
  return { ok: true, private: meta.private === true };
}

export const startCodeAudit = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: StartCodeAuditInput) => {
    if (
      !input ||
      typeof input.auditId !== "string" ||
      typeof input.repoUrl !== "string" ||
      typeof input.profile !== "string" ||
      (input.gitRef != null && typeof input.gitRef !== "string") ||
      (input.token != null && typeof input.token !== "string")
    )
      throw new Error("Invalid input");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: audit } = await supabase
      .from("audits")
      .select("id, created_by")
      .eq("id", data.auditId)
      .maybeSingle();
    if (!audit || audit.created_by !== userId)
      return { ok: false as const, error: "Audit not found or access denied." };

    const repoUrl = normalizeGithubRepo(data.repoUrl);
    if (!repoUrl)
      return {
        ok: false as const,
        error: "Enter a GitHub repository URL like https://github.com/owner/repo.",
      };
    // Own keys only: `"toString" in PROFILE_BUDGETS` is true.
    if (!Object.hasOwn(PROFILE_BUDGETS, data.profile))
      return { ok: false as const, error: "Choose a profile." };
    if (data.clientConsent !== true) {
      return {
        ok: false as const,
        error:
          "Confirm the client has agreed to their source code being analysed by Anthropic's API.",
      };
    }
    const gitRef = data.gitRef?.trim() || null;
    // No leading "-" (git would read it as an option), no "..", no "//".
    if (gitRef && !isSafeGitRef(gitRef))
      return { ok: false as const, error: "Invalid branch, tag or commit." };
    const token = data.token?.trim() || null;
    if (token && (token.length < 20 || token.length > 300 || /\s/.test(token))) {
      return { ok: false as const, error: "That GitHub token doesn't look right." };
    }

    const dispatch = await import("./code-audit-dispatch.server");
    if (!dispatch.codeAuditRunnerConfigured()) {
      return {
        ok: false as const,
        error: "The deep-audit runner isn't configured yet (see runner/README.md).",
      };
    }

    // Fail here, not minutes later on a paid machine, if the repo can't be cloned.
    const access = await checkRepoAccess(repoUrl, token);
    if (!access.ok) return { ok: false as const, error: access.error };

    const quota = await consumeQuota(supabase, "code_audit", 1);
    if (!quota.ok) return { ok: false as const, error: quota.error };

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const budget = PROFILE_BUDGETS[data.profile];
    const { data: run, error: insErr } = await supabaseAdmin
      .from("code_audit_runs")
      .insert({
        audit_id: data.auditId,
        created_by: userId,
        repo_url: repoUrl,
        git_ref: gitRef,
        profile: data.profile,
        budget_agents: budget,
        status: "dispatching",
      })
      .select("id")
      .single();
    if (insErr || !run) return { ok: false as const, error: "Could not create the audit run." };

    const res = await dispatch.dispatchCodeAudit({
      runId: run.id,
      repoUrl,
      gitRef,
      githubToken: token,
      profile: data.profile,
      budget,
      callbackUrl: dispatch.callbackUrl(),
      issuedAt: new Date().toISOString(),
    });
    if (!res.ok) {
      await supabaseAdmin
        .from("code_audit_runs")
        .update({ status: "failed", finished_at: new Date().toISOString(), error: res.error })
        .eq("id", run.id);
      return { ok: false as const, error: `Could not start the runner: ${res.error}` };
    }
    await supabaseAdmin
      .from("code_audit_runs")
      .update({ status: "queued", runner_machine_id: res.machineId || null })
      .eq("id", run.id);
    return { ok: true as const, runId: run.id as string };
  });

/**
 * Stop a deep audit that is queued or running: destroys the Fly machine and
 * marks the run failed. Also the way to clear a run whose runner never
 * reported back.
 */
export const stopCodeAudit = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { runId: string }) => {
    if (!input?.runId || typeof input.runId !== "string") throw new Error("runId required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: run } = await supabase
      .from("code_audit_runs")
      .select("id, created_by, status, runner_machine_id")
      .eq("id", data.runId)
      .maybeSingle();
    if (!run || (run as any).created_by !== userId) return { ok: false as const, error: "Run not found." };
    if (!["queued", "dispatching", "running"].includes((run as any).status))
      return { ok: false as const, error: "This run has already finished." };
    const dispatch = await import("./code-audit-dispatch.server");
    const machine = (run as any).runner_machine_id as string | null;
    const destroyed = machine ? await dispatch.destroyRunnerMachine(machine) : { ok: true };
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    await supabaseAdmin
      .from("code_audit_runs")
      .update({
        status: "failed",
        finished_at: new Date().toISOString(),
        error: destroyed.ok ? "Stopped by you." : `Stopped by you (the runner machine may still be running: ${destroyed.error}).`,
      })
      .eq("id", data.runId);
    return { ok: true as const };
  });

/**
 * Link a confirmed code-audit finding to a checklist item. This can only ever
 * record a FAIL on the item: the deep audit finding nothing is not evidence
 * that an item passes.
 */
export const mapCodeAuditFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { findingId: string; checklistItemId: string }) => input)
  .handler(async ({ data, context }) => {
    const { supabase } = context;
    // RLS limits this to findings on the caller's own audits.
    const { data: f } = await supabase
      .from("code_audit_findings")
      .select("id, audit_id, verdict, severity, title, description, fingerprint, run_id")
      .eq("id", data.findingId)
      .maybeSingle();
    if (!f) return { ok: false as const, error: "Finding not found." };
    if (f.verdict !== "confirmed") {
      return {
        ok: false as const,
        error: "Only confirmed findings can mark a checklist item as failing.",
      };
    }
    const { data: item } = await supabase
      .from("checklist_items")
      .select("id, title")
      .eq("id", data.checklistItemId)
      .maybeSingle();
    if (!item) return { ok: false as const, error: "Checklist item not found." };

    const { data: existing } = await supabase
      .from("audit_findings")
      .select("status, notes")
      .eq("audit_id", f.audit_id)
      .eq("checklist_item_id", item.id)
      .maybeSingle();

    const stamp = new Date().toISOString();
    const summary = (f.description ?? "").split(/\n/)[0].slice(0, 600);
    const note = `[Deep code audit ${stamp}] ${f.severity ? `(${f.severity}) ` : ""}${f.title}\n${summary}\nRecord: ${f.fingerprint}`;

    if (existing?.status === "resolved") {
      await supabase
        .from("code_audit_findings")
        .update({ checklist_item_id: item.id })
        .eq("id", f.id);
      return {
        ok: true as const,
        message: `Linked. "${item.title}" is marked resolved, so its status was left alone. Re-open it if this finding shows it regressed.`,
      };
    }

    const notes = existing?.notes ? `${note}\n\n${existing.notes}` : note;
    const { error: upErr } = await supabase.from("audit_findings").upsert(
      {
        audit_id: f.audit_id,
        checklist_item_id: item.id,
        status: "fail",
        notes,
        auto_scanned: false,
        ai_assisted: false,
      },
      { onConflict: "audit_id,checklist_item_id" },
    );
    if (upErr) return { ok: false as const, error: upErr.message };
    await supabase
      .from("code_audit_findings")
      .update({ checklist_item_id: item.id, review_state: "accepted" })
      .eq("id", f.id);
    return {
      ok: true as const,
      message: `"${item.title}" is now marked as failing, with this finding as evidence.`,
    };
  });
