import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { decodeBase64Utf8 } from "./decode-blob";
import { redactForPrompt } from "./secret-redaction";

// Mirror the file-selection strategy used by AI Assist, but cap at ~20 files for
// a single holistic pass that fits in one Claude call.
const ARCH_MAX_FILES = 20;
const MAX_FILE_CHARS = 14_000;
const PRIORITY_KEYWORDS = [
  "auth", "api", "middleware", "supabase", "openai", "anthropic",
  "stripe", "generate", "prompt", "rls", "policy",
];
const PRIORITY_DIRS = ["src/lib/", "src/api/", "src/server/", "supabase/functions/"];

export type ArchitecturalReviewInput = {
  auditId: string;
  repoUrl: string;
  token: string;
};

export type ArchitecturalFindingRow = {
  id: string;
  audit_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | string;
  affected_files: string[];
  explanation: string | null;
  recommendation: string | null;
  fix_steps: string[];
  include_in_report: boolean;
  created_at: string;
};


function parseRepo(raw: string): { owner: string; repo: string } | null {
  try {
    const u = new URL(raw.trim());
    if (!/github\.com$/i.test(u.hostname)) return null;
    const [owner, repo] = u.pathname.replace(/^\/+|\/+$/g, "").split("/");
    if (!owner || !repo) return null;
    return { owner, repo: repo.replace(/\.git$/, "") };
  } catch { return null; }
}

async function gh<T = any>(url: string, token: string): Promise<T> {
  const res = await fetch(url, {
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "AuditKit-ArchReview/1.0",
    },
  });
  if (!res.ok) throw new Error(`GitHub ${res.status}: ${await res.text().catch(() => res.statusText)}`);
  return res.json() as Promise<T>;
}

function scoreFile(path: string): number {
  const lower = path.toLowerCase();
  if (lower.includes("node_modules/") || lower.includes("/dist/") || lower.includes("/build/")) return -1;
  if (lower.endsWith(".lock") || lower.endsWith(".min.js") || lower.endsWith(".map")) return -1;
  if (!/\.(ts|tsx|js|jsx|mjs|cjs|sql|toml)$|(^|\/)package\.json$|(^|\/)\.env(\.|$)/.test(lower)) return -1;
  let s = 1;
  for (const dir of PRIORITY_DIRS) if (lower.startsWith(dir)) s += 10;
  for (const kw of PRIORITY_KEYWORDS) if (lower.includes(kw)) s += 5;
  if (lower.startsWith("src/") || lower.startsWith("supabase/")) s += 2;
  if (lower.endsWith("package.json")) s += 2;
  if (lower.includes("/components/ui/")) s -= 3;
  if (lower.includes("/components/")) s -= 1;
  return s;
}

async function fetchTopFiles(owner: string, repo: string, token: string, maxFiles: number) {
  const repoMeta = await gh<{ default_branch: string }>(
    `https://api.github.com/repos/${owner}/${repo}`, token,
  );
  const branch = repoMeta.default_branch || "main";
  const tree = await gh<{ tree: { path: string; type: string; sha: string }[] }>(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, token,
  );
  const candidates = tree.tree
    .filter((n) => n.type === "blob")
    .map((n) => ({ ...n, score: scoreFile(n.path) }))
    .filter((n) => n.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFiles);

  const picked: { path: string; content: string }[] = [];
  for (const f of candidates) {
    try {
      const blob = await gh<{ content: string; encoding: string }>(
        `https://api.github.com/repos/${owner}/${repo}/git/blobs/${f.sha}`, token,
      );
      let content = "";
      if (blob.encoding === "base64") {
        content = decodeBase64Utf8(blob.content);
      } else { content = String(blob.content || ""); }
      if (!content) continue;

      // Strip secret values before this content is sent to the Anthropic API.
      content = redactForPrompt(f.path, content).content;

      if (content.length > MAX_FILE_CHARS) content = content.slice(0, MAX_FILE_CHARS) + "\n…[truncated]";
      picked.push({ path: f.path, content });
    } catch { /* skip */ }
  }
  return { branch, files: picked };
}

async function callClaude(systemPrompt: string, userPrompt: string): Promise<string> {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) throw new Error("ANTHROPIC_API_KEY is not configured.");
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-haiku-4-5",
      max_tokens: 8192,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Claude ${res.status}: ${text.slice(0, 400)}`);
  const body = JSON.parse(text);
  const out = Array.isArray(body.content)
    ? body.content.map((c: any) => c?.text ?? "").join("\n").trim()
    : "";
  if (!out) throw new Error("Claude returned an empty response.");
  return out;
}

function extractJsonArray(text: string): any[] {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : text;
  const start = candidate.indexOf("[");
  const end = candidate.lastIndexOf("]");
  if (start < 0 || end <= start) throw new Error("No JSON array found in Claude response.");
  const parsed = JSON.parse(candidate.slice(start, end + 1));
  if (!Array.isArray(parsed)) throw new Error("Claude JSON is not an array.");
  return parsed;
}

const ARCH_SYSTEM_PROMPT =
  "You are a senior security architect reviewing a codebase holistically, not file by file. " +
  "You have already seen individual findings from a line-level security scan. Your job now is different: " +
  "look ACROSS the entire codebase for architectural inconsistencies, duplicated systems, and structural " +
  "risks that only become visible when comparing files against each other. Specifically look for: " +
  "(1) Multiple competing implementations of the same concern — e.g. more than one authentication system, " +
  "more than one way of checking permissions, redundant or conflicting validation logic. " +
  "(2) Inconsistent enforcement — e.g. some API endpoints validate object ownership before returning data " +
  "while others do not, some routes check auth and others skip it. " +
  "(3) Privilege concentration — e.g. a single service, function, or AI assistant that has broader database " +
  "or API access than its actual job requires. " +
  "(4) Exposure that should not exist — e.g. an internal or admin-only API reachable without any access " +
  "restriction. For each issue found, write one plain-English sentence in the exact style of: " +
  "\"You created three different authentication systems.\" or \"Half your endpoints validate ownership. " +
  "Half don't.\" or \"Your AI assistant has access to the admin database.\" or \"This API should never be " +
  "public.\" Be specific and cite the actual files or function names involved. Return a JSON array of " +
  "findings with fields: title (the one-sentence finding in that exact blunt style), severity " +
  "(critical/high/medium/low), affected_files (array of file paths or names), explanation (2-3 sentences " +
  "of supporting detail), recommendation (1-2 sentence high-level direction of what to consolidate, " +
  "restrict, or fix), fix_steps (an ordered array of 3-7 concrete, project-specific remediation steps " +
  "a developer can execute in THIS repo — each step must name the actual file path, function, table, " +
  "policy, route, or symbol from the source provided, e.g. \"Delete the duplicate auth helper in " +
  "src/lib/legacy-auth.ts and update its 4 importers to use requireSupabaseAuth from " +
  "src/integrations/supabase/auth-middleware.ts\". Do NOT write generic advice like \"add input " +
  "validation\" or \"use RLS\" — every step must reference something that actually exists in the files " +
  "above). Return only valid JSON.";


export const runArchitecturalReview = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: ArchitecturalReviewInput) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const parsed = parseRepo(data.repoUrl ?? "");
    if (!parsed) return { ok: false as const, error: "Invalid GitHub repo URL." };
    if (!data.token?.trim()) return { ok: false as const, error: "GitHub token is required." };

    const { data: auditRow, error: aerr } = await supabase
      .from("audits").select("id, created_by").eq("id", data.auditId).single();
    if (aerr || !auditRow || auditRow.created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }

    // Pull every existing finding for this audit, joined with checklist metadata.
    const { data: existingFindings, error: ferr } = await supabase
      .from("audit_findings")
      .select("status, notes, auto_scanned, ai_assisted, checklist_item:checklist_items(checklist_key, title, category)")
      .eq("audit_id", data.auditId);
    if (ferr) return { ok: false as const, error: ferr.message };

    let repoData;
    try {
      repoData = await fetchTopFiles(parsed.owner, parsed.repo, data.token.trim(), ARCH_MAX_FILES);
    } catch (e: any) {
      return { ok: false as const, error: e?.message ?? "Failed to read repository." };
    }
    if (repoData.files.length === 0) {
      return { ok: false as const, error: "No security-relevant source files found in the repo." };
    }

    const findingsBlob = (existingFindings ?? [])
      .map((f: any) => {
        const it = f.checklist_item ?? {};
        const key = it.checklist_key ?? "(unknown)";
        const status = f.status ?? "unrated";
        const notes = (f.notes ?? "").toString().replace(/\s+/g, " ").slice(0, 400);
        return `- [${status}] ${it.category ?? "?"} :: ${it.title ?? key} (key=${key})${notes ? ` — ${notes}` : ""}`;
      })
      .join("\n") || "(no prior findings)";

    const codeBlob = repoData.files
      .map((f) => `=== FILE: ${f.path} ===\n${f.content}`)
      .join("\n\n");

    const userPrompt =
      `Repository: ${parsed.owner}/${parsed.repo}@${repoData.branch}\n` +
      `Files included for architectural review: ${repoData.files.length}\n\n` +
      `EXISTING LINE-LEVEL FINDINGS (do not repeat these; use them as context):\n${findingsBlob}\n\n` +
      `SOURCE FILES:\n${codeBlob}`;

    let raw: string;
    try {
      raw = await callClaude(ARCH_SYSTEM_PROMPT, userPrompt);
    } catch (e: any) {
      return { ok: false as const, error: e?.message ?? "Claude request failed" };
    }

    let arr: any[];
    try { arr = extractJsonArray(raw); }
    catch (e: any) {
      console.error("[arch-review] parse failure", { head: raw.slice(0, 400), tail: raw.slice(-400) });
      return { ok: false as const, error: "Could not parse architectural findings from Claude response." };
    }

    const allowedSev = new Set(["critical", "high", "medium", "low"]);
    const rows = arr
      .map((f) => {
        const title = String(f?.title ?? "").trim();
        if (!title) return null;
        const sev = String(f?.severity ?? "medium").toLowerCase();
        const severity = allowedSev.has(sev) ? sev : "medium";
        const affected = Array.isArray(f?.affected_files)
          ? f.affected_files.map((x: any) => String(x)).filter(Boolean).slice(0, 30)
          : [];
        return {
          audit_id: data.auditId,
          title: title.slice(0, 500),
          severity,
          affected_files: affected,
          explanation: f?.explanation ? String(f.explanation).slice(0, 2000) : null,
          recommendation: f?.recommendation ? String(f.recommendation).slice(0, 2000) : null,
          fix_steps: Array.isArray(f?.fix_steps)
            ? f.fix_steps.map((s: any) => String(s).slice(0, 600)).filter(Boolean).slice(0, 10)
            : [],
          include_in_report: true,
        };
      })
      .filter(Boolean) as any[];

    // Replace any prior architectural findings for this audit, so a re-run gives a fresh view.
    await supabase.from("architectural_findings").delete().eq("audit_id", data.auditId);

    let inserted: ArchitecturalFindingRow[] = [];
    if (rows.length > 0) {
      const { data: ins, error: ierr } = await supabase
        .from("architectural_findings")
        .insert(rows)
        .select("id, audit_id, title, severity, affected_files, explanation, recommendation, fix_steps, include_in_report, created_at");

      if (ierr) return { ok: false as const, error: ierr.message };
      inserted = (ins ?? []) as any;
    }

    return {
      ok: true as const,
      repo: `${parsed.owner}/${parsed.repo}`,
      filesScanned: repoData.files.length,
      findings: inserted,
    };
  });

export const setArchitecturalFindingInclude = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { id: string; include: boolean }) => input)
  .handler(async ({ data, context }) => {
    const { supabase } = context;
    const { error } = await supabase
      .from("architectural_findings")
      .update({ include_in_report: data.include })
      .eq("id", data.id);
    if (error) return { ok: false as const, error: error.message };
    return { ok: true as const };
  });

export const deleteArchitecturalFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data, context }) => {
    const { supabase } = context;
    const { error } = await supabase.from("architectural_findings").delete().eq("id", data.id);
    if (error) return { ok: false as const, error: error.message };
    return { ok: true as const };
  });
