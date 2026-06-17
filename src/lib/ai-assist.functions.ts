import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const MAX_FILES = 20;
const MAX_TOTAL_CHARS = 50_000;
const MAX_FILE_CHARS = 12_000;
const PRIORITY_KEYWORDS = [
  "auth", "api", "middleware", "supabase", "openai", "anthropic",
  "stripe", "generate", "prompt", "rls", "policy",
];
const PRIORITY_DIRS = ["src/lib/", "src/api/", "src/server/", "supabase/functions/"];

export type AIAssistInput = { auditId: string; repoUrl: string; token: string };

export type AIAssistFinding = {
  checklist_item_id: string;
  checklist_title: string;
  category: string;
  suggested_status: "pass" | "fail";
  confidence: "high" | "medium" | "low";
  reasoning: string;
  evidence: string;
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
      "user-agent": "AuditKit-AIAssist/1.0",
    },
  });
  if (!res.ok) throw new Error(`GitHub ${res.status}: ${await res.text().catch(() => res.statusText)}`);
  return res.json() as Promise<T>;
}

function scoreFile(path: string): number {
  const lower = path.toLowerCase();
  if (lower.includes("node_modules/") || lower.includes(".lock") || lower.endsWith(".min.js")) return -1;
  if (!/\.(ts|tsx|js|jsx|mjs|cjs|sql|toml|json|yml|yaml|env\.example)$/.test(lower)) return -1;
  let s = 0;
  for (const dir of PRIORITY_DIRS) if (lower.startsWith(dir)) s += 10;
  for (const kw of PRIORITY_KEYWORDS) if (lower.includes(kw)) s += 5;
  if (lower.endsWith("package.json")) s += 2;
  if (lower.includes("/components/")) s -= 2;
  return s;
}

async function fetchRepoFiles(owner: string, repo: string, token: string) {
  const repoMeta = await gh<{ default_branch: string }>(
    `https://api.github.com/repos/${owner}/${repo}`, token,
  );
  const branch = repoMeta.default_branch || "main";
  const tree = await gh<{ tree: { path: string; type: string; sha: string; size?: number }[]; truncated: boolean }>(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, token,
  );
  const candidates = tree.tree
    .filter((n) => n.type === "blob")
    .map((n) => ({ ...n, score: scoreFile(n.path) }))
    .filter((n) => n.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, MAX_FILES * 2);

  const picked: { path: string; content: string }[] = [];
  let total = 0;
  for (const f of candidates) {
    if (picked.length >= MAX_FILES) break;
    if (total >= MAX_TOTAL_CHARS) break;
    try {
      const blob = await gh<{ content: string; encoding: string }>(
        `https://api.github.com/repos/${owner}/${repo}/git/blobs/${f.sha}`, token,
      );
      let content = "";
      if (blob.encoding === "base64") {
        try { content = atob(blob.content.replace(/\n/g, "")); }
        catch { content = ""; }
      } else { content = String(blob.content || ""); }
      if (!content) continue;
      if (content.length > MAX_FILE_CHARS) content = content.slice(0, MAX_FILE_CHARS) + "\n…[truncated]";
      const remaining = MAX_TOTAL_CHARS - total;
      if (content.length > remaining) content = content.slice(0, remaining) + "\n…[truncated]";
      picked.push({ path: f.path, content });
      total += content.length;
    } catch { /* skip */ }
  }
  return { branch, files: picked, totalChars: total, scanned: candidates.length };
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
      model: "claude-sonnet-4-6",
      max_tokens: 4096,
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

function extractJson(text: string): any[] {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : text;
  const start = candidate.indexOf("[");
  const end = candidate.lastIndexOf("]");
  if (start < 0 || end < 0 || end < start) throw new Error("No JSON array found in Claude response.");
  const slice = candidate.slice(start, end + 1);
  const parsed = JSON.parse(slice);
  if (!Array.isArray(parsed)) throw new Error("Claude JSON is not an array.");
  return parsed;
}

const SYSTEM_PROMPT =
  "You are a security auditor specializing in vibe-coded applications built with Lovable, Supabase, and React. " +
  "Analyze the provided code and identify security issues mapped to these checklist categories: Database Security, " +
  "Authentication & Sessions, API & Endpoint Security, AI Prompt Security, Environment & Secrets, Frontend Security, " +
  "Infrastructure & Configuration. For each issue found return a JSON array of findings with fields: " +
  "checklist_key (matching the exact key from the checklist), suggested_status (pass or fail), " +
  "confidence (high/medium/low), reasoning (one sentence explaining what you found and where), " +
  "evidence (the specific code snippet or line that supports the finding). Return only valid JSON, no other text.";

export const runAIAssist = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: AIAssistInput) => input)
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

    const { data: checklist, error: cerr } = await supabase
      .from("checklist_items")
      .select("id, title, category, checklist_key")
      .eq("is_active", true);
    if (cerr) throw new Error(cerr.message);
    const items = checklist ?? [];

    let repoData;
    try {
      repoData = await fetchRepoFiles(parsed.owner, parsed.repo, data.token.trim());
    } catch (e: any) {
      return { ok: false as const, error: e?.message ?? "Failed to read repository." };
    }
    if (repoData.files.length === 0) {
      return { ok: false as const, error: "No security-relevant source files found in the repo." };
    }

    const checklistList = items
      .map((it: any) => `- key="${it.checklist_key || slugify(it.title)}" | title="${it.title}" | category=${it.category}`)
      .join("\n");

    const codeBlob = repoData.files
      .map((f) => `=== FILE: ${f.path} ===\n${f.content}`).join("\n\n");

    const userPrompt =
      `Repository: ${parsed.owner}/${parsed.repo}@${repoData.branch}\n` +
      `Files reviewed: ${repoData.files.length} (${repoData.totalChars} chars)\n\n` +
      `CHECKLIST ITEMS (use these exact checklist_key values):\n${checklistList}\n\n` +
      `SOURCE FILES:\n${codeBlob}`;

    let raw: string;
    try { raw = await callClaude(SYSTEM_PROMPT, userPrompt); }
    catch (e: any) { return { ok: false as const, error: e?.message ?? "Claude request failed." }; }

    let arr: any[];
    try { arr = extractJson(raw); }
    catch (e: any) { return { ok: false as const, error: `Could not parse Claude output: ${e?.message}` }; }

    const itemByKey = new Map<string, any>();
    for (const it of items) {
      const key = (it.checklist_key || slugify(it.title)).toLowerCase();
      itemByKey.set(key, it);
      itemByKey.set(it.title.toLowerCase(), it);
    }

    const stamp = new Date().toISOString();
    const high: AIAssistFinding[] = [];
    const medium: AIAssistFinding[] = [];
    for (const f of arr) {
      const key = String(f?.checklist_key ?? "").toLowerCase().trim();
      const item = itemByKey.get(key);
      if (!item) continue;
      const status = f?.suggested_status === "fail" ? "fail" : f?.suggested_status === "pass" ? "pass" : null;
      const confidence = f?.confidence === "high" ? "high" : f?.confidence === "medium" ? "medium" : f?.confidence === "low" ? "low" : null;
      if (!status || !confidence) continue;
      const finding: AIAssistFinding = {
        checklist_item_id: item.id,
        checklist_title: item.title,
        category: item.category,
        suggested_status: status,
        confidence,
        reasoning: String(f?.reasoning ?? "").slice(0, 1000),
        evidence: String(f?.evidence ?? "").slice(0, 2000),
      };
      if (confidence === "high") high.push(finding);
      else if (confidence === "medium") medium.push(finding);
    }

    // Auto-apply high
    let applied = 0;
    for (const f of high) {
      const notes = `[AI Assist ${stamp}] (high confidence)\n${f.reasoning}\n\nEvidence:\n${f.evidence}`;
      const { error } = await supabase.from("audit_findings").upsert(
        { audit_id: data.auditId, checklist_item_id: f.checklist_item_id, status: f.suggested_status, notes, ai_assisted: true },
        { onConflict: "audit_id,checklist_item_id" },
      );
      if (!error) applied++;
    }

    return {
      ok: true as const,
      repo: `${parsed.owner}/${parsed.repo}`,
      filesScanned: repoData.files.length,
      highApplied: applied,
      mediumPending: medium,
      total: arr.length,
    };
  });

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

export const applyAIAssistFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string; finding: AIAssistFinding }) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: auditRow } = await supabase
      .from("audits").select("id, created_by").eq("id", data.auditId).single();
    if (!auditRow || auditRow.created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }
    const f = data.finding;
    const notes = `[AI Assist ${new Date().toISOString()}] (medium confidence, accepted)\n${f.reasoning}\n\nEvidence:\n${f.evidence}`;
    const { error } = await supabase.from("audit_findings").upsert(
      { audit_id: data.auditId, checklist_item_id: f.checklist_item_id, status: f.suggested_status, notes, ai_assisted: true },
      { onConflict: "audit_id,checklist_item_id" },
    );
    if (error) return { ok: false as const, error: error.message };
    return { ok: true as const };
  });
