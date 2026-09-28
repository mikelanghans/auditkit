import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { decodeBase64Utf8 } from "./decode-blob";
import { redactForPrompt } from "./secret-redaction";

// Per-batch budget sent to Claude (well under 200k-token context window)
const BATCH_MAX_FILES = 40;
const BATCH_MAX_CHARS = 120_000;
const MAX_FILE_CHARS = 12_000;
// Hard cap on total files scanned across batches to bound cost/time
const MAX_TOTAL_FILES = 400;
const MAX_BATCHES = 12;
const PRIORITY_KEYWORDS = [
  "auth", "api", "middleware", "supabase", "openai", "anthropic",
  "stripe", "generate", "prompt", "rls", "policy",
];
const PRIORITY_DIRS = ["src/lib/", "src/api/", "src/server/", "supabase/functions/"];

export type AIAssistDepth = "quick" | "standard" | "deep" | "full";
export type AIAssistInput = { auditId: string; repoUrl: string; token: string; depth?: AIAssistDepth };

const DEPTH_CAPS: Record<AIAssistDepth, { maxFiles: number; maxBatches: number }> = {
  quick:    { maxFiles: 12,  maxBatches: 1  },
  standard: { maxFiles: 60,  maxBatches: 2  },
  deep:     { maxFiles: 200, maxBatches: 6  },
  full:     { maxFiles: 400, maxBatches: 12 },
};

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
  if (lower.includes("node_modules/") || lower.includes("/dist/") || lower.includes("/build/")) return -1;
  if (lower.endsWith(".lock") || lower.endsWith(".min.js") || lower.endsWith(".map")) return -1;
  if (!/\.(ts|tsx|js|jsx|mjs|cjs|sql|toml)$|(^|\/)package\.json$|(^|\/)\.env(\.|$)/.test(lower)) return -1;
  let s = 1; // baseline so any eligible source file is considered
  for (const dir of PRIORITY_DIRS) if (lower.startsWith(dir)) s += 10;
  for (const kw of PRIORITY_KEYWORDS) if (lower.includes(kw)) s += 5;
  if (lower.startsWith("src/") || lower.startsWith("supabase/")) s += 2;
  if (lower.endsWith("package.json")) s += 2;
  if (lower.includes("/components/ui/")) s -= 3;
  if (lower.includes("/components/")) s -= 1;
  return s;
}

async function fetchRepoFiles(owner: string, repo: string, token: string, maxFiles: number) {
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
    .slice(0, maxFiles);

  const picked: { path: string; content: string }[] = [];
  const redactedPaths: string[] = [];
  let total = 0;
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

      // Redact before truncation and before this content reaches any prompt.
      // These files come from a private client repo and can contain live
      // credentials — a committed .env is something the repo scan reports as a
      // critical finding, so shipping it verbatim to a third-party API would
      // mean leaking the very secret we just told the client about.
      const red = redactForPrompt(f.path, content);
      content = red.content;
      if (red.redacted) redactedPaths.push(f.path);

      if (content.length > MAX_FILE_CHARS) content = content.slice(0, MAX_FILE_CHARS) + "\n…[truncated]";
      picked.push({ path: f.path, content });
      total += content.length;
    } catch { /* skip */ }
  }
  return {
    branch,
    files: picked,
    totalChars: total,
    scanned: candidates.length,
    truncatedTree: tree.truncated === true,
    redactedPaths,
  };
}

/**
 * Pack files into at most `maxBatches` prompts. Returns the files that did not
 * fit, so the caller reports what the model actually saw instead of claiming
 * every fetched file was reviewed.
 */
function chunkFiles(files: { path: string; content: string }[], maxBatches: number) {
  const batches: { path: string; content: string }[][] = [];
  let cur: { path: string; content: string }[] = [];
  let curChars = 0;
  for (const f of files) {
    if (cur.length >= BATCH_MAX_FILES || curChars + f.content.length > BATCH_MAX_CHARS) {
      if (cur.length) batches.push(cur);
      cur = []; curChars = 0;
      if (batches.length >= maxBatches) break;
    }
    cur.push(f);
    curChars += f.content.length;
  }
  if (cur.length && batches.length < maxBatches) batches.push(cur);
  const sent = new Set(batches.flat().map((f) => f.path));
  const dropped = files.filter((f) => !sent.has(f.path)).map((f) => f.path);
  return { batches, dropped };
}

async function callClaude(systemPrompt: string, userPrompt: string): Promise<{ text: string; truncated: boolean }> {
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
  return { text: out, truncated: body.stop_reason === "max_tokens" };
}

function repairTruncatedArray(slice: string): string {
  const inner = slice.replace(/^\s*\[/, "").replace(/\]\s*$/, "");
  let depth = 0, inStr = false, esc = false, lastGood = -1;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") { depth--; if (depth === 0 && ch === "}") lastGood = i; }
  }
  if (lastGood < 0) return "[]";
  return "[" + inner.slice(0, lastGood + 1) + "]";
}

function extractJson(text: string, truncated: boolean): any[] {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : text;
  const start = candidate.indexOf("[");
  const end = candidate.lastIndexOf("]");
  if (start < 0) throw new Error("No JSON array found in Claude response.");
  const slice = end > start ? candidate.slice(start, end + 1) : candidate.slice(start);
  try {
    const parsed = JSON.parse(slice);
    if (!Array.isArray(parsed)) throw new Error("Claude JSON is not an array.");
    return parsed;
  } catch (e) {
    const repaired = repairTruncatedArray(slice);
    const parsed = JSON.parse(repaired);
    if (!Array.isArray(parsed)) throw new Error("Claude JSON is not an array.");
    if (!truncated && parsed.length === 0) throw e;
    return parsed;
  }
}

const SYSTEM_PROMPT =
  "You are a security auditor for Lovable + Supabase + React apps. " +
  "For each checklist item, decide pass or fail STRICTLY based on whether the literal condition stated in the title is violated by the provided code. " +
  "Rules: (1) Read the checklist title literally — e.g. 'No service role key in client-side code' means FAIL only if the service role key appears in client-bundled code (src/, components/, hooks/, browser entry, files imported by them). " +
  "Service role usage inside Supabase edge functions, *.server.ts, server route handlers, or createServerFn handlers is server-side and therefore PASS for client-side checks. " +
  "(2) Do NOT fail an item when your own evidence shows the condition is satisfied. If your reasoning contains phrases like 'which is correct', 'is properly scoped', 'is server-side', or 'no client-side usage found', the suggested_status MUST be pass (or omit the item). " +
  "(3) Only return items where you found concrete code evidence; do not speculate about files you did not see. " +
  "(4) Confidence: high = direct violation with quoted code; medium = strong indirect signal; low = guess (omit low). " +
  "Return ONLY a JSON array (no prose, no markdown fences) of findings with fields: checklist_key (exact key), suggested_status (pass|fail), confidence (high|medium), reasoning (one sentence), evidence (the specific code snippet or file:line that supports the finding).";


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

    const depth: AIAssistDepth = data.depth ?? "standard";
    const caps = DEPTH_CAPS[depth];

    let repoData;
    try {
      repoData = await fetchRepoFiles(parsed.owner, parsed.repo, data.token.trim(), caps.maxFiles);
    } catch (e: any) {
      return { ok: false as const, error: e?.message ?? "Failed to read repository." };
    }
    if (repoData.files.length === 0) {
      return { ok: false as const, error: "No security-relevant source files found in the repo." };
    }

    const checklistList = items
      .map((it: any) => `- key="${it.checklist_key || slugify(it.title)}" | title="${it.title}" | category=${it.category}`)
      .join("\n");

    const itemByKey = new Map<string, any>();
    for (const it of items) {
      const key = (it.checklist_key || slugify(it.title)).toLowerCase();
      itemByKey.set(key, it);
      itemByKey.set(it.title.toLowerCase(), it);
    }

    const { batches, dropped } = chunkFiles(repoData.files, caps.maxBatches);
    let reviewedFiles = 0;
    const stamp = new Date().toISOString();
    // dedupe findings across batches: keep highest confidence per checklist item
    const confRank: Record<string, number> = { high: 3, medium: 2, low: 1 };
    const bestByItem = new Map<string, AIAssistFinding>();
    let totalRaw = 0;
    const batchErrors: string[] = [];

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      const codeBlob = batch.map((f) => `=== FILE: ${f.path} ===\n${f.content}`).join("\n\n");
      const userPrompt =
        `Repository: ${parsed.owner}/${parsed.repo}@${repoData.branch}\n` +
        `Batch ${i + 1}/${batches.length} — files in this batch: ${batch.length}\n\n` +
        `CHECKLIST ITEMS (use these exact checklist_key values):\n${checklistList}\n\n` +
        `SOURCE FILES:\n${codeBlob}`;

      let raw: string;
      let truncated = false;
      try {
        const result = await callClaude(SYSTEM_PROMPT, userPrompt);
        raw = result.text;
        truncated = result.truncated;
      } catch (e: any) {
        batchErrors.push(`batch ${i + 1}: ${e?.message ?? "Claude request failed"}`);
        continue;
      }

      let arr: any[];
      try { arr = extractJson(raw, truncated); }
      catch (e: any) {
        // Deliberately does not log the model output. On a parse failure the
        // raw text still contains `evidence` snippets lifted from the client's
        // source, which would put client code into our server logs.
        console.error("[ai-assist] parse failure", { batch: i + 1, truncated, len: raw.length });
        batchErrors.push(`batch ${i + 1}: parse error${truncated ? " (truncated)" : ""}`);
        continue;
      }

      reviewedFiles += batch.length;
      totalRaw += arr.length;
      for (const f of arr) {
        const key = String(f?.checklist_key ?? "").toLowerCase().trim();
        const item = itemByKey.get(key);
        if (!item) continue;
        const status = f?.suggested_status === "fail" ? "fail" : f?.suggested_status === "pass" ? "pass" : null;
        // Low-confidence answers are not strong enough to change a verdict.
        const confidence = f?.confidence === "high" ? "high" : f?.confidence === "medium" ? "medium" : null;
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
        const prev = bestByItem.get(item.id);
        // prefer fail over pass; then higher confidence
        const prevScore = prev ? (prev.suggested_status === "fail" ? 10 : 0) + confRank[prev.confidence] : -1;
        const newScore = (status === "fail" ? 10 : 0) + confRank[confidence];
        if (newScore > prevScore) bestByItem.set(item.id, finding);
      }
    }

    const high: AIAssistFinding[] = [];
    const medium: AIAssistFinding[] = [];
    for (const f of bestByItem.values()) {
      if (f.confidence === "high") high.push(f);
      else if (f.confidence === "medium") medium.push(f);
    }


    if (batches.length > 0 && batchErrors.length === batches.length) {
      return { ok: false as const, error: `AI Assist could not review any files: ${batchErrors.join("; ")}` };
    }
    const incomplete = dropped.length > 0 || batchErrors.length > 0 || repoData.truncatedTree;

    // Auto-apply high-confidence results, with two guards:
    //  1. Never overwrite a verdict an auditor or a deterministic scanner already
    //     recorded. Model output is shaped by the client's own repo content, so it
    //     must not silently replace a human "fail" with a "pass".
    //  2. On a partial run, only auto-apply failures. A "pass" drawn from a subset
    //     of the code goes to review instead.
    const { data: existingRows, error: exErr } = await supabase
      .from("audit_findings")
      .select("checklist_item_id, status, ai_assisted")
      .eq("audit_id", data.auditId);
    if (exErr) throw new Error(exErr.message);
    const existingById = new Map<string, { status: string | null; ai_assisted: boolean | null }>();
    for (const row of existingRows ?? []) existingById.set((row as any).checklist_item_id, row as any);

    let applied = 0;
    const heldForReview: AIAssistFinding[] = [];
    for (const f of high) {
      const prev = existingById.get(f.checklist_item_id);
      const hasHumanOrScannerVerdict = !!prev?.status && !prev.ai_assisted;
      if (hasHumanOrScannerVerdict || prev?.status === "resolved" || (incomplete && f.suggested_status === "pass")) {
        heldForReview.push(f);
        continue;
      }
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
      // Files the model actually reviewed (in batches that succeeded).
      filesScanned: reviewedFiles,
      filesFetched: repoData.files.length,
      droppedFiles: dropped.length > 0 ? dropped : undefined,
      batches: batches.length,
      highApplied: applied,
      // Held-back high-confidence results are shown for review alongside medium ones.
      mediumPending: [...heldForReview, ...medium],
      heldForReview: heldForReview.length,
      total: totalRaw,
      partial: batchErrors.length > 0 ? batchErrors : undefined,
      truncatedTree: repoData.truncatedTree || undefined,
      // Surfaced so the auditor can state, on the record, which files had
      // secret values stripped before anything was sent to the model.
      redactedFiles: repoData.redactedPaths.length > 0 ? repoData.redactedPaths : undefined,
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

export type RecheckInput = {
  auditId: string;
  checklistItemId: string;
  repoUrl: string;
  token: string;
};

export const recheckAIAssistItem = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: RecheckInput) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const parsed = parseRepo(data.repoUrl ?? "");
    if (!parsed) return { ok: false as const, error: "Invalid GitHub repo URL." };
    if (!data.token?.trim()) return { ok: false as const, error: "GitHub token is required." };

    const { data: auditRow } = await supabase
      .from("audits").select("id, created_by").eq("id", data.auditId).single();
    if (!auditRow || auditRow.created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }

    const { data: item, error: ierr } = await supabase
      .from("checklist_items")
      .select("id, title, category, checklist_key")
      .eq("id", data.checklistItemId)
      .single();
    if (ierr || !item) return { ok: false as const, error: "Checklist item not found." };

    let repoData;
    try {
      repoData = await fetchRepoFiles(parsed.owner, parsed.repo, data.token.trim(), DEPTH_CAPS.deep.maxFiles);
    } catch (e: any) {
      return { ok: false as const, error: e?.message ?? "Failed to read repository." };
    }
    if (repoData.files.length === 0) {
      return { ok: false as const, error: "No source files found in the repo." };
    }

    const { batches, dropped } = chunkFiles(repoData.files, DEPTH_CAPS.deep.maxBatches);
    const itemKey = (item.checklist_key || slugify(item.title)).toLowerCase();
    const checklistList = `- key="${itemKey}" | title="${item.title}" | category=${item.category}`;
    const confRank: Record<string, number> = { high: 3, medium: 2, low: 1 };
    let best: AIAssistFinding | null = null;
    const batchErrors: string[] = [];

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      const codeBlob = batch.map((f) => `=== FILE: ${f.path} ===\n${f.content}`).join("\n\n");
      const userPrompt =
        `Repository: ${parsed.owner}/${parsed.repo}@${repoData.branch}\n` +
        `Batch ${i + 1}/${batches.length} — files in this batch: ${batch.length}\n\n` +
        `RE-CHECK A SINGLE CHECKLIST ITEM. Only return a finding if you have concrete code evidence in these files. If the code satisfies the condition, return a pass with the supporting evidence. If you have no evidence either way, return an empty array.\n\n` +
        `CHECKLIST ITEM:\n${checklistList}\n\n` +
        `SOURCE FILES:\n${codeBlob}`;

      let raw: string;
      let truncated = false;
      try {
        const result = await callClaude(SYSTEM_PROMPT, userPrompt);
        raw = result.text;
        truncated = result.truncated;
      } catch (e: any) {
        batchErrors.push(`batch ${i + 1}: ${e?.message ?? "Claude request failed"}`);
        continue;
      }

      let arr: any[];
      try { arr = extractJson(raw, truncated); }
      catch { batchErrors.push(`batch ${i + 1}: parse error`); continue; }

      for (const f of arr) {
        const key = String(f?.checklist_key ?? "").toLowerCase().trim();
        if (key !== itemKey) continue;
        const status = f?.suggested_status === "fail" ? "fail" : f?.suggested_status === "pass" ? "pass" : null;
        // Low-confidence answers are not strong enough to change a verdict.
        const confidence = f?.confidence === "high" ? "high" : f?.confidence === "medium" ? "medium" : null;
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
        const prevScore = best ? (best.suggested_status === "fail" ? 10 : 0) + confRank[best.confidence] : -1;
        const newScore = (status === "fail" ? 10 : 0) + confRank[confidence];
        if (newScore > prevScore) best = finding;
      }
    }

    if (batches.length > 0 && batchErrors.length === batches.length) {
      return { ok: false as const, error: `Re-check could not review any files: ${batchErrors.join("; ")}` };
    }
    const incomplete = dropped.length > 0 || batchErrors.length > 0;
    if (!best) {
      return {
        ok: true as const,
        applied: false as const,
        message: incomplete
          ? `No evidence found in the files that were reviewed, but ${dropped.length ? `${dropped.length} file(s) didn't fit` : ""}${dropped.length && batchErrors.length ? " and " : ""}${batchErrors.length ? `${batchErrors.length} batch(es) failed` : ""} — status unchanged.`
          : "No evidence found in the scanned files — status unchanged.",
        partial: batchErrors.length > 0 ? batchErrors : undefined,
      };
    }
    if (incomplete && best.suggested_status === "pass") {
      return {
        ok: true as const,
        applied: false as const,
        message: "The model suggested a pass, but the re-check didn't cover every file, so the status was left unchanged. Review the suggestion manually.",
        partial: batchErrors.length > 0 ? batchErrors : undefined,
      };
    }

    const stamp = new Date().toISOString();
    const notes = `[AI Re-check ${stamp}] (${best.confidence} confidence)\n${best.reasoning}\n\nEvidence:\n${best.evidence}`;
    const { error } = await supabase.from("audit_findings").upsert(
      { audit_id: data.auditId, checklist_item_id: item.id, status: best.suggested_status, notes, ai_assisted: true },
      { onConflict: "audit_id,checklist_item_id" },
    );
    if (error) return { ok: false as const, error: error.message };

    return {
      ok: true as const,
      applied: true as const,
      status: best.suggested_status,
      confidence: best.confidence,
      reasoning: best.reasoning,
      partial: batchErrors.length > 0 ? batchErrors : undefined,
    };
  });
