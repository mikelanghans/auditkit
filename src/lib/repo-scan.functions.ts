import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { runDepScan } from "./dep-scan-core";
import { detectAIEndpointsCore, type DetectedEndpoint } from "./ai-endpoint-detect.functions";
import { GITHUB_HOSTS, safeFetch } from "./ssrf-guard";
import { decodeBase64Utf8 } from "./decode-blob";
import { upsertScanFinding } from "./finding-writer";
import { consumeQuota } from "./quota";
import { gitignoreIgnoresEnv, isEnvFilePath } from "./repo-hygiene";
import { checkXss, findXssSinks, xssCandidatePaths, type XssHit } from "./xss-scan";


const TIMEOUT_MS = 15_000;
const MAX_COMMITS = 100;
const MAX_XSS_FILES = 150;
const MAX_XSS_FILE_BYTES = 300_000;
const COMMIT_CONCURRENCY = 6;

export type RepoFinding = {
  pattern: string;
  sample: string;
  commit: string;
  date: string | null;
  file: string;
};

/**
 * Pinned to GitHub hosts. These requests carry the client's PAT, and
 * raw.githubusercontent.com legitimately redirects to object storage — so we
 * follow redirects, but only within GitHub, and safeFetch drops the
 * Authorization header on any cross-origin hop.
 */
async function timedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return await safeFetch(url, init, { timeoutMs: TIMEOUT_MS, allowHosts: GITHUB_HOSTS });
}

function parseRepo(raw: string): { owner: string; repo: string } | null {
  const m = raw
    .trim()
    .replace(/\.git$/, "")
    .match(/(?:github\.com[/:])?([^/\s]+)\/([^/?#\s]+)/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

function ghHeaders(token: string): Record<string, string> {
  return {
    accept: "application/vnd.github+json",
    "user-agent": "AuditKit-RepoScan/1.0",
    "x-github-api-version": "2022-11-28",
    authorization: `Bearer ${token}`,
  };
}

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "SUPABASE_SERVICE_ROLE_KEY", re: /SUPABASE_SERVICE_ROLE_KEY\s*[:=]?\s*['"`]?[A-Za-z0-9._-]{20,}/gi },
  { name: "service_role reference", re: /service_role['"`]?\s*[:=]\s*['"`][A-Za-z0-9._-]{20,}['"`]/gi },
  { name: "STRIPE_SECRET_KEY", re: /STRIPE_SECRET_KEY\s*[:=]?\s*['"`]?sk_[A-Za-z0-9]{16,}/gi },
  { name: "Stripe live secret (sk_live_)", re: /\bsk_live_[A-Za-z0-9]{16,}\b/g },
  { name: "OPENAI_API_KEY", re: /OPENAI_API_KEY\s*[:=]?\s*['"`]?sk-[A-Za-z0-9_-]{20,}/gi },
  { name: "OpenAI key (sk-…)", re: /\bsk-[A-Za-z0-9]{32,}\b/g },
  { name: "Anthropic key (sk-ant-)", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: "AWS_SECRET_ACCESS_KEY", re: /AWS_SECRET_ACCESS_KEY\s*[:=]?\s*['"`]?[A-Za-z0-9/+=]{30,}/gi },
  { name: "PEM private key header", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { name: "GitHub personal access token (ghp_)", re: /\bghp_[A-Za-z0-9]{30,}\b/g },
];

function redact(s: string): string {
  return s.length > 16 ? s.slice(0, 8) + "…[" + (s.length - 12) + " chars]…" + s.slice(-4) : s;
}

function scanForSecrets(text: string): { pattern: string; sample: string }[] {
  const hits: { pattern: string; sample: string }[] = [];
  const seen = new Set<string>();
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    const matches = text.match(p.re);
    if (!matches || !matches.length) continue;
    const key = `${p.name}|${matches[0]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hits.push({ pattern: p.name, sample: redact(matches[0]) });
  }
  return hits;
}

async function pMap<T, R>(items: T[], n: number, fn: (it: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  async function worker() {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      out[idx] = await fn(items[idx]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
}

export const runRepoScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string; repoUrl: string; token: string; appUrl?: string | null }) => {
    if (!input?.auditId || typeof input.auditId !== "string") throw new Error("auditId required");
    if (!input?.repoUrl || typeof input.repoUrl !== "string") throw new Error("repoUrl required");
    if (!input?.token || typeof input.token !== "string") throw new Error("token required");
    if (input.token.length < 20) throw new Error("token looks too short to be a valid PAT");
    return { ...input, appUrl: input.appUrl ?? null };
  })

  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const parsed = parseRepo(data.repoUrl);
    if (!parsed) return { ok: false as const, error: `Could not parse GitHub URL: ${data.repoUrl}` };

    // Check ownership before doing any work (RLS would also block the writes,
    // but only after the GitHub calls had run).
    const { data: auditRow, error: aerr } = await supabase
      .from("audits").select("id, created_by").eq("id", data.auditId).single();
    if (aerr || !auditRow || (auditRow as any).created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }

    const quota = await consumeQuota(supabase, "scan", 1);
    if (!quota.ok) return { ok: false as const, error: quota.error };
    const headers = ghHeaders(data.token);

    // Verify the repo & token up front (and discover default branch).
    const repoMeta = await timedFetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`, { headers });
    if (repoMeta.status === 401) return { ok: false as const, error: "GitHub rejected the token (401). Check that it has read access to this repo." };
    if (repoMeta.status === 404) return { ok: false as const, error: "Repo not found (404). Check the URL and that the token can see it." };
    if (!repoMeta.ok) return { ok: false as const, error: `GitHub repo lookup failed (${repoMeta.status}).` };
    const meta = await repoMeta.json();
    const defaultBranch = meta.default_branch as string;

    // ---- Check 1: .env files in .gitignore ----
    const tree = await timedFetch(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
      { headers },
    );
    let envCheck: { status: "pass" | "fail" | "inconclusive"; notes: string };
    let treePaths: string[] | null = null;
    let treeWasTruncated = false;
    if (!tree.ok) {
      envCheck = { status: "inconclusive", notes: `Not checked: the repository file listing could not be fetched (HTTP ${tree.status}).` };
    } else {
      const treeJson = await tree.json();
      // GitHub cuts off very large recursive listings. A .env outside the
      // returned subset would be invisible, so a truncated tree can't pass.
      const treeTruncated = treeJson.truncated === true;
      const paths: string[] = (treeJson.tree ?? [])
        .filter((n: any) => n.type === "blob")
        .map((n: any) => n.path);
      treePaths = (treeJson.tree ?? [])
        .filter((n: any) => n.type === "blob" && (n.size ?? 0) < MAX_XSS_FILE_BYTES)
        .map((n: any) => n.path as string);
      treeWasTruncated = treeTruncated;
      const envFiles = paths.filter(isEnvFilePath);
      // Read .gitignore through the API with the PAT, so private repos work.
      let gitignore = "";
      const gi = await timedFetch(
        `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/contents/.gitignore?ref=${encodeURIComponent(defaultBranch)}`,
        { headers },
      );
      if (gi.ok) {
        const giJson = await gi.json();
        gitignore = decodeBase64Utf8(String(giJson?.content ?? ""));
      }
      const ignoresEnv = gitignoreIgnoresEnv(gitignore);

      if (envFiles.length > 0) {
        envCheck = {
          status: "fail",
          notes: `Found .env file(s) committed to default branch (${defaultBranch}):\n${envFiles.map((p) => "- " + p).join("\n")}\n\n.gitignore ${ignoresEnv ? "does" : "does NOT"} include a .env rule. Already-tracked files remain in git history even after being added to .gitignore.`,
        };
      } else if (!gi.ok && gi.status !== 404) {
        envCheck = { status: "inconclusive", notes: `Not checked: .gitignore could not be read (HTTP ${gi.status}).` };
      } else if (!gi.ok) {
        envCheck = { status: "fail", notes: "No .gitignore file at repository root. Add one that excludes .env and .env.*" };
      } else if (!ignoresEnv) {
        envCheck = { status: "fail", notes: ".gitignore exists but contains no .env rule. Recommended:\n\n  .env\n  .env.*\n  !.env.example" };
      } else if (treeTruncated) {
        envCheck = {
          status: "inconclusive",
          notes: `.gitignore ignores .env, but GitHub truncated the file listing for ${defaultBranch} (the repo is very large), so committed .env files could not be ruled out. Verify manually.`,
        };
      } else {
        envCheck = { status: "pass", notes: `No .env files committed to ${defaultBranch}; .gitignore ignores .env.` };
      }
    }

    // ---- Check 2: scan last 100 commits ----
    const commitsResp = await timedFetch(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/commits?per_page=${MAX_COMMITS}`,
      { headers },
    );
    if (!commitsResp.ok) throw new Error(`Commit list fetch failed (${commitsResp.status}).`);
    const commits = (await commitsResp.json()) as any[];

    const findings: RepoFinding[] = [];
    // Commits and file diffs we could not actually inspect. If any exist, a
    // clean result is not a pass: the secret may be in exactly what we skipped.
    const unevaluated: string[] = [];
    let evaluatedCommits = 0;
    await pMap(commits, COMMIT_CONCURRENCY, async (c) => {
      const sha = c.sha as string;
      const date: string | null = c.commit?.author?.date ?? c.commit?.committer?.date ?? null;
      const r = await timedFetch(
        `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/commits/${sha}`,
        { headers },
      );
      if (!r.ok) {
        unevaluated.push(`${sha.slice(0, 7)} — commit detail not returned (HTTP ${r.status})`);
        return;
      }
      const detail = await r.json();
      const files: any[] = detail.files ?? [];
      // GitHub returns at most 300 files per commit on this endpoint.
      if (files.length >= 300) unevaluated.push(`${sha.slice(0, 7)} — file list truncated by GitHub (300+ files)`);
      for (const f of files) {
        const filename = String(f.filename ?? "");
        // .env file additions
        if ((f.status === "added" || f.status === "modified") && isEnvFilePath(filename)) {
          findings.push({
            pattern: ".env file added/modified",
            sample: filename,
            commit: sha,
            date,
            file: filename,
          });
        }
        const patch = (f.patch as string | undefined) ?? "";
        if (!patch) {
          // No patch means GitHub withheld the diff (large or binary file).
          // Removed files have nothing added, so they're not a gap.
          if (f.status !== "removed" && (f.additions ?? 1) > 0) {
            unevaluated.push(`${sha.slice(0, 7)} — ${filename} (diff not returned by GitHub)`);
          }
          continue;
        }
        const added = patch
          .split("\n")
          .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
          .map((l) => l.slice(1))
          .join("\n");
        if (!added) continue;
        const hits = scanForSecrets(added);
        for (const h of hits) {
          findings.push({ pattern: h.pattern, sample: h.sample, commit: sha, date, file: filename });
        }
      }
      evaluatedCommits++;
    });

    // Group findings for the note
    const dedup = new Map<string, RepoFinding>();
    for (const f of findings) {
      const key = `${f.commit}|${f.file}|${f.pattern}|${f.sample}`;
      if (!dedup.has(key)) dedup.set(key, f);
    }
    const unique = Array.from(dedup.values());

    const unevaluatedNote = unevaluated.length
      ? `\n\n${unevaluated.length} commit(s)/file diff(s) could NOT be inspected:\n${unevaluated.slice(0, 30).map((u) => `• ${u}`).join("\n")}${unevaluated.length > 30 ? `\n• …and ${unevaluated.length - 30} more` : ""}`
      : "";
    let historyCheck: { status: "pass" | "fail" | "inconclusive"; notes: string };
    if (unique.length === 0 && unevaluated.length > 0) {
      historyCheck = {
        status: "inconclusive",
        notes: `No secret patterns found in the ${evaluatedCommits} of ${commits.length} recent commits that could be inspected on ${defaultBranch}, but the scan was incomplete, so this is not a pass. Re-run (GitHub rate limits are often transient) or review the listed items manually.${unevaluatedNote}`,
      };
    } else if (unique.length === 0) {
      historyCheck = {
        status: "pass",
        notes: `Scanned the last ${commits.length} commits on ${defaultBranch} — no .env file additions or secret patterns (.env, SUPABASE_SERVICE_ROLE_KEY, service_role, STRIPE_SECRET_KEY, sk_live_, OPENAI_API_KEY, sk-ant-, AWS_SECRET_ACCESS_KEY, PEM private keys, ghp_ tokens) detected in added lines.`,
      };
    } else {
      const lines = unique.slice(0, 30).map((f) => {
        const short = f.commit.slice(0, 7);
        const when = f.date ? new Date(f.date).toISOString().slice(0, 10) : "unknown date";
        return `• ${short} (${when}) — ${f.file}\n    ${f.pattern}: ${f.sample}`;
      });
      historyCheck = {
        status: "fail",
        notes: `Scanned ${evaluatedCommits} of the last ${commits.length} commits on ${defaultBranch}. Found ${unique.length} potential secret exposure(s):\n\n${lines.join("\n\n")}${unique.length > 30 ? `\n\n…and ${unique.length - 30} more.` : ""}\n\nRotate any real credentials and rewrite history (git filter-repo or BFG).${unevaluatedNote}`,
      };
    }

    // ---- XSS: raw-HTML rendering in the source ----
    let xssCheck: { status: "pass" | "fail" | "inconclusive"; notes: string };
    if (!treePaths) {
      xssCheck = { status: "inconclusive", notes: "Not checked: the repository file listing could not be fetched." };
    } else {
      const { pick, total } = xssCandidatePaths(treePaths, MAX_XSS_FILES);
      let failed = 0;
      const hits: XssHit[] = [];
      await pMap(pick, 8, async (path) => {
        try {
          const r = await timedFetch(
            `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(defaultBranch)}`,
            { headers: { ...headers, accept: "application/vnd.github.raw" } },
          );
          if (!r.ok) {
            await r.body?.cancel().catch(() => {});
            failed++;
            return;
          }
          hits.push(...findXssSinks(path, await r.text()));
        } catch {
          failed++;
        }
      });
      hits.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
      xssCheck = checkXss(hits, { scanned: pick.length - failed, total: treeWasTruncated ? total + 1 : total, failed });
    }

    // ---- Persist findings by checklist title ----
    const titleToResult: Record<string, { status: "pass" | "fail" | "inconclusive"; notes: string }> = {
      ".env files in .gitignore": envCheck,
      "No secrets in git history": historyCheck,
      "XSS protections in place": xssCheck,
    };
    const titles = Object.keys(titleToResult);
    const { data: items, error: ierr } = await supabase
      .from("checklist_items")
      .select("id, title")
      .in("title", titles);
    if (ierr) throw new Error(ierr.message);
    const byTitle = new Map<string, string>();
    (items ?? []).forEach((it: any) => byTitle.set(it.title, it.id));

    const stamp = new Date().toISOString();
    const written: { title: string; status: string; matched: boolean }[] = [];
    for (const [title, res] of Object.entries(titleToResult)) {
      const itemId = byTitle.get(title);
      if (!itemId) {
        written.push({ title, status: res.status, matched: false });
        continue;
      }
      const note = `[Repo scan ${stamp}]\nRepo: ${parsed.owner}/${parsed.repo}\n\n${res.notes}`;
      const w = await upsertScanFinding(supabase, {
        audit_id: data.auditId,
        checklist_item_id: itemId,
        status: res.status,
        notes: note,
      });
      written.push({ title, status: w.written ? res.status : `${res.status} (kept existing ${w.keptStatus})`, matched: true });
    }

    // ---- Phase 2: dependency vulnerability scan ----
    const dep = await runDepScan({
      owner: parsed.owner,
      repo: parsed.repo,
      token: data.token,
      defaultBranch,
      supabase,
      auditId: data.auditId,
    });

    // ---- Phase 3: AI endpoint discovery ----
    let aiEndpoints: DetectedEndpoint[] = [];
    let aiDetectError: string | null = null;
    try {
      const detectRes = await detectAIEndpointsCore({
        owner: parsed.owner,
        repo: parsed.repo,
        token: data.token,
        branch: defaultBranch,
        appUrl: data.appUrl,
      });
      if (detectRes.ok) {
        aiEndpoints = detectRes.endpoints;
      } else {
        aiDetectError = detectRes.error;
      }
    } catch (e: any) {
      aiDetectError = e?.message ?? "AI endpoint detection failed";
    }

    // If endpoints found but no test recorded yet, write an "inconclusive" finding
    // on "Prompt injection test performed" — do NOT overwrite an existing pass/fail.
    if (aiEndpoints.length > 0) {
      const { data: piItems } = await supabase
        .from("checklist_items")
        .select("id, title")
        .eq("title", "Prompt injection test performed")
        .limit(1);
      const piItem = piItems?.[0];
      if (piItem) {
        const { data: existing } = await supabase
          .from("audit_findings")
          .select("id, status")
          .eq("audit_id", data.auditId)
          .eq("checklist_item_id", piItem.id)
          .maybeSingle();
        const already = existing?.status === "pass" || existing?.status === "fail";
        if (!already) {
          const lines = aiEndpoints.slice(0, 10).map(
            (e) => `• ${e.source} — ${e.url || "(URL not resolved)"} (field: ${e.promptField}${e.requiresAuth ? ", auth" : ""})\n    ${e.filePath}`,
          ).join("\n");
          // "inconclusive", not "na": the check applies, it just hasn't been run.
          await upsertScanFinding(supabase, {
              audit_id: data.auditId,
              checklist_item_id: piItem.id,
              status: "inconclusive",
              notes: `[Repo scan ${stamp}] ⚠ ${aiEndpoints.length} AI endpoint${aiEndpoints.length === 1 ? "" : "s"} discovered in ${parsed.owner}/${parsed.repo} but no prompt-injection test has been run yet. Use “Test for Injection” in the AI Endpoints Discovered panel.\n\n${lines}${aiEndpoints.length > 10 ? `\n\n…and ${aiEndpoints.length - 10} more.` : ""}`,
          });
        }
      }
    }

    return {
      ok: true as const,
      repo: `${parsed.owner}/${parsed.repo}`,
      commitsScanned: evaluatedCommits,
      commitsListed: commits.length,
      commitsNotInspected: unevaluated.length,
      findings: unique,
      results: written,
      dep,
      aiEndpoints,
      aiDetectError,
    };
  });

