import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

type CheckResult = { title: string; status: "pass" | "fail"; notes: string };

const TIMEOUT_MS = 15_000;
const MAX_COMMITS = 100;
const MAX_BUNDLES = 8;
const COMMIT_CONCURRENCY = 6;

async function timedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: ctl.signal, redirect: "follow" });
  } finally {
    clearTimeout(t);
  }
}

function parseRepo(raw: string): { owner: string; repo: string } | null {
  const m = raw
    .trim()
    .replace(/\.git$/, "")
    .match(/github\.com[/:]([^/]+)\/([^/?#]+)/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

function ghHeaders(token: string): Record<string, string> {
  return {
    accept: "application/vnd.github+json",
    "user-agent": "AuditKit-Scanner/1.0",
    "x-github-api-version": "2022-11-28",
    authorization: `Bearer ${token}`,
  };
}

// Patterns user explicitly named
const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "SUPABASE_SERVICE_ROLE", re: /SUPABASE_SERVICE_ROLE[_A-Z0-9]*\s*[:=]\s*['"`]?[A-Za-z0-9._-]{20,}/g },
  { name: "Supabase service-role JWT", re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g },
  { name: "sk-live-… secret", re: /\bsk-live[_-][A-Za-z0-9]{16,}\b/g },
  { name: "sk-… (OpenAI-style)", re: /\bsk-[A-Za-z0-9]{32,}\b/g },
  { name: "API_KEY=…", re: /\b[A-Z][A-Z0-9_]*API_KEY[A-Z0-9_]*\s*[:=]\s*['"`][^'"`\n]{16,}['"`]/g },
  { name: "AWS access key", re: /\bAKIA[0-9A-Z]{16}\b/g },
];

function scanForSecrets(text: string): { pattern: string; sample: string }[] {
  const hits: { pattern: string; sample: string }[] = [];
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    const m = text.match(p.re);
    if (m && m.length) {
      // redact middle of the match
      const first = m[0];
      const redacted = first.length > 16 ? first.slice(0, 8) + "…[" + (first.length - 12) + " chars]…" + first.slice(-4) : first;
      hits.push({ pattern: p.name, sample: redacted });
    }
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

async function checkEnvIgnored(owner: string, repo: string, token: string): Promise<CheckResult> {
  const title = ".env files in .gitignore";
  // Default branch
  const repoMeta = await timedFetch(`https://api.github.com/repos/${owner}/${repo}`, { headers: ghHeaders(token) });
  if (!repoMeta.ok) return { title, status: "fail", notes: `GitHub repo lookup failed (${repoMeta.status}): ${await repoMeta.text().then((t) => t.slice(0, 300))}` };
  const meta = await repoMeta.json();
  const branch = meta.default_branch as string;

  // Recursive tree
  const tree = await timedFetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, { headers: ghHeaders(token) });
  if (!tree.ok) return { title, status: "fail", notes: `Tree fetch failed (${tree.status}).` };
  const treeJson = await tree.json();
  const paths: string[] = (treeJson.tree ?? []).filter((n: any) => n.type === "blob").map((n: any) => n.path);

  const envFiles = paths.filter((p) => /(^|\/)\.env(\..+)?$/.test(p) && !/\.env\.example$/i.test(p) && !/\.env\.sample$/i.test(p));

  // Fetch .gitignore (root)
  let gitignore = "";
  const gi = await timedFetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/.gitignore`, { headers: { "user-agent": "AuditKit-Scanner/1.0" } });
  if (gi.ok) gitignore = await gi.text();

  const ignoresEnv = /(^|\n)\s*(\.env\*?|\*\.env|\.env(\.|$))/m.test(gitignore);

  if (envFiles.length > 0) {
    return {
      title,
      status: "fail",
      notes: `Found .env file(s) committed to the default branch (${branch}):\n${envFiles.map((p) => "- " + p).join("\n")}\n\n.gitignore ${ignoresEnv ? "does" : "does NOT"} include a .env rule. Even if listed in .gitignore, an already-tracked file remains in git history.`,
    };
  }
  if (!gi.ok) {
    return { title, status: "fail", notes: `No .gitignore file at repository root. Add one that excludes .env and .env.*` };
  }
  if (!ignoresEnv) {
    return { title, status: "fail", notes: `.gitignore exists but contains no .env rule. Recommended: add\n\n  .env\n  .env.*\n  !.env.example` };
  }
  return { title, status: "pass", notes: `No .env files committed to ${branch}; .gitignore contains a .env rule.` };
}

async function checkGitHistory(owner: string, repo: string, token: string): Promise<CheckResult> {
  const title = "No secrets in git history";
  const commitsResp = await timedFetch(`https://api.github.com/repos/${owner}/${repo}/commits?per_page=${MAX_COMMITS}`, { headers: ghHeaders(token) });
  if (!commitsResp.ok) return { title, status: "fail", notes: `Commit list fetch failed (${commitsResp.status}).` };
  const commits = (await commitsResp.json()) as any[];

  const findings: string[] = [];
  await pMap(commits, COMMIT_CONCURRENCY, async (c) => {
    const sha = c.sha as string;
    const r = await timedFetch(`https://api.github.com/repos/${owner}/${repo}/commits/${sha}`, { headers: ghHeaders(token) });
    if (!r.ok) return;
    const detail = await r.json();
    const files: any[] = detail.files ?? [];
    for (const f of files) {
      const patch = (f.patch as string | undefined) ?? "";
      // Only look at additions
      const added = patch
        .split("\n")
        .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
        .map((l) => l.slice(1))
        .join("\n");
      if (!added) continue;
      const hits = scanForSecrets(added);
      if (hits.length) {
        findings.push(
          `Commit ${sha.slice(0, 7)} — ${f.filename}:\n` +
            hits.map((h) => `  • ${h.pattern}: ${h.sample}`).join("\n"),
        );
      }
    }
  });

  if (findings.length) {
    return {
      title,
      status: "fail",
      notes: `Scanned last ${commits.length} commits. Potential secrets found:\n\n${findings.slice(0, 25).join("\n\n")}${findings.length > 25 ? `\n\n…and ${findings.length - 25} more.` : ""}\n\nRotate any real credentials and rewrite history (git filter-repo or BFG).`,
    };
  }
  return { title, status: "pass", notes: `Scanned last ${commits.length} commits for SUPABASE_SERVICE_ROLE, sk-live, API_KEY, JWTs, and AWS keys — no matches in added lines.` };
}

async function checkBundleSecrets(appUrl: string): Promise<CheckResult> {
  const title = "No secrets in client-side bundle";
  let html = "";
  try {
    const r = await timedFetch(appUrl, { headers: { "user-agent": "AuditKit-Scanner/1.0" } });
    if (!r.ok) return { title, status: "fail", notes: `App URL returned ${r.status}; could not fetch HTML to discover bundles.` };
    html = await r.text();
  } catch (e: any) {
    return { title, status: "fail", notes: `Failed to fetch app URL: ${e?.message ?? String(e)}` };
  }

  const scriptSrcs = Array.from(html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)).map((m) => m[1]);
  const base = new URL(appUrl);
  const absSrcs = scriptSrcs.map((s) => new URL(s, base).toString()).slice(0, MAX_BUNDLES);

  if (absSrcs.length === 0) {
    // Still scan inline HTML
    const hits = scanForSecrets(html);
    if (hits.length) {
      return { title, status: "fail", notes: `No external scripts found; inline HTML contained:\n${hits.map((h) => `• ${h.pattern}: ${h.sample}`).join("\n")}` };
    }
    return { title, status: "pass", notes: `No external script bundles linked from ${appUrl}; inline HTML clean.` };
  }

  const findings: string[] = [];
  await pMap(absSrcs, 4, async (u) => {
    try {
      const r = await timedFetch(u);
      if (!r.ok) return;
      const text = (await r.text()).slice(0, 2_000_000);
      const hits = scanForSecrets(text);
      if (hits.length) {
        findings.push(`${u}:\n` + hits.map((h) => `  • ${h.pattern}: ${h.sample}`).join("\n"));
      }
    } catch {
      /* ignore */
    }
  });

  if (findings.length) {
    return {
      title,
      status: "fail",
      notes: `Scanned ${absSrcs.length} bundle(s); matches found:\n\n${findings.join("\n\n")}\n\nReact apps inline VITE_* env vars — anything in the bundle is public.`,
    };
  }
  return { title, status: "pass", notes: `Scanned ${absSrcs.length} bundle(s) from ${appUrl}; no secret patterns matched.` };
}

export const runGithubScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string }) => {
    if (!input?.auditId || typeof input.auditId !== "string") throw new Error("auditId required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase } = context;

    const { data: audit, error: aerr } = await supabase
      .from("audits")
      .select("id, client:clients(id, name, app_url, github_repo_url, github_token)")
      .eq("id", data.auditId)
      .single();
    if (aerr) throw new Error(aerr.message);

    const client = (audit as any)?.client;
    if (!client?.github_repo_url) throw new Error("Client has no GitHub repo URL set.");
    if (!client?.github_token) throw new Error("Client has no GitHub access token set (needs a fine-grained PAT with repo: read).");

    const parsed = parseRepo(client.github_repo_url);
    if (!parsed) throw new Error(`Could not parse GitHub URL: ${client.github_repo_url}`);

    const results: CheckResult[] = [];

    const [envRes, histRes] = await Promise.all([
      checkEnvIgnored(parsed.owner, parsed.repo, client.github_token).catch((e: any) => ({
        title: ".env files in .gitignore",
        status: "fail" as const,
        notes: `Scan error: ${e?.message ?? String(e)}`,
      })),
      checkGitHistory(parsed.owner, parsed.repo, client.github_token).catch((e: any) => ({
        title: "No secrets in git history",
        status: "fail" as const,
        notes: `Scan error: ${e?.message ?? String(e)}`,
      })),
    ]);
    results.push(envRes, histRes);

    if (client.app_url) {
      const bundleRes = await checkBundleSecrets(
        /^https?:\/\//i.test(client.app_url) ? client.app_url : `https://${client.app_url}`,
      ).catch((e: any) => ({
        title: "No secrets in client-side bundle",
        status: "fail" as const,
        notes: `Scan error: ${e?.message ?? String(e)}`,
      }));
      results.push(bundleRes);
    } else {
      results.push({
        title: "No secrets in client-side bundle",
        status: "fail",
        notes: "Client has no app URL set — cannot fetch the deployed JS bundle.",
      });
    }

    // Map titles → checklist item ids
    const titles = results.map((r) => r.title);
    const { data: items, error: ierr } = await supabase.from("checklist_items").select("id, title").in("title", titles);
    if (ierr) throw new Error(ierr.message);
    const byTitle = new Map<string, string>();
    (items ?? []).forEach((it: any) => byTitle.set(it.title, it.id));

    const written: { title: string; status: string; matched: boolean }[] = [];
    const stamp = new Date().toISOString();
    for (const r of results) {
      const itemId = byTitle.get(r.title);
      if (!itemId) {
        written.push({ title: r.title, status: r.status, matched: false });
        continue;
      }
      const note = `[GitHub scan ${stamp}]\nRepo: ${parsed.owner}/${parsed.repo}\n\n${r.notes}`;
      const { error: upErr } = await supabase.from("audit_findings").upsert(
        { audit_id: data.auditId, checklist_item_id: itemId, status: r.status, notes: note },
        { onConflict: "audit_id,checklist_item_id" },
      );
      if (upErr) throw new Error(upErr.message);
      written.push({ title: r.title, status: r.status, matched: true });
    }

    return { repo: `${parsed.owner}/${parsed.repo}`, results: written };
  });
