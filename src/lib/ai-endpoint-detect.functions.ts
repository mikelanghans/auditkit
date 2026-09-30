import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { GITHUB_HOSTS, safeFetch } from "./ssrf-guard";
import { parseGithubRepo } from "./github-repo";

const TIMEOUT_MS = 15_000;
const MAX_FILES_TO_FETCH = 40;
const MAX_FILE_BYTES = 80_000;
const FETCH_CONCURRENCY = 6;

export type DetectedEndpoint = {
  /** Best-guess full URL. May be empty if base URL couldn't be inferred. */
  url: string;
  /** Inferred prompt field name (default "prompt"). */
  promptField: string;
  /** True if the file references Authorization / auth middleware. */
  requiresAuth: boolean;
  /** Source descriptor — "supabase function: chat" or "tanstack route: /api/chat". */
  source: string;
  kind: "supabase-function" | "tanstack-route" | "nextjs-route";
  /** Path in the repo. */
  filePath: string;
  /** Short evidence string showing why we flagged it. */
  evidence: string;
  /** True when the URL had to be guessed / left relative. */
  partialUrl: boolean;
};

const parseRepo = parseGithubRepo;

function ghHeaders(token: string): Record<string, string> {
  return {
    accept: "application/vnd.github+json",
    "user-agent": "AuditKit-AIDetect/1.0",
    "x-github-api-version": "2022-11-28",
    authorization: `Bearer ${token}`,
  };
}

/** Pinned to GitHub hosts; the PAT is dropped on any cross-origin redirect. */
async function timedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return await safeFetch(url, init, { timeoutMs: TIMEOUT_MS, allowHosts: GITHUB_HOSTS });
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

const AI_SIGNALS = [
  /ai\.gateway\.lovable\.dev/i,
  /createLovableAiGatewayProvider/,
  /LOVABLE_API_KEY/,
  /\bstreamText\b/,
  /\bgenerateText\b/,
  /\bgenerateObject\b/,
  /@ai-sdk\//,
  /openai\.com\/v1\/(chat|completions|responses)/i,
  /\banthropic\b.*messages/i,
  /api\.anthropic\.com/i,
  /generativelanguage\.googleapis\.com/i,
  /\bgemini-[\w.-]+/i,
  /\bclaude-[\w.-]+/i,
  /\bgpt-[\w.-]+/i,
  /\bOpenAI\(/,
  /\bAnthropic\(/,
];

function looksLikeAiCode(text: string): { hit: boolean; evidence: string } {
  for (const re of AI_SIGNALS) {
    const m = text.match(re);
    if (m) {
      const idx = m.index ?? 0;
      const snip = text.slice(Math.max(0, idx - 20), Math.min(text.length, idx + m[0].length + 30)).replace(/\s+/g, " ").trim();
      return { hit: true, evidence: snip.length > 120 ? snip.slice(0, 117) + "…" : snip };
    }
  }
  return { hit: false, evidence: "" };
}

function detectPromptField(text: string): string {
  // Highest priority: explicit destructure from request body
  const destruct = text.match(/(?:const|let)\s*\{\s*([^}]+)\}\s*=\s*(?:await\s+)?(?:req|request)\.json\(\)/);
  if (destruct) {
    const names = destruct[1].split(",").map((s) => s.trim().split(/[:=\s]/)[0]).filter(Boolean);
    for (const candidate of ["messages", "prompt", "message", "text", "query", "input", "content"]) {
      if (names.includes(candidate)) return candidate;
    }
    if (names[0]) return names[0];
  }
  // Look for body.<field>
  for (const candidate of ["messages", "prompt", "message", "text", "query", "input", "content"]) {
    const re = new RegExp(`\\b(?:body|data|payload|json)\\.${candidate}\\b`);
    if (re.test(text)) return candidate;
  }
  // useChat / DefaultChatTransport implies "messages"
  if (/\buseChat\(|DefaultChatTransport/.test(text)) return "messages";
  return "prompt";
}

function detectRequiresAuth(text: string): boolean {
  return (
    /requireSupabaseAuth/.test(text) ||
    /\bauthorization\b/i.test(text) ||
    /auth\.uid\(\)/.test(text) ||
    /verifyJWT|verify_jwt/i.test(text) ||
    /getUser\(\)/.test(text)
  );
}

function normalizeAppBase(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const u = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const parsed = new URL(u);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

/** Convert TanStack file route file like `src/routes/api/chat.ts` to `/api/chat`. */
function tanstackPathFromFile(filePath: string): string | null {
  const m = filePath.match(/^src\/routes\/(.+)\.(?:ts|tsx|js|jsx)$/);
  if (!m) return null;
  let body = m[1];
  if (body.endsWith("/index")) body = body.slice(0, -"/index".length);
  // dot-routing: "api.chat" -> "api/chat"
  body = body.replace(/\./g, "/");
  // $param -> :param
  body = body.replace(/\$([A-Za-z0-9_]+)/g, ":$1");
  return "/" + body;
}

function nextRoutePathFromFile(filePath: string): string | null {
  // app/api/foo/route.ts -> /api/foo
  const app = filePath.match(/^app\/(api\/.+)\/route\.(?:ts|tsx|js|jsx)$/);
  if (app) return "/" + app[1];
  // pages/api/foo.ts -> /api/foo
  const pages = filePath.match(/^pages\/(api\/.+)\.(?:ts|tsx|js|jsx)$/);
  if (pages) return "/" + pages[1].replace(/\/index$/, "");
  return null;
}

function supabaseFnNameFromFile(filePath: string): string | null {
  const m = filePath.match(/^supabase\/functions\/([^/]+)\/index\.(?:ts|js)$/);
  return m ? m[1] : null;
}

export type DetectAIEndpointsResult =
  | { ok: true; repo: string; filesScanned: number; supabaseBaseDetected: boolean; appBaseDetected: boolean; endpoints: DetectedEndpoint[] }
  | { ok: false; error: string };

/** Core detection logic — callable from other server functions without going through RPC. */
export async function detectAIEndpointsCore(input: {
  owner: string;
  repo: string;
  token: string;
  branch?: string | null;
  appUrl: string | null;
}): Promise<DetectAIEndpointsResult> {
  const { owner, repo, token, appUrl } = input;
  const headers = ghHeaders(token);

  let branch = input.branch ?? null;
  if (!branch) {
    const repoMeta = await timedFetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
    if (repoMeta.status === 401) return { ok: false, error: "GitHub rejected the token (401)." };
    if (repoMeta.status === 404) return { ok: false, error: "Repo not found (404)." };
    if (!repoMeta.ok) return { ok: false, error: `GitHub repo lookup failed (${repoMeta.status}).` };
    const meta = await repoMeta.json();
    branch = meta.default_branch as string;
  }

  const tree = await timedFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
    { headers },
  );
  if (!tree.ok) return { ok: false, error: `Tree fetch failed (${tree.status}).` };
  const treeJson = await tree.json();
  const paths: string[] = (treeJson.tree ?? [])
    .filter((n: any) => n.type === "blob" && typeof n.path === "string" && (n.size ?? 0) < MAX_FILE_BYTES)
    .map((n: any) => n.path as string);

  const candidates = paths.filter(
    (p) =>
      /^supabase\/functions\/[^/]+\/index\.(?:ts|js)$/.test(p) ||
      /^src\/routes\/api\/.+\.(?:ts|tsx|js|jsx)$/.test(p) ||
      /^app\/api\/.+\/route\.(?:ts|tsx|js|jsx)$/.test(p) ||
      /^pages\/api\/.+\.(?:ts|tsx|js|jsx)$/.test(p),
  ).slice(0, MAX_FILES_TO_FETCH);

  const envCandidates = paths.filter((p) =>
    /(^|\/)(\.env\.example|\.env\.sample|\.env\.local\.example)$/i.test(p) ||
    /src\/integrations\/supabase\/client\.(?:ts|tsx|js|jsx)$/.test(p),
  ).slice(0, 5);

  async function fetchRaw(path: string): Promise<string> {
    try {
      const r = await timedFetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`, {
        headers: { "user-agent": "AuditKit-AIDetect/1.0" },
      });
      if (!r.ok) return "";
      const buf = await r.arrayBuffer();
      return new TextDecoder("utf-8", { fatal: false }).decode(buf.slice(0, MAX_FILE_BYTES));
    } catch {
      return "";
    }
  }

  const envContents = await pMap(envCandidates, FETCH_CONCURRENCY, fetchRaw);
  let supabaseBase: string | null = null;
  for (const text of envContents) {
    const m =
      text.match(/SUPABASE_URL\s*[:=]\s*['"`]?(https?:\/\/[^\s'"`]+)/i) ||
      text.match(/VITE_SUPABASE_URL\s*[:=]\s*['"`]?(https?:\/\/[^\s'"`]+)/i) ||
      text.match(/supabaseUrl\s*[:=]\s*['"`](https?:\/\/[^'"`]+)/);
    if (m) { supabaseBase = m[1].replace(/\/+$/, ""); break; }
  }

  const appBase = normalizeAppBase(appUrl);
  const fileContents = await pMap(candidates, FETCH_CONCURRENCY, async (p) => ({ path: p, text: await fetchRaw(p) }));
  const endpoints: DetectedEndpoint[] = [];

  for (const { path, text } of fileContents) {
    if (!text) continue;
    const ai = looksLikeAiCode(text);
    if (!ai.hit) continue;
    const promptField = detectPromptField(text);
    const requiresAuth = detectRequiresAuth(text);

    const fnName = supabaseFnNameFromFile(path);
    if (fnName) {
      const url = supabaseBase ? `${supabaseBase}/functions/v1/${fnName}` : "";
      endpoints.push({ url, promptField, requiresAuth, source: `Edge function: ${fnName}`, kind: "supabase-function", filePath: path, evidence: ai.evidence, partialUrl: !url });
      continue;
    }
    const tsPath = tanstackPathFromFile(path);
    if (tsPath) {
      const url = appBase ? `${appBase}${tsPath}` : tsPath;
      endpoints.push({ url, promptField, requiresAuth, source: `TanStack route: ${tsPath}`, kind: "tanstack-route", filePath: path, evidence: ai.evidence, partialUrl: !appBase });
      continue;
    }
    const nxPath = nextRoutePathFromFile(path);
    if (nxPath) {
      const url = appBase ? `${appBase}${nxPath}` : nxPath;
      endpoints.push({ url, promptField, requiresAuth, source: `Next.js route: ${nxPath}`, kind: "nextjs-route", filePath: path, evidence: ai.evidence, partialUrl: !appBase });
    }
  }

  return {
    ok: true,
    repo: `${owner}/${repo}`,
    filesScanned: fileContents.length,
    supabaseBaseDetected: !!supabaseBase,
    appBaseDetected: !!appBase,
    endpoints,
  };
}

export const detectAIEndpoints = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { repoUrl: string; token: string; appUrl: string | null }) => {
    if (!input?.repoUrl) throw new Error("repoUrl required");
    if (!input?.token) throw new Error("token required");
    return input;
  })
  .handler(async ({ data }) => {
    const parsed = parseRepo(data.repoUrl);
    if (!parsed) return { ok: false as const, error: `Could not parse GitHub URL: ${data.repoUrl}` };
    return await detectAIEndpointsCore({ owner: parsed.owner, repo: parsed.repo, token: data.token, appUrl: data.appUrl });
  });

