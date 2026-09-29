// Fetch the JavaScript a web page ships to browsers, for secret scanning.
// Shared by the audit website scan and the public /check page.
//
// Coverage is tracked honestly: anything we could not fetch, or chose not to
// fetch because of the cap, is reported, and `complete` is false. Callers must
// never turn "we didn't see it" into "it's clean".

import { assertSafeOutboundUrl, safeFetch } from "./ssrf-guard";

export type BundleCoverage = {
  complete: boolean;
  summary: string;
  fetched: number;
  discovered: number;
  skipped: string[];
  overCap: number;
};

export type CollectOptions = {
  maxBundles?: number;
  timeoutMs?: number;
  maxBytesPerFile?: number;
  userAgent?: string;
  /** Stop starting new fetches after this many ms; the rest count as not scanned. */
  totalBudgetMs?: number;
};

const JS_PATH = String.raw`[^"'\s<>]+\.[mc]?js(?:\?[^"'\s<>]*)?`;

/** Script URLs referenced by the HTML: <script src> and <link rel=modulepreload>. */
export function extractScriptUrls(html: string, base: string): string[] {
  const urls = new Set<string>();
  const add = (raw: string) => {
    try {
      const u = new URL(raw, base.endsWith("/") ? base : base + "/");
      if (u.protocol === "http:" || u.protocol === "https:") urls.add(u.toString());
    } catch {
      /* ignore */
    }
  };
  for (const m of html.matchAll(
    new RegExp(String.raw`<script\b[^>]*\bsrc=["'](${JS_PATH})["']`, "gi"),
  ))
    add(m[1]);
  for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/\brel=["']?(?:modulepreload|preload)\b/i.test(tag)) continue;
    const href = new RegExp(String.raw`\bhref=["'](${JS_PATH})["']`, "i").exec(tag);
    if (href) add(href[1]);
  }
  return Array.from(urls);
}

/**
 * Lazy-loaded chunks referenced from inside a bundle, e.g. Vite's
 * `import("./Dashboard-a1b2c3.js")` or `"/assets/Settings-d4e5f6.js"`.
 * Only same-origin relative paths are followed.
 */
export function discoverChunkUrls(body: string, bundleUrl: string, origin: string): string[] {
  const out = new Set<string>();
  const re = /["'`]((?:\.{1,2}\/|\/)[A-Za-z0-9_\-./@]+\.[mc]?js)["'`]/g;
  for (const m of body.matchAll(re)) {
    try {
      const u = new URL(m[1], bundleUrl);
      if (u.origin === origin) out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return Array.from(out);
}

export async function collectBundles(
  base: string,
  html: string,
  opts: CollectOptions = {},
): Promise<{ sources: { url: string; body: string }[]; coverage: BundleCoverage }> {
  const {
    maxBundles = 30,
    timeoutMs = 10_000,
    maxBytesPerFile = 8_000_000,
    userAgent = "AuditKit-Scanner/1.0",
    totalBudgetMs,
  } = opts;
  const deadline = totalBudgetMs ? Date.now() + totalBudgetMs : Infinity;
  let outOfTime = 0;
  const origin = new URL(base).origin;
  const sources: { url: string; body: string }[] = [{ url: base, body: html }];
  const skipped: string[] = [];
  const seen = new Set<string>();
  const queue = extractScriptUrls(html, base);
  for (const u of queue) seen.add(u);
  let overCap = 0;
  let fetched = 0;

  while (queue.length > 0) {
    const url = queue.shift()!;
    if (fetched + skipped.length >= maxBundles) {
      overCap = queue.length + 1;
      break;
    }
    if (Date.now() >= deadline) {
      outOfTime = queue.length + 1;
      break;
    }
    try {
      await assertSafeOutboundUrl(url);
      const r = await safeFetch(
        url,
        { headers: { "user-agent": userAgent } },
        { timeoutMs, maxBodyBytes: maxBytesPerFile },
      );
      if (!r.ok) {
        await r.body?.cancel().catch(() => {});
        skipped.push(`${url} (HTTP ${r.status})`);
        continue;
      }
      const body = await r.text();
      sources.push({ url, body });
      fetched++;
      for (const c of discoverChunkUrls(body, url, origin)) {
        if (!seen.has(c)) {
          seen.add(c);
          queue.push(c);
        }
      }
    } catch (e: any) {
      skipped.push(`${url} (${e?.message ?? "fetch failed"})`);
    }
  }

  const discovered = seen.size;
  const lines: string[] = [
    `Scanned the HTML and ${fetched} of ${discovered} JavaScript file(s) found.`,
  ];
  if (skipped.length)
    lines.push(
      `Could not fetch ${skipped.length}:\n${skipped
        .slice(0, 15)
        .map((u) => `- ${u}`)
        .join("\n")}`,
    );
  if (overCap > 0)
    lines.push(`${overCap} file(s) beyond the ${maxBundles}-file scan limit were not fetched.`);
  if (outOfTime > 0)
    lines.push(`${outOfTime} file(s) were not fetched because the scan hit its time limit.`);
  return {
    sources,
    coverage: {
      complete: skipped.length === 0 && overCap === 0 && outOfTime === 0,
      summary: lines.join("\n\n"),
      fetched,
      discovered,
      skipped,
      overCap: overCap + outOfTime,
    },
  };
}
