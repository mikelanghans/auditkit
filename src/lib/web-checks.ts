// Pure evaluation logic for the extra website checks: source maps, cookie
// flags, exposed files, third-party scripts, open redirects and the
// "security headers configured" roll-up. No network and no imports, so the
// rules can be unit-tested; scan.functions.ts does the fetching.
//
// Every rule separates "we saw it was fine" from "we couldn't tell". A single
// page fetch can't see cookies set after login or redirects done in browser
// JavaScript, so those cases are reported as such rather than as a pass.

export type WebStatus = "pass" | "fail" | "warn" | "inconclusive";
export type WebResult = { key: string; status: WebStatus; notes: string };

// ---------------------------------------------------------------------------
// Source maps
// ---------------------------------------------------------------------------

const SOURCE_MAP_COMMENT = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/m;

/**
 * Map URLs worth probing for each same-origin script: the one named by a
 * sourceMappingURL comment, and `<file>.map` (Vite's "hidden" maps are served
 * without the comment). Inline data: maps are reported separately.
 */
export function sourceMapCandidates(
  sources: { url: string; body: string }[],
  origin: string,
  max = 6,
): { candidates: string[]; inline: string[] } {
  const candidates: string[] = [];
  const inline: string[] = [];
  const add = (u: string) => {
    if (candidates.length < max && !candidates.includes(u)) candidates.push(u);
  };
  for (const s of sources) {
    let url: URL;
    try {
      url = new URL(s.url);
    } catch {
      continue;
    }
    if (url.origin !== origin || !/\.[mc]?js$/.test(url.pathname)) continue;
    const m = SOURCE_MAP_COMMENT.exec(s.body.slice(-2000));
    if (m) {
      if (m[1].startsWith("data:")) {
        inline.push(s.url);
        continue;
      }
      try {
        add(new URL(m[1], s.url).toString());
      } catch {
        /* ignore */
      }
    }
    const plain = new URL(url.toString());
    plain.search = "";
    add(`${plain.toString()}.map`);
  }
  return { candidates, inline };
}

/** A real source map is JSON with version/mappings/sources. SPA fallbacks return HTML. */
export function looksLikeSourceMap(head: string): boolean {
  const t = head.trimStart();
  if (!t.startsWith("{")) return false;
  return /"mappings"\s*:/.test(t) || (/"version"\s*:\s*3/.test(t) && /"sources"\s*:/.test(t));
}

export type ProbeOutcome = { url: string; status?: number; head?: string; error?: string };

export function checkSourceMaps(
  probes: ProbeOutcome[],
  inline: string[],
  scriptsFetched: number,
): WebResult {
  const key = "source_maps_exposed";
  const exposed = probes.filter((p) => p.status === 200 && p.head && looksLikeSourceMap(p.head));
  if (exposed.length || inline.length) {
    const lines = [
      ...exposed.map((p) => `- ${p.url}`),
      ...inline.map((u) => `- ${u} (inline source map embedded in the file)`),
    ];
    return {
      key,
      status: "fail",
      notes:
        `Source maps are publicly downloadable, which hands anyone the app's original source code (component names, comments, API calls, business logic):\n${lines.join("\n")}\n\n` +
        "Disable production source maps (Vite: build.sourcemap = false) or stop serving .map files publicly.",
    };
  }
  if (scriptsFetched === 0)
    return { key, status: "inconclusive", notes: "Not checked: no same-origin JavaScript files were fetched." };
  const errored = probes.filter((p) => p.error);
  if (probes.length === 0 || errored.length === probes.length)
    return {
      key,
      status: "inconclusive",
      notes: `Not checked: the source map probes failed.${errored.length ? `\n${errored.map((p) => `- ${p.url}: ${p.error}`).join("\n")}` : ""}`,
    };
  return {
    key,
    status: "pass",
    notes: `No source maps served. Probed ${probes.length} map location(s):\n${probes
      .map((p) => `- ${p.url} → ${p.error ? `error: ${p.error}` : `HTTP ${p.status}${p.status === 200 ? " (not a source map)" : ""}`}`)
      .join("\n")}`,
  };
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

export type ParsedCookie = {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
};

export function parseSetCookie(raw: string): ParsedCookie | null {
  const parts = raw.split(";").map((p) => p.trim());
  const first = parts.shift() ?? "";
  const eq = first.indexOf("=");
  if (eq <= 0) return null;
  const name = first.slice(0, eq).trim();
  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;
  for (const p of parts) {
    const [k, v] = p.split("=").map((x) => x?.trim());
    const lk = (k ?? "").toLowerCase();
    if (lk === "secure") secure = true;
    else if (lk === "httponly") httpOnly = true;
    else if (lk === "samesite") sameSite = (v ?? "").toLowerCase() || null;
  }
  return { name, secure, httpOnly, sameSite };
}

const SESSION_COOKIE = /(sess|sid$|^sid|auth|token|jwt|login|remember|connect\.sid|sb-.*-auth)/i;

export function checkCookieFlags(setCookies: string[], isHttps: boolean): WebResult {
  const key = "cookie_flags";
  const cookies = setCookies.map(parseSetCookie).filter((c): c is ParsedCookie => !!c);
  if (cookies.length === 0)
    return {
      key,
      status: "inconclusive",
      notes:
        "The page response sets no cookies, so there was nothing to check. Cookies set after sign-in (session cookies) aren't visible to an anonymous scan; check them in the browser's DevTools → Application → Cookies while signed in.",
    };
  const problems: string[] = [];
  const minor: string[] = [];
  for (const c of cookies) {
    const session = SESSION_COOKIE.test(c.name);
    if (isHttps && !c.secure) (session ? problems : minor).push(`${c.name}: missing Secure`);
    if (session && !c.httpOnly) problems.push(`${c.name}: looks like a session/auth cookie but lacks HttpOnly (readable by any injected script)`);
    if (c.sameSite === "none" && !c.secure) problems.push(`${c.name}: SameSite=None without Secure (browsers reject it)`);
    if (!c.sameSite) minor.push(`${c.name}: no SameSite (browsers default to Lax)`);
  }
  const listing = cookies
    .map((c) => `- ${c.name}: ${[c.secure && "Secure", c.httpOnly && "HttpOnly", c.sameSite && `SameSite=${c.sameSite}`].filter(Boolean).join(", ") || "no flags"}`)
    .join("\n");
  if (problems.length)
    return {
      key,
      status: "fail",
      notes: `Cookie flag problems:\n${problems.map((p) => `- ${p}`).join("\n")}${minor.length ? `\n\nAlso:\n${minor.map((p) => `- ${p}`).join("\n")}` : ""}\n\nCookies on the page response:\n${listing}`,
    };
  return {
    key,
    status: "pass",
    notes: `Cookies on the page response are flagged correctly.${minor.length ? `\n\nMinor:\n${minor.map((p) => `- ${p}`).join("\n")}` : ""}\n\n${listing}\n\nOnly cookies on the anonymous page response were checked; confirm session cookies after sign-in.`,
  };
}

// ---------------------------------------------------------------------------
// Exposed files
// ---------------------------------------------------------------------------

/**
 * Each probe has a content test, because single-page apps answer every path
 * with index.html and HTTP 200. Only a body that really is the file counts.
 */
export const EXPOSED_FILE_PROBES: { path: string; label: string; test: (head: string) => boolean }[] = [
  { path: "/.env", label: "environment file", test: isEnvFile },
  { path: "/.env.local", label: "environment file", test: isEnvFile },
  { path: "/.env.production", label: "environment file", test: isEnvFile },
  { path: "/.git/HEAD", label: "git repository", test: (h) => /^ref:\s*refs\/|^[0-9a-f]{40}\s*$/.test(h.trim()) },
  { path: "/.git/config", label: "git repository", test: (h) => /^\s*\[core\]/m.test(h) && !/<html/i.test(h) },
  { path: "/.DS_Store", label: "macOS folder index (lists file names)", test: (h) => h.startsWith("\u0000\u0000\u0000\u0001Bud1") },
];

function isEnvFile(head: string): boolean {
  if (/<(!doctype|html|head|body)\b/i.test(head)) return false;
  const lines = head.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (lines.length === 0) return false;
  const kv = lines.filter((l) => /^(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l));
  return kv.length >= 1 && kv.length / lines.length >= 0.6;
}

export function checkExposedFiles(probes: (ProbeOutcome & { path: string })[]): WebResult {
  const key = "exposed_files";
  const hits: string[] = [];
  for (const p of probes) {
    const spec = EXPOSED_FILE_PROBES.find((s) => s.path === p.path);
    if (spec && p.status === 200 && p.head !== undefined && spec.test(p.head)) hits.push(`- ${p.url} (${spec.label})`);
  }
  if (hits.length)
    return {
      key,
      status: "fail",
      notes: `Files that should never be public are being served:\n${hits.join("\n")}\n\nRemove them from the deployed output and rotate any secrets an exposed .env contained. An exposed .git lets anyone download the full source and its history.`,
    };
  const answered = probes.filter((p) => p.status !== undefined);
  if (answered.length === 0)
    return { key, status: "inconclusive", notes: `Not checked: every probe failed.\n${probes.map((p) => `- ${p.url}: ${p.error ?? "no response"}`).join("\n")}` };
  return {
    key,
    status: answered.length === probes.length ? "pass" : "inconclusive",
    notes: `None of these are served:\n${probes
      .map((p) => `- ${p.path} → ${p.error ? `error: ${p.error}` : `HTTP ${p.status}${p.status === 200 ? " (app page, not the file)" : ""}`}`)
      .join("\n")}`,
  };
}

// ---------------------------------------------------------------------------
// Third-party scripts
// ---------------------------------------------------------------------------

export function thirdPartyScripts(html: string, base: string): { src: string; integrity: boolean }[] {
  const origin = new URL(base).origin;
  const out: { src: string; integrity: boolean }[] = [];
  for (const m of html.matchAll(/<script\b[^>]*>/gi)) {
    const tag = m[0];
    const src = /\bsrc=["']([^"']+)["']/i.exec(tag)?.[1];
    if (!src) continue;
    let u: URL;
    try {
      u = new URL(src, base.endsWith("/") ? base : `${base}/`);
    } catch {
      continue;
    }
    if (u.origin === origin || !/^https?:$/.test(u.protocol)) continue;
    out.push({ src: u.toString(), integrity: /\bintegrity=["']sha(256|384|512)-/i.test(tag) });
  }
  return out;
}

export function checkThirdPartyScripts(html: string, base: string): WebResult {
  const key = "third_party_scripts";
  const scripts = thirdPartyScripts(html, base);
  if (scripts.length === 0)
    return {
      key,
      status: "pass",
      notes: "The page loads no scripts from other domains in its HTML. (Scripts injected later by tag managers aren't visible here.)",
    };
  const hosts = Array.from(new Set(scripts.map((s) => new URL(s.src).host)));
  const noSri = scripts.filter((s) => !s.integrity);
  const listing = scripts.map((s) => `- ${s.src}${s.integrity ? " (integrity hash ✓)" : " (no integrity hash)"}`).join("\n");
  if (noSri.length === 0)
    return { key, status: "pass", notes: `Third-party scripts are pinned with integrity hashes:\n${listing}` };
  return {
    key,
    status: "inconclusive",
    notes:
      `The page runs code from ${hosts.length} other domain(s): ${hosts.join(", ")}. Each one can read everything on the page, including session tokens. Review that each is needed and trusted.\n\n${listing}\n\n` +
      "Pin fixed-version files with integrity=\"sha384-…\" crossorigin=\"anonymous\". Providers that update their script in place (Stripe.js, analytics tags) can't be pinned; for those, confirm the provider and restrict them in the CSP.",
  };
}

// ---------------------------------------------------------------------------
// Open redirects
// ---------------------------------------------------------------------------

export const REDIRECT_PARAMS = ["redirect", "redirect_to", "redirectTo", "next", "returnTo", "return_to", "returnUrl", "url", "continue"];
export const REDIRECT_SENTINEL = "https://auditkit-redirect-probe.example.com/";

export function redirectProbeUrls(base: string, paths: string[] = ["/", "/login", "/auth", "/signin"]): string[] {
  const b = base.replace(/\/+$/, "");
  const out: string[] = [];
  for (const p of paths) for (const param of ["redirect", "next", "returnTo", "redirect_to"]) out.push(`${b}${p}?${param}=${encodeURIComponent(REDIRECT_SENTINEL)}`);
  return out;
}

export function isSentinelRedirect(location: string | null | undefined, from: string): boolean {
  if (!location) return false;
  try {
    return new URL(location, from).hostname === new URL(REDIRECT_SENTINEL).hostname;
  } catch {
    return false;
  }
}

/** Client code that sends the browser to a URL read straight from the query string. */
export function clientRedirectHints(sources: { url: string; body: string }[]): string[] {
  // Minified code renames the params object, so any `.get("redirect")` counts;
  // generic names like "url" are left out to avoid matching unrelated maps.
  const names = REDIRECT_PARAMS.filter((n) => n !== "url" && n !== "continue").join("|");
  const read = String.raw`[\w$)\]]\.get\(\s*["'](?:${names})["']\s*\)`;
  const sink = String.raw`(?:(?:window\.|document\.)?location(?:\.href)?\s*=|location\.(?:assign|replace)\(|window\.open\()`;
  const re = new RegExp(String.raw`${sink}[^;\n]{0,120}${read}|${read}[^;\n]{0,160}${sink}`, "g");
  const hits: string[] = [];
  for (const s of sources) {
    for (const m of s.body.matchAll(re)) {
      hits.push(`${s.url}: …${m[0].slice(0, 160)}…`);
      if (hits.length >= 5) return hits;
    }
  }
  return hits;
}

export function checkOpenRedirect(
  probes: { url: string; status?: number; location?: string | null; error?: string }[],
  clientHints: string[],
): WebResult {
  const key = "open_redirect";
  const open = probes.filter((p) => isSentinelRedirect(p.location, p.url));
  if (open.length)
    return {
      key,
      status: "fail",
      notes: `The server redirects to any site named in the URL, which lets attackers send phishing links that start on this domain:\n${open
        .map((p) => `- ${p.url} → ${p.location}`)
        .join("\n")}\n\nOnly redirect to relative paths or an allowlist of your own URLs.`,
    };
  if (clientHints.length)
    return {
      key,
      status: "inconclusive",
      notes: `The server doesn't redirect, but the app's JavaScript sends the browser to a URL taken from the query string. Check it only allows your own paths:\n${clientHints
        .map((h) => `- ${h}`)
        .join("\n")}`,
    };
  const answered = probes.filter((p) => p.status !== undefined);
  if (answered.length === 0) return { key, status: "inconclusive", notes: "Not checked: every redirect probe failed." };
  return {
    key,
    status: "pass",
    notes: `No open redirect found. Probed ${probes.length} URL(s) with redirect/next/returnTo parameters pointing off-site; none redirected there, and no client code was found sending the browser to a query-string URL.`,
  };
}

// ---------------------------------------------------------------------------
// Security headers roll-up
// ---------------------------------------------------------------------------

export const HEADER_KEYS = ["csp_header", "hsts_header", "xframe_header", "xcontent_type", "referrer_policy", "permissions_policy"];

export function checkSecurityHeadersRollup(results: { key: string; status: WebStatus }[]): WebResult {
  const key = "security_headers";
  const got = HEADER_KEYS.map((k) => ({ k, r: results.find((x) => x.key === k) }));
  const missing = got.filter((g) => !g.r || g.r.status === "inconclusive");
  const failed = got.filter((g) => g.r?.status === "fail");
  if (failed.length)
    return { key, status: "fail", notes: `${failed.length} of ${HEADER_KEYS.length} security header checks failed: ${failed.map((f) => f.k).join(", ")}. See each header's finding for detail.` };
  if (missing.length)
    return { key, status: "inconclusive", notes: `Not all header checks could run: ${missing.map((m) => m.k).join(", ")}.` };
  return { key, status: "pass", notes: `All ${HEADER_KEYS.length} security header checks passed.` };
}
