import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { assertSafeOutboundUrl, safeFetch, SSRFBlockedError } from "./ssrf-guard";
import { upsertScanFinding } from "./finding-writer";
import { consumeQuota } from "./quota";


// "warn" = advisory, left for manual review and not written.
// "inconclusive" = the scanner could not observe what it needed to; written so the
// item is visibly unverified, but never allowed to overwrite a known failure.
type ScanStatus = "pass" | "fail" | "warn" | "inconclusive";
type CheckResult = { key: string; status: ScanStatus; notes: string };

const TIMEOUT_MS = 10_000;
// Bodies from the client's site are capped. A bigger one errors and the check
// that needed it is reported as inconclusive instead of judged on part of it.
const MAX_FETCH_BYTES = 8_000_000;

/**
 * Routed through safeFetch so every redirect hop is re-validated. The target is
 * a client-supplied site, so a 302 into an internal address is a realistic
 * bypass rather than a theoretical one.
 */
async function timedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return await safeFetch(url, init, { timeoutMs: TIMEOUT_MS, maxBodyBytes: MAX_FETCH_BYTES });
}

function normalizeUrl(raw: string): string {
  let u = raw.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u.replace(/\/+$/, "");
}

function checkSsl(url: string, ok: boolean, err?: string): CheckResult {
  if (!url.startsWith("https://")) return { key: "ssl_valid", status: "fail", notes: `URL is not HTTPS: ${url}` };
  if (!ok) return { key: "ssl_valid", status: "fail", notes: `HTTPS request failed: ${err ?? "unknown error"}` };
  return { key: "ssl_valid", status: "pass", notes: `HTTPS reachable and certificate validated by runtime fetch (${url}).` };
}

function header(h: Headers, name: string, key: string, friendly: string): CheckResult {
  const v = h.get(name);
  return v
    ? { key, status: "pass", notes: `${friendly} present: ${name}: ${v}` }
    : { key, status: "fail", notes: `Missing ${name} header.` };
}

function checkCors(h: Headers): CheckResult {
  const acao = h.get("access-control-allow-origin");
  const acac = (h.get("access-control-allow-credentials") ?? "").toLowerCase() === "true";
  if (!acao) {
    // No CORS header on the top-level document is normal and safe.
    return { key: "cors_policy", status: "pass", notes: "No Access-Control-Allow-Origin header on the main response — no cross-origin exposure from this endpoint." };
  }
  if (acao === "*" && acac) {
    // The genuinely dangerous pair: wildcard origin with credentials. Browsers
    // block literal "*"+credentials, but servers that reflect the origin AND set
    // credentials achieve the same effect — flag the wildcard as a strong signal.
    return { key: "cors_policy", status: "fail", notes: "Access-Control-Allow-Origin is '*' together with Access-Control-Allow-Credentials: true — any site can make credentialed cross-origin requests. Restrict the allowed origin to a specific trusted host." };
  }
  if (acao === "*") {
    return { key: "cors_policy", status: "warn", notes: "Access-Control-Allow-Origin is '*' — any origin may read responses from this endpoint. Fine for genuinely public data; scope it to a trusted origin if the endpoint ever returns anything user-specific." };
  }
  return { key: "cors_policy", status: "pass", notes: `Access-Control-Allow-Origin is scoped: ${acao}${acac ? " (with credentials)" : ""}.` };
}

function parseCspDirectives(csp: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const rawDirective of csp.split(";")) {
    const parts = rawDirective.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) continue;
    const [name, ...values] = parts;
    directives.set(name.toLowerCase(), values.map((v) => v.toLowerCase()));
  }
  return directives;
}

function checkCsp(h: Headers): CheckResult {
  const csp = h.get("content-security-policy");
  const reportOnly = h.get("content-security-policy-report-only");
  if (!csp) {
    return {
      key: "csp_header",
      status: "fail",
      notes: reportOnly
        ? `Only Content-Security-Policy-Report-Only is present; no enforced Content-Security-Policy header found.\n\nReport-only policy:\n${reportOnly}`
        : "No Content-Security-Policy header on the response.",
    };
  }

  const directives = parseCspDirectives(csp);
  const scriptSrc = directives.get("script-src") ?? directives.get("default-src") ?? [];
  const unsafeScriptTokens = scriptSrc.filter((token) =>
    token === "'unsafe-inline'" ||
    token === "'unsafe-eval'" ||
    token === "*" ||
    token.includes("*") ||
    token === "http:" ||
    token === "https:"
  );

  return {
    key: "csp_header",
    status: unsafeScriptTokens.length > 0 ? "fail" : "pass",
    notes: `CSP found:\n${csp}${unsafeScriptTokens.length > 0 ? `\n\nWarning: script-src allows unsafe sources: ${unsafeScriptTokens.join(", ")}` : ""}`,
  };
}

function checkErrorVerbosity(body: string, statusCode: number): CheckResult {
  const lower = body.toLowerCase();
  const markers = ["stack trace", "at /", "node_modules", ".js:", ".ts:", "traceback", "exception in", "syntaxerror", "referenceerror"];
  const hit = markers.filter((m) => lower.includes(m));
  if (hit.length > 1) {
    return { key: "error_verbosity", status: "fail", notes: `Probe (${statusCode}) returned response containing developer-detail markers: ${hit.join(", ")}.` };
  }
  return { key: "error_verbosity", status: "pass", notes: `404/error probe returned a clean response (${statusCode}); no stack-trace markers detected.` };
}

function checkSensitiveUrlParams(body: string, base: string): CheckResult {
  const re = /[?&](?:token|access_token|api_key|apikey|password|secret|sessionid|auth)=([^&"'<\s]{4,})/gi;
  const hits: string[] = [];
  let m;
  while ((m = re.exec(body)) !== null && hits.length < 5) hits.push(m[0]);
  if (hits.length === 0) {
    return { key: "sensitive_url_params", status: "pass", notes: `No obvious sensitive query parameters detected in HTML returned from ${base}.` };
  }
  return { key: "sensitive_url_params", status: "fail", notes: `Found possible sensitive query parameters in HTML:\n${hits.join("\n")}` };
}

function checkBundleSecrets(sources: { url: string; body: string }[], coverage: BundleCoverage): CheckResult {
  const patterns: Array<[RegExp, string]> = [
    [/sk_live_[A-Za-z0-9]{16,}/g, "Stripe live secret key"],
    [/sk_test_[A-Za-z0-9]{16,}/g, "Stripe test secret key"],
    [/AKIA[0-9A-Z]{16}/g, "AWS access key"],
    [/AIza[0-9A-Za-z\-_]{35}/g, "Google API key"],
    [/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "JWT-like token"],
    [/service_role[^A-Za-z0-9]{0,5}[:=][^,\n]{20,}/gi, "service_role reference"],
  ];
  const hits: string[] = [];
  for (const { url, body } of sources) {
    for (const [re, label] of patterns) {
      const matches = body.match(re);
      if (matches) hits.push(`${label} (${matches.length} match${matches.length > 1 ? "es" : ""}) in ${url}`);
    }
  }
  if (hits.length > 0) {
    return { key: "bundle_secrets", status: "fail", notes: `Possible secret patterns detected in client-side code:\n- ${hits.join("\n- ")}` };
  }
  if (!coverage.complete) {
    return {
      key: "bundle_secrets",
      status: "inconclusive",
      notes: `No secret patterns found in what could be scanned, but the scan was incomplete, so this is not a pass.\n\n${coverage.summary}`,
    };
  }
  return {
    key: "bundle_secrets",
    status: "pass",
    notes: `No obvious secret patterns detected in the HTML and ${sources.length - 1} JS bundle(s).`,
  };
}

function checkDebugMode(body: string, h: Headers): CheckResult {
  const lower = body.toLowerCase();
  const markers = ["debug=true", "vite-plugin", "__vite_", "react devtools", "redux devtools", "process.env.node_env\":\"development", '"development"'];
  const hit = markers.filter((m) => lower.includes(m));
  const xpb = h.get("x-powered-by");
  if (hit.length === 0 && !xpb) {
    return { key: "debug_mode", status: "pass", notes: "No debug/development markers found in served HTML or response headers." };
  }
  const notes = [
    hit.length ? `Markers in HTML: ${hit.join(", ")}` : null,
    xpb ? `X-Powered-By: ${xpb}` : null,
  ].filter(Boolean).join("\n");
  return { key: "debug_mode", status: "fail", notes: `Possible debug-mode signals:\n${notes}` };
}

const SENSITIVE_VITE_KEYWORDS = ["SECRET", "KEY", "TOKEN", "PASSWORD", "PRIVATE", "SERVICE_ROLE", "API"];
// Values that are designed to be public in a browser bundle. Flagging these as
// "sensitive" would put a false critical in every Supabase app's report.
const PUBLIC_BY_DESIGN_VITE = /^VITE_[A-Z0-9_]*(PUBLISHABLE_KEY|ANON_KEY|_URL|PROJECT_ID)$/;
const MAX_BUNDLES = 15;
const MAX_BUNDLE_BYTES = MAX_FETCH_BYTES;

type BundleCoverage = { complete: boolean; summary: string };

function extractScriptUrls(html: string, base: string): string[] {
  const urls = new Set<string>();
  const re = /<script\b[^>]*\bsrc=["']([^"']+\.[mc]?js(?:\?[^"']*)?)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      urls.add(new URL(m[1], base + "/").toString());
    } catch {
      /* ignore */
    }
  }
  return Array.from(urls);
}

/**
 * Fetch the page's JS bundles once, for both bundle checks. Tracks what could
 * NOT be scanned, because "we didn't see it" must never be reported as "clean".
 */
async function collectBundles(base: string, html: string): Promise<{ sources: { url: string; body: string }[]; coverage: BundleCoverage }> {
  const allUrls = extractScriptUrls(html, base);
  const scriptUrls = allUrls.slice(0, MAX_BUNDLES);
  const sources: { url: string; body: string }[] = [{ url: base, body: html }];
  const skipped: string[] = [];
  for (const url of scriptUrls) {
    try {
      await assertSafeOutboundUrl(url);
      const r = await timedFetch(url, { headers: { "user-agent": "AuditKit-Scanner/1.0" } });
      if (!r.ok) {
        skipped.push(`${url} (HTTP ${r.status})`);
        continue;
      }
      const text = (await r.text()).slice(0, MAX_BUNDLE_BYTES);
      sources.push({ url, body: text });
    } catch (e: any) {
      skipped.push(`${url} (${e?.message ?? "fetch failed"})`);
    }
  }
  const overCap = allUrls.length - scriptUrls.length;
  const lines: string[] = [`Scanned the HTML and ${sources.length - 1} of ${allUrls.length} referenced JS bundle(s).`];
  if (skipped.length) lines.push(`Could not fetch ${skipped.length}:\n${skipped.slice(0, 15).map((u) => `- ${u}`).join("\n")}`);
  if (overCap > 0) lines.push(`${overCap} bundle(s) beyond the ${MAX_BUNDLES}-file scan limit were not fetched.`);
  return { sources, coverage: { complete: skipped.length === 0 && overCap === 0, summary: lines.join("\n\n") } };
}

function checkViteExposure(sources: { url: string; body: string }[], coverage: BundleCoverage): CheckResult {

  const viteVarRe = /\bVITE_[A-Z0-9_]+/g;
  const foundByVar = new Map<string, Set<string>>();
  for (const { url, body } of sources) {
    const matches = body.match(viteVarRe);
    if (!matches) continue;
    for (const name of matches) {
      const upper = name.toUpperCase();
      if (PUBLIC_BY_DESIGN_VITE.test(upper)) continue;
      if (!SENSITIVE_VITE_KEYWORDS.some((kw) => upper.includes(kw))) continue;
      if (!foundByVar.has(upper)) foundByVar.set(upper, new Set());
      foundByVar.get(upper)!.add(url);
    }
  }

  if (foundByVar.size === 0) {
    if (!coverage.complete) {
      return {
        key: "vite_exposure",
        status: "inconclusive",
        notes: `No sensitive VITE_ variable names found in what could be scanned, but the scan was incomplete, so this is not a pass.\n\n${coverage.summary}`,
      };
    }
    return {
      key: "vite_exposure",
      status: "pass",
      notes: `Scanned the HTML and ${sources.length - 1} JS bundle(s). No VITE_ variable names containing sensitive keywords (${SENSITIVE_VITE_KEYWORDS.join(", ")}) were detected in the served bundle.`,
    };
  }
  const lines = Array.from(foundByVar.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, urls]) => `- ${name}  (in ${urls.size} file${urls.size > 1 ? "s" : ""})`);
  return {
    key: "vite_exposure",
    status: "fail",
    notes: `Found ${foundByVar.size} sensitive VITE_-prefixed variable name(s) in the served client bundle (scanned ${sources.length} source(s)). Anything prefixed VITE_ is inlined by Vite into the public browser bundle and is readable by every visitor. Rotate these secrets and move them to server-only env vars (drop the VITE_ prefix).\n\nDetected:\n${lines.join("\n")}`,
  };
}

export const runAutoScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string }) => {
    if (!input?.auditId || typeof input.auditId !== "string") throw new Error("auditId required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase } = context;

    const { data: audit, error: aerr } = await supabase
      .from("audits")
      .select("id, website_url, client:clients(id, websites, name)")
      .eq("id", data.auditId)
      .single();
    if (aerr) throw new Error(aerr.message);
    const fromAudit = (audit as any)?.website_url as string | null | undefined;
    const fromClient = ((audit as any)?.client?.websites as string[] | undefined)?.[0];
    const appUrl = fromAudit || fromClient;
    if (!appUrl) throw new Error("This audit has no website set. Add a website to the client and select it on the audit.");
    const base = normalizeUrl(appUrl);
    try {
      await assertSafeOutboundUrl(base);
    } catch (e) {
      if (e instanceof SSRFBlockedError) {
        throw new Error(`Refusing to probe internal/private destination: ${e.message}`);
      }
      throw e;
    }

    const quota = await consumeQuota(supabase, "scan", 1);
    if (!quota.ok) throw new Error(quota.error);

    const results: CheckResult[] = [];
    let mainResp: Response | null = null;
    let mainErr: string | undefined;
    let body = "";
    // Content checks only count when we actually read the site's real page:
    // a 2xx response whose body was read in full. An error page, a WAF challenge
    // or a connection reset mid-body is not evidence that the site is clean.
    let bodyObserved = false;
    let unobservedReason = "";
    try {
      mainResp = await timedFetch(base, { method: "GET", headers: { "user-agent": "AuditKit-Scanner/1.0" } });
    } catch (e: any) {
      mainErr = e?.message ?? String(e);
    }
    if (mainResp) {
      try {
        body = (await mainResp.text()).slice(0, 200_000);
        if (mainResp.ok) bodyObserved = true;
        else unobservedReason = `${base} returned HTTP ${mainResp.status}, so its content and headers may not be the real page's.`;
      } catch (e: any) {
        unobservedReason = `Reading the response body from ${base} failed: ${e?.message ?? String(e)}`;
      }
    }

    // TLS was negotiated if response headers arrived at all.
    results.push(checkSsl(base, !!mainResp, mainErr));

    if (mainResp && bodyObserved) {
      const h = mainResp.headers;
      results.push(header(h, "x-frame-options", "xframe_header", "X-Frame-Options"));
      results.push(header(h, "x-content-type-options", "xcontent_type", "X-Content-Type-Options"));
      results.push(header(h, "referrer-policy", "referrer_policy", "Referrer-Policy"));
      results.push(header(h, "strict-transport-security", "hsts_header", "HSTS"));
      results.push(header(h, "permissions-policy", "permissions_policy", "Permissions-Policy"));
      results.push(checkCsp(h));
      results.push(checkCors(h));
      results.push(checkSensitiveUrlParams(body, base));
      results.push(checkDebugMode(body, h));
      const bundles = await collectBundles(base, body);
      results.push(checkBundleSecrets(bundles.sources, bundles.coverage));
      results.push(checkViteExposure(bundles.sources, bundles.coverage));
    } else {
      const reason = mainResp ? unobservedReason : `Could not fetch ${base}: ${mainErr ?? "unknown error"}`;
      const unobservedKeys = ["xframe_header", "xcontent_type", "referrer_policy", "hsts_header", "permissions_policy", "csp_header", "cors_policy", "sensitive_url_params", "bundle_secrets", "debug_mode", "vite_exposure"];
      for (const key of unobservedKeys) {
        results.push({ key, status: "inconclusive", notes: `Not checked: ${reason}` });
      }
    }

    // Error verbosity probe
    try {
      const probeUrl = `${base}/__auditkit_probe_${Date.now()}`;
      const probe = await timedFetch(probeUrl, { method: "GET", headers: { "user-agent": "AuditKit-Scanner/1.0" } });
      const text = (await probe.text()).slice(0, 50_000);
      results.push(checkErrorVerbosity(text, probe.status));
    } catch (e: any) {
      results.push({ key: "error_verbosity", status: "inconclusive", notes: `Not checked: the probe request failed (${e?.message ?? String(e)}).` });
    }

    // Map keys → checklist item ids
    const keys = results.map((r) => r.key);
    const { data: items, error: ierr } = await supabase
      .from("checklist_items")
      .select("id, checklist_key")
      .in("checklist_key", keys);
    if (ierr) throw new Error(ierr.message);
    const byKey = new Map<string, string>();
    (items ?? []).forEach((it: any) => byKey.set(it.checklist_key, it.id));

    const stamp = new Date().toISOString();
    const written: { key: string; status: ScanStatus; matched: boolean; stored: boolean }[] = [];

    for (const r of results) {
      const itemId = byKey.get(r.key);
      if (!itemId) {
        written.push({ key: r.key, status: r.status, matched: false, stored: false });
        continue;
      }
      // Warn results: skip writing — leave for manual review
      if (r.status === "warn") {
        written.push({ key: r.key, status: r.status, matched: true, stored: false });
        continue;
      }
      const note = `[Auto-scan ${stamp}]\nTarget: ${base}\n\n${r.notes}`;
      const res = await upsertScanFinding(supabase, {
        audit_id: data.auditId,
        checklist_item_id: itemId,
        status: r.status,
        notes: note,
      });
      written.push({ key: r.key, status: r.status, matched: true, stored: res.written });
    }

    const passes = written.filter((w) => w.status === "pass").length;
    const fails = written.filter((w) => w.status === "fail").length;
    const warnings = written.filter((w) => w.status === "warn").length;
    const inconclusive = written.filter((w) => w.status === "inconclusive").length;

    return { target: base, results: written, passes, fails, warnings, inconclusive };
  });
