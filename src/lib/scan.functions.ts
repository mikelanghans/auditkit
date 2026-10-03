import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { assertSafeOutboundUrl, safeFetch, SSRFBlockedError, describeBlockedUrl } from "./ssrf-guard";
import { upsertScanFinding } from "./finding-writer";
import { saveScanRun, type RecordedResult } from "./scan-history";
import { httpExchange, type EvidenceInput } from "./evidence";
import { consumeQuota } from "./quota";
import { collectBundles, type BundleCoverage } from "./bundle-collect";
import { scanForSecrets } from "./bundle-secrets";
import {
  EXPOSED_FILE_PROBES,
  checkCookieFlags,
  checkExposedFiles,
  checkOpenRedirect,
  checkSecurityHeadersRollup,
  checkSourceMaps,
  checkThirdPartyScripts,
  clientRedirectHints,
  redirectProbeUrls,
  sourceMapCandidates,
  type ProbeOutcome,
} from "./web-checks";


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

const UA = { "user-agent": "AuditKit-Scanner/1.0" };

/** GET a URL and keep only the status and the first few KB of the body. */
async function probeHead(url: string, bytes = 4096): Promise<ProbeOutcome> {
  try {
    const res = await safeFetch(url, { headers: UA }, { timeoutMs: TIMEOUT_MS, maxBodyBytes: MAX_FETCH_BYTES });
    let head = "";
    if (res.body) {
      const reader = res.body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (total < bytes) {
        const { value, done } = await reader.read();
        if (done || !value) break;
        chunks.push(value);
        total += value.length;
      }
      await reader.cancel().catch(() => {});
      const buf = new Uint8Array(Math.min(total, bytes));
      let off = 0;
      for (const c of chunks) {
        const take = c.subarray(0, buf.length - off);
        buf.set(take, off);
        off += take.length;
        if (off >= buf.length) break;
      }
      head = new TextDecoder("latin1").decode(buf);
    }
    return { url, status: res.status, head };
  } catch (e: any) {
    return { url, error: e?.message ?? String(e) };
  }
}

/** First hop only, never followed: we need the Location header itself. */
async function probeRedirect(url: string): Promise<{ url: string; status?: number; location?: string | null; error?: string }> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    await assertSafeOutboundUrl(url);
    const res = await fetch(url, { headers: UA, redirect: "manual", signal: ctl.signal });
    await res.body?.cancel().catch(() => {});
    return { url, status: res.status, location: res.headers.get("location") };
  } catch (e: any) {
    return { url, error: e?.message ?? String(e) };
  } finally {
    clearTimeout(t);
  }
}

function getSetCookies(h: Headers): string[] {
  const anyH = h as any;
  if (typeof anyH.getSetCookie === "function") return anyH.getSetCookie();
  const raw = h.get("set-cookie");
  return raw ? raw.split(/,(?=\s*[A-Za-z0-9_\-.]+=)/) : [];
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
  // Public-by-design keys (Supabase anon/publishable, Stripe publishable) are
  // not findings. Values are masked; the full secret never reaches the notes.
  const findings = scanForSecrets(sources);
  const serious = findings.filter((f) => f.severity !== "low");
  const describe = (list: typeof findings) =>
    list
      .map((f) => `- [${f.severity}] ${f.label}: ${f.masked} (in ${f.urls.join(", ")})\n  ${f.advice}`)
      .join("\n");
  if (serious.length > 0) {
    return {
      key: "bundle_secrets",
      status: "fail",
      notes: `Secrets found in client-side code served to every visitor:\n${describe(findings)}`,
    };
  }
  const lowNote = findings.length ? `\n\nWorth checking (usually fine when restricted):\n${describe(findings)}` : "";
  if (!coverage.complete) {
    return {
      key: "bundle_secrets",
      status: "inconclusive",
      notes: `No secrets found in what could be scanned, but the scan was incomplete, so this is not a pass.\n\n${coverage.summary}${lowNote}`,
    };
  }
  return {
    key: "bundle_secrets",
    status: "pass",
    notes: `No secret keys found in the HTML and ${sources.length - 1} JavaScript file(s).${lowNote}`,
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
const MAX_BUNDLES = 30;

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
  .inputValidator((input: { auditId: string; parentRunId?: string | null }) => {
    if (!input?.auditId || typeof input.auditId !== "string") throw new Error("auditId required");
    if (input.parentRunId != null && typeof input.parentRunId !== "string") throw new Error("invalid parentRunId");
    return input;
  })
  .handler(async ({ data, context }) => websiteScanCore(context.supabase, data, { checkQuota: true }));

export type ScanCoreOptions = {
  /** Interactive scans spend the user's daily quota; scheduled ones don't. */
  checkQuota: boolean;
  trigger?: "manual" | "full" | "schedule" | "retest";
  /** Owner to record on the run when running without a user session. */
  createdBy?: string | null;
};

/**
 * The website scan itself, callable from the server function (user session,
 * RLS) or from the scheduler (service role, createdBy set).
 */
export async function websiteScanCore(supabase: any, data: { auditId: string; parentRunId?: string | null }, opts: ScanCoreOptions) {
  {
    const { data: audit, error: aerr } = await supabase
      .from("audits")
      .select("id, website_url, client:clients(id, websites, name)")
      .eq("id", data.auditId)
      .single();
    if (aerr) throw new Error(aerr.message);
    // Only the audit's own website. Falling back to the client's first site
    // mixed one site's results into another site's audit.
    const appUrl = (audit as any)?.website_url as string | null | undefined;
    if (!appUrl) throw new Error("This audit has no website set. Each audit covers one website: create a new audit for the site you want to scan.");
    const base = normalizeUrl(appUrl);
    try {
      await assertSafeOutboundUrl(base);
    } catch (e) {
      if (e instanceof SSRFBlockedError) {
        throw new Error(describeBlockedUrl(e));
      }
      throw e;
    }

    if (opts.checkQuota) {
      const quota = await consumeQuota(supabase, "scan", 1);
      if (!quota.ok) throw new Error(quota.error);
    }

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

    // Evidence: what each check was judged on. Keys → evidence refs.
    const evidence: EvidenceInput[] = [];
    const evidenceFor = new Map<string, string[]>();
    const attach = (ref: string, keys: string[]) => {
      for (const k of keys) evidenceFor.set(k, [...(evidenceFor.get(k) ?? []), ref]);
    };
    evidence.push({
      ref: "main",
      kind: "http_exchange",
      title: `GET ${base}`,
      content: httpExchange(
        { url: base },
        mainResp ? { status: mainResp.status, headers: mainResp.headers, body } : { error: mainErr ?? "no response" },
      ),
    });
    attach("main", [
      "ssl_valid", "xframe_header", "xcontent_type", "referrer_policy", "hsts_header", "permissions_policy",
      "csp_header", "cors_policy", "sensitive_url_params", "debug_mode", "cookie_flags", "third_party_scripts",
      "security_headers",
    ]);

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
      const bundles = await collectBundles(base, body, { maxBundles: MAX_BUNDLES, timeoutMs: TIMEOUT_MS, maxBytesPerFile: MAX_FETCH_BYTES });
      results.push(checkBundleSecrets(bundles.sources, bundles.coverage));
      results.push(checkViteExposure(bundles.sources, bundles.coverage));
      results.push(checkCookieFlags(getSetCookies(h), base.startsWith("https://")));
      results.push(checkThirdPartyScripts(body, base));
      evidence.push({
        ref: "bundles",
        kind: "probe_set",
        title: `Scripts fetched from ${base}`,
        content: { coverage: bundles.coverage, files: bundles.sources.map((b) => ({ url: b.url, bytes: b.body.length })) },
      });
      attach("bundles", ["bundle_secrets", "vite_exposure", "third_party_scripts"]);

      const origin = new URL(base).origin;
      const maps = sourceMapCandidates(bundles.sources, origin);
      const [mapProbes, redirectProbes] = await Promise.all([
        Promise.all(maps.candidates.map((u) => probeHead(u, 512))),
        Promise.all(redirectProbeUrls(base, ["/", "/login", "/auth"]).map(probeRedirect)),
      ]);
      results.push(checkSourceMaps(mapProbes, maps.inline, bundles.coverage.fetched));
      results.push(checkOpenRedirect(redirectProbes, clientRedirectHints(bundles.sources)));
      evidence.push({
        ref: "source_maps",
        kind: "probe_set",
        title: "Source map requests",
        content: { inline_maps: maps.inline, probes: mapProbes.map((p) => ({ url: p.url, status: p.status ?? null, error: p.error ?? null, head: p.head?.slice(0, 200) ?? null })) },
      });
      attach("source_maps", ["source_maps_exposed"]);
      evidence.push({ ref: "redirects", kind: "probe_set", title: "Open redirect probes", content: { probes: redirectProbes } });
      attach("redirects", ["open_redirect"]);
    } else {
      const reason = mainResp ? unobservedReason : `Could not fetch ${base}: ${mainErr ?? "unknown error"}`;
      const unobservedKeys = ["xframe_header", "xcontent_type", "referrer_policy", "hsts_header", "permissions_policy", "csp_header", "cors_policy", "sensitive_url_params", "bundle_secrets", "debug_mode", "vite_exposure", "cookie_flags", "third_party_scripts", "source_maps_exposed", "open_redirect"];
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
      evidence.push({
        ref: "error_probe",
        kind: "http_exchange",
        title: `GET ${probeUrl}`,
        content: httpExchange({ url: probeUrl }, { status: probe.status, headers: probe.headers, body: text }, 1_500),
      });
      attach("error_probe", ["error_verbosity"]);
    } catch (e: any) {
      results.push({ key: "error_verbosity", status: "inconclusive", notes: `Not checked: the probe request failed (${e?.message ?? String(e)}).` });
    }

    // Files that must never be public. Checked even when the home page itself
    // couldn't be read: each probe is judged on its own response.
    const exposedProbes = await Promise.all(
      EXPOSED_FILE_PROBES.map(async (p) => ({ ...(await probeHead(`${base.replace(/\/+$/, "")}${p.path}`)), path: p.path })),
    );
    results.push(checkExposedFiles(exposedProbes));
    evidence.push({
      ref: "exposed_files",
      kind: "probe_set",
      title: "Sensitive file requests",
      content: { probes: exposedProbes.map((p) => ({ path: p.path, url: p.url, status: p.status ?? null, error: p.error ?? null, head: p.head?.slice(0, 300) ?? null })) },
    });
    attach("exposed_files", ["exposed_files"]);

    results.push(checkSecurityHeadersRollup(results));

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
    const recorded: RecordedResult[] = [];

    for (const r of results) {
      const itemId = byKey.get(r.key);
      if (!itemId) {
        written.push({ key: r.key, status: r.status, matched: false, stored: false });
        recorded.push({ checklist_item_id: null, checklist_key: r.key, status: r.status, notes: r.notes, stored: false, evidence: evidenceFor.get(r.key) });
        continue;
      }
      // Warn results: skip writing — leave for manual review
      if (r.status === "warn") {
        written.push({ key: r.key, status: r.status, matched: true, stored: false });
        recorded.push({ checklist_item_id: itemId, checklist_key: r.key, status: r.status, notes: r.notes, stored: false, evidence: evidenceFor.get(r.key) });
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
      recorded.push({ checklist_item_id: itemId, checklist_key: r.key, status: r.status, notes: note, stored: res.written, evidence: evidenceFor.get(r.key) });
    }

    const history = await saveScanRun(
      supabase,
      {
        auditId: data.auditId,
        scanner: "website",
        target: base,
        trigger: opts.trigger ?? (data.parentRunId ? "full" : "manual"),
        parentRunId: data.parentRunId ?? null,
        createdBy: opts.createdBy ?? null,
      },
      recorded,
      { evidence },
    );

    const passes = written.filter((w) => w.status === "pass").length;
    const fails = written.filter((w) => w.status === "fail").length;
    const warnings = written.filter((w) => w.status === "warn").length;
    const inconclusive = written.filter((w) => w.status === "inconclusive").length;

    return { target: base, results: written, passes, fails, warnings, inconclusive, history };
  }
}
