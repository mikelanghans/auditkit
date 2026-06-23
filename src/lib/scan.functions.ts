import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { assertSafeOutboundUrl, SSRFBlockedError } from "./ssrf-guard";


type ScanStatus = "pass" | "fail" | "warn";
type CheckResult = { key: string; status: ScanStatus; notes: string };

const TIMEOUT_MS = 10_000;

async function timedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: ctl.signal, redirect: "follow" });
  } finally {
    clearTimeout(t);
  }
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

function checkCsp(h: Headers): CheckResult {
  const csp = h.get("content-security-policy") ?? h.get("content-security-policy-report-only");
  if (!csp) return { key: "csp_header", status: "fail", notes: "No Content-Security-Policy header on the response." };
  const unsafe = /unsafe-inline|unsafe-eval|\*/.test(csp);
  return {
    key: "csp_header",
    status: unsafe ? "fail" : "pass",
    notes: `CSP found:\n${csp}${unsafe ? "\n\nWarning: contains wildcard or unsafe-* directive." : ""}`,
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

function checkBundleSecrets(body: string): CheckResult {
  const patterns: Array<[RegExp, string]> = [
    [/sk_live_[A-Za-z0-9]{16,}/g, "Stripe live secret key"],
    [/sk_test_[A-Za-z0-9]{16,}/g, "Stripe test secret key"],
    [/AKIA[0-9A-Z]{16}/g, "AWS access key"],
    [/AIza[0-9A-Za-z\-_]{35}/g, "Google API key"],
    [/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "JWT-like token"],
    [/service_role[^A-Za-z0-9]{0,5}[:=][^,\n]{20,}/gi, "service_role reference"],
  ];
  const hits: string[] = [];
  for (const [re, label] of patterns) {
    const matches = body.match(re);
    if (matches) hits.push(`${label} (${matches.length} match${matches.length > 1 ? "es" : ""})`);
  }
  if (hits.length === 0) {
    return { key: "bundle_secrets", status: "pass", notes: "No obvious secret patterns detected in the served HTML." };
  }
  return { key: "bundle_secrets", status: "fail", notes: `Possible secret patterns detected in served HTML:\n- ${hits.join("\n- ")}` };
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

const SENSITIVE_VITE_KEYWORDS = ["SECRET", "KEY", "TOKEN", "PASSWORD", "PRIVATE", "SERVICE_ROLE", "ANON", "API"];
const MAX_BUNDLES = 15;
const MAX_BUNDLE_BYTES = 2_000_000;

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
  return Array.from(urls).slice(0, MAX_BUNDLES);
}

async function checkViteExposure(base: string, html: string): Promise<CheckResult> {
  const scriptUrls = extractScriptUrls(html, base);
  const sources: { url: string; body: string }[] = [{ url: base, body: html }];
  for (const url of scriptUrls) {
    try {
      const r = await timedFetch(url, { headers: { "user-agent": "AuditKit-Scanner/1.0" } });
      if (!r.ok) continue;
      const text = (await r.text()).slice(0, MAX_BUNDLE_BYTES);
      sources.push({ url, body: text });
    } catch {
      /* skip */
    }
  }

  const viteVarRe = /\bVITE_[A-Z0-9_]+/g;
  const foundByVar = new Map<string, Set<string>>();
  for (const { url, body } of sources) {
    const matches = body.match(viteVarRe);
    if (!matches) continue;
    for (const name of matches) {
      const upper = name.toUpperCase();
      if (!SENSITIVE_VITE_KEYWORDS.some((kw) => upper.includes(kw))) continue;
      if (!foundByVar.has(upper)) foundByVar.set(upper, new Set());
      foundByVar.get(upper)!.add(url);
    }
  }

  if (foundByVar.size === 0) {
    return {
      key: "vite_exposure",
      status: "pass",
      notes: `Scanned ${sources.length} source(s) (HTML + ${scriptUrls.length} JS bundle(s)). No VITE_ variable names containing sensitive keywords (${SENSITIVE_VITE_KEYWORDS.join(", ")}) were detected in the served bundle.`,
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



    const results: CheckResult[] = [];
    let mainResp: Response | null = null;
    let mainErr: string | undefined;
    let body = "";
    try {
      mainResp = await timedFetch(base, { method: "GET", headers: { "user-agent": "AuditKit-Scanner/1.0" } });
      body = (await mainResp.text()).slice(0, 200_000);
    } catch (e: any) {
      mainErr = e?.message ?? String(e);
    }

    results.push(checkSsl(base, !!mainResp, mainErr));

    if (mainResp) {
      const h = mainResp.headers;
      results.push(header(h, "x-frame-options", "xframe_header", "X-Frame-Options"));
      results.push(header(h, "x-content-type-options", "xcontent_type", "X-Content-Type-Options"));
      results.push(header(h, "referrer-policy", "referrer_policy", "Referrer-Policy"));
      results.push(header(h, "strict-transport-security", "hsts_header", "HSTS"));
      results.push(header(h, "permissions-policy", "permissions_policy", "Permissions-Policy"));
      results.push(checkCsp(h));
      results.push(checkSensitiveUrlParams(body, base));
      results.push(checkBundleSecrets(body));
      results.push(checkDebugMode(body, h));
      results.push(await checkViteExposure(base, body));
    } else {
      const warnKeys = ["xframe_header", "xcontent_type", "referrer_policy", "hsts_header", "permissions_policy", "csp_header", "sensitive_url_params", "bundle_secrets", "debug_mode", "vite_exposure"];
      for (const key of warnKeys) {
        results.push({ key, status: "warn", notes: `Could not fetch ${base}: ${mainErr ?? "unknown error"}` });
      }
    }

    // Error verbosity probe
    try {
      const probeUrl = `${base}/__auditkit_probe_${Date.now()}`;
      const probe = await timedFetch(probeUrl, { method: "GET", headers: { "user-agent": "AuditKit-Scanner/1.0" } });
      const text = (await probe.text()).slice(0, 50_000);
      results.push(checkErrorVerbosity(text, probe.status));
    } catch (e: any) {
      results.push({ key: "error_verbosity", status: "warn", notes: `Probe request failed: ${e?.message ?? String(e)}` });
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
    const written: { key: string; status: ScanStatus; matched: boolean }[] = [];

    for (const r of results) {
      const itemId = byKey.get(r.key);
      if (!itemId) {
        written.push({ key: r.key, status: r.status, matched: false });
        continue;
      }
      // Warn results: skip writing — leave for manual review
      if (r.status === "warn") {
        written.push({ key: r.key, status: r.status, matched: true });
        continue;
      }
      const note = `[Auto-scan ${stamp}]\nTarget: ${base}\n\n${r.notes}`;
      const { error: upErr } = await supabase.from("audit_findings").upsert(
        {
          audit_id: data.auditId,
          checklist_item_id: itemId,
          status: r.status,
          notes: note,
          auto_scanned: true,
        },
        { onConflict: "audit_id,checklist_item_id" },
      );
      if (upErr) throw new Error(upErr.message);
      written.push({ key: r.key, status: r.status, matched: true });
    }

    const passes = written.filter((w) => w.status === "pass").length;
    const fails = written.filter((w) => w.status === "fail").length;
    const warnings = written.filter((w) => w.status === "warn").length;

    return { target: base, results: written, passes, fails, warnings };
  });
