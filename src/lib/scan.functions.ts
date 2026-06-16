import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

type CheckResult = { title: string; status: "pass" | "fail"; notes: string };

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

function checkSsl(url: string, ok: boolean, err?: string): CheckResult {
  const title = "Custom domain with valid SSL";
  if (!url.startsWith("https://")) {
    return { title, status: "fail", notes: `URL is not HTTPS: ${url}` };
  }
  if (!ok) {
    return { title, status: "fail", notes: `HTTPS request failed: ${err ?? "unknown error"}` };
  }
  return { title, status: "pass", notes: `HTTPS reachable and certificate validated by runtime fetch (${url}).` };
}

function checkSecurityHeaders(headers: Headers): CheckResult {
  const title = "Security headers configured";
  const xfo = headers.get("x-frame-options");
  const xcto = headers.get("x-content-type-options");
  const ref = headers.get("referrer-policy");
  const hsts = headers.get("strict-transport-security");
  const required = [
    ["X-Frame-Options", xfo],
    ["X-Content-Type-Options", xcto],
    ["Referrer-Policy", ref],
    ["Strict-Transport-Security", hsts],
  ] as const;
  const missing = required.filter(([, v]) => !v).map(([k]) => k);
  const present = required.filter(([, v]) => !!v).map(([k, v]) => `${k}: ${v}`);
  if (missing.length === 0) {
    return { title, status: "pass", notes: `All four headers present.\n${present.join("\n")}` };
  }
  return {
    title,
    status: "fail",
    notes: `Missing: ${missing.join(", ")}\n\nPresent:\n${present.join("\n") || "(none)"}`,
  };
}

function checkCsp(headers: Headers): CheckResult {
  const title = "Content Security Policy set";
  const csp = headers.get("content-security-policy") ?? headers.get("content-security-policy-report-only");
  if (!csp) {
    return { title, status: "fail", notes: "No Content-Security-Policy header on the response." };
  }
  const unsafe = /unsafe-inline|unsafe-eval|\*/.test(csp);
  return {
    title,
    status: unsafe ? "fail" : "pass",
    notes: `CSP found:\n${csp}${unsafe ? "\n\nWarning: contains wildcard or unsafe-* directive." : ""}`,
  };
}

function checkErrorVerbosity(body: string, statusCode: number): CheckResult {
  const title = "Verbose error messages suppressed in production";
  const lower = body.toLowerCase();
  const markers = [
    "stack trace",
    "at /",
    "node_modules",
    ".js:",
    ".ts:",
    "traceback",
    "exception in",
    "error:",
    "syntaxerror",
    "referenceerror",
  ];
  const hit = markers.filter((m) => lower.includes(m));
  if (hit.length > 1) {
    return {
      title,
      status: "fail",
      notes: `Probe (${statusCode}) returned response containing developer-detail markers: ${hit.join(", ")}.`,
    };
  }
  return {
    title,
    status: "pass",
    notes: `404/error probe returned a clean response (${statusCode}); no stack-trace markers detected.`,
  };
}

function normalizeUrl(raw: string): string {
  let u = raw.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u.replace(/\/+$/, "");
}

export const runAutoScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string }) => {
    if (!input?.auditId || typeof input.auditId !== "string") throw new Error("auditId required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase } = context;

    // Load audit + client URL (RLS ensures ownership)
    const { data: audit, error: aerr } = await supabase
      .from("audits")
      .select("id, client:clients(id, app_url, name)")
      .eq("id", data.auditId)
      .single();
    if (aerr) throw new Error(aerr.message);
    const appUrl = (audit as any)?.client?.app_url as string | null | undefined;
    if (!appUrl) {
      throw new Error("Client has no app URL set. Add one on the client and try again.");
    }
    const base = normalizeUrl(appUrl);

    // Main request
    const results: CheckResult[] = [];
    let mainResp: Response | null = null;
    let mainErr: string | undefined;
    try {
      mainResp = await timedFetch(base, { method: "GET", headers: { "user-agent": "AuditKit-Scanner/1.0" } });
    } catch (e: any) {
      mainErr = e?.message ?? String(e);
    }

    results.push(checkSsl(base, !!mainResp, mainErr));

    if (mainResp) {
      results.push(checkSecurityHeaders(mainResp.headers));
      results.push(checkCsp(mainResp.headers));
    } else {
      results.push({ title: "Security headers configured", status: "fail", notes: `Could not fetch ${base}: ${mainErr}` });
      results.push({ title: "Content Security Policy set", status: "fail", notes: `Could not fetch ${base}: ${mainErr}` });
    }

    // Error verbosity probe
    try {
      const probeUrl = `${base}/__auditkit_probe_${Date.now()}`;
      const probe = await timedFetch(probeUrl, { method: "GET", headers: { "user-agent": "AuditKit-Scanner/1.0" } });
      const text = (await probe.text()).slice(0, 50_000);
      results.push(checkErrorVerbosity(text, probe.status));
    } catch (e: any) {
      results.push({
        title: "Verbose error messages suppressed in production",
        status: "fail",
        notes: `Probe request failed: ${e?.message ?? String(e)}`,
      });
    }

    // Map check titles → checklist item ids
    const titles = results.map((r) => r.title);
    const { data: items, error: ierr } = await supabase
      .from("checklist_items")
      .select("id, title")
      .in("title", titles);
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
      const note = `[Auto-scan ${stamp}]\nTarget: ${base}\n\n${r.notes}`;
      const { error: upErr } = await supabase.from("audit_findings").upsert(
        {
          audit_id: data.auditId,
          checklist_item_id: itemId,
          status: r.status,
          notes: note,
        },
        { onConflict: "audit_id,checklist_item_id" },
      );
      if (upErr) throw new Error(upErr.message);
      written.push({ title: r.title, status: r.status, matched: true });
    }

    return { target: base, results: written };
  });
