import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { assertSafeOutboundUrl, safeFetch, SSRFBlockedError } from "./ssrf-guard";


const TIMEOUT_MS = 15_000;
const MAX_TABLES_PROBED = 60;
const MAX_BUNDLE_FILES = 40;
const MAX_BUNDLE_BYTES = 4_000_000;

export type SupabaseScanInput = {
  auditId: string;
  projectUrl: string;
  anonKey: string;
  serviceRoleKey: string;
  managementPat?: string | null;
  appUrl?: string | null;
  /**
   * Opt in to probes that write to or stress the client's project:
   *  - POST /auth/v1/signup with a weak password (creates a real user row,
   *    and may send a confirmation email)
   *  - a burst of 8 sign-in attempts against /auth/v1/token to detect rate
   *    limiting (trips alerting, pollutes auth logs, may lock out an IP)
   *
   * Defaults to false. These are legitimate audit techniques, but they are
   * active testing against production infrastructure, so they need the client's
   * informed consent rather than being bundled into a "read-only" scan.
   */
  intrusiveProbes?: boolean;
};

type CheckResult = { status: "pass" | "fail" | "na"; notes: string };

/**
 * Carries the client's anon key, service-role key or Management PAT depending on
 * the probe, against a project URL they typed in. safeFetch re-validates every
 * redirect hop and strips credential headers on cross-origin hops so a wrong or
 * hostile project URL cannot walk those keys off to another host.
 */
async function timedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return await safeFetch(url, init, { timeoutMs: TIMEOUT_MS });
}

function normalizeProjectUrl(raw: string): string | null {
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(trimmed)) return null;
  try {
    const u = new URL(trimmed);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function projectRefFromUrl(u: string): string | null {
  try {
    const host = new URL(u).host;
    const m = host.match(/^([a-z0-9]{16,})\.supabase\.(co|in|net)$/i);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

type TableListing = { ok: boolean; tables: string[]; http: number; error?: string };

async function listExposedTables(projectUrl: string, anonKey: string): Promise<TableListing> {
  // PostgREST root returns an OpenAPI spec listing every exposed table.
  // IMPORTANT: distinguish "couldn't read the schema" from "read it, no tables".
  // If this returned a bare [] on failure, the caller would probe nothing and then
  // report a PASS ("0 tables probed") — telling a client their database is safe
  // having tested nothing. That false pass is the bug this shape exists to prevent.
  let r: Response;
  try {
    r = await timedFetch(`${projectUrl}/rest/v1/`, {
      headers: { apikey: anonKey, accept: "application/openapi+json" },
    });
  } catch (e: any) {
    return { ok: false, tables: [], http: 0, error: e?.message ?? "request failed" };
  }
  if (!r.ok) {
    return { ok: false, tables: [], http: r.status, error: `PostgREST root returned HTTP ${r.status}` };
  }
  let spec: any;
  try {
    spec = await r.json();
  } catch {
    return { ok: false, tables: [], http: r.status, error: "Could not parse the PostgREST OpenAPI spec." };
  }
  const paths = spec?.paths ?? {};
  const tables = Object.keys(paths)
    .filter((p) => p.startsWith("/") && p.length > 1 && !p.startsWith("/rpc/"))
    .map((p) => p.replace(/^\//, ""))
    .filter((t) => !!t);
  return { ok: true, tables: Array.from(new Set(tables)), http: r.status };
}

type TableProbe = {
  table: string;
  status: "leaks" | "exposed_empty" | "blocked" | "error";
  http: number;
  rows?: number;
};

async function probeAnon(projectUrl: string, anonKey: string, table: string): Promise<TableProbe> {
  try {
    const r = await timedFetch(
      `${projectUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`,
      { headers: { apikey: anonKey, accept: "application/json" } },
    );
    if (r.status === 401 || r.status === 403) return { table, status: "blocked", http: r.status };
    if (!r.ok) return { table, status: "error", http: r.status };
    const body = (await r.json().catch(() => null)) as unknown;
    if (Array.isArray(body) && body.length > 0) return { table, status: "leaks", http: r.status, rows: body.length };
    return { table, status: "exposed_empty", http: r.status };
  } catch {
    return { table, status: "error", http: 0 };
  }
}

async function pMap<T, U>(items: T[], concurrency: number, fn: (t: T) => Promise<U>): Promise<U[]> {
  const out: U[] = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      out[idx] = await fn(items[idx]);
    }
  });
  await Promise.all(workers);
  return out;
}

async function probeServiceRole(projectUrl: string, serviceRoleKey: string): Promise<boolean> {
  // A real service role key is accepted at /rest/v1/ root; an invalid key returns 401.
  const r = await timedFetch(`${projectUrl}/rest/v1/`, {
    headers: { apikey: serviceRoleKey, authorization: `Bearer ${serviceRoleKey}` },
  });
  return r.ok;
}

async function listBuckets(projectUrl: string, serviceRoleKey: string): Promise<{ ok: boolean; buckets: { name: string; public: boolean }[]; error?: string }> {
  try {
    const r = await timedFetch(`${projectUrl}/storage/v1/bucket`, {
      headers: { apikey: serviceRoleKey, authorization: `Bearer ${serviceRoleKey}` },
    });
    if (!r.ok) return { ok: false, buckets: [], error: `HTTP ${r.status}` };
    const data = (await r.json()) as any[];
    return {
      ok: true,
      buckets: (data ?? []).map((b) => ({ name: String(b.name ?? b.id), public: !!b.public })),
    };
  } catch (e: any) {
    return { ok: false, buckets: [], error: e?.message ?? "fetch failed" };
  }
}

async function probeAuthBehavior(projectUrl: string, anonKey: string, intrusive: boolean): Promise<{
  enumeration: CheckResult;
  passwordPolicy: CheckResult;
}> {
  const headers = { apikey: anonKey, "content-type": "application/json" };
  // Email enumeration: ask for password recovery on a clearly fake address.
  // Supabase with enumeration protection returns 200 regardless of existence.
  let enumeration: CheckResult = { status: "na", notes: "Could not probe." };
  try {
    const r = await timedFetch(`${projectUrl}/auth/v1/recover`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: `auditkit-probe-${Date.now()}@example.invalid` }),
    });
    const txt = await r.text();
    if (r.status === 200 || r.status === 204) {
      enumeration = {
        status: "pass",
        notes: `Password-recover endpoint returned ${r.status} for an unknown address — enumeration protection appears enabled.`,
      };
    } else if (r.status === 400 || r.status === 422) {
      enumeration = {
        status: "fail",
        notes: `Password-recover endpoint distinguished an unknown address (HTTP ${r.status}). Enumeration protection is OFF.\n\nResponse: ${txt.slice(0, 300)}`,
      };
    } else {
      enumeration = {
        status: "na",
        notes: `Unexpected status ${r.status} from /auth/v1/recover — could not determine enumeration setting.`,
      };
    }
  } catch (e: any) {
    enumeration = { status: "na", notes: `Probe failed: ${e?.message ?? "unknown"}` };
  }

  // Password policy: try signing up with a 4-char password.
  // This creates a real user in the client's project and can trigger a
  // confirmation email, so it only runs with explicit consent.
  let passwordPolicy: CheckResult = { status: "na", notes: "Could not probe." };
  if (!intrusive) {
    return {
      enumeration,
      passwordPolicy: {
        status: "na",
        notes:
          "Not tested. Verifying the minimum password length requires submitting a real signup to /auth/v1/signup, " +
          "which creates a user record in the project and may send a confirmation email. " +
          "Re-run with active probes enabled, with the client's consent, to test this. " +
          "Alternatively, confirm the setting manually under Authentication → Providers → Email.",
      },
    };
  }
  try {
    const r = await timedFetch(`${projectUrl}/auth/v1/signup`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: `auditkit-probe-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@example.invalid`,
        password: "abcd",
      }),
    });
    const txt = await r.text();
    const lower = txt.toLowerCase();
    if (r.status >= 400 && (lower.includes("password") && (lower.includes("short") || lower.includes("length") || lower.includes("at least") || lower.includes("weak")))) {
      passwordPolicy = {
        status: "pass",
        notes: `Weak password (4 chars) rejected by /auth/v1/signup. A minimum length policy is enforced.\n\nResponse: ${txt.slice(0, 300)}`,
      };
    } else if (r.status >= 200 && r.status < 300) {
      passwordPolicy = {
        status: "fail",
        notes: `Weak password (4 chars) was ACCEPTED by /auth/v1/signup (status ${r.status}). Raise the minimum password length and enable leaked-password protection.`,
      };
    } else {
      passwordPolicy = {
        status: "na",
        notes: `Inconclusive response (status ${r.status}). Body: ${txt.slice(0, 300)}`,
      };
    }
  } catch (e: any) {
    passwordPolicy = { status: "na", notes: `Probe failed: ${e?.message ?? "unknown"}` };
  }

  return { enumeration, passwordPolicy };
}

async function fetchManagementRls(projectRef: string, pat: string): Promise<{ ok: boolean; rows?: { schema: string; table: string; rls: boolean }[]; error?: string }> {
  try {
    const r = await timedFetch(
      `https://api.supabase.com/v1/projects/${projectRef}/database/query`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${pat}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          query:
            "select n.nspname as schema, c.relname as table, c.relrowsecurity as rls from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind='r' and n.nspname='public' order by c.relname;",
        }),
      },
    );
    if (!r.ok) return { ok: false, error: `Management API HTTP ${r.status}` };
    const rows = (await r.json()) as any[];
    return {
      ok: true,
      rows: (rows ?? []).map((row) => ({ schema: row.schema, table: row.table, rls: !!row.rls })),
    };
  } catch (e: any) {
    return { ok: false, error: e?.message ?? "fetch failed" };
  }
}

type AnonWriteRow = { table: string; insert: boolean; update: boolean; delete: boolean; rls: boolean };

/**
 * Authoritative anon write-access check via the Management API.
 *
 * The most common critical failure in these apps is not that a table is
 * *readable* by anon, but that it is *writable* — agents write a SELECT policy
 * and forget INSERT/UPDATE/DELETE. Rather than probe writes blind (which risks
 * inserting live rows and can't reliably distinguish an RLS block from a schema
 * error), we read the truth directly: which write privileges the `anon` role
 * holds on each public table, joined with whether RLS is enabled.
 *
 * A table where anon holds a write grant AND RLS is disabled is writable by
 * anyone on the internet — a definitive hole. A write grant WITH RLS enabled is
 * flagged for policy review (the grant is only as safe as the policy scoping it).
 */
async function fetchAnonWriteAccess(projectRef: string, pat: string): Promise<{ ok: boolean; rows?: AnonWriteRow[]; error?: string }> {
  const query = `
    select t.relname as table,
      coalesce(bool_or(g.privilege_type = 'INSERT'), false) as ins,
      coalesce(bool_or(g.privilege_type = 'UPDATE'), false) as upd,
      coalesce(bool_or(g.privilege_type = 'DELETE'), false) as del,
      bool_or(t.relrowsecurity) as rls
    from pg_class t
    join pg_namespace n on n.oid = t.relnamespace
    left join information_schema.role_table_grants g
      on g.table_schema = n.nspname and g.table_name = t.relname and g.grantee = 'anon'
    where n.nspname = 'public' and t.relkind = 'r'
    group by t.relname
    order by t.relname;`;
  try {
    const r = await timedFetch(
      `https://api.supabase.com/v1/projects/${projectRef}/database/query`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${pat}`, "content-type": "application/json" },
        body: JSON.stringify({ query }),
      },
    );
    if (!r.ok) return { ok: false, error: `Management API HTTP ${r.status}` };
    const rows = (await r.json()) as any[];
    return {
      ok: true,
      rows: (rows ?? []).map((row) => ({
        table: row.table,
        insert: !!row.ins,
        update: !!row.upd,
        delete: !!row.del,
        rls: !!row.rls,
      })),
    };
  } catch (e: any) {
    return { ok: false, error: e?.message ?? "fetch failed" };
  }
}

async function fetchManagementAuth(projectRef: string, pat: string): Promise<{ ok: boolean; data?: Record<string, unknown>; error?: string }> {
  try {
    const r = await timedFetch(
      `https://api.supabase.com/v1/projects/${projectRef}/config/auth`,
      { headers: { authorization: `Bearer ${pat}` } },
    );
    if (!r.ok) return { ok: false, error: `Management API HTTP ${r.status}` };
    return { ok: true, data: await r.json() };
  } catch (e: any) {
    return { ok: false, error: e?.message ?? "fetch failed" };
  }
}

async function scanBundleForSecret(appUrl: string, secret: string): Promise<{ ok: boolean; checkedUrls: string[]; matches: string[]; bytesScanned: number; error?: string }> {
  if (!secret) return { ok: false, checkedUrls: [], matches: [], bytesScanned: 0, error: "no secret to scan for" };
  const normalized = appUrl.trim().replace(/\/+$/, "");
  const base = /^https?:\/\//i.test(normalized) ? normalized : `https://${normalized}`;
  try {
    const htmlRes = await timedFetch(base, { headers: { accept: "text/html" } });
    if (!htmlRes.ok) return { ok: false, checkedUrls: [base], matches: [], bytesScanned: 0, error: `HTTP ${htmlRes.status} fetching ${base}` };
    const html = await htmlRes.text();
    const matches: string[] = [];
    const checked: string[] = [base];
    let bytes = html.length;
    if (html.includes(secret)) matches.push(base);

    const scriptSrcs = Array.from(html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)).map((m) => m[1]);
    const resolved = scriptSrcs
      .map((s) => {
        try {
          return new URL(s, base + "/").toString();
        } catch {
          return null;
        }
      })
      .filter((u): u is string => !!u)
      .slice(0, MAX_BUNDLE_FILES);

    for (const u of resolved) {
      if (bytes > MAX_BUNDLE_BYTES) break;
      try {
        await assertSafeOutboundUrl(u);
        const r = await timedFetch(u);
        if (!r.ok) continue;
        const body = await r.text();
        bytes += body.length;
        checked.push(u);
        if (body.includes(secret)) matches.push(u);
      } catch {
        // skip — SSRF-blocked or fetch error
      }
    }

    return { ok: true, checkedUrls: checked, matches, bytesScanned: bytes };
  } catch (e: any) {
    return { ok: false, checkedUrls: [], matches: [], bytesScanned: 0, error: e?.message ?? "fetch failed" };
  }
}

export const runSupabaseScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: SupabaseScanInput) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const projectUrl = normalizeProjectUrl(data.projectUrl);
    if (!projectUrl) {
      return { ok: false as const, error: "Project URL must look like https://xxxxx.supabase.co" };
    }
    if (!data.anonKey?.trim() || !data.serviceRoleKey?.trim()) {
      return { ok: false as const, error: "Anon key and service role key are required." };
    }
    const anonKey = data.anonKey.trim();
    const serviceRoleKey = data.serviceRoleKey.trim();
    const pat = data.managementPat?.trim() || null;
    const appUrl = data.appUrl?.trim() || null;
    const projectRef = projectRefFromUrl(projectUrl);

    try {
      await assertSafeOutboundUrl(projectUrl);
      if (appUrl) await assertSafeOutboundUrl(appUrl);
    } catch (e) {
      if (e instanceof SSRFBlockedError) {
        return { ok: false as const, error: `Refusing to probe internal/private destination: ${e.message}` };
      }
      throw e;
    }



    // Confirm audit ownership
    const { data: auditRow, error: aerr } = await supabase
      .from("audits")
      .select("id, created_by, client_id")
      .eq("id", data.auditId)
      .single();
    if (aerr || !auditRow || auditRow.created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }

    // 0) Validate service role key
    const srOk = await probeServiceRole(projectUrl, serviceRoleKey);
    if (!srOk) {
      return { ok: false as const, error: "Service role key was rejected by the project. Double-check the key." };
    }

    // 1) Discover exposed tables and probe anon access
    const tableListing = await listExposedTables(projectUrl, anonKey);
    const schemaReadable = tableListing.ok;
    const tables = tableListing.tables.slice(0, MAX_TABLES_PROBED);
    const probes = await pMap(tables, 6, (t) => probeAnon(projectUrl, anonKey, t));
    const leaks = probes.filter((p) => p.status === "leaks");
    const exposedEmpty = probes.filter((p) => p.status === "exposed_empty");

    // 2) RLS truth check + anon write-access check (only when PAT provided)
    let rlsRows: { schema: string; table: string; rls: boolean }[] | null = null;
    let rlsError: string | null = null;
    let writeRows: AnonWriteRow[] | null = null;
    if (pat && projectRef) {
      const [rls, wr] = await Promise.all([
        fetchManagementRls(projectRef, pat),
        fetchAnonWriteAccess(projectRef, pat),
      ]);
      if (rls.ok) rlsRows = rls.rows ?? [];
      else rlsError = rls.error ?? null;
      if (wr.ok) writeRows = wr.rows ?? [];
    }
    const rlsDisabled = (rlsRows ?? []).filter((r) => !r.rls);

    // 3) Auth checks
    const intrusive = data.intrusiveProbes === true;
    const authBehavior = await probeAuthBehavior(projectUrl, anonKey, intrusive);
    let authConfig: { ok: boolean; data?: Record<string, unknown>; error?: string } | null = null;
    if (pat && projectRef) authConfig = await fetchManagementAuth(projectRef, pat);

    // 4) Storage buckets
    const buckets = await listBuckets(projectUrl, serviceRoleKey);
    const publicBuckets = buckets.buckets.filter((b) => b.public);

    // 5) Bundle scan for service role exposure
    let bundle: Awaited<ReturnType<typeof scanBundleForSecret>> | null = null;
    if (appUrl) bundle = await scanBundleForSecret(appUrl, serviceRoleKey);

    // ---- Build check results ----
    const stamp = new Date().toISOString();
    const projectLabel = projectRef ? `${projectRef}.supabase.co` : projectUrl;

    // RLS
    let rlsCheck: CheckResult;
    if (rlsRows) {
      if (rlsDisabled.length === 0) {
        rlsCheck = {
          status: "pass",
          notes: `Checked ${rlsRows.length} public table(s) via Management API. RLS is enabled on every table.`,
        };
      } else {
        const list = rlsDisabled.map((r) => `• ${r.table}`).join("\n");
        rlsCheck = {
          status: "fail",
          notes: `RLS is DISABLED on ${rlsDisabled.length} public table(s):\n\n${list}\n\nEnable RLS and add policies before exposing through the Data API.`,
        };
      }
    } else if (leaks.length > 0) {
      const list = leaks.map((p) => `• ${p.table} — returned ${p.rows} row(s) to anon`).join("\n");
      rlsCheck = {
        status: "fail",
        notes: `Anon probe returned rows from ${leaks.length} table(s) — RLS is either off or has overly permissive policies:\n\n${list}\n\nProvide a Management API PAT for an authoritative RLS check.${rlsError ? `\n\nPAT lookup error: ${rlsError}` : ""}`,
      };
    } else if (exposedEmpty.length > 0) {
      rlsCheck = {
        status: "na",
        notes: `Could not determine RLS status without a Management API PAT.\n\n${exposedEmpty.length} table(s) responded 200 to anon but returned no rows — they could be empty, or RLS could be filtering. Re-run with a PAT to confirm.`,
      };
    } else if (!schemaReadable) {
      rlsCheck = {
        status: "na",
        notes: `Could not read the project's Data API schema (${tableListing.error ?? "unknown error"}), and no Management API PAT was provided — RLS status could NOT be determined. This is not a pass. Confirm the project URL and anon key are correct, or supply a PAT, and re-run.`,
      };
    } else if (tables.length === 0) {
      rlsCheck = {
        status: "na",
        notes: `No tables were exposed through the Data API to probe, and no Management API PAT was provided — RLS status could NOT be determined. Supply a PAT for an authoritative check.`,
      };
    } else {
      rlsCheck = {
        status: "pass",
        notes: `Anon-key probe across ${tables.length} exposed table(s) returned no data — none were readable without authentication. (For an authoritative RLS-enabled check, re-run with a Management API PAT.)`,
      };
    }

    // Anon scope / unauth endpoints / direct table access
    let anonScope: CheckResult;
    if (leaks.length > 0) {
      const list = leaks.slice(0, 20).map((p) => `• ${p.table} (${p.rows} row${p.rows === 1 ? "" : "s"})`).join("\n");
      anonScope = {
        status: "fail",
        notes: `${leaks.length} table(s) returned data to an unauthenticated request using only the anon key:\n\n${list}\n\nTighten RLS so anon SELECT is scoped, or revoke anon GRANTs on these tables.`,
      };
    } else if (!schemaReadable) {
      anonScope = {
        status: "na",
        notes: `Could not read the project's Data API schema (${tableListing.error ?? "unknown error"}). No tables were probed, so anon access was NOT verified — this is not a pass. Confirm the project URL and anon key are reachable and re-run.`,
      };
    } else if (exposedEmpty.length > 0) {
      anonScope = {
        status: "pass",
        notes: `${exposedEmpty.length} table(s) accepted the anon key but returned no rows — RLS appears to be filtering correctly. ${tables.length - exposedEmpty.length} table(s) rejected anon entirely.`,
      };
    } else if (tables.length === 0) {
      anonScope = {
        status: "na",
        notes: `The Data API exposed no tables to probe. Anon read access was not verified — treat as inconclusive, not safe.`,
      };
    } else {
      anonScope = {
        status: "pass",
        notes: `No tables returned data without authentication. ${tables.length} table(s) probed.`,
      };
    }

    // Rate limiting on auth endpoints — best effort: send a burst, look for 429.
    // A burst of failed sign-ins pollutes the client's auth logs and can trip
    // their alerting or IP lockout, so it is gated behind explicit consent.
    let rateLimit: CheckResult = { status: "na", notes: "Not probed." };
    if (!intrusive) {
      rateLimit = {
        status: "na",
        notes:
          "Not tested. Detecting rate limiting requires sending a burst of failed sign-in attempts to /auth/v1/token, " +
          "which writes to the project's auth logs and may trigger alerting or temporary IP lockout. " +
          "Re-run with active probes enabled, with the client's consent, to test this.",
      };
    } else {
      try {
        const bursts = await Promise.all(
          Array.from({ length: 8 }, () =>
            timedFetch(`${projectUrl}/auth/v1/token?grant_type=password`, {
              method: "POST",
              headers: { apikey: anonKey, "content-type": "application/json" },
              body: JSON.stringify({ email: `auditkit-rl-${Date.now()}@example.invalid`, password: "x" }),
            }).then((r) => r.status).catch(() => 0),
          ),
        );
        const got429 = bursts.includes(429);
        rateLimit = got429
          ? { status: "pass", notes: `Burst of 8 sign-in attempts triggered HTTP 429 — rate limiting is active.\n\nStatuses: ${bursts.join(", ")}` }
          : { status: "fail", notes: `Burst of 8 sign-in attempts did NOT trigger HTTP 429. Confirm rate limits on /auth/v1/token in project settings.\n\nStatuses: ${bursts.join(", ")}` };
      } catch (e: any) {
        rateLimit = { status: "na", notes: `Probe failed: ${e?.message ?? "unknown"}` };
      }
    }

    // Bundle / service role exposure
    let bundleCheck: CheckResult;
    let serviceRoleCheck: CheckResult;
    if (!appUrl) {
      bundleCheck = { status: "na", notes: "No website URL provided — cannot fetch JS bundle to scan." };
      serviceRoleCheck = { status: "na", notes: "No website URL provided — cannot verify the service role key is absent from the bundle." };
    } else if (!bundle || !bundle.ok) {
      const reason = bundle?.error ?? "unknown";
      bundleCheck = { status: "na", notes: `Could not fetch bundle from ${appUrl}: ${reason}` };
      serviceRoleCheck = { status: "na", notes: `Could not verify — bundle fetch failed: ${reason}` };
    } else if (bundle.matches.length > 0) {
      const list = bundle.matches.map((u) => `• ${u}`).join("\n");
      const msg = `CRITICAL: the provided service role key was found in the live JS bundle at:\n\n${list}\n\nRotate this key IMMEDIATELY and remove it from client code.`;
      bundleCheck = { status: "fail", notes: msg };
      serviceRoleCheck = { status: "fail", notes: msg };
    } else {
      const note = `Service role key not present in ${bundle.checkedUrls.length} bundle file(s) scanned from ${appUrl} (${Math.round(bundle.bytesScanned / 1024)} KB).`;
      bundleCheck = { status: "pass", notes: note };
      serviceRoleCheck = { status: "pass", notes: note };
    }

    // Anon write access (authoritative, PAT only)
    let writeAccessCheck: CheckResult;
    if (!writeRows) {
      writeAccessCheck = {
        status: "na",
        notes: pat
          ? "Could not read anon write grants from the Management API. Re-run to verify whether anon can INSERT/UPDATE/DELETE."
          : "Not checked. Verifying that the anon role cannot write to tables requires a Management API PAT. Supply one and re-run — this is the highest-value database check, because agents routinely write a read policy and forget the write side.",
      };
    } else {
      const openWrite = writeRows.filter((r) => (r.insert || r.update || r.delete) && !r.rls);
      const grantedButRls = writeRows.filter((r) => (r.insert || r.update || r.delete) && r.rls);
      if (openWrite.length > 0) {
        const list = openWrite
          .map((r) => {
            const ops = [r.insert && "INSERT", r.update && "UPDATE", r.delete && "DELETE"].filter(Boolean).join("/");
            return `• ${r.table} — anon can ${ops} (RLS OFF)`;
          })
          .join("\n");
        writeAccessCheck = {
          status: "fail",
          notes: `CRITICAL: the anon role holds write privileges on ${openWrite.length} table(s) with RLS DISABLED — anyone with the public anon key can modify or delete this data:\n\n${list}\n\nEnable RLS on these tables (and add scoped write policies), or revoke the anon INSERT/UPDATE/DELETE grants.`,
        };
      } else if (grantedButRls.length > 0) {
        const list = grantedButRls.map((r) => `• ${r.table}`).join("\n");
        writeAccessCheck = {
          status: "na",
          notes: `${grantedButRls.length} table(s) grant the anon role write access but have RLS enabled:\n\n${list}\n\nThe grant is only as safe as the policy scoping it — review each write policy to confirm anon cannot INSERT/UPDATE/DELETE rows it shouldn't. (Where possible, revoke unused anon write grants entirely.)`,
        };
      } else {
        writeAccessCheck = {
          status: "pass",
          notes: `The anon role holds no INSERT/UPDATE/DELETE privileges on any public table. Unauthenticated writes are not possible via the Data API.`,
        };
      }
    }

    // Public storage buckets
    let bucketCheck: CheckResult;
    if (!buckets.ok) {
      bucketCheck = { status: "na", notes: `Could not enumerate storage buckets: ${buckets.error ?? "unknown error"}.` };
    } else if (publicBuckets.length > 0) {
      const list = publicBuckets.map((b) => `• ${b.name}`).join("\n");
      bucketCheck = {
        status: "fail",
        notes: `${publicBuckets.length} storage bucket(s) are marked PUBLIC — their objects are readable by anyone with the URL:\n\n${list}\n\nConfirm nothing sensitive is stored here; make buckets private and serve via signed URLs where possible.`,
      };
    } else {
      bucketCheck = {
        status: "pass",
        notes: `No public storage buckets. ${buckets.buckets.length} bucket(s) checked; all are private.`,
      };
    }

    // Email confirmation (from Management auth config)
    let emailConfirmCheck: CheckResult;
    if (!authConfig || !authConfig.ok || !authConfig.data) {
      emailConfirmCheck = {
        status: "na",
        notes: pat
          ? "Could not read the auth configuration from the Management API."
          : "Not checked. Verifying email confirmation requires a Management API PAT.",
      };
    } else {
      const autoconfirm = authConfig.data["mailer_autoconfirm"] === true;
      emailConfirmCheck = autoconfirm
        ? {
            status: "fail",
            notes: "Email auto-confirm is ON (mailer_autoconfirm = true): new signups are confirmed without verifying the address, so anyone can register as any email. Turn on email confirmation under Authentication → Providers → Email.",
          }
        : {
            status: "pass",
            notes: "Email confirmation is required for new signups (mailer_autoconfirm is off).",
          };
    }

    // ---- Persist findings by title (only items that exist in the checklist) ----
    const titleToResult: Record<string, CheckResult> = {
      "RLS enabled on all tables": rlsCheck,
      "Anon key permissions scoped correctly": anonScope,
      "No direct table access without auth check": anonScope,
      "No unauthenticated endpoints returning user data": anonScope,
      "Anon role cannot write to tables": writeAccessCheck,
      "Minimum password length enforced": authBehavior.passwordPolicy,
      "Email confirmation required for signup": emailConfirmCheck,
      "No public storage buckets": bucketCheck,
      "Email enumeration not possible": authBehavior.enumeration,
      "Rate limiting on auth endpoints": rateLimit,
      "No secrets in client-side bundle": bundleCheck,
      "No service role key in client-side code": serviceRoleCheck,
    };

    const titles = Object.keys(titleToResult);
    const { data: items, error: ierr } = await supabase
      .from("checklist_items")
      .select("id, title")
      .in("title", titles);
    if (ierr) throw new Error(ierr.message);
    const byTitle = new Map<string, string>();
    (items ?? []).forEach((it: any) => byTitle.set(it.title, it.id));

    const written: { title: string; status: string; matched: boolean }[] = [];
    let passes = 0;
    let fails = 0;
    for (const [title, res] of Object.entries(titleToResult)) {
      const itemId = byTitle.get(title);
      if (res.status === "pass") passes++;
      if (res.status === "fail") fails++;
      if (!itemId) {
        written.push({ title, status: res.status, matched: false });
        continue;
      }
      const header = `[Supabase scan ${stamp}]\nProject: ${projectLabel}\n\n`;
      const { error: upErr } = await supabase.from("audit_findings").upsert(
        {
          audit_id: data.auditId,
          checklist_item_id: itemId,
          status: res.status,
          notes: header + res.notes,
          auto_scanned: true,
        },
        { onConflict: "audit_id,checklist_item_id" },
      );
      if (upErr) throw new Error(upErr.message);
      written.push({ title, status: res.status, matched: true });
    }

    return {
      ok: true as const,
      project: projectLabel,
      tablesProbed: tables.length,
      leaks: leaks.length,
      publicBuckets: publicBuckets.map((b) => b.name),
      bundleMatches: bundle?.matches.length ?? 0,
      patUsed: !!pat,
      authConfig: authConfig?.ok ? "fetched" : authConfig ? `error: ${authConfig.error}` : "skipped",
      passes,
      fails,
      results: written,
    };
  });
