// Tests for the storage-listing, definer-function, edge-function and password
// checks in the Supabase scan. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb, stubFetch, json, text } from "./harness/fakes.mts";

const AUDIT = "audit-1";
const USER = "user-1";
const TITLES = [
  "Storage files can't be listed without auth",
  "No SECURITY DEFINER functions callable without auth",
  "Edge functions verify their callers",
  "Minimum password length enforced",
  "Leaked password protection enabled",
];
const HOST = "abcdefghijklmnopqrst.supabase.co";
const INPUT = { auditId: AUDIT, projectUrl: `https://${HOST}`, anonKey: "ANON", serviceRoleKey: "SERVICE", managementPat: "sbp_pat" };

function db() {
  return new FakeDb({ audits: [{ id: AUDIT, created_by: USER, client_id: "c1" }], checklist_items: TITLES.map((t, i) => ({ id: `n${i}`, title: t })) });
}
function ctx(d: FakeDb) {
  const c = { supabase: d.client(), userId: USER };
  (globalThis as any).__TEST_CONTEXT__ = c;
  return c;
}
const status = (d: FakeDb, i: number) => d.finding(AUDIT, `n${i}`)?.status;
const notes = (d: FakeDb, i: number) => String(d.finding(AUDIT, `n${i}`)?.notes ?? "");

type Opts = {
  buckets?: string[];
  anonList?: (b: string) => Response;
  serviceList?: (b: string) => Response;
  definers?: { name: string; args: string }[] | Response;
  functions?: unknown[] | Response;
  auth?: Record<string, unknown>;
};

function routes(o: Opts) {
  return (url: string, init: RequestInit) => {
    const u = new URL(url);
    const h = new Headers(init.headers as any);
    const bearer = h.get("authorization");
    if (u.host === HOST) {
      if (u.pathname === "/rest/v1/") return bearer === "Bearer SERVICE" ? json({}) : json({ paths: {} });
      if (u.pathname === "/storage/v1/bucket") return json((o.buckets ?? []).map((name) => ({ name, public: false })));
      const m = u.pathname.match(/^\/storage\/v1\/object\/list\/(.+)$/);
      if (m) {
        const b = decodeURIComponent(m[1]);
        return bearer === "Bearer ANON" ? (o.anonList?.(b) ?? json([])) : (o.serviceList?.(b) ?? json([{ name: "x" }]));
      }
      if (u.pathname === "/auth/v1/recover") return json({});
    }
    if (u.host === "api.supabase.com") {
      if (u.pathname.endsWith("/database/query")) {
        const q = String(JSON.parse(String(init.body)).query);
        if (q.includes("prosecdef")) return o.definers instanceof Response ? o.definers : json(o.definers ?? []);
        return json([]);
      }
      if (u.pathname.endsWith("/functions")) return o.functions instanceof Response ? o.functions : json(o.functions ?? []);
      if (u.pathname.endsWith("/config/auth")) return json(o.auth ?? { mailer_autoconfirm: false, password_min_length: 8, password_hibp_enabled: true });
    }
    return text("nf", 404);
  };
}

async function scan(o: Opts, input: Record<string, unknown> = INPUT) {
  const d = db();
  const c = ctx(d);
  stubFetch(routes(o));
  const { runSupabaseScan } = await import("../supabase-scan.functions.ts");
  const res: any = await runSupabaseScan({ data: input, context: c } as any);
  assert.equal(res.ok, true, res.error);
  return d;
}

test("storage: a bucket anon can list fails; an empty bucket is not mistaken for a leak or a proof", async () => {
  let d = await scan({ buckets: ["avatars", "invoices"], anonList: (b) => (b === "invoices" ? json([{ name: "inv-1.pdf" }]) : json([])) });
  assert.equal(status(d, 0), "fail");
  assert.match(notes(d, 0), /invoices/);
  assert.doesNotMatch(notes(d, 0), /avatars \(/);

  d = await scan({ buckets: ["avatars"], anonList: () => json([]), serviceList: () => json([]) });
  assert.equal(status(d, 0), "pass");
  assert.match(notes(d, 0), /empty/);

  d = await scan({ buckets: ["avatars"], anonList: () => text("boom", 500) });
  assert.equal(status(d, 0), "inconclusive");
});

test("definer functions: anon-callable SECURITY DEFINER functions fail; none passes; no PAT is inconclusive", async () => {
  let d = await scan({ definers: [{ name: "get_all_users", args: "" }] });
  assert.equal(status(d, 1), "fail");
  assert.match(notes(d, 1), /get_all_users\(\)/);
  d = await scan({ definers: [] });
  assert.equal(status(d, 1), "pass");
  d = await scan({}, { ...INPUT, managementPat: null });
  assert.equal(status(d, 1), "inconclusive");
  d = await scan({ definers: text("no", 500) });
  assert.equal(status(d, 1), "inconclusive");
});

test("edge functions: verify_jwt off needs review (never a pass); all protected passes", async () => {
  let d = await scan({ functions: [{ slug: "stripe-webhook", verify_jwt: false }, { slug: "api", verify_jwt: true }] });
  assert.equal(status(d, 2), "inconclusive");
  assert.match(notes(d, 2), /stripe-webhook/);
  d = await scan({ functions: [{ slug: "api", verify_jwt: true }] });
  assert.equal(status(d, 2), "pass");
});

test("password settings are read from the auth config when a PAT is given", async () => {
  let d = await scan({ auth: { mailer_autoconfirm: false, password_min_length: 6, password_hibp_enabled: false } });
  assert.equal(status(d, 3), "fail");
  assert.equal(status(d, 4), "fail");
  d = await scan({ auth: { mailer_autoconfirm: false, password_min_length: 10, password_hibp_enabled: true } });
  assert.equal(status(d, 3), "pass");
  assert.equal(status(d, 4), "pass");
  d = await scan({ auth: { mailer_autoconfirm: false } });
  assert.equal(status(d, 4), "inconclusive");
});

test("project URL: only https://<ref>.supabase.co is accepted (keys are sent there)", async () => {
  const { normalizeProjectUrl } = await import("../supabase-scan.functions.ts");
  assert.equal(normalizeProjectUrl(`https://${HOST}/`), `https://${HOST}`);
  assert.equal(normalizeProjectUrl(`  https://${HOST.toUpperCase()}  `), `https://${HOST}`);
  for (const bad of [
    `http://${HOST}`,
    `https://${HOST}:8443`,
    `https://${HOST}/rest/v1`,
    `https://user:pw@${HOST}`,
    "https://api.example.com",
    "https://abcdefghijklmnopqrst.supabase.co.evil.com",
    "https://short.supabase.co",
    "not a url",
  ]) {
    assert.equal(normalizeProjectUrl(bad), null, bad);
  }
});
