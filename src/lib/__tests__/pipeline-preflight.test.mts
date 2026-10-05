// Full-audit preflight: every credential is checked before anything runs.
// Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { stubFetch, json } from "./harness/fakes.mts";

const PROJECT = "https://abcdefghijklmnop.supabase.co";

test("preflight: good credentials pass, each bad one fails with its own reason", async () => {
  const { runPreflight } = await import("../pipeline-preflight.ts");
  stubFetch((url, init) => {
    const h = new Headers(init.headers as any);
    if (url === "https://api.github.com/repos/o/app") return h.get("authorization") ? json({ private: true, permissions: { pull: true } }) : json({}, 404);
    if (url.startsWith("https://github.com/o/app.git/info/refs"))
      return h.get("authorization")?.startsWith("Basic ") ? new Response("ok") : new Response("", { status: 401 });
    if (url === `${PROJECT}/auth/v1/settings`) return h.get("apikey") === "anon-good" ? json({}) : json({}, 401);
    if (url === `${PROJECT}/auth/v1/admin/users?per_page=1`) return h.get("apikey") === "sb_secret_good" ? json({ users: [] }) : json({}, 401);
    if (url === "https://api.supabase.com/v1/projects/abcdefghijklmnop") return h.get("authorization") === "Bearer sbp_good" ? json({}) : json({}, 401);
    return undefined;
  });

  const base = {
    websiteUrl: "https://app.example.com",
    repos: ["https://github.com/o/app"],
    supabase: PROJECT,
    aiEndpoints: ["https://app.example.com/api/chat"],
  };
  const good = await runPreflight({
    ...base,
    creds: { githubToken: "github_pat_0123456789abcdef", anonKey: "anon-good", serviceRoleKey: "sb_secret_good", managementPat: "sbp_good" },
  });
  assert.equal(good.ok, true, JSON.stringify(good.checks));
  assert.equal(good.checks.length, 6);

  const bad = await runPreflight({
    ...base,
    creds: { githubToken: "github_pat_0123456789abcdef", anonKey: "anon-bad", serviceRoleKey: "anon-good", managementPat: "sbp_bad" },
  });
  assert.equal(bad.ok, false);
  const byKey = Object.fromEntries(bad.checks.map((c) => [c.key, c]));
  assert.match(byKey["supabase:anon"].detail, /rejected the anon key/);
  assert.match(byKey["supabase:service"].detail, /isn't this project's service-role/);
  assert.match(byKey["supabase:pat"].detail, /rejected the access token/);
  assert.equal(byKey["repo:https://github.com/o/app"].status, "pass");
});

test("preflight: a token that can see the repo but not clone it fails before the run", async () => {
  const { runPreflight } = await import("../pipeline-preflight.ts");
  stubFetch((url) => {
    if (url === "https://api.github.com/repos/o/app") return json({ private: true, permissions: { pull: true } });
    if (url.startsWith("https://github.com/o/app.git/info/refs")) return new Response("", { status: 403 });
    return undefined;
  });
  const r = await runPreflight({ websiteUrl: null, repos: ["https://github.com/o/app"], supabase: null, aiEndpoints: [], creds: { githubToken: "github_pat_0123456789abcdef" } });
  assert.equal(r.ok, false);
  assert.match(r.checks[0].detail, /Contents to Read-only/);
});

test("preflight: private addresses are refused, and nothing is checked that wasn't given", async () => {
  const { runPreflight } = await import("../pipeline-preflight.ts");
  stubFetch(() => undefined);
  const r = await runPreflight({ websiteUrl: "http://127.0.0.1:8080", repos: [], supabase: PROJECT, aiEndpoints: [], creds: {} });
  assert.equal(r.ok, false);
  assert.equal(r.checks.length, 1);
  assert.equal(r.checks[0].key, "website");
});
