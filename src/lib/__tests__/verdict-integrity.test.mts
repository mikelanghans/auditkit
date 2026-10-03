// Regression tests for the "false pass" findings in docs/security-audit/REPORT.md.
// Each test runs the real scanner handler with network and database faked, and
// asserts that a check which could not actually be performed is never recorded
// as a pass. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb, stubFetch, json, text, b64 } from "./harness/fakes.mts";

const AUDIT = "audit-1";
const USER = "user-1";

function ctx(db: FakeDb) {
  const c = { supabase: db.client(), userId: USER };
  (globalThis as any).__TEST_CONTEXT__ = c;
  return c;
}
const status = (db: FakeDb, item: string) => db.finding(AUDIT, item)?.status;

// ---------------------------------------------------------------- pure logic

test("coverage: inconclusive is not assessed, resolved is, and blocks a green verdict", async () => {
  const { computeCoverage, launchRecommendation, computeSecurityScore, failuresBySeverity } = await import("../security-score.ts");
  const items = [
    { id: "a", category: "Database Security", severity: "critical" },
    { id: "b", category: "Database Security", severity: "high" },
    { id: "c", category: "Authentication & Sessions", severity: "high" },
    { id: "d", category: "API & Endpoint Security", severity: "high" },
  ];
  const statuses = new Map<string, string>([["a", "inconclusive"], ["b", "inconclusive"], ["c", "pass"], ["d", "resolved"]]);
  const cov = computeCoverage(items, statuses);
  assert.equal(cov.inconclusive, 2);
  assert.equal(cov.assessed, 2); // pass + resolved
  const v = launchRecommendation(computeSecurityScore(items, statuses).score, failuresBySeverity(items, statuses), cov);
  assert.notEqual(v.verdict, "go");

  // Even with full coverage otherwise, one inconclusive check blocks "go".
  const all = new Map<string, string>([["a", "pass"], ["b", "pass"], ["c", "pass"], ["d", "inconclusive"]]);
  const cov2 = computeCoverage(items, all);
  const v2 = launchRecommendation(computeSecurityScore(items, all).score, failuresBySeverity(items, all), cov2);
  assert.equal(v2.verdict, "insufficient");
});

test("inconclusive never overwrites a known failure, resolution or auditor N/A", async () => {
  const { shouldKeepExisting } = await import("../finding-writer.ts");
  assert.equal(shouldKeepExisting("fail", true), true);
  assert.equal(shouldKeepExisting("resolved", false), true);
  assert.equal(shouldKeepExisting("na", false), true);
  assert.equal(shouldKeepExisting("na", true), false);
  assert.equal(shouldKeepExisting("pass", true), false);
  assert.equal(shouldKeepExisting(null, false), false);
});

test(".gitignore detection only accepts rules that really ignore .env", async () => {
  const { gitignoreIgnoresEnv } = await import("../repo-hygiene.ts");
  for (const bad of [".envrc", ".env.local", ".environment-cache/", ".env/", ".env.*", ".env\n!.env", "# .env"]) {
    assert.equal(gitignoreIgnoresEnv(bad), false, bad);
  }
  for (const good of [".env", "/.env", "**/.env", ".env*", "*.env", ".env\n.env.*\n!.env.example"]) {
    assert.equal(gitignoreIgnoresEnv(good), true, good);
  }
});

test("dependency specs: aliases resolve, local packages are skipped, unknown versions are flagged", async () => {
  const { resolveSpec, collectDeps } = await import("../dep-manifest.ts");
  assert.deepEqual(resolveSpec("left-pad", "npm:lodash@4.17.20"), { name: "lodash", version: "4.17.20" });
  assert.deepEqual(resolveSpec("react", "^18"), { name: "react", version: "18.0.0" });
  assert.equal(resolveSpec("ui", "workspace:*"), "local");
  assert.equal(resolveSpec("x", "latest"), null);
  assert.equal(resolveSpec("x", "github:owner/repo"), null);
  const d = collectDeps([
    { path: "package.json", json: { devDependencies: { typescript: "5.6.3" } } },
    { path: "apps/api/package.json", json: { dependencies: { lodash: "4.17.20" }, optionalDependencies: { fsevents: "2.3.3" } } },
  ]);
  assert.deepEqual(Object.keys(d.query).sort(), ["fsevents", "lodash", "typescript"]);
});

// ---------------------------------------------------------------- website scan

const SCAN_ITEMS = ["ssl_valid", "xframe_header", "xcontent_type", "referrer_policy", "hsts_header", "permissions_policy", "csp_header", "cors_policy", "sensitive_url_params", "bundle_secrets", "debug_mode", "vite_exposure", "error_verbosity"];
function scanDb(extraFindings: any[] = []) {
  return new FakeDb({
    audits: [{ id: AUDIT, created_by: USER, website_url: "https://app.example.com", client: null }],
    checklist_items: SCAN_ITEMS.map((k) => ({ id: `ci_${k}`, checklist_key: k })),
    audit_findings: extraFindings,
  });
}
const SEC_HEADERS = {
  "content-type": "text/html",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=63072000",
  "permissions-policy": "camera=()",
  "content-security-policy": "default-src 'self'",
};
const page = (scripts: string[]) => `<html><head>${scripts.map((s) => `<script type="module" src="${s}"></script>`).join("")}</head><body></body></html>`;

test("website scan: a bundle that fails to load is inconclusive and cannot auto-resolve a critical fail", async () => {
  const db = scanDb([{ id: "f1", audit_id: AUDIT, checklist_item_id: "ci_vite_exposure", status: "fail", auto_scanned: true, notes: "[Auto-scan x]", checklist_item: { checklist_key: "vite_exposure", title: "VITE exposure" } }]);
  const c = ctx(db);
  stubFetch((url) => {
    if (url === "https://app.example.com") return text(page(["/assets/index.js"]), 200, SEC_HEADERS);
    if (url.endsWith("/assets/index.js")) return text("unavailable", 503);
    return text("not found", 404);
  });
  const { resolveFinding } = await import("../finding-resolution.functions.ts");
  const res: any = await resolveFinding({ data: { auditId: AUDIT, checklistItemId: "ci_vite_exposure", mode: "automated" }, context: c } as any);
  assert.equal(res.ok, false);
  assert.match(res.reason, /couldn't verify/);
  assert.equal(status(db, "ci_vite_exposure"), "fail"); // still open, not resolved
});

test("website scan: secrets in a JS bundle fail bundle_secrets; public Supabase keys are not flagged", async () => {
  const db = scanDb();
  const c = ctx(db);
  stubFetch((url) => {
    if (url === "https://app.example.com") return text(page(["/assets/index.js"]), 200, SEC_HEADERS);
    if (url.endsWith("/assets/index.js")) return text('const a="VITE_SUPABASE_ANON_KEY";const b="VITE_SUPABASE_URL";const k="sk_live_DUMMYDUMMYDUMMY00000000";', 200);
    return text("not found", 404);
  });
  const { runAutoScan } = await import("../scan.functions.ts");
  const res: any = await runAutoScan({ data: { auditId: AUDIT }, context: c } as any);
  assert.equal(status(db, "ci_bundle_secrets"), "fail");
  assert.equal(status(db, "ci_vite_exposure"), "pass");

  // The run is kept with its evidence, and the evidence never holds the secret.
  assert.equal(res.history.history_error, undefined);
  assert.equal(db.rows("scan_runs").length, 1);
  const bundleResult = db.rows("scan_results").find((r) => r.checklist_key === "bundle_secrets");
  const linked = db.rows("evidence").filter((e) => bundleResult.evidence_ids.includes(e.id));
  assert.equal(linked.length, 1);
  assert.match(linked[0].title, /Scripts fetched/, "bundle check points at the list of scripts it read");
  const stored = db.rows("evidence").map((e) => e.content_text).join("\n");
  assert.match(stored, /assets\/index\.js/);
  assert.doesNotMatch(stored, /sk_live_DUMMYDUMMYDUMMY00000000/);
});

test("website scan: more bundles than the scan limit is inconclusive, not pass", async () => {
  const db = scanDb();
  const c = ctx(db);
  const scripts = Array.from({ length: 31 }, (_, i) => `/assets/c${i}.js`);
  stubFetch((url) => {
    if (url === "https://app.example.com") return text(page(scripts), 200, SEC_HEADERS);
    if (/\/assets\/c30\.js$/.test(url)) return text("VITE_STRIPE_SECRET_KEY", 200);
    if (/\/assets\/c\d+\.js$/.test(url)) return text("console.log(1)", 200);
    return text("not found", 404);
  });
  const { runAutoScan } = await import("../scan.functions.ts");
  await runAutoScan({ data: { auditId: AUDIT }, context: c } as any);
  assert.equal(status(db, "ci_vite_exposure"), "inconclusive");
  assert.equal(status(db, "ci_bundle_secrets"), "inconclusive");
});

test("website scan: an error page or a failed body read is not scored as the site", async () => {
  for (const mode of ["403", "body-error"]) {
    const db = scanDb();
    const c = ctx(db);
    stubFetch((url) => {
      if (url === "https://app.example.com") {
        if (mode === "403") return text("Access denied", 403, SEC_HEADERS);
        const body = new ReadableStream({ start(ctrl) { ctrl.enqueue(new TextEncoder().encode("<html>")); ctrl.error(new Error("ECONNRESET")); } });
        return new Response(body, { status: 200, headers: SEC_HEADERS });
      }
      return text("not found", 404);
    });
    const { runAutoScan } = await import("../scan.functions.ts");
    await runAutoScan({ data: { auditId: AUDIT }, context: c } as any);
    for (const k of ["sensitive_url_params", "bundle_secrets", "debug_mode", "vite_exposure", "csp_header"]) {
      assert.equal(status(db, `ci_${k}`), "inconclusive", `${mode}: ${k}`);
    }
  }
});

// ---------------------------------------------------------------- AI endpoint scan

test("AI scan: an endpoint that rejects every probe writes no pass", async () => {
  const titles = ["User input sanitized before prompt interpolation", "System prompt not exposed to users", "Prompt injection test performed"];
  const db = new FakeDb({
    audits: [{ id: AUDIT, created_by: USER }],
    checklist_items: titles.map((t, i) => ({ id: `ai${i}`, title: t })),
  });
  const c = ctx(db);
  stubFetch(() => json({ error: "invalid api key" }, 401));
  const { runAIScan } = await import("../ai-scan.functions.ts");
  const res: any = await runAIScan({ data: { auditId: AUDIT, endpointUrl: "https://ai.example.com/api/chat", promptField: "prompt", authToken: "wrong" }, context: c } as any);
  assert.equal(res.counts.passes, 0);
  for (let i = 0; i < 3; i++) assert.equal(status(db, `ai${i}`), "inconclusive");
});

// ---------------------------------------------------------------- Supabase scan

const SB_TITLES = ["RLS enabled on all tables", "Anon key permissions scoped correctly", "No direct table access without auth check", "No unauthenticated endpoints returning user data", "No service role key in client-side code", "No secrets in client-side bundle"];
function sbDb() {
  return new FakeDb({
    audits: [{ id: AUDIT, created_by: USER, client_id: "c1" }],
    checklist_items: SB_TITLES.map((t, i) => ({ id: `sb${i}`, title: t })),
  });
}
function sbRoutes(tables: string[], probe: (t: string) => Response, extra?: (url: string) => Response | undefined) {
  return (url: string, init: RequestInit) => {
    const h = new Headers(init.headers as any);
    const u = new URL(url);
    if (u.host === "abcdefghijklmnopqrst.supabase.co") {
      if (u.pathname === "/rest/v1/") {
        if (h.get("authorization") === "Bearer SERVICE") return json({});
        return json({ paths: Object.fromEntries(tables.map((t) => [`/${t}`, {}])) });
      }
      const m = u.pathname.match(/^\/rest\/v1\/(.+)$/);
      if (m) return probe(decodeURIComponent(m[1]));
      if (u.pathname === "/storage/v1/bucket") return json([]);
      if (u.pathname === "/auth/v1/recover") return json({});
    }
    return extra?.(url) ?? text("nf", 404);
  };
}
const SB_INPUT = { auditId: AUDIT, projectUrl: "https://abcdefghijklmnopqrst.supabase.co", anonKey: "ANON", serviceRoleKey: "SERVICE" };

test("Supabase scan: errored table probes are inconclusive, not 'no tables readable'", async () => {
  const db = sbDb();
  const c = ctx(db);
  stubFetch(sbRoutes(["profiles", "orders"], () => text("boom", 500)));
  const { runSupabaseScan } = await import("../supabase-scan.functions.ts");
  await runSupabaseScan({ data: SB_INPUT, context: c } as any);
  for (let i = 0; i < 4; i++) assert.equal(status(db, `sb${i}`), "inconclusive", SB_TITLES[i]);
});

test("Supabase scan: tables beyond the probe limit make the result inconclusive", async () => {
  const db = sbDb();
  const c = ctx(db);
  const tables = [...Array.from({ length: 60 }, (_, i) => `t${String(i).padStart(2, "0")}`), "zz_user_pii"];
  stubFetch(sbRoutes(tables, (t) => (t === "zz_user_pii" ? json([{ id: 1 }]) : text("", 401))));
  const { runSupabaseScan } = await import("../supabase-scan.functions.ts");
  await runSupabaseScan({ data: SB_INPUT, context: c } as any);
  assert.equal(status(db, "sb1"), "inconclusive");
});

test("Supabase scan: bundles that fail to load don't pass the service-role check, and the generic bundle item isn't touched", async () => {
  const db = sbDb();
  const c = ctx(db);
  stubFetch(
    sbRoutes(["profiles"], () => text("", 401), (url) => {
      if (url === "https://shop.example.com") return text(page(["/assets/main.js", "/assets/chunk.js"]), 200, { "content-type": "text/html" });
      if (url.includes("/assets/")) return text("nf", 404);
      return undefined;
    }),
  );
  const { runSupabaseScan } = await import("../supabase-scan.functions.ts");
  await runSupabaseScan({ data: { ...SB_INPUT, appUrl: "https://shop.example.com" }, context: c } as any);
  assert.equal(status(db, "sb4"), "inconclusive");
  assert.equal(status(db, "sb5"), undefined);
});

// ---------------------------------------------------------------- repo + dependency scan

const REPO_TITLES = [".env files in .gitignore", "No secrets in git history", "Dependency vulnerabilities scanned"];
function repoDb() {
  return new FakeDb({
    audits: [{ id: AUDIT, created_by: USER }],
    checklist_items: REPO_TITLES.map((t, i) => ({ id: `rp${i}`, title: t, checklist_key: i === 2 ? "dep_vulns" : null })),
  });
}
type RepoOpts = { tree?: any; gitignore?: string | null; detail?: (sha: string) => Response; manifests?: Record<string, any>; advisories?: () => Response };
function repoRoutes(o: RepoOpts) {
  const files = { ...(o.manifests ?? { "package.json": { dependencies: { react: "18.3.1" } } }) };
  const treeEntries = o.tree ?? { truncated: false, tree: [{ path: "src/a.ts", type: "blob" }, ...Object.keys(files).map((p) => ({ path: p, type: "blob" }))] };
  return (url: string) => {
    const u = new URL(url);
    const p = u.pathname;
    if (u.host === "api.github.com") {
      if (p === "/repos/o/r") return json({ default_branch: "main" });
      if (p.startsWith("/repos/o/r/git/trees/")) return json(treeEntries);
      if (p === "/repos/o/r/contents/.gitignore") return o.gitignore === null ? text("nf", 404) : json({ content: b64(o.gitignore ?? ".env\n") });
      const c = p.match(/^\/repos\/o\/r\/contents\/(.+)$/);
      if (c && files[decodeURIComponent(c[1])]) return json({ content: b64(JSON.stringify(files[decodeURIComponent(c[1])])) });
      if (p === "/repos/o/r/commits") return json([{ sha: "a".repeat(40) }, { sha: "b".repeat(40) }]);
      const d = p.match(/^\/repos\/o\/r\/commits\/([0-9a-f]+)$/);
      if (d) return o.detail ? o.detail(d[1]) : json({ files: [] });
    }
    if (u.host === "registry.npmjs.org") {
      if (p.includes("advisories/bulk")) return o.advisories ? o.advisories() : json({});
      return json({ "dist-tags": { latest: "18.3.1" }, time: {} });
    }
    return text("nf", 404);
  };
}
const REPO_INPUT = { auditId: AUDIT, repoUrl: "https://github.com/o/r", token: "x".repeat(24) };

test("repo scan: commit diffs GitHub didn't return make history inconclusive", async () => {
  const db = repoDb();
  const c = ctx(db);
  stubFetch(repoRoutes({ detail: () => json({ message: "API rate limit exceeded" }, 403) }));
  const { runRepoScan } = await import("../repo-scan.functions.ts");
  await runRepoScan({ data: REPO_INPUT, context: c } as any);
  assert.equal(status(db, "rp1"), "inconclusive");
});

test("repo scan: a truncated file listing can't pass the .env check", async () => {
  const db = repoDb();
  const c = ctx(db);
  stubFetch(repoRoutes({ tree: { truncated: true, tree: [{ path: "src/a.ts", type: "blob" }, { path: "package.json", type: "blob" }] } }));
  const { runRepoScan } = await import("../repo-scan.functions.ts");
  await runRepoScan({ data: REPO_INPUT, context: c } as any);
  assert.equal(status(db, "rp0"), "inconclusive");
});

test("repo scan: '.env.local' alone is not a .env rule", async () => {
  const db = repoDb();
  const c = ctx(db);
  stubFetch(repoRoutes({ gitignore: "node_modules\n.env.local\n" }));
  const { runRepoScan } = await import("../repo-scan.functions.ts");
  await runRepoScan({ data: REPO_INPUT, context: c } as any);
  assert.equal(status(db, "rp0"), "fail");
});

test("dependency scan: advisory database outage is inconclusive, not 'no CVEs'", async () => {
  const db = repoDb();
  const c = ctx(db);
  stubFetch(repoRoutes({ advisories: () => text("Service Unavailable", 503) }));
  const { runRepoScan } = await import("../repo-scan.functions.ts");
  await runRepoScan({ data: REPO_INPUT, context: c } as any);
  assert.equal(status(db, "rp2"), "inconclusive");
});

test("dependency scan: a vulnerable package in a workspace sub-package is found", async () => {
  const db = repoDb();
  const c = ctx(db);
  stubFetch(
    repoRoutes({
      manifests: {
        "package.json": { private: true, workspaces: ["apps/*"], devDependencies: { typescript: "5.6.3" } },
        "apps/api/package.json": { dependencies: { lodash: "4.17.20" } },
      },
      advisories: () => json({ lodash: [{ severity: "critical", title: "Prototype pollution", cves: ["CVE-2021-23337"] }] }),
    }),
  );
  const { runRepoScan } = await import("../repo-scan.functions.ts");
  await runRepoScan({ data: REPO_INPUT, context: c } as any);
  assert.equal(status(db, "rp2"), "fail");
});
