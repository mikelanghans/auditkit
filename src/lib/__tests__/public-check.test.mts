// Tests for the public /check lead magnet and the shared bundle secret
// detector. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb, stubFetch, text } from "./harness/fakes.mts";
import { scanForSecrets, maskSecret } from "../bundle-secrets.ts";
import { runPublicCheck, unlockPublicReport, normalizePublicUrl } from "../public-check-core.ts";

const b64u = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload: object) => `${b64u({ alg: "HS256", typ: "JWT" })}.${b64u(payload)}.${"s".repeat(43)}`;
const ANON = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon", iat: 1, exp: 2 });
const SERVICE = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role", iat: 1, exp: 2 });
const STRIPE_LIVE = "sk_live_" + "A1b2C3d4E5f6G7h8I9j0K1l2";

test("detector: Supabase anon key and publishable keys are not findings; service_role is critical", () => {
  const f = scanForSecrets([
    { url: "a.js", body: `const k="${ANON}";const p="sb_publishable_abc123def456ghi789";const s="pk_live_123456789012345678";` },
    { url: "b.js", body: `const admin="${SERVICE}"` },
  ]);
  assert.equal(f.length, 1);
  assert.equal(f[0].ruleId, "supabase_service_role_jwt");
  assert.equal(f[0].severity, "critical");
});

test("detector: masking never exposes the usable part of a key", () => {
  const f = scanForSecrets([{ url: "a.js", body: `x="${STRIPE_LIVE}"; y="${STRIPE_LIVE}"` }]);
  assert.equal(f.length, 1);
  assert.equal(f[0].occurrences, 2);
  assert.ok(!f[0].masked.includes(STRIPE_LIVE.slice(8, 20)), f[0].masked);
  assert.ok(f[0].masked.startsWith("sk_live_"));
  assert.ok(!maskSecret(SERVICE).includes(SERVICE.split(".")[1].slice(0, 20)));
  assert.equal(maskSecret("postgres://app:hunter2hunter2@db.example.com:5432/x").includes("hunter2"), false);
});

test("detector: catches common provider keys", () => {
  const body = [
    "sb_secret_" + "x".repeat(32),
    "sk-proj-" + "a".repeat(40),
    "sk-ant-api03-" + "b".repeat(40),
    "ghp_" + "c".repeat(36),
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "-----BEGIN RSA PRIVATE KEY-----",
    "postgres://u:supersecret@db.host.com/db",
    "whsec_" + "d".repeat(32),
  ].join("\n");
  const ids = scanForSecrets([{ url: "a.js", body }]).map((f) => f.ruleId).sort();
  assert.deepEqual(ids, [
    "anthropic_key", "aws_access_key", "db_connection_string", "github_token",
    "openai_key", "private_key", "stripe_webhook_secret", "supabase_secret_key",
  ]);
});

function db() {
  const d = new FakeDb({ public_checks: [] });
  let n = 0;
  d.rpcs.begin_public_check = (args) => {
    const rows = d.rows("public_checks").filter((r) => r.ip_hash === args.p_ip_hash);
    if (rows.length >= 5) return { data: { allowed: false, reason: "ip_limit" }, error: null };
    const id = `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;
    d.rows("public_checks").push({ id, ip_hash: args.p_ip_hash, url: args.p_url, hostname: args.p_hostname, status: "running" });
    return { data: { allowed: true, id }, error: null };
  };
  return d;
}

const site = (routes: Record<string, string>) =>
  stubFetch((url) => (routes[url] !== undefined ? text(routes[url], 200) : text("nf", 404)));

test("public check: summary before email shows counts and key types only, never values or locations", async () => {
  const d = db();
  site({
    "https://app.example.com/": `<html><script type="module" src="/assets/index.js"></script></html>`,
    "https://app.example.com/assets/index.js": `const a="${ANON}";import("./Admin-x1.js")`,
    "https://app.example.com/assets/Admin-x1.js": `const s="${STRIPE_LIVE}"`,
  });
  const res: any = await runPublicCheck("app.example.com", { db: d.client() as any, ipHash: "h".repeat(64) });
  assert.equal(res.ok, true);
  assert.equal(res.summary.counts.critical, 1);
  assert.equal(res.summary.filesScanned, 2); // lazy chunk discovered and scanned
  assert.equal(res.summary.complete, true);
  const shown = JSON.stringify(res);
  assert.ok(!shown.includes("sk_live_"), "no masked value before email");
  assert.ok(!shown.includes("Admin-x1.js"), "no location before email");
  assert.deepEqual(res.teaser, [{ label: "Stripe live secret key", severity: "critical" }]);
  // Stored row never holds the full key.
  assert.ok(!JSON.stringify(d.rows("public_checks")).includes(STRIPE_LIVE));

  const bad: any = await unlockPublicReport({ id: res.id, email: "not-an-email" }, { db: d.client() as any });
  assert.equal(bad.ok, false);
  const rep: any = await unlockPublicReport({ id: res.id, email: "Founder@Example.com", marketingConsent: true }, { db: d.client() as any });
  assert.equal(rep.ok, true);
  assert.equal(rep.findings[0].urls[0], "https://app.example.com/assets/Admin-x1.js");
  assert.ok(!rep.findings[0].masked.includes(STRIPE_LIVE.slice(8, 20)));
  const row = d.rows("public_checks")[0];
  assert.equal(row.email, "founder@example.com");
  assert.equal(row.marketing_consent, true);
});

test("public check: refuses internal targets before using a rate-limit slot", async () => {
  const d = db();
  const calls = stubFetch(() => text("x"));
  for (const u of ["http://localhost:3000", "http://169.254.169.254/latest", "http://[::ffff:127.0.0.1]/"]) {
    const res: any = await runPublicCheck(u, { db: d.client() as any, ipHash: "h".repeat(64) });
    assert.equal(res.ok, false, u);
  }
  assert.equal(d.rows("public_checks").length, 0);
  assert.equal(calls.length, 0);
});

test("public check: rate limit message is returned and no fetch is made", async () => {
  const d = db();
  site({ "https://app.example.com/": "<html></html>" });
  for (let i = 0; i < 5; i++) await runPublicCheck("https://app.example.com", { db: d.client() as any, ipHash: "i".repeat(64) });
  const calls = stubFetch(() => text("x"));
  const res: any = await runPublicCheck("https://app.example.com", { db: d.client() as any, ipHash: "i".repeat(64) });
  assert.equal(res.ok, false);
  assert.match(res.error, /try again in an hour/);
  assert.equal(calls.length, 0);
});

test("public check: a site whose bundle can't be loaded is not reported clean", async () => {
  const d = db();
  stubFetch((url) =>
    url === "https://app.example.com/" ? text(`<script src="/assets/index.js"></script>`, 200) : text("down", 503),
  );
  const res: any = await runPublicCheck("https://app.example.com", { db: d.client() as any, ipHash: "j".repeat(64) });
  assert.equal(res.ok, true);
  assert.equal(res.summary.total, 0);
  assert.equal(res.summary.complete, false);
});

test("public check: URL normalisation rejects credentials and bare words", () => {
  assert.equal(normalizePublicUrl("https://user:pw@example.com"), null);
  assert.equal(normalizePublicUrl("localhost"), null);
  assert.equal(normalizePublicUrl("ftp://example.com"), null);
  assert.equal(normalizePublicUrl("example.com/#x")?.toString(), "https://example.com/");
});
