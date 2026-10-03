// Code rules and current-code secrets (3.5-lite). Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";

test("webhook without a signature check is flagged; with one it isn't", async () => {
  const { findRuleHits } = await import("../code-rules.ts");
  const bad = `export async function POST(req) {\n  const event = await req.json();\n  if (event.type === "checkout.session.completed") await markPaid(event);\n}`;
  const good = `export async function POST(req) {\n  const body = await req.text();\n  const event = stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature"), secret);\n  if (event.type === "checkout.session.completed") {}\n}`;
  assert.deepEqual(findRuleHits("app/api/stripe/webhook/route.ts", bad).map((h) => [h.rule, h.line]), [["webhook_signatures", 2]]);
  assert.deepEqual(findRuleHits("app/api/stripe/webhook/route.ts", good), []);
  assert.deepEqual(findRuleHits("supabase/functions/stripe-webhook/index.ts", bad.replace("req.json()", "req.json()")).map((h) => h.rule), ["webhook_signatures"]);
});

test("service role in client code, eval of dynamic values, sensitive fields in logs", async () => {
  const { findRuleHits, isClientFile } = await import("../code-rules.ts");
  assert.equal(isClientFile("src/lib/supabase.ts"), true);
  assert.equal(isClientFile("supabase/functions/admin/index.ts"), false);
  assert.equal(isClientFile("src/lib/admin.server.ts"), false);
  assert.deepEqual(findRuleHits("src/lib/supabase.ts", "createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY)").map((h) => h.rule), ["service_role_in_source"]);
  assert.deepEqual(findRuleHits("supabase/functions/admin/index.ts", "Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')"), []);
  assert.deepEqual(findRuleHits("src/x.ts", "const f = eval(userCode);\nconst g = eval('1+1');\nconst h = new Function(body);").map((h) => [h.rule, h.line]), [["dynamic_code_eval", 1], ["dynamic_code_eval", 3]]);
  assert.deepEqual(findRuleHits("src/auth.ts", "console.log('login', email, password);\nconsole.log('ok', userId);").map((h) => [h.rule, h.line]), [["pii_in_logs", 1]]);
  assert.deepEqual(findRuleHits("src/__tests__/auth.test.ts", "console.log(password); eval(x)"), [], "tests are skipped");
});

test("judging: pass only with full coverage; logging never auto-passes; head secrets", async () => {
  const { judgeRule, judgeHeadSecrets } = await import("../code-rules.ts");
  const full = { scanned: 10, total: 10, failed: 0 };
  assert.equal(judgeRule("webhook_signatures", [], full).status, "pass");
  assert.equal(judgeRule("webhook_signatures", [], { scanned: 9, total: 10, failed: 0 }).status, "inconclusive");
  assert.equal(judgeRule("pii_in_logs", [], full).status, "inconclusive");
  assert.equal(judgeRule("dynamic_code_eval", [{ rule: "dynamic_code_eval", file: "a.ts", line: 1, snippet: "eval(x)" }], full).status, "fail");
  assert.equal(judgeHeadSecrets([{ file: "config.json", pattern: "Stripe live secret (sk_live_)", sample: "sk_live_…" }], full).status, "fail");
  assert.equal(judgeHeadSecrets([], full).status, "pass");
});
