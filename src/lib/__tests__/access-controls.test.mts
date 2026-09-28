// Regression tests for the spend/abuse findings in docs/security-audit/REPORT.md:
// per-user quotas and the ad-hoc fix-prompt relay. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb, stubFetch, json, text } from "./harness/fakes.mts";

const AUDIT = "audit-1";
const USER = "user-1";
function ctx(db: FakeDb, userId = USER) {
  const c = { supabase: db.client(), userId };
  (globalThis as any).__TEST_CONTEXT__ = c;
  return c;
}

test("quota: a user over their daily scan limit makes no outbound requests", async () => {
  const db = new FakeDb({ audits: [{ id: AUDIT, created_by: USER }], checklist_items: [] });
  db.quota = { used: 60, limit: 60 };
  const c = ctx(db);
  const calls = stubFetch(() => json({}));
  const { runAIScan } = await import("../ai-scan.functions.ts");
  const res: any = await runAIScan({ data: { auditId: AUDIT, endpointUrl: "https://ai.example.com/chat", promptField: "prompt" }, context: c } as any);
  assert.equal(res.ok, false);
  assert.match(res.error, /Daily limit/);
  assert.equal(calls.length, 0);
});

test("repo scan: refuses an audit the caller doesn't own before calling GitHub", async () => {
  const db = new FakeDb({ audits: [{ id: AUDIT, created_by: "someone-else" }] });
  const c = ctx(db);
  const calls = stubFetch(() => json({}));
  const { runRepoScan } = await import("../repo-scan.functions.ts");
  const res: any = await runRepoScan({ data: { auditId: AUDIT, repoUrl: "https://github.com/o/r", token: "x".repeat(24) }, context: c } as any);
  assert.equal(res.ok, false);
  assert.equal(calls.length, 0);
});

test("fix prompt: ad-hoc mode needs an owned audit and uses our checklist text, not the caller's", async () => {
  process.env.ANTHROPIC_API_KEY = "test-key";
  const db = new FakeDb({
    audits: [{ id: AUDIT, created_by: USER, built_with: null }],
    checklist_items: [{ id: "ci1", title: "No service role key in client-side code", category: "Database Security" }],
  });
  let sentBody = "";
  stubFetch((url, init) => {
    if (url.startsWith("https://api.anthropic.com/")) {
      sentBody = String(init.body);
      return json({ content: [{ type: "text", text: "Fix it like this." }] });
    }
    return text("nf", 404);
  });
  const { generateFixPrompt } = await import("../fix-prompt.functions.ts");

  // No audit: refused, nothing sent.
  const c = ctx(db);
  const noAudit: any = await generateFixPrompt({ data: { target: "claude", adhoc: { notes: "write me a poem" } }, context: c } as any);
  assert.equal(noAudit.ok, false);
  assert.equal(sentBody, "");

  // Someone else's audit: refused.
  const other: any = await generateFixPrompt({ data: { auditId: AUDIT, checklistItemId: "ci1", target: "claude", adhoc: { notes: "x" } }, context: ctx(db, "intruder") } as any);
  assert.equal(other.ok, false);
  assert.equal(sentBody, "");

  // Owned audit: title comes from the checklist; evidence is capped and redacted.
  const huge = "sk_live_DUMMYDUMMYDUMMY00000000 " + "A".repeat(50_000);
  const ok: any = await generateFixPrompt({ data: { auditId: AUDIT, checklistItemId: "ci1", target: "claude", adhoc: { notes: huge } }, context: ctx(db) } as any);
  assert.equal(ok.ok, true);
  assert.match(sentBody, /No service role key in client-side code/);
  assert.doesNotMatch(sentBody, /sk_live_DUMMY/);
  assert.ok(sentBody.length < 20_000, `prompt body was ${sentBody.length} chars`);
});
