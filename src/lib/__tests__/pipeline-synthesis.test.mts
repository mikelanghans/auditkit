// Synthesis: one merged list of issues across every scanner in a run.
// Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { synthesize, filesIn, synthesisFacts } from "../pipeline-synthesis.ts";

const items = [
  { id: "secrets", title: "No secrets in the current code", category: "Secrets", severity: "critical" },
  { id: "webhook", title: "Webhooks verify their signatures", category: "API", severity: "high" },
  { id: "headers", title: "Security headers present", category: "Web", severity: "low" },
  { id: "rls", title: "RLS enabled on every table", category: "Database", severity: "critical" },
];

test("synthesis: same check failing in two scanners is one corroborated issue", () => {
  const s = synthesize({
    results: [
      { scanner: "website", status: "fail", checklist_item_id: "secrets", checklist_key: null, change: "new" },
      { scanner: "repo", status: "fail", checklist_item_id: "secrets", checklist_key: null },
      { scanner: "website", status: "fail", checklist_item_id: "headers", checklist_key: null },
      { scanner: "supabase", status: "pass", checklist_item_id: "rls", checklist_key: null },
    ],
    items,
    codeFindings: [],
    repoLeads: null,
    gaps: [],
  });
  assert.equal(s.issues.length, 2);
  assert.deepEqual(s.issues[0].sources, ["website", "repo"]);
  assert.equal(s.issues[0].corroborated, true);
  assert.equal(s.issues[0].change, "new");
  assert.equal(s.issues[1].title, "Security headers present");
  assert.equal(s.corroborated, 1);
  assert.equal(s.counts.critical, 1);
});

test("synthesis: deep-audit findings join by checklist link or by a file the repo scan flagged", () => {
  const s = synthesize({
    results: [{ scanner: "repo", status: "fail", checklist_item_id: "webhook", checklist_key: null }],
    items,
    codeFindings: [
      // Linked by the auditor.
      { id: "c1", title: "Service key in client", severity: "critical", verdict: "confirmed", checklist_item_id: "secrets" },
      // Same file as a repo-scan webhook lead.
      { id: "c2", title: "Stripe webhook accepts unsigned events", severity: "critical", verdict: "confirmed", checklist_item_id: null, evidence: [{ file: "supabase/functions/stripe/index.ts:14" }] },
      // Nothing to join.
      { id: "c3", title: "IDOR on /api/orders", severity: "high", verdict: "needs_validation", checklist_item_id: null, trace: { steps: [{ path: "src/routes/api/orders.ts" }] } },
      { id: "c4", title: "False alarm", severity: "high", verdict: "rejected", checklist_item_id: null },
    ],
    repoLeads: { rules: [{ rule: "webhook_signatures", file: "supabase/functions/stripe/index.ts", line: 9 }] },
    gaps: [{ scanner: "ai_endpoint", label: "AI endpoint", status: "skipped", reason: "No AI endpoint target." }],
  });
  const byTitle = Object.fromEntries(s.issues.map((i) => [i.title, i]));
  const webhook = byTitle["Webhooks verify their signatures"];
  assert.deepEqual(webhook.sources, ["repo", "code_audit"]);
  assert.equal(webhook.corroborated, true);
  // Raised to the deep audit's severity, with its file.
  assert.equal(webhook.severity, "critical");
  assert.deepEqual(webhook.files, ["supabase/functions/stripe/index.ts"]);
  assert.equal(webhook.deepVerdict, "confirmed");
  assert.deepEqual(byTitle["No secrets in the current code"].sources, ["code_audit"]);
  assert.equal(byTitle["IDOR on /api/orders"].deepVerdict, "needs_validation");
  assert.deepEqual(byTitle["IDOR on /api/orders"].files, ["src/routes/api/orders.ts"]);
  assert.ok(!byTitle["False alarm"]);
  // Critical + corroborated first.
  assert.equal(s.issues[0].title, "Webhooks verify their signatures");
  assert.equal(s.gaps.length, 1);
  const facts = synthesisFacts(s, (x) => x.toUpperCase());
  assert.deepEqual(facts.merged_issues[0].found_by, ["REPO", "CODE_AUDIT"]);
  assert.equal(facts.not_tested[0].why, "No AI endpoint target.");
  // No evidence or file paths in what goes to the model.
  assert.ok(!JSON.stringify(facts).includes("stripe/index.ts"));
});

test("filesIn: picks file-like keys at any depth, strips line numbers, ignores prose", () => {
  const got = [...filesIn({ a: [{ file: "./src/x.ts:10:2" }, { location: "has spaces in it" }], b: { deep: { path: "lib/y.js" } }, file: 3 })];
  assert.deepEqual(got.sort(), ["lib/y.js", "src/x.ts"]);
});
