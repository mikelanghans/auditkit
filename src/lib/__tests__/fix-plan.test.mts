// Client fix plan. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";

test("fix plan: open issues only, accepted risks left out, overrides change the order, prompts per tool", async () => {
  const { buildFixPlan, fixPlanMarkdown } = await import("../fix-plan.ts");
  const items = [
    { id: "a", title: "CSP missing", category: "Frontend", severity: "medium", sort_order: 1 },
    { id: "b", title: "RLS off", category: "Database", severity: "critical", sort_order: 2 },
    { id: "c", title: "Weak passwords", category: "Auth", severity: "high", sort_order: 3 },
    { id: "d", title: "Passing thing", category: "Auth", severity: "high", sort_order: 4 },
    { id: "e", title: "Accepted thing", category: "Auth", severity: "critical", sort_order: 5 },
  ];
  const f = new Map<string, any>([
    ["a", { status: "fail", severity_override: "high", severity_override_reason: "login page", lovable_prompt: "Add a CSP header…", cursor_prompt: null }],
    ["b", { status: "fail", lovable_prompt: "Enable RLS…", remediation_owner: "Dev", remediation_due: "2026-10-01" }],
    ["c", { status: "fail" }],
    ["d", { status: "pass" }],
    ["e", { status: "fail", risk_accepted_at: "2026-09-01", risk_accepted_by: "CTO", risk_accepted_reason: "WAF rule", risk_accepted_until: "2027-01-01" }],
  ]);
  const plan = buildFixPlan(items, f, "lovable", "2026-10-03");
  assert.deepEqual(plan.map((p) => [p.id, p.severity]), [["b", "critical"], ["a", "high"], ["c", "high"]]);
  assert.equal(plan[0].overdue, true);
  assert.equal(buildFixPlan(items, f, "cursor", "2026-10-03")[1].prompt, null);

  const md = fixPlanMarkdown(plan, { audit: "Acme", client: "Acme Inc", tool: "lovable", generatedAt: "2026-10-03T00:00:00Z" });
  assert.match(md, /\| 1 \| RLS off \| critical \| Dev \| 2026-10-01 \(overdue\) \|/);
  assert.match(md, /```text\nEnable RLS…\n```/);
  assert.match(md, /No Lovable prompt generated yet/);
  assert.doesNotMatch(md, /Accepted thing|Passing thing/);
});
