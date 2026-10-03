// Accepted risk, severity override and remediation. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";

test("lifecycle: acceptance expires, overrides apply, overdue only while failing", async () => {
  const { lifecycleOf } = await import("../finding-lifecycle.ts");
  const today = "2026-10-03";
  const accepted = { status: "fail", risk_accepted_at: "2026-09-01T00:00:00Z", risk_accepted_by: "CTO", risk_accepted_reason: "compensating control", risk_accepted_until: "2026-12-31" };

  assert.equal(lifecycleOf(accepted, "high", today).acceptedActive, true);
  const expired = lifecycleOf({ ...accepted, risk_accepted_until: "2026-10-02" }, "high", today);
  assert.equal(expired.acceptedActive, false);
  assert.equal(expired.acceptedExpired, true);
  assert.equal(lifecycleOf({ ...accepted, risk_accepted_until: today }, "high", today).acceptedActive, true, "valid through the expiry date");
  assert.equal(lifecycleOf({ ...accepted, status: "pass" }, "high", today).acceptedActive, false, "only failing findings are 'accepted'");

  const o = lifecycleOf({ status: "fail", severity_override: "low", severity_override_reason: "internal tool only" }, "critical", today);
  assert.deepEqual([o.severity, o.defaultSeverity, o.overridden], ["low", "critical", true]);
  assert.equal(lifecycleOf({ status: "fail" }, null, today).severity, "medium");

  assert.equal(lifecycleOf({ status: "fail", remediation_due: "2026-10-01" }, "high", today).overdue, true);
  assert.equal(lifecycleOf({ status: "pass", remediation_due: "2026-10-01" }, "high", today).overdue, false);
  assert.equal(lifecycleOf({ ...accepted, remediation_due: "2026-10-01" }, "high", today).overdue, false, "accepted risk isn't overdue");
});
