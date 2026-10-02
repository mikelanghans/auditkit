// Run history: every scan leaves a run and its results, labelled against the
// previous pass/fail for the same item. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb } from "./harness/fakes.mts";

const AUDIT = "audit-1";

test("classifyChange labels results against the previous pass/fail", async () => {
  const { classifyChange } = await import("../scan-history.ts");
  const P = (status: "pass" | "fail") => ({ status, run_id: "r0" });
  assert.equal(classifyChange("fail", null), "new");
  assert.equal(classifyChange("fail", P("pass")), "regressed");
  assert.equal(classifyChange("fail", P("fail")), "unchanged");
  assert.equal(classifyChange("pass", P("fail")), "fixed");
  assert.equal(classifyChange("pass", P("pass")), "unchanged");
  assert.equal(classifyChange("pass", null), null);
  assert.equal(classifyChange("inconclusive", P("fail")), "unverified");
  assert.equal(classifyChange("not_run", P("pass")), "unverified");
  assert.equal(classifyChange("inconclusive", null), null);
  assert.equal(classifyChange("warn", P("fail")), null);
  assert.equal(classifyChange("na", P("fail")), null);
});

test("saveScanRun keeps every run and diffs it against the last one", async () => {
  const { saveScanRun } = await import("../scan-history.ts");
  const db = new FakeDb();
  const sb = db.client() as any;
  const opts = { auditId: AUDIT, scanner: "website" as const, target: "https://example.com" };

  const first = await saveScanRun(sb, opts, [
    { checklist_item_id: "i1", checklist_key: "csp_header", status: "fail", notes: "no CSP", stored: true },
    { checklist_item_id: "i2", checklist_key: "hsts_header", status: "pass", notes: "ok", stored: true },
    { checklist_item_id: null, checklist_key: "unseeded_check", status: "fail", notes: "x", stored: false },
  ]);
  assert.equal(first.history_error, undefined);
  assert.deepEqual(first.changes, { new: 2 });

  // Make the first run's results strictly older than the second's.
  for (const r of db.rows("scan_results")) r.created_at = "2026-10-01T00:00:00Z";

  const second = await saveScanRun(sb, opts, [
    { checklist_item_id: "i1", checklist_key: "csp_header", status: "pass", notes: "CSP set", stored: true },
    { checklist_item_id: "i2", checklist_key: "hsts_header", status: "fail", notes: "gone", stored: true },
    { checklist_item_id: null, checklist_key: "unseeded_check", status: "inconclusive", notes: "y", stored: false },
  ]);
  assert.deepEqual(second.changes, { fixed: 1, regressed: 1, unverified: 1 });

  const runs = db.rows("scan_runs");
  assert.equal(runs.length, 2);
  assert.equal(runs[0].status, "done");
  assert.equal(runs[1].status, "partial", "an inconclusive result makes the run partial");
  assert.deepEqual(runs[1].summary.counts, { pass: 1, fail: 1, inconclusive: 1 });

  const latest = db.rows("scan_results").filter((r) => r.run_id === second.run_id);
  const csp = latest.find((r) => r.checklist_key === "csp_header");
  assert.equal(csp.change, "fixed");
  assert.equal(csp.previous_status, "fail");
  assert.equal(csp.previous_run_id, first.run_id);
  assert.equal(latest.find((r) => r.checklist_key === "unseeded_check").checklist_item_id, null, "results without a checklist item are still kept");
});

test("saveScanRun never throws: a history failure is reported, not fatal", async () => {
  const { saveScanRun } = await import("../scan-history.ts");
  const broken = {
    from() {
      throw new Error('relation "public.scan_results" does not exist');
    },
  } as any;
  const out = await saveScanRun(broken, { auditId: AUDIT, scanner: "repo" }, [
    { checklist_item_id: "i1", checklist_key: null, status: "fail", stored: true },
  ]);
  assert.match(String(out.history_error), /does not exist/);
  assert.equal(out.run_id, null);
});
