// Full-audit pipeline engine against an in-memory database.
// Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb, stubFetch } from "./harness/fakes.mts";
import { planPipeline } from "../pipeline.ts";

const AUDIT = "11111111-1111-4111-8111-111111111111";
const RUN = "22222222-2222-4222-8222-222222222222";
const USER = "33333333-3333-4333-8333-333333333333";

function seed(stages: any[], extra: Record<string, any[]> = {}) {
  return new FakeDb({
    audits: [{ id: AUDIT, created_by: USER, website_url: null, summary_approved_at: null }],
    scan_runs: [{ id: RUN, audit_id: AUDIT, created_by: USER, scanner: "full", status: "running", pipeline_driver: "browser", summary: {}, started_at: new Date().toISOString() }],
    pipeline_stages: stages.map((s) => ({ run_id: RUN, audit_id: AUDIT, status: "pending", reason: null, output: {}, attempts: 0, started_at: null, finished_at: null, ...s })),
    checklist_items: [],
    ...extra,
  });
}
const opts = { websiteUrl: null, deepAudit: false, aiDeep: false, writeTestsAllowed: false };

test("engine: nothing to scan — every stage skipped with a reason, synthesis runs, the run closes as partial", async () => {
  stubFetch(() => undefined);
  delete process.env.ANTHROPIC_API_KEY;
  const { advancePipeline } = await import("../pipeline-engine.server.ts");
  const db = seed(planPipeline([], opts));
  const admin = db.client();
  let calls = 0;
  for (; calls < 20; calls++) {
    const r = await advancePipeline(admin, RUN, {}, { profile: "quick" });
    if (!r.more) break;
  }
  const stages = db.rows("pipeline_stages");
  assert.equal(calls, stages.length - 1, "one stage per call");
  for (const s of stages.filter((x) => x.scanner !== "synthesis")) {
    assert.equal(s.status, "skipped", s.key);
    assert.ok(s.reason, s.key);
  }
  const synth = stages.find((s) => s.scanner === "synthesis");
  assert.equal(synth.status, "done");
  assert.match(synth.reason, /0 issues · 5 not tested/);
  const run = db.rows("scan_runs")[0];
  assert.equal(run.status, "partial");
  assert.equal(run.summary.pipeline, true);
  // Gaps recorded once, as not_run results on the parent run.
  const gaps = db.rows("scan_results").filter((r) => r.run_id === RUN);
  assert.equal(gaps.length, 5);
  assert.ok(gaps.every((g) => g.status === "not_run" && g.checklist_key.startsWith("step:")));
  // Closed runs don't advance.
  const again = await advancePipeline(admin, RUN, {}, { profile: "quick" });
  assert.equal(again.more, false);
  assert.equal(db.rows("scan_results").filter((r) => r.run_id === RUN).length, 5);
});

test("engine: the run waits for the deep audit, then synthesizes and closes when the runner reports back", async () => {
  stubFetch(() => undefined);
  process.env.FULL_AUDIT_SECRETS_KEY = "k".repeat(40);
  const eng = await import("../pipeline-engine.server.ts");
  const plan = planPipeline([{ id: "r1", kind: "repo", value: "https://github.com/o/app", in_scope: true }], { ...opts, deepAudit: true });
  const db = seed(
    plan.map((s) =>
      s.scanner === "code_audit"
        ? { ...s, status: "waiting", started_at: new Date().toISOString(), output: { codeAuditRunId: "car1" } }
        : s.scanner === "synthesis"
          ? s
          : s.scanner === "repo"
            ? { ...s, status: "done", output: { codeReadable: true, leads: { rules: [{ rule: "webhook_signatures", file: "fn/stripe.ts", line: 3 }] } } }
            : { ...s, status: "skipped", reason: "n/a" },
    ),
    {
      code_audit_runs: [{ id: "car1", status: "running" }],
      code_audit_findings: [
        { id: "f1", run_id: "car1", title: "Unsigned webhook", severity: "critical", verdict: "confirmed", checklist_item_id: null, review_state: "pending", evidence: { file: "fn/stripe.ts" } },
      ],
      checklist_items: [{ id: "w", title: "Webhooks verify their signatures", category: "API", severity: "high", is_active: true }],
    },
  );
  const admin = db.client();
  await eng.storeRunSecrets(admin, RUN, { githubToken: "github_pat_x" });
  assert.equal((await eng.loadRunSecrets(admin, RUN)).githubToken, "github_pat_x");
  assert.notEqual(db.rows("pipeline_secrets")[0].sealed.includes("github_pat_x"), true, "sealed, not plain");

  // Nothing to do while the runner works.
  const r = await eng.advancePipeline(admin, RUN, {}, { profile: "quick" });
  assert.equal(r.more, false);
  assert.equal(db.rows("scan_runs")[0].status, "running");
  assert.equal(db.rows("pipeline_secrets").length, 0, "credentials dropped once only the deep audit is left");

  // Still running: no change.
  await eng.onCodeAuditFinished(admin, "car1");
  assert.equal(db.rows("pipeline_stages").find((s) => s.scanner === "code_audit").status, "waiting");

  db.rows("code_audit_runs")[0].status = "done";
  await eng.onCodeAuditFinished(admin, "car1");
  const stages = db.rows("pipeline_stages");
  assert.equal(stages.find((s) => s.scanner === "code_audit").status, "done");
  const synth = stages.find((s) => s.scanner === "synthesis");
  assert.equal(synth.status, "done");
  // The deep finding joined the repo lead's check through the shared file.
  assert.equal(synth.output.issues[0].title, "Webhooks verify their signatures");
  assert.deepEqual(synth.output.issues[0].sources, ["repo", "code_audit"]);
  assert.equal(db.rows("scan_runs")[0].status, "partial");
  assert.equal(db.rows("scan_runs")[0].summary.synthesis.corroborated, 1);
});

test("engine: a run nobody is driving any more is closed out by the sweep", async () => {
  stubFetch(() => undefined);
  const eng = await import("../pipeline-engine.server.ts");
  const old = new Date(Date.now() - 5 * 3600_000).toISOString();
  const db = seed(planPipeline([], opts).map((s, i) => (i === 0 ? { ...s, status: "skipped", reason: "x", started_at: old, finished_at: old } : s)));
  db.rows("scan_runs")[0].started_at = old;
  const out = await eng.sweepStalePipelines(db.client());
  assert.deepEqual(out.swept, [RUN]);
  const stages = db.rows("pipeline_stages");
  assert.ok(stages.filter((s) => s.scanner !== "synthesis" && s.key !== "website").every((s) => /browser tab/.test(s.reason)));
  assert.equal(stages.find((s) => s.scanner === "synthesis").status, "done");
  assert.equal(db.rows("scan_runs")[0].status, "partial");
});
