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

test("evidence: credentials masked, secrets redacted, hashed, and linked from results", async () => {
  const { saveScanRun } = await import("../scan-history.ts");
  const { httpExchange, sha256Hex } = await import("../evidence.ts");
  const db = new FakeDb();
  const sb = db.client() as any;

  const exchange = httpExchange(
    { url: "https://example.com" },
    {
      status: 200,
      headers: new Headers({
        "content-security-policy": "default-src 'self'",
        "set-cookie": "sid=abc123secret; Path=/; HttpOnly",
        authorization: "Bearer xyz",
      }),
      body: 'const k = "sk_live_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxXYZ";',
    },
  );
  const out = await saveScanRun(
    sb,
    { auditId: AUDIT, scanner: "website", target: "https://example.com" },
    [
      { checklist_item_id: "i1", checklist_key: "csp_header", status: "pass", stored: true, evidence: ["main"] },
      { checklist_item_id: "i2", checklist_key: "cookie_flags", status: "fail", stored: true, evidence: ["main", "unused-ref"] },
      { checklist_item_id: "i3", checklist_key: "error_verbosity", status: "pass", stored: true },
    ],
    {
      evidence: [
        { ref: "main", kind: "http_exchange", title: "GET https://example.com", content: exchange },
        { ref: "orphan", kind: "note", title: "not referenced by any result", content: "x" },
      ],
    },
  );
  assert.equal(out.history_error, undefined);
  assert.equal(out.evidence_count, 1, "evidence nobody points at is not stored");

  const [ev] = db.rows("evidence");
  assert.equal(ev.run_id, out.run_id);
  assert.match(ev.content_text, /default-src 'self'/);
  assert.match(ev.content_text, /sid=\[REDACTED\]; Path=\/; HttpOnly/, "cookie attributes kept, value masked");
  assert.doesNotMatch(ev.content_text, /abc123secret|Bearer xyz|sk_live_51H/);
  assert.equal(ev.sha256, await sha256Hex(ev.content_text));
  assert.equal(ev.size_bytes, new TextEncoder().encode(ev.content_text).length);

  const res = db.rows("scan_results");
  assert.deepEqual(res.find((r) => r.checklist_key === "cookie_flags").evidence_ids, [ev.id]);
  assert.deepEqual(res.find((r) => r.checklist_key === "error_verbosity").evidence_ids, []);
});

test("HAR uploads lose their credentials before they are stored", async () => {
  const { redactHar } = await import("../evidence.ts");
  const har = {
    log: {
      entries: [
        {
          request: {
            url: "https://api.example.com/v1/x?apikey=sk_live_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxXYZ",
            headers: [{ name: "Authorization", value: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.abc" }, { name: "Accept", value: "application/json" }],
            cookies: [{ name: "sb-access-token", value: "tok123" }],
            postData: { text: '{"password":"hunter2hunter2"}' },
          },
          response: { status: 200, headers: [{ name: "Set-Cookie", value: "sid=zzz; HttpOnly" }], cookies: [], content: { text: "ok" } },
        },
      ],
    },
  };
  const out = redactHar(JSON.stringify(har));
  assert.doesNotMatch(out, /sk_live_51H|Bearer eyJ|tok123|zzz|hunter2/);
  assert.match(out, /application\/json/);
  assert.match(out, /sid=\[REDACTED\]; HttpOnly/);
  assert.throws(() => redactHar('{"not":"a har"}'), /Not a HAR/);
});

test("full audit: steps that didn't run are recorded as gaps, children are summed", async () => {
  const { startFullAudit, finishFullAudit, summarizeFullAudit } = await import("../full-audit.functions.ts");
  const db = new FakeDb({ audits: [{ id: AUDIT, created_by: "user-1", title: "Acme" }] });
  const c = { supabase: db.client(), userId: "user-1" };
  (globalThis as any).__TEST_CONTEXT__ = c;

  const started: any = await startFullAudit({ data: { auditId: AUDIT }, context: c } as any);
  assert.equal(started.ok, true);
  db.rows("scan_runs").push(
    { id: "child-1", audit_id: AUDIT, parent_run_id: started.runId, scanner: "website", status: "done", summary: { counts: { pass: 10, fail: 2 }, changes: { new: 2 }, evidence: 6 } },
    { id: "child-2", audit_id: AUDIT, parent_run_id: started.runId, scanner: "repo", status: "partial", summary: { counts: { pass: 1, inconclusive: 1 }, changes: {}, evidence: 1 } },
  );
  const steps = [
    { scanner: "website", target: "https://acme.test", outcome: "done" },
    { scanner: "repo", target: "https://github.com/acme/app", outcome: "done" },
    { scanner: "supabase", target: "https://abcdefghijklmnopqrst.supabase.co", outcome: "not_run", reason: "No service-role key given" },
    { scanner: "ai_endpoint", target: "https://acme.test/api/chat", outcome: "failed", reason: "HTTP 500" },
  ];
  const done: any = await finishFullAudit({ data: { auditId: AUDIT, runId: started.runId, steps }, context: c } as any);
  assert.equal(done.ok, true);
  assert.equal(done.status, "partial");
  assert.deepEqual(done.summary.counts, { pass: 11, fail: 2, inconclusive: 1, not_run: 2 });
  assert.equal(done.summary.evidence, 7);

  const gaps = db.rows("scan_results").filter((r) => r.run_id === started.runId);
  assert.deepEqual(gaps.map((g) => g.checklist_key).sort(), ["step:ai_endpoint", "step:supabase"]);
  assert.ok(gaps.every((g) => g.status === "not_run"));

  const again: any = await finishFullAudit({ data: { auditId: AUDIT, runId: started.runId, steps }, context: c } as any);
  assert.equal(again.ok, false, "a closed run can't be closed twice");

  assert.equal(summarizeFullAudit([{ scanner: "website", target: null, outcome: "done" }], []).status, "done");
});

test("scheduled scans: a due schedule runs passive scans as the owner and is pushed to its next slot", async () => {
  const { runDueSchedules, alertWorthy } = await import("../scheduled-scans.server.ts");
  assert.equal(alertWorthy([{ status: "fail", change: "new" }, { status: "fail", change: "unchanged" }, { status: "pass", change: "fixed" }, { status: "fail", change: "regressed" }]).length, 2);

  const { stubFetch, text } = await import("./harness/fakes.mts");
  const db = new FakeDb({
    audits: [{ id: AUDIT, created_by: "owner-1", title: "Acme", website_url: null }],
    audit_schedules: [{ audit_id: AUDIT, enabled: true, cadence: "daily", scanners: ["website"], alert_email: true, next_run_at: "2026-10-01T00:00:00Z" }],
  });
  // The fake can't join; give the schedule its audit the way PostgREST would.
  db.rows("audit_schedules")[0].audit = db.rows("audits")[0];
  stubFetch(() => text("nf", 404));
  const now = new Date("2026-10-03T12:00:00Z");
  const out = await runDueSchedules(db.client() as any, now);
  assert.equal(out.ran.length, 1);
  const parent = db.rows("scan_runs").find((r) => r.scanner === "full");
  assert.equal(parent.trigger, "schedule");
  assert.equal(parent.created_by, "owner-1");
  assert.equal(parent.status, "partial", "website step couldn't run: no website set");
  assert.ok(db.rows("scan_results").some((r) => r.checklist_key === "step:website" && r.status === "not_run"));
  assert.equal(db.rows("audit_schedules")[0].next_run_at, "2026-10-04T12:00:00.000Z");
});
