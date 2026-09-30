// Tests for the deep code audit integration: job/callback crypto, callback
// import rules, starting a run and mapping findings. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb, stubFetch, json } from "./harness/fakes.mts";
import { encryptJob, decryptJob, signCallback, verifyCallback } from "../code-audit-contract.ts";
import { applyCallback, normalizeFindings } from "../code-audit-import.ts";

const SECRET = "s".repeat(40);
const AUDIT = "audit-1";
const USER = "user-1";
const RUN = "11111111-2222-4333-8444-555555555555";

const job = {
  runId: RUN,
  repoUrl: "https://github.com/o/r",
  gitRef: null,
  githubToken: "github_pat_SECRETSECRETSECRET",
  profile: "standard" as const,
  budget: 80,
  callbackUrl: "https://app.example.com/api/public/hooks/code-audit",
  issuedAt: new Date().toISOString(),
};

test("contract: job is encrypted (token not readable) and tamper-evident", async () => {
  const blob = await encryptJob(job, SECRET);
  assert.ok(!Buffer.from(blob, "base64").toString("latin1").includes("SECRETSECRET"));
  assert.deepEqual(await decryptJob(blob, SECRET), job);
  const bytes = Buffer.from(blob, "base64");
  bytes[bytes.length - 1] ^= 1;
  await assert.rejects(decryptJob(bytes.toString("base64"), SECRET));
  await assert.rejects(decryptJob(blob, "x".repeat(40)));
  await assert.rejects(encryptJob(job, "short"));
});

test("contract: callback signatures bind body and time; stale or altered ones fail", async () => {
  const body = JSON.stringify({ runId: RUN, event: "started" });
  const now = Math.floor(Date.now() / 1000);
  const { timestamp, signature } = await signCallback(body, SECRET, now);
  assert.equal(await verifyCallback(body, timestamp, signature, SECRET, now), true);
  assert.equal(await verifyCallback(body + " ", timestamp, signature, SECRET, now), false);
  assert.equal(await verifyCallback(body, String(now + 1), signature, SECRET, now), false);
  assert.equal(await verifyCallback(body, timestamp, signature, "y".repeat(40), now), false);
  assert.equal(await verifyCallback(body, timestamp, signature, SECRET, now + 3600), false); // replay later
  assert.equal(await verifyCallback(body, null, signature, SECRET, now), false);
  assert.equal(await verifyCallback(body, timestamp, "zz", SECRET, now), false);
});

const confirmed = (fp: string, sev = "high") => ({
  verdict: "confirmed",
  fingerprint: fp,
  title: `Finding ${fp}`,
  description: "desc",
  root_cause: "rc",
  trace: [{ kind: "entrypoint", file: "a.ts", line: 1 }],
  evidence: [],
  remediation: { strategy: "fix it" },
  severity: { overall_severity: sev },
});

function runDb(status = "running") {
  return new FakeDb({ code_audit_runs: [{ id: RUN, audit_id: AUDIT, status }], code_audit_findings: [] });
}

const completed = (findings: unknown[], validators = { findings: "PASS: 2 findings valid", ledger: "PASS: 3 coverage units valid" }) => ({
  runId: RUN,
  event: "completed",
  runStatus: "complete",
  sourceCommit: "abc123",
  agentsUsed: 42,
  validators,
  findings,
  coverageLedger: [{ surface: "s", status: "covered" }, { surface: "t", status: "covered" }, { surface: "u", status: "candidate" }],
  reportMd: "# Report",
});

test("import: a validated completion stores findings and closes the run", async () => {
  const db = runDb();
  const res = await applyCallback(completed([confirmed("a"), { ...confirmed("b"), verdict: "needs_validation", severity: undefined }]), { db: db.client() as any });
  assert.equal(res.ok, true);
  const run = db.rows("code_audit_runs")[0];
  assert.equal(run.status, "done");
  assert.equal(run.confirmed_count, 1);
  assert.equal(run.needs_validation_count, 1);
  assert.deepEqual(run.coverage.byStatus, { covered: 2, candidate: 1 });
  const rows = db.rows("code_audit_findings");
  assert.equal(rows.length, 2);
  assert.equal(rows.find((r) => r.fingerprint === "a").severity, "high");
  assert.equal(rows.find((r) => r.fingerprint === "b").severity, null);
});

test("import: a replayed completion can't rewrite a finished run", async () => {
  const db = runDb("done");
  const res: any = await applyCallback(completed([confirmed("evil", "critical")]), { db: db.client() as any });
  assert.equal(res.ok, true);
  assert.match(res.message, /ignored/);
  assert.equal(db.rows("code_audit_findings").length, 0);
});

test("import: output that failed the skill's validators is not imported", async () => {
  const db = runDb();
  const res: any = await applyCallback(completed([confirmed("a")], { findings: "FAIL: $[0].trace missing", ledger: "PASS" }), { db: db.client() as any });
  assert.equal(res.ok, false);
  assert.equal(res.status, 422);
  assert.equal(db.rows("code_audit_runs")[0].status, "failed");
  assert.equal(db.rows("code_audit_findings").length, 0);
});

test("import: malformed records are rejected, not partially stored", () => {
  const { errors } = normalizeFindings([confirmed("a"), { verdict: "maybe", fingerprint: "x", title: "t" }, confirmed("a")]);
  assert.equal(errors.length, 2);
  assert.equal(normalizeFindings({}).errors.length, 1);
});

test("import: an incomplete run is recorded as incomplete, not done", async () => {
  const db = runDb();
  await applyCallback({ ...completed([]), runStatus: "incomplete", incompleteReason: "validation_budget_exhausted" }, { db: db.client() as any });
  const run = db.rows("code_audit_runs")[0];
  assert.equal(run.status, "incomplete");
  assert.equal(run.incomplete_reason, "validation_budget_exhausted");
});

function ctx(db: FakeDb, userId = USER) {
  const c = { supabase: db.client(), userId };
  (globalThis as any).__TEST_CONTEXT__ = c;
  (globalThis as any).__TEST_ADMIN__ = db.client();
  return c;
}

function setRunnerEnv(on: boolean) {
  const vars = {
    FLY_API_TOKEN: "fly-token",
    CODE_AUDIT_FLY_APP: "runner-app",
    CODE_AUDIT_RUNNER_IMAGE: "registry.fly.io/runner-app:1",
    CODE_AUDIT_WEBHOOK_SECRET: SECRET,
    PUBLIC_APP_URL: "https://app.example.com",
  };
  for (const [k, v] of Object.entries(vars)) {
    if (on) process.env[k] = v;
    else delete process.env[k];
  }
}

test("start: needs an owned audit, client consent and a configured runner", async () => {
  const { startCodeAudit } = await import("../code-audit.functions.ts");
  const db = new FakeDb({ audits: [{ id: AUDIT, created_by: "other" }] });
  const base = { auditId: AUDIT, repoUrl: "https://github.com/o/r", profile: "standard", clientConsent: true };
  let res: any = await startCodeAudit({ data: base, context: ctx(db) } as any);
  assert.equal(res.ok, false);

  const own = new FakeDb({ audits: [{ id: AUDIT, created_by: USER }] });
  res = await startCodeAudit({ data: { ...base, clientConsent: false }, context: ctx(own) } as any);
  assert.match(res.error, /agreed/);
  res = await startCodeAudit({ data: { ...base, repoUrl: "https://gitlab.com/o/r" }, context: ctx(own) } as any);
  assert.match(res.error, /GitHub repository/);
  setRunnerEnv(false);
  res = await startCodeAudit({ data: base, context: ctx(own) } as any);
  assert.match(res.error, /isn't configured/);
});

test("start: dispatches one Fly machine with the job encrypted, and records the run", async () => {
  setRunnerEnv(true);
  const { startCodeAudit } = await import("../code-audit.functions.ts");
  const db = new FakeDb({ audits: [{ id: AUDIT, created_by: USER }], code_audit_runs: [] });
  let flyBody = "";
  stubFetch((url, init) => {
    if (url === "https://api.machines.dev/v1/apps/runner-app/machines") {
      flyBody = String(init.body);
      return json({ id: "m-123" });
    }
    return undefined;
  });
  const res: any = await startCodeAudit({
    data: { auditId: AUDIT, repoUrl: "https://github.com/o/r.git", token: "github_pat_TOPSECRETTOKENVALUE", profile: "quick", clientConsent: true },
    context: ctx(db),
  } as any);
  assert.equal(res.ok, true);
  assert.ok(flyBody, "Fly API called");
  assert.ok(!flyBody.includes("TOPSECRET"), "token must not appear in machine config");
  const cfg = JSON.parse(flyBody).config;
  assert.equal(cfg.auto_destroy, true);
  const decoded = await decryptJob(cfg.env.AUDITKIT_JOB, SECRET);
  assert.equal(decoded.githubToken, "github_pat_TOPSECRETTOKENVALUE");
  assert.equal(decoded.repoUrl, "https://github.com/o/r");
  assert.equal(decoded.budget, 30);
  const run = db.rows("code_audit_runs")[0];
  assert.equal(run.status, "queued");
  assert.equal(run.runner_machine_id, "m-123");
  assert.ok(!JSON.stringify(run).includes("TOPSECRET"));
  setRunnerEnv(false);
});

test("map: only confirmed findings can mark a checklist item failing; resolved items are left alone", async () => {
  const { mapCodeAuditFinding } = await import("../code-audit.functions.ts");
  const db = new FakeDb({
    checklist_items: [{ id: "ci1", title: "RLS on all tables" }, { id: "ci2", title: "Secrets" }],
    code_audit_findings: [
      { id: "f1", audit_id: AUDIT, verdict: "confirmed", severity: "high", title: "T", description: "D", fingerprint: "fp" },
      { id: "f2", audit_id: AUDIT, verdict: "needs_validation", title: "N", fingerprint: "fp2" },
    ],
    audit_findings: [
      { audit_id: AUDIT, checklist_item_id: "ci1", status: "pass", notes: "looked fine" },
      { audit_id: AUDIT, checklist_item_id: "ci2", status: "resolved", notes: "fixed" },
    ],
  });
  const c = ctx(db);
  let res: any = await mapCodeAuditFinding({ data: { findingId: "f2", checklistItemId: "ci1" }, context: c } as any);
  assert.equal(res.ok, false);
  res = await mapCodeAuditFinding({ data: { findingId: "f1", checklistItemId: "ci1" }, context: c } as any);
  assert.equal(res.ok, true);
  const row = db.finding(AUDIT, "ci1");
  assert.equal(row.status, "fail");
  assert.match(row.notes, /Deep code audit/);
  assert.match(row.notes, /looked fine/);
  res = await mapCodeAuditFinding({ data: { findingId: "f1", checklistItemId: "ci2" }, context: c } as any);
  assert.equal(res.ok, true);
  assert.equal(db.finding(AUDIT, "ci2").status, "resolved");
});

test("fly auth header: macaroon tokens are sent as-is, plain tokens as Bearer", async () => {
  const { flyAuthHeader } = await import("../code-audit-dispatch.server.ts");
  assert.equal(flyAuthHeader("FlyV1 fm2_abc,fm2_def"), "FlyV1 fm2_abc,fm2_def");
  assert.equal(flyAuthHeader("  FlyV1 fm2_abc\n"), "FlyV1 fm2_abc");
  assert.equal(flyAuthHeader("fo1_plain"), "Bearer fo1_plain");
});
