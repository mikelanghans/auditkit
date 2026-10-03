// The report built from data: method, re-test comparison, evidence index,
// Markdown and the evidence bundle zip. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const run = (o: any) => ({ trigger: "manual", target: null, status: "done", finished_at: null, parent_run_id: null, summary: null, ...o });
const res = (o: any) => ({ checklist_key: null, evidence_ids: [], scanner: "website", ...o });

test("method: scanners, dates and the latest full run's gaps", async () => {
  const { summarizeMethod } = await import("../report-model.ts");
  const m = summarizeMethod([
    run({ id: "f1", scanner: "full", started_at: "2026-10-01T10:00:00Z", summary: { steps: [{ scanner: "supabase", target: "https://x.supabase.co", outcome: "not_run", reason: "no keys" }] } }),
    run({ id: "w1", scanner: "website", target: "https://a.test", started_at: "2026-10-01T10:00:01Z", parent_run_id: "f1" }),
    run({ id: "w2", scanner: "website", target: "https://a.test", started_at: "2026-10-03T09:00:00Z" }),
    run({ id: "r1", scanner: "repo", target: "acme/app", started_at: "2026-10-02T09:00:00Z" }),
  ]);
  assert.deepEqual(m.scanners.map((s) => [s.scanner, s.runs]), [["website", 2], ["repo", 1]]);
  assert.equal(m.firstActivity, "2026-10-01T10:00:00Z");
  assert.equal(m.lastActivity, "2026-10-03T09:00:00Z");
  assert.deepEqual(m.notRun, [{ scanner: "supabase", target: "https://x.supabase.co", reason: "no keys" }]);
});

test("re-test: before = state at the end of the baseline run, now = current status", async () => {
  const { retestComparison } = await import("../report-model.ts");
  const baseline = run({ id: "f1", scanner: "full", started_at: "2026-10-01T10:00:00Z", finished_at: "2026-10-01T10:05:00Z" });
  const runs = [baseline, run({ id: "c1", scanner: "website", started_at: "2026-10-01T10:00:01Z", parent_run_id: "f1" })];
  const results = [
    res({ run_id: "c1", checklist_item_id: "a", status: "fail", created_at: "2026-10-01T10:01:00Z" }),
    res({ run_id: "c1", checklist_item_id: "b", status: "pass", created_at: "2026-10-01T10:01:00Z" }),
    res({ run_id: "c1", checklist_item_id: "c", status: "fail", created_at: "2026-10-01T10:01:00Z" }),
    res({ run_id: "c1", checklist_item_id: "e", status: "fail", created_at: "2026-10-01T10:01:00Z" }),
    // After the baseline: must not count as "before".
    res({ run_id: "later", checklist_item_id: "a", status: "pass", created_at: "2026-10-05T00:00:00Z" }),
  ];
  const now = new Map<string, string | null>([["a", "pass"], ["b", "fail"], ["c", "fail"], ["d", "fail"], ["e", "resolved"]]);
  const rows = retestComparison(baseline, runs, results, now);
  const by = Object.fromEntries(rows.map((r) => [r.itemId, r.change]));
  assert.deepEqual(by, { a: "fixed", b: "regressed", c: "still_failing", d: "new", e: "fixed" });
  assert.equal(rows[0].change, "regressed", "worst first");
});

test("evidence index: numbered in report order, latest result per scanner, manual evidence included", async () => {
  const { buildEvidenceIndex } = await import("../report-model.ts");
  const ev = (id: string, o: any = {}) => ({ id, kind: "note", title: id, sha256: "0".repeat(64), size_bytes: 1, source: "scanner", captured_at: "2026-10-01T00:00:00Z", checklist_item_id: null, storage_path: null, ...o });
  const { byItem, index } = buildEvidenceIndex(
    ["x", "y"],
    [
      res({ run_id: "r1", checklist_item_id: "y", status: "fail", evidence_ids: ["old"], created_at: "2026-10-01T00:00:00Z" }),
      res({ run_id: "r2", checklist_item_id: "y", status: "fail", evidence_ids: ["shared", "new"], created_at: "2026-10-02T00:00:00Z" }),
      res({ run_id: "r2", checklist_item_id: "x", status: "fail", evidence_ids: ["shared"], created_at: "2026-10-02T00:00:00Z" }),
    ],
    [ev("old"), ev("shared"), ev("new"), ev("manual", { source: "manual", checklist_item_id: "x" })],
  );
  assert.deepEqual(index.map((e) => `${e.label}=${e.id}`), ["E1=shared", "E2=manual", "E3=new"]);
  assert.deepEqual(byItem.get("y")!.map((e) => e.label), ["E1", "E3"], "shared evidence keeps one number");
  assert.ok(!index.some((e) => e.id === "old"), "superseded evidence isn't cited");
});

test("markdown: scope, gaps, issues with evidence refs, appendix with hashes and chain head", async () => {
  const { buildReportMarkdown } = await import("../report-model.ts");
  const md = buildReportMarkdown({
    audit: { title: "Acme", client: "Acme Inc", website: "https://acme.test", started_at: "2026-10-01T00:00:00Z", completed_at: null, status: "in_progress" },
    summary: "Two issues need fixing before launch.",
    score: { score: 72, grade: "C" },
    counts: { pass: 10, fail: 2, na: 1, inconclusive: 1, unanswered: 3, resolved: 0, total: 17 },
    scope: { environment: "staging", authorized_by: "Jane, CTO", authorized_at: "2026-09-30", authorization_ref: "SOW #4", testing_window: null, out_of_scope: "Billing", write_tests_allowed: false },
    targets: [{ kind: "website", value: "https://acme.test", in_scope: true, label: null }],
    method: { scanners: [{ scanner: "website", label: "Website scan", runs: 2, targets: ["https://acme.test"], first: "2026-10-01T00:00:00Z", last: "2026-10-02T00:00:00Z" }], firstActivity: "2026-10-01T00:00:00Z", lastActivity: "2026-10-02T00:00:00Z", notRun: [{ scanner: "supabase", target: null, reason: "no keys" }] },
    untested: [{ title: "RLS enabled", category: "Database", status: "inconclusive" }],
    failed: [{ item: { id: "i1", title: "No CSP | header", category: "Frontend", severity: "high" }, notes: "missing", evidence: [{ id: "e", label: "E1", kind: "http_exchange", title: "GET /", sha256: "a".repeat(64), size_bytes: 9, source: "scanner", captured_at: "2026-10-01T00:00:00Z", checklist_item_id: null, storage_path: null }], controls: ["ASVS V14.4.3"] }],
    retest: null,
    evidenceIndex: [{ id: "e", label: "E1", kind: "http_exchange", title: "GET /", sha256: "a".repeat(64), size_bytes: 9, source: "scanner", captured_at: "2026-10-01T00:00:00Z", checklist_item_id: null, storage_path: null }],
    chain: { ok: true, events: 42, head_hash: "b".repeat(64), problem: null },
    generatedAt: "2026-10-03T00:00:00Z",
  });
  for (const s of ["Jane, CTO on 2026-09-30 (SOW #4)", "not performed (not authorized)", "Supabase scan: no keys", "RLS enabled (Database): could not be verified", "**Evidence:** E1 GET /", "ASVS V14.4.3", "a".repeat(64), "Chain head at export: `" + "b".repeat(64)]) {
    assert.ok(md.includes(s), `missing: ${s}`);
  }
});

test("zip: a valid archive whose files come back byte for byte", async () => {
  const { buildZip, crc32 } = await import("../zip-store.ts");
  assert.equal(crc32(new TextEncoder().encode("The quick brown fox jumps over the lazy dog")), 0x414fa339);
  const bytes = new Uint8Array([0, 1, 2, 255, 254]);
  const zip = buildZip([
    { name: "report.md", data: "# hello ✓\n" },
    { name: "evidence/E1-shot.bin", data: bytes },
  ]);
  const dir = mkdtempSync(join(tmpdir(), "ak-zip-"));
  const p = join(dir, "b.zip");
  writeFileSync(p, zip);
  let py: string;
  try {
    py = execFileSync("python3", ["-c", "import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);assert z.testzip() is None;print(z.read('report.md').decode());print(list(z.read('evidence/E1-shot.bin')))", p], { encoding: "utf8" });
  } catch (e: any) {
    if (e?.code === "ENOENT") return; // no python here; the CRC check above still ran
    throw e;
  }
  assert.match(py, /# hello ✓/);
  assert.match(py, /\[0, 1, 2, 255, 254\]/);
});

test("frameworks: per-control pass/fail/not assessed, failing checks named, natural order", async () => {
  const { summarizeFrameworks, controlLabel } = await import("../report-model.ts");
  const ASVS = "OWASP ASVS 4.0.3";
  const controls = [
    { checklist_item_id: "a", framework: "SOC 2", control_id: "CC6.1", control_title: "Logical access" },
    { checklist_item_id: "a", framework: ASVS, control_id: "V4.1.1", control_title: "Access control" },
    { checklist_item_id: "b", framework: ASVS, control_id: "V4.1.1", control_title: "Access control" },
    { checklist_item_id: "c", framework: ASVS, control_id: "V4.1.1", control_title: "Access control" },
    { checklist_item_id: "c", framework: ASVS, control_id: "V14.4.3", control_title: "CSP" },
    { checklist_item_id: "zz", framework: ASVS, control_id: "V2.1.1", control_title: "not in this audit" },
  ];
  const status = new Map<string, string | null>([["a", "fail"], ["b", "resolved"], ["c", null]]);
  const titles: Record<string, string> = { a: "RLS on", b: "No public buckets", c: "CSP set" };
  const fw = summarizeFrameworks(controls, status, (id) => titles[id]);
  assert.deepEqual(fw.map((f) => f.framework), [ASVS, "SOC 2"]);
  assert.deepEqual(fw[0].controls.map((c) => c.control_id), ["V4.1.1", "V14.4.3"], "V4 before V14");
  assert.deepEqual(fw[0].controls[0], { control_id: "V4.1.1", control_title: "Access control", checks: 3, pass: 1, fail: 1, other: 1, failing: ["RLS on"] });
  assert.equal(controlLabel({ framework: "HIPAA", control_id: "164.312(a)(1)" }), "HIPAA §164.312(a)(1)");
  assert.equal(controlLabel({ framework: ASVS, control_id: "V3.4.1" }), "ASVS V3.4.1");
});
