// The report, built from data (build plan, phase 2c). Pure functions only, so
// the on-screen report, the Markdown export and tests all agree.

export type RunRow = {
  id: string;
  scanner: string;
  trigger: string;
  target: string | null;
  status: string;
  started_at: string;
  finished_at: string | null;
  parent_run_id: string | null;
  summary: { counts?: Record<string, number>; steps?: { scanner: string; target: string | null; outcome: string; reason?: string | null }[] } | null;
};

export type ResultRow = {
  run_id: string;
  checklist_item_id: string | null;
  checklist_key: string | null;
  scanner: string;
  status: string;
  evidence_ids: string[];
  created_at: string;
};

export type EvidenceMeta = {
  id: string;
  kind: string;
  title: string;
  sha256: string;
  size_bytes: number;
  source: string;
  captured_at: string;
  checklist_item_id: string | null;
  storage_path: string | null;
};

export type ItemRow = { id: string; title: string; category: string; severity: string | null; sort_order?: number | null };

export const SCANNER_LABEL: Record<string, string> = {
  website: "Website scan",
  supabase: "Supabase scan",
  repo: "Repository scan",
  dependencies: "Dependency scan",
  ai_endpoint: "AI endpoint scan",
  code_audit: "Deep code audit",
  full: "Full audit",
};

// ---------------------------------------------------------------- method

export type MethodSummary = {
  scanners: { scanner: string; label: string; runs: number; targets: string[]; first: string; last: string }[];
  firstActivity: string | null;
  lastActivity: string | null;
  /** Steps of the latest full audit that didn't run, with the reason. */
  notRun: { scanner: string; target: string | null; reason: string }[];
};

export function summarizeMethod(runs: RunRow[]): MethodSummary {
  const by = new Map<string, { runs: number; targets: Set<string>; first: string; last: string }>();
  for (const r of runs) {
    if (r.scanner === "full") continue;
    const cur = by.get(r.scanner) ?? { runs: 0, targets: new Set<string>(), first: r.started_at, last: r.started_at };
    cur.runs++;
    if (r.target) cur.targets.add(r.target);
    if (r.started_at < cur.first) cur.first = r.started_at;
    if (r.started_at > cur.last) cur.last = r.started_at;
    by.set(r.scanner, cur);
  }
  const order = ["website", "supabase", "repo", "dependencies", "ai_endpoint", "code_audit"];
  const scanners = [...by.entries()]
    .sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]))
    .map(([scanner, v]) => ({ scanner, label: SCANNER_LABEL[scanner] ?? scanner, runs: v.runs, targets: [...v.targets], first: v.first, last: v.last }));
  const times = runs.map((r) => r.started_at).sort();
  const latestFull = runs.filter((r) => r.scanner === "full").sort((a, b) => b.started_at.localeCompare(a.started_at))[0];
  const notRun = (latestFull?.summary?.steps ?? [])
    .filter((s) => s.outcome === "not_run" || s.outcome === "failed")
    .map((s) => ({ scanner: s.scanner, target: s.target, reason: s.reason ?? (s.outcome === "failed" ? "failed" : "not run") }));
  return { scanners, firstActivity: times[0] ?? null, lastActivity: times[times.length - 1] ?? null, notRun };
}

// ---------------------------------------------------------------- re-test

export type RetestChange = "fixed" | "regressed" | "new" | "still_failing";
export type RetestRow = { itemId: string; before: string | null; now: string; change: RetestChange };

/**
 * Compare where each item stood at the end of a baseline run with where it
 * stands now. "Before" is the latest pass/fail scanner result recorded up to
 * the baseline run's finish; "now" is the current status on the audit.
 */
export function retestComparison(
  baseline: RunRow,
  allRuns: RunRow[],
  results: ResultRow[],
  currentStatus: Map<string, string | null | undefined>,
): RetestRow[] {
  const cutoff = baseline.finished_at ?? baseline.started_at;
  // A full run's results sit on its child runs.
  const inBaseline = new Set([baseline.id, ...allRuns.filter((r) => r.parent_run_id === baseline.id).map((r) => r.id)]);
  const before = new Map<string, { status: string; at: string }>();
  for (const r of results) {
    if (!r.checklist_item_id || (r.status !== "pass" && r.status !== "fail")) continue;
    if (r.created_at > cutoff && !inBaseline.has(r.run_id)) continue;
    const cur = before.get(r.checklist_item_id);
    if (!cur || r.created_at > cur.at) before.set(r.checklist_item_id, { status: r.status, at: r.created_at });
  }
  const out: RetestRow[] = [];
  const ids = new Set([...before.keys(), ...[...currentStatus.entries()].filter(([, s]) => s === "fail").map(([k]) => k)]);
  for (const id of ids) {
    const was = before.get(id)?.status ?? null;
    const raw = currentStatus.get(id) ?? null;
    const now = raw === "resolved" ? "pass" : raw;
    if (!now) continue;
    let change: RetestChange | null = null;
    if (was === "fail" && now === "pass") change = "fixed";
    else if (was === "pass" && now === "fail") change = "regressed";
    else if (was === null && now === "fail") change = "new";
    else if (was === "fail" && now === "fail") change = "still_failing";
    if (change) out.push({ itemId: id, before: was, now: raw ?? now, change });
  }
  const rank: Record<RetestChange, number> = { regressed: 0, new: 1, still_failing: 2, fixed: 3 };
  return out.sort((a, b) => rank[a.change] - rank[b.change]);
}

// ---------------------------------------------------------------- evidence index

export type EvidenceRef = EvidenceMeta & { label: string };

/**
 * Evidence per item (latest scanner results' evidence plus manual evidence),
 * and one numbered index for the appendix: E1, E2… in order of first use,
 * following the order the items appear in the report.
 */
export function buildEvidenceIndex(
  orderedItemIds: string[],
  results: ResultRow[],
  evidence: EvidenceMeta[],
): { byItem: Map<string, EvidenceRef[]>; index: EvidenceRef[] } {
  const byId = new Map(evidence.map((e) => [e.id, e]));
  // Latest scanner result per item (per scanner), and the evidence it points at.
  const latest = new Map<string, ResultRow>();
  for (const r of results) {
    if (!r.checklist_item_id) continue;
    const k = `${r.checklist_item_id}|${r.scanner}`;
    const cur = latest.get(k);
    if (!cur || r.created_at > cur.created_at) latest.set(k, r);
  }
  const idsForItem = new Map<string, string[]>();
  for (const r of latest.values()) {
    const list = idsForItem.get(r.checklist_item_id!) ?? [];
    for (const id of r.evidence_ids ?? []) if (!list.includes(id)) list.push(id);
    idsForItem.set(r.checklist_item_id!, list);
  }
  for (const e of evidence) {
    if (e.source === "manual" && e.checklist_item_id) {
      const list = idsForItem.get(e.checklist_item_id) ?? [];
      if (!list.includes(e.id)) list.push(e.id);
      idsForItem.set(e.checklist_item_id, list);
    }
  }
  const labels = new Map<string, string>();
  const index: EvidenceRef[] = [];
  const byItem = new Map<string, EvidenceRef[]>();
  for (const itemId of orderedItemIds) {
    const refs: EvidenceRef[] = [];
    for (const id of idsForItem.get(itemId) ?? []) {
      const e = byId.get(id);
      if (!e) continue;
      let label = labels.get(id);
      if (!label) {
        label = `E${labels.size + 1}`;
        labels.set(id, label);
        index.push({ ...e, label });
      }
      refs.push({ ...e, label });
    }
    if (refs.length) byItem.set(itemId, refs);
  }
  return { byItem, index };
}

// ---------------------------------------------------------------- markdown

export type ReportModel = {
  audit: { title: string; client: string | null; website: string | null; started_at: string | null; completed_at: string | null; status: string | null };
  summary: string | null;
  score: { score: number | null; grade: string };
  counts: { pass: number; fail: number; na: number; inconclusive: number; unanswered: number; resolved: number; total: number };
  scope: {
    environment: string;
    authorized_by: string | null;
    authorized_at: string | null;
    authorization_ref: string | null;
    testing_window: string | null;
    out_of_scope: string | null;
    write_tests_allowed: boolean;
  } | null;
  targets: { kind: string; value: string; in_scope: boolean; label: string | null }[];
  method: MethodSummary;
  untested: { title: string; category: string; status: string }[];
  failed: { item: ItemRow; notes: string | null; evidence: EvidenceRef[]; controls: string[] }[];
  retest: { baselineLabel: string; rows: (RetestRow & { title: string })[] } | null;
  evidenceIndex: EvidenceRef[];
  chain: { ok: boolean; events: number; head_hash: string | null; problem: string | null } | null;
  generatedAt: string;
};

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : "—");

export function buildReportMarkdown(m: ReportModel): string {
  const L: string[] = [];
  L.push(`# Security Audit Report: ${m.audit.title}`, "");
  L.push(`- **Client:** ${m.audit.client ?? "—"}`);
  if (m.audit.website) L.push(`- **Website:** ${m.audit.website}`);
  L.push(`- **Started:** ${day(m.audit.started_at)}${m.audit.completed_at ? ` · **Completed:** ${day(m.audit.completed_at)}` : ""}`);
  L.push(`- **Generated:** ${m.generatedAt}`, "");

  L.push("## Executive summary", "");
  if (m.summary) L.push(m.summary.trim(), "");
  L.push(`Score: **${m.score.score ?? "—"}** (${m.score.grade}). ${m.counts.fail} open issue(s), ${m.counts.pass + m.counts.resolved} passed, ${m.counts.inconclusive} could not be verified, ${m.counts.unanswered} not assessed, ${m.counts.na} not applicable, of ${m.counts.total} checks.`, "");

  L.push("## Scope and method", "");
  if (m.scope) {
    L.push(`- **Environment:** ${m.scope.environment}`);
    L.push(`- **Authorized by:** ${m.scope.authorized_by ?? "not recorded"}${m.scope.authorized_at ? ` on ${m.scope.authorized_at}` : ""}${m.scope.authorization_ref ? ` (${m.scope.authorization_ref})` : ""}`);
    if (m.scope.testing_window) L.push(`- **Testing window:** ${m.scope.testing_window}`);
    L.push(`- **Write/stress tests:** ${m.scope.write_tests_allowed ? "allowed" : "not performed (not authorized)"}`);
    if (m.scope.out_of_scope) L.push(`- **Out of scope:** ${m.scope.out_of_scope}`);
  } else {
    L.push("- Scope and authorization were not recorded.");
  }
  L.push("");
  if (m.targets.length) {
    L.push("| Target | Type | In scope |", "|---|---|---|");
    for (const t of m.targets) L.push(`| ${esc(t.value)}${t.label ? ` (${esc(t.label)})` : ""} | ${t.kind} | ${t.in_scope ? "yes" : "no"} |`);
    L.push("");
  }
  if (m.method.scanners.length) {
    L.push(`Automated testing ran between ${day(m.method.firstActivity)} and ${day(m.method.lastActivity)}:`, "");
    L.push("| Check | Runs | Targets | Last run |", "|---|---|---|---|");
    for (const s of m.method.scanners) L.push(`| ${s.label} | ${s.runs} | ${esc(s.targets.join(", ") || "—")} | ${day(s.last)} |`);
    L.push("");
  }
  if (m.method.notRun.length || m.untested.length) {
    L.push("### Not tested, and why", "");
    for (const n of m.method.notRun) L.push(`- ${SCANNER_LABEL[n.scanner] ?? n.scanner}${n.target ? ` (${n.target})` : ""}: ${n.reason}`);
    for (const u of m.untested) L.push(`- ${u.title} (${u.category}): ${u.status === "inconclusive" ? "could not be verified" : "not assessed"}`);
    L.push("");
  }

  L.push(`## Issues (${m.failed.length})`, "");
  m.failed.forEach((f, i) => {
    L.push(`### ${i + 1}. ${f.item.title}`, "");
    L.push(`- **Severity:** ${f.item.severity ?? "medium"} · **Category:** ${f.item.category}`);
    if (f.controls.length) L.push(`- **Controls:** ${f.controls.join(", ")}`);
    if (f.evidence.length) L.push(`- **Evidence:** ${f.evidence.map((e) => `${e.label} ${e.title}`).join("; ")}`);
    L.push("");
    if (f.notes) L.push("```", f.notes.trim(), "```", "");
  });

  if (m.retest) {
    L.push(`## Re-test (compared with ${m.retest.baselineLabel})`, "");
    if (!m.retest.rows.length) L.push("No changes.", "");
    else {
      L.push("| Check | Before | Now | Change |", "|---|---|---|---|");
      for (const r of m.retest.rows) L.push(`| ${esc(r.title)} | ${r.before ?? "—"} | ${r.now} | ${r.change.replace("_", " ")} |`);
      L.push("");
    }
  }

  L.push("## Appendix: evidence index", "");
  if (!m.evidenceIndex.length) L.push("No evidence recorded.", "");
  else {
    L.push("| Ref | Evidence | Type | Captured | SHA-256 |", "|---|---|---|---|---|");
    for (const e of m.evidenceIndex) L.push(`| ${e.label} | ${esc(e.title)} | ${e.kind} | ${e.captured_at.slice(0, 16).replace("T", " ")} | \`${e.sha256}\` |`);
    L.push("");
  }
  L.push("## Appendix: audit trail", "");
  if (m.chain) {
    L.push(m.chain.ok ? `Verified: ${m.chain.events} events, each chained to the one before it.` : `NOT verified: ${m.chain.problem}.`);
    if (m.chain.head_hash) L.push("", `Chain head at export: \`${m.chain.head_hash}\``);
  } else L.push("Audit trail not available.");
  L.push("");
  return L.join("\n");
}
