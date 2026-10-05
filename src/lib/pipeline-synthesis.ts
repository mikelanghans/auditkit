// The pipeline's last stage: one view of everything the run found. Pure, so
// it can be tested and re-run on stored data.
//
// Merges by what an issue IS, not which scanner found it:
//   1. Failing results for the same checklist item (website bundle secrets and
//      repo secrets both fail "No secrets in the current code") become one
//      issue that lists both scanners.
//   2. A deep-audit finding linked to a checklist item joins that issue.
//   3. A deep-audit finding in a file the repo scan already flagged joins the
//      repo check that flagged it (corroborated by two independent methods).
//   4. Everything else stands alone.
// Issues found by more than one method are marked corroborated and rank first
// within their severity.

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type SynthResult = {
  scanner: string;
  status: string;
  checklist_item_id: string | null;
  checklist_key: string | null;
  change?: string | null;
  target?: string | null;
};
export type SynthItem = { id: string; title: string; category: string; severity: string };
export type SynthCodeFinding = {
  id: string;
  title: string;
  severity: string | null;
  verdict: string;
  checklist_item_id: string | null;
  trace?: unknown;
  evidence?: unknown;
};
export type RepoLeads = {
  rules?: { rule: string; file: string; line?: number }[];
  xss?: { sink: string; file: string; line?: number }[];
  secrets?: { pattern: string; file: string }[];
} | null;
export type SynthGap = { scanner: string; label: string; status: "failed" | "skipped"; reason: string | null };

export type SynthIssue = {
  key: string;
  title: string;
  category: string | null;
  severity: Severity;
  /** Scanner names that found it ("website", "repo", "code_audit", …). */
  sources: string[];
  corroborated: boolean;
  checklistItemId: string | null;
  codeFindingIds: string[];
  /** Deep-audit verdict when it's part of the issue. */
  deepVerdict: "confirmed" | "needs_validation" | null;
  files: string[];
  /** "new" / "regressed" against the previous run, when any result says so. */
  change: string | null;
};

export type Synthesis = {
  issues: SynthIssue[];
  gaps: SynthGap[];
  counts: Record<Severity, number>;
  corroborated: number;
  generatedAt: string;
};

/** Which checklist title each repo-scan lead kind feeds. */
export const LEAD_TITLE: Record<string, string> = {
  webhook_signatures: "Webhooks verify their signatures",
  service_role_in_source: "Service-role key not referenced in client code",
  dynamic_code_eval: "No eval of dynamic values",
  pii_in_logs: "Logging configured without PII capture",
  xss: "XSS protections in place",
  secrets: "No secrets in the current code",
};

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const normSev = (s: string | null | undefined): Severity =>
  (s && s in SEV_RANK ? s : "medium") as Severity;
const maxSev = (a: Severity, b: Severity): Severity => (SEV_RANK[a] <= SEV_RANK[b] ? a : b);

/** File paths mentioned in a deep-audit finding's trace/evidence JSON. */
export function filesIn(value: unknown, out = new Set<string>(), depth = 0): Set<string> {
  if (depth > 6 || value == null) return out;
  if (Array.isArray(value)) {
    for (const v of value.slice(0, 200)) filesIn(v, out, depth + 1);
  } else if (typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof v === "string" && /^(file|path|location|filename|file_path)$/i.test(k)) {
        const f = v.replace(/:\d+(:\d+)?$/, "").replace(/^\.?\//, "").trim();
        if (f && f.length <= 300 && !/\s/.test(f)) out.add(f);
      } else filesIn(v, out, depth + 1);
    }
  }
  return out;
}

export function synthesize(input: {
  results: SynthResult[];
  items: SynthItem[];
  codeFindings: SynthCodeFinding[];
  repoLeads: RepoLeads;
  gaps: SynthGap[];
  now?: Date;
}): Synthesis {
  const itemById = new Map(input.items.map((i) => [i.id, i]));
  const itemByTitle = new Map(input.items.map((i) => [i.title, i]));
  const issues = new Map<string, SynthIssue>();

  const forItem = (itemId: string): SynthIssue => {
    let issue = issues.get(`item:${itemId}`);
    if (!issue) {
      const it = itemById.get(itemId);
      issue = {
        key: `item:${itemId}`,
        title: it?.title ?? "Checklist item",
        category: it?.category ?? null,
        severity: normSev(it?.severity),
        sources: [],
        corroborated: false,
        checklistItemId: itemId,
        codeFindingIds: [],
        deepVerdict: null,
        files: [],
        change: null,
      };
      issues.set(issue.key, issue);
    }
    return issue;
  };
  const addSource = (i: SynthIssue, s: string) => {
    if (!i.sources.includes(s)) i.sources.push(s);
  };

  // 1. Failing scanner results, grouped by checklist item.
  for (const r of input.results) {
    if (r.status !== "fail" || !r.checklist_item_id) continue;
    const issue = forItem(r.checklist_item_id);
    addSource(issue, r.scanner);
    if (r.change === "new" || r.change === "regressed") issue.change = issue.change === "regressed" ? "regressed" : r.change;
  }

  // Files the repo scan flagged, by the checklist item they feed.
  const leadFiles = new Map<string, Set<string>>(); // item id → files
  const addLead = (kind: string, file: string) => {
    const it = itemByTitle.get(LEAD_TITLE[kind] ?? "");
    if (!it || !file) return;
    if (!leadFiles.has(it.id)) leadFiles.set(it.id, new Set());
    leadFiles.get(it.id)!.add(file);
  };
  for (const r of input.repoLeads?.rules ?? []) addLead(r.rule, r.file);
  for (const x of input.repoLeads?.xss ?? []) addLead("xss", x.file);
  for (const s of input.repoLeads?.secrets ?? []) addLead("secrets", s.file);

  // 2–4. Deep-audit findings.
  for (const f of input.codeFindings) {
    if (f.verdict === "rejected") continue;
    const files = [...filesIn([f.trace, f.evidence])];
    let itemId = f.checklist_item_id;
    if (!itemId) {
      for (const [id, set] of leadFiles) if (files.some((x) => set.has(x))) itemId = id;
    }
    let issue: SynthIssue;
    if (itemId) {
      issue = forItem(itemId);
      if (itemId !== f.checklist_item_id) addSource(issue, "repo"); // matched through a repo lead
    } else {
      issue = {
        key: `code:${f.id}`,
        title: f.title,
        category: null,
        severity: normSev(f.severity),
        sources: [],
        corroborated: false,
        checklistItemId: null,
        codeFindingIds: [],
        deepVerdict: null,
        files: [],
        change: null,
      };
      issues.set(issue.key, issue);
    }
    addSource(issue, "code_audit");
    issue.codeFindingIds.push(f.id);
    issue.severity = maxSev(issue.severity, normSev(f.severity));
    issue.deepVerdict = issue.deepVerdict === "confirmed" || f.verdict === "confirmed" ? "confirmed" : "needs_validation";
    for (const x of files) if (!issue.files.includes(x) && issue.files.length < 10) issue.files.push(x);
  }

  const list = [...issues.values()];
  for (const i of list) i.corroborated = i.sources.length > 1;
  list.sort(
    (a, b) =>
      SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
      Number(b.corroborated) - Number(a.corroborated) ||
      b.sources.length - a.sources.length ||
      a.title.localeCompare(b.title),
  );
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const i of list) counts[i.severity]++;
  return {
    issues: list,
    gaps: input.gaps,
    counts,
    corroborated: list.filter((i) => i.corroborated).length,
    generatedAt: (input.now ?? new Date()).toISOString(),
  };
}

/** Facts for the executive-summary draft: titles and counts only, no evidence. */
export function synthesisFacts(s: Synthesis, scannerLabel: (s: string) => string) {
  return {
    merged_issues: s.issues.slice(0, 25).map((i) => ({
      title: i.title,
      severity: i.severity,
      found_by: i.sources.map(scannerLabel),
      confirmed_by_more_than_one_method: i.corroborated,
      ...(i.change ? { change_since_last_run: i.change } : {}),
    })),
    issue_counts: s.counts,
    not_tested: s.gaps.map((g) => ({ check: g.label, why: g.reason })),
  };
}
