// Severity-weighted security score for an audit.
// Score = passed_weight / (passed_weight + failed_weight) * 100, ignoring N/A, inconclusive and unanswered.
// Grade: A 90+, B 80-89, C 70-79, D 60-69, F <60.

const WEIGHTS: Record<string, number> = {
  critical: 10,
  high: 5,
  medium: 3,
  low: 1,
};

export type ScoredItem = { severity?: string | null; status?: "pass" | "fail" | "na" | null | string };

export type SecurityScore = {
  score: number | null; // null when nothing has been rated yet
  grade: "A" | "B" | "C" | "D" | "F" | "—";
  passWeight: number;
  failWeight: number;
  rated: number; // count of pass+fail items
};

export function computeSecurityScore(
  items: { id: string; severity?: string | null }[],
  statusByItemId: Map<string, "pass" | "fail" | "na" | null | string | undefined>,
): SecurityScore {
  let passWeight = 0;
  let failWeight = 0;
  let rated = 0;
  for (const it of items) {
    const status = statusByItemId.get(it.id);
    if (status !== "pass" && status !== "fail") continue;
    const w = WEIGHTS[(it.severity ?? "medium").toLowerCase()] ?? 3;
    if (status === "pass") passWeight += w;
    else failWeight += w;
    rated++;
  }
  if (rated === 0 || passWeight + failWeight === 0) {
    return { score: null, grade: "—", passWeight, failWeight, rated };
  }
  const score = Math.round((passWeight / (passWeight + failWeight)) * 100);
  const grade: SecurityScore["grade"] =
    score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { score, grade, passWeight, failWeight, rated };
}

export function gradeTone(grade: SecurityScore["grade"]): "pass" | "warn" | "fail" | "muted" {
  if (grade === "A" || grade === "B") return "pass";
  if (grade === "C") return "warn";
  if (grade === "D" || grade === "F") return "fail";
  return "muted";
}

export type RiskBreakdown = { critical: number; high: number; medium: number; low: number };

export function failuresBySeverity(
  items: { id: string; severity?: string | null }[],
  statusByItemId: Map<string, "pass" | "fail" | "na" | null | string | undefined>,
): RiskBreakdown {
  const r: RiskBreakdown = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const it of items) {
    if (statusByItemId.get(it.id) !== "fail") continue;
    const sev = (it.severity ?? "medium").toLowerCase();
    if (sev === "critical") r.critical++;
    else if (sev === "high") r.high++;
    else if (sev === "low") r.low++;
    else r.medium++;
  }
  return r;
}

// Rough hours-of-work estimate per severity, used for a remediation effort range.
const EFFORT_HOURS: Record<keyof RiskBreakdown, [number, number]> = {
  critical: [2, 4],
  high: [1.5, 3],
  medium: [0.5, 1.5],
  low: [0.25, 0.75],
};

export function estimateRemediationHours(r: RiskBreakdown): { min: number; max: number } {
  let min = 0;
  let max = 0;
  (Object.keys(r) as (keyof RiskBreakdown)[]).forEach((k) => {
    const [a, b] = EFFORT_HOURS[k];
    min += a * r[k];
    max += b * r[k];
  });
  return { min: Math.round(min * 2) / 2, max: Math.round(max * 2) / 2 };
}

export type LaunchVerdict = "go" | "fix-first" | "insufficient" | "block";

// Categories that must be meaningfully assessed before any green verdict.
export const CRITICAL_CATEGORIES = [
  "Database Security",
  "Authentication & Sessions",
  "API & Endpoint Security",
];

export const COVERAGE_THRESHOLD = 0.8;
export const CRITICAL_CATEGORY_THRESHOLD = 0.5;

export type CategoryCoverage = { category: string; assessed: number; total: number; ratio: number };

export type Coverage = {
  assessed: number;
  total: number;
  unanswered: number; // includes inconclusive items
  inconclusive: number; // scanner ran but could not determine the result
  ratio: number; // 0..1
  criticalCategories: CategoryCoverage[];
  underCoveredCategories: CategoryCoverage[]; // critical categories below threshold
  sufficient: boolean;
};

export function computeCoverage(
  items: { id: string; category?: string | null }[],
  statusByItemId: Map<string, "pass" | "fail" | "na" | null | string | undefined>,
): Coverage {
  // "inconclusive" means a scanner tried and could not tell, so it is NOT
  // assessed. "resolved" is a failure that was fixed and verified, so it is.
  const isAssessed = (id: string) => {
    const s = statusByItemId.get(id);
    return s === "pass" || s === "fail" || s === "na" || s === "resolved";
  };
  const total = items.length;
  const assessed = items.filter((it) => isAssessed(it.id)).length;
  const inconclusive = items.filter((it) => statusByItemId.get(it.id) === "inconclusive").length;
  const ratio = total === 0 ? 0 : assessed / total;

  const criticalCategories: CategoryCoverage[] = CRITICAL_CATEGORIES.map((category) => {
    const list = items.filter((it) => (it.category ?? "") === category);
    const a = list.filter((it) => isAssessed(it.id)).length;
    return { category, assessed: a, total: list.length, ratio: list.length === 0 ? 1 : a / list.length };
  }).filter((c) => c.total > 0);

  const underCoveredCategories = criticalCategories.filter((c) => c.ratio < CRITICAL_CATEGORY_THRESHOLD);

  return {
    assessed,
    total,
    unanswered: total - assessed,
    inconclusive,
    ratio,
    criticalCategories,
    underCoveredCategories,
    sufficient: total > 0 && ratio >= COVERAGE_THRESHOLD && underCoveredCategories.length === 0,
  };
}

export function launchRecommendation(
  score: number | null,
  r: RiskBreakdown,
  coverage?: Coverage,
): { verdict: LaunchVerdict; label: string; reason: string } {
  if (r.critical > 0 || r.high > 0) {
    const parts = [];
    if (r.critical) parts.push(`${r.critical} critical`);
    if (r.high) parts.push(`${r.high} high`);
    return {
      verdict: "block",
      label: "Do not launch",
      reason: `${parts.join(" + ")} finding${r.critical + r.high === 1 ? "" : "s"} must be resolved before going live.`,
    };
  }

  if (coverage && !coverage.sufficient) {
    const missing = coverage.underCoveredCategories.map((c) => c.category);
    const pct = Math.round(coverage.ratio * 100);
    const inc = coverage.inconclusive
      ? ` ${coverage.inconclusive} check${coverage.inconclusive === 1 ? "" : "s"} could not be verified by the scanners and need a manual review.`
      : "";
    return {
      verdict: "insufficient",
      label: "Insufficient coverage — not assessed",
      reason: missing.length
        ? `${missing.join(", ")} ${missing.length === 1 ? "has" : "have"} not been sufficiently assessed (${pct}% of checks run). Not enough coverage to certify readiness.${inc}`
        : `Only ${pct}% of checks have been run. Not enough coverage to certify readiness.${inc}`,
    };
  }

  if (score === null) {
    return { verdict: "insufficient", label: "Insufficient coverage — not assessed", reason: "Rate more items to get a launch recommendation." };
  }

  if (r.medium > 0 || r.low > 0 || score < 80) {
    const parts = [];
    if (r.medium) parts.push(`${r.medium} medium`);
    if (r.low) parts.push(`${r.low} low`);
    return {
      verdict: "fix-first",
      label: "Fix findings first",
      reason: `Resolve ${parts.join(" + ") || "outstanding findings"} before launch.`,
    };
  }

  // A green verdict is a certification. It must not be issued while any check
  // is sitting at "the scanner couldn't tell".
  if (coverage && coverage.inconclusive > 0) {
    return {
      verdict: "insufficient",
      label: "Insufficient coverage — not assessed",
      reason: `${coverage.inconclusive} check${coverage.inconclusive === 1 ? "" : "s"} could not be verified by the scanners. Review ${coverage.inconclusive === 1 ? "it" : "them"} manually before certifying readiness.`,
    };
  }

  if (coverage && coverage.unanswered > 0) {
    return {
      verdict: "go",
      label: "Ready to launch",
      reason: `No outstanding findings across ${coverage.assessed} assessed checks (${coverage.unanswered} not yet reviewed).`,
    };
  }

  return { verdict: "go", label: "Ready to launch", reason: "All checks assessed with no outstanding findings." };
}


