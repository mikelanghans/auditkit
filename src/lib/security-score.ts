// Severity-weighted security score for an audit.
// Score = passed_weight / (passed_weight + failed_weight) * 100, ignoring N/A and unanswered.
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

export type LaunchVerdict = "go" | "fix-first" | "block";

export function launchRecommendation(score: number | null, r: RiskBreakdown): { verdict: LaunchVerdict; label: string; reason: string } {
  if (score === null) {
    return { verdict: "fix-first", label: "Not enough data", reason: "Rate more items to get a launch recommendation." };
  }
  if (r.critical > 0) {
    return {
      verdict: "block",
      label: `Block launch — ${r.critical} critical finding${r.critical === 1 ? "" : "s"}`,
      reason: "Critical issues should be resolved before going live.",
    };
  }
  if (r.high > 0 || score < 80) {
    const parts = [];
    if (r.high) parts.push(`${r.high} high`);
    if (r.medium) parts.push(`${r.medium} medium`);
    return {
      verdict: "fix-first",
      label: `Launch after resolving ${parts.join(" + ") || "outstanding findings"}`,
      reason: "Address high-impact items before launch.",
    };
  }
  return { verdict: "go", label: "Ready to launch", reason: "No critical or high findings detected." };
}

