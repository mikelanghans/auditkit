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
