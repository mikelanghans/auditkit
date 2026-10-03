// Where a failed finding stands beyond pass/fail: accepted risk (with
// expiry), a severity override for this audit, and remediation tracking.

export type Severity = "critical" | "high" | "medium" | "low";

export type LifecycleFields = {
  status?: string | null;
  risk_accepted_reason?: string | null;
  risk_accepted_by?: string | null;
  risk_accepted_at?: string | null;
  risk_accepted_until?: string | null;
  severity_override?: string | null;
  severity_override_reason?: string | null;
  remediation_owner?: string | null;
  remediation_due?: string | null;
  remediation_status?: string | null;
};

export type Lifecycle = {
  severity: Severity;
  defaultSeverity: Severity;
  overridden: boolean;
  /** Risk accepted and the acceptance hasn't expired. */
  acceptedActive: boolean;
  /** Risk was accepted but the date has passed, so it's open again. */
  acceptedExpired: boolean;
  /** A remediation due date in the past on a finding that's still failing. */
  overdue: boolean;
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const asSeverity = (s: string | null | undefined, fallback: Severity): Severity =>
  SEVERITIES.includes((s ?? "").toLowerCase() as Severity) ? ((s as string).toLowerCase() as Severity) : fallback;

/** today is YYYY-MM-DD (local date of the viewer); dates compare as strings. */
export function lifecycleOf(f: LifecycleFields | null | undefined, itemSeverity: string | null | undefined, today: string): Lifecycle {
  const defaultSeverity = asSeverity(itemSeverity, "medium");
  const severity = asSeverity(f?.severity_override, defaultSeverity);
  const accepted = !!(f?.risk_accepted_at && f?.risk_accepted_until);
  const acceptedActive = accepted && f!.risk_accepted_until! >= today;
  const failing = f?.status === "fail";
  return {
    severity,
    defaultSeverity,
    overridden: !!f?.severity_override && severity !== defaultSeverity,
    acceptedActive: acceptedActive && failing,
    acceptedExpired: accepted && !acceptedActive && failing,
    overdue: failing && !acceptedActive && !!f?.remediation_due && f.remediation_due < today,
  };
}

export const REMEDIATION_LABEL: Record<string, string> = {
  open: "Open",
  in_progress: "In progress",
  fixed_pending_retest: "Fixed, awaiting re-test",
  verified: "Verified fixed",
  wont_fix: "Won't fix",
};

export function todayLocal(d = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
