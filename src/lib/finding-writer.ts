// Single write path for scanner results.
//
// Every automated scanner records its verdicts through upsertScanFinding so the
// same rule applies everywhere: a result of "inconclusive" (the scanner could not
// actually check the item) never overwrites something we already know. It will
// not erase an open failure, a resolution, or an N/A the auditor set by hand.
// It does replace an earlier scanner "pass", because that pass was not
// re-confirmed this time.
import type { SupabaseClient } from "@supabase/supabase-js";

export type ScanFindingStatus = "pass" | "fail" | "na" | "inconclusive";

export type ScanFindingRow = {
  audit_id: string;
  checklist_item_id: string;
  status: ScanFindingStatus;
  notes: string;
  [extra: string]: unknown;
};

export type ScanWriteResult = { written: boolean; keptStatus?: string };

export async function upsertScanFinding(
  supabase: SupabaseClient<any>,
  row: ScanFindingRow,
): Promise<ScanWriteResult> {
  if (row.status === "inconclusive") {
    const { data: existing, error } = await supabase
      .from("audit_findings")
      .select("status, auto_scanned")
      .eq("audit_id", row.audit_id)
      .eq("checklist_item_id", row.checklist_item_id)
      .maybeSingle();
    if (error) throw new Error(error.message);
    const prev = (existing as { status?: string | null; auto_scanned?: boolean | null } | null) ?? null;
    if (prev && shouldKeepExisting(prev.status ?? null, !!prev.auto_scanned)) {
      return { written: false, keptStatus: prev.status ?? undefined };
    }
  }
  const { error } = await supabase
    .from("audit_findings")
    .upsert({ auto_scanned: true, ...row } as never, { onConflict: "audit_id,checklist_item_id" });
  if (error) throw new Error(error.message);
  return { written: true };
}

/** Exported for tests. */
export function shouldKeepExisting(prevStatus: string | null, prevAutoScanned: boolean): boolean {
  if (prevStatus === "fail" || prevStatus === "resolved") return true;
  if (prevStatus === "na" && !prevAutoScanned) return true;
  return false;
}
