// The audit's tamper-evident trail (phase 2b): verification result and events.
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";

export type ChainStatus = {
  ok: boolean;
  events: number;
  head_hash: string | null;
  head_at: string | null;
  first_bad_seq: number | null;
  problem: string | null;
};

export function useChainStatus(auditId: string) {
  return useQuery({
    queryKey: ["audit-chain", auditId],
    queryFn: async (): Promise<ChainStatus | null> => {
      const { data, error } = await supabase.rpc("verify_audit_chain", { p_audit: auditId });
      if (error) throw new Error(error.message);
      return ((data as ChainStatus[] | null) ?? [])[0] ?? null;
    },
  });
}

export async function fetchAuditEvents(auditId: string, limit = 5000) {
  const { data, error } = await supabase
    .from("audit_events")
    .select("seq, event, entity, entity_id, actor, occurred_at, data, prev_hash, row_hash")
    .eq("audit_id", auditId)
    .order("seq", { ascending: true })
    .limit(limit);
  if (error) throw new Error(error.message);
  return data ?? [];
}

/** Record a report export in the trail. Best effort: never blocks the export. */
export async function logReportExport(auditId: string, format: "pdf" | "markdown" | "evidence_bundle" | "print", sha256: string | null, headHash: string | null) {
  const { error } = await supabase.rpc("log_report_export", {
    p_audit: auditId,
    p_format: format,
    // The SQL function accepts NULL for both; generated types mark them required.
    p_sha256: sha256 as string,
    p_head_hash: headHash as string,
  });
  if (error) console.warn("[audit-trail] export not logged:", error.message);
}
