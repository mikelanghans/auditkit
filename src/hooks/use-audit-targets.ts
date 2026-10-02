// Targets and scope for one audit, shared by the targets panel and the scanner dialogs.
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import type { AuditScope, AuditTarget } from "@/lib/audit-targets";

export function useAuditTargets(auditId: string) {
  return useQuery({
    queryKey: ["audit-targets", auditId],
    queryFn: async (): Promise<AuditTarget[]> => {
      const { data, error } = await supabase
        .from("audit_targets")
        .select("id, audit_id, kind, value, label, meta, in_scope")
        .eq("audit_id", auditId)
        .order("created_at", { ascending: true });
      if (error) throw new Error(error.message);
      return (data ?? []) as AuditTarget[];
    },
  });
}

export function useAuditScope(auditId: string) {
  return useQuery({
    queryKey: ["audit-scope", auditId],
    queryFn: async (): Promise<AuditScope | null> => {
      const { data, error } = await supabase
        .from("audit_scope")
        .select("audit_id, environment, write_tests_allowed, authorized_by, authorized_at, authorization_ref, testing_window, out_of_scope, notes")
        .eq("audit_id", auditId)
        .maybeSingle();
      if (error) throw new Error(error.message);
      return (data ?? null) as AuditScope | null;
    },
  });
}
