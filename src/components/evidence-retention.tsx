// Evidence retention for one audit: keep-until date and purge.
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { todayLocal } from "@/lib/finding-lifecycle";

export function EvidenceRetention({ auditId }: { auditId: string }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["evidence-retention", auditId],
    queryFn: async () => {
      const [a, purged] = await Promise.all([
        supabase.from("audits").select("evidence_retain_until").eq("id", auditId).single(),
        supabase.from("evidence").select("id", { count: "exact", head: true }).eq("audit_id", auditId).not("purged_at", "is", null),
      ]);
      if (a.error) throw new Error(a.error.message);
      return { until: (a.data as any)?.evidence_retain_until as string | null, purged: purged.count ?? 0 };
    },
  });
  const [until, setUntil] = useState("");
  const [busy, setBusy] = useState<null | "save" | "purge">(null);
  useEffect(() => setUntil(q.data?.until ?? ""), [q.data?.until]);

  const save = async () => {
    setBusy("save");
    const { error } = await supabase.from("audits").update({ evidence_retain_until: until || null } as any).eq("id", auditId);
    setBusy(null);
    if (error) return toast.error(error.message);
    toast.success(until ? `Evidence kept until ${until}.` : "Retention date cleared.");
    qc.invalidateQueries({ queryKey: ["evidence-retention", auditId] });
  };

  const purge = async () => {
    if (!window.confirm("Permanently delete this audit's captured evidence (responses, files, scan notes)? Hashes, findings and the audit trail are kept.")) return;
    setBusy("purge");
    try {
      const { data, error } = await supabase.rpc("purge_audit_evidence", { p_audit: auditId });
      if (error) throw new Error(error.message);
      const paths = ((data ?? []) as { storage_path: string }[]).map((r) => r.storage_path).filter(Boolean);
      let failed = 0;
      for (let i = 0; i < paths.length; i += 100) {
        const { error: rmErr } = await supabase.storage.from("evidence").remove(paths.slice(i, i + 100));
        if (rmErr) failed += paths.slice(i, i + 100).length;
      }
      if (failed) toast.warning(`Evidence purged, but ${failed} file(s) couldn't be deleted from storage. Run purge again.`);
      else toast.success(`Evidence purged${paths.length ? `, ${paths.length} file(s) deleted` : ""}.`);
      qc.invalidateQueries({ queryKey: ["evidence-retention", auditId] });
      qc.invalidateQueries({ queryKey: ["evidence"] });
    } catch (e: any) {
      toast.error(e?.message ?? "Purge failed.");
    } finally {
      setBusy(null);
    }
  };

  const due = !!q.data?.until && q.data.until < todayLocal();
  return (
    <div className="space-y-1.5 rounded-md border border-border/60 p-2.5">
      <Label className="text-xs">Keep captured evidence until</Label>
      <div className="flex gap-2 items-center">
        <Input type="date" className="h-8 text-xs w-[170px]" value={until} onChange={(e) => setUntil(e.target.value)} />
        <Button size="sm" variant="outline" className="h-8 text-xs" onClick={save} disabled={!!busy || until === (q.data?.until ?? "")}>
          {busy === "save" && <Loader2 className="h-3 w-3 mr-1 animate-spin" />} Save
        </Button>
        {due && (
          <Button size="sm" variant="destructive" className="h-8 text-xs" onClick={purge} disabled={!!busy}>
            {busy === "purge" ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Trash2 className="h-3 w-3 mr-1" />} Purge now
          </Button>
        )}
      </div>
      <p className="text-[11px] text-muted-foreground">
        After this date the client's captured data (responses, files, scan notes) can be purged. Findings, hashes and the audit trail stay.
        {q.data?.purged ? ` ${q.data.purged} item(s) already purged.` : ""}
      </p>
    </div>
  );
}
