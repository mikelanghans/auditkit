// Scheduled passive rescans for one audit (phase 4).
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { format } from "date-fns";
import { CalendarClock, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

type Schedule = {
  audit_id: string;
  enabled: boolean;
  cadence: "daily" | "weekly";
  alert_email: boolean;
  last_run_at: string | null;
  last_error: string | null;
  next_run_at: string;
};

export function ScheduleSettings({ auditId }: { auditId: string }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["audit-schedule", auditId],
    queryFn: async (): Promise<Schedule | null> => {
      const { data, error } = await (supabase as any)
        .from("audit_schedules")
        .select("audit_id, enabled, cadence, alert_email, last_run_at, last_error, next_run_at")
        .eq("audit_id", auditId)
        .maybeSingle();
      if (error) throw new Error(error.message);
      return data as Schedule | null;
    },
  });
  const [enabled, setEnabled] = useState(false);
  const [cadence, setCadence] = useState<"daily" | "weekly">("weekly");
  const [alertEmail, setAlertEmail] = useState(true);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (q.data) {
      setEnabled(q.data.enabled);
      setCadence(q.data.cadence);
      setAlertEmail(q.data.alert_email);
    }
  }, [q.data]);

  const save = async (runNow = false) => {
    setBusy(true);
    const db = supabase as any;
    const fields: Record<string, unknown> = { enabled, cadence, alert_email: alertEmail, scanners: ["website", "surface", "dependencies"] };
    if (runNow) fields.next_run_at = new Date().toISOString();
    const { error } = q.data
      ? await db.from("audit_schedules").update(fields).eq("audit_id", auditId)
      : await db.from("audit_schedules").insert({ audit_id: auditId, ...fields });
    setBusy(false);
    if (error) return toast.error(error.message);
    toast.success(runNow ? "Queued: it runs at the next hourly check." : "Schedule saved.");
    qc.invalidateQueries({ queryKey: ["audit-schedule", auditId] });
  };

  return (
    <div className="space-y-2 rounded-md border border-border/60 p-2.5">
      <Label className="text-xs flex items-center gap-1"><CalendarClock className="h-3.5 w-3.5" /> Scheduled passive rescans</Label>
      <div className="flex items-center gap-3 flex-wrap text-xs">
        <label className="flex items-center gap-2"><Switch checked={enabled} onCheckedChange={setEnabled} /> On</label>
        <Select value={cadence} onValueChange={(v) => setCadence(v as any)}>
          <SelectTrigger className="h-8 w-[110px] text-xs"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="daily">Daily</SelectItem>
            <SelectItem value="weekly">Weekly</SelectItem>
          </SelectContent>
        </Select>
        <label className="flex items-center gap-2"><Switch checked={alertEmail} onCheckedChange={setAlertEmail} /> Email me new or regressed failures</label>
        <div className="ml-auto flex gap-1.5">
          <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => save(false)} disabled={busy}>
            {busy && <Loader2 className="h-3 w-3 mr-1 animate-spin" />} Save
          </Button>
          {enabled && (
            <Button size="sm" variant="ghost" className="h-8 text-xs" onClick={() => save(true)} disabled={busy}>Run at next check</Button>
          )}
        </div>
      </div>
      <p className="text-[11px] text-muted-foreground">
        Website and attack-surface scans, plus a re-check of the packages recorded by the last repo scan against new advisories. No client keys, nothing that writes to their systems.
        {q.data?.last_run_at ? ` Last run ${format(new Date(q.data.last_run_at), "PP p")}.` : ""}
        {q.data?.enabled ? ` Next ${format(new Date(q.data.next_run_at), "PP p")}.` : ""}
        {q.data?.last_error ? ` Last error: ${q.data.last_error}` : ""}
      </p>
    </div>
  );
}
