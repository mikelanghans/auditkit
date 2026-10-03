// Manage a failed finding: severity override, accepted risk, remediation.
// Every change is recorded in the audit trail by the database.
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Loader2, ShieldQuestion, SlidersHorizontal } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { REMEDIATION_LABEL, lifecycleOf, todayLocal, type LifecycleFields } from "@/lib/finding-lifecycle";

export function LifecycleBadges({ finding, itemSeverity }: { finding: LifecycleFields | null | undefined; itemSeverity: string | null }) {
  const l = lifecycleOf(finding, itemSeverity, todayLocal());
  return (
    <>
      {l.overridden && (
        <Badge variant="outline" className="text-[10px] uppercase" title={finding?.severity_override_reason ?? ""}>
          severity {l.defaultSeverity} → {l.severity}
        </Badge>
      )}
      {l.acceptedActive && (
        <Badge variant="outline" className="text-[10px] uppercase border-status-warn/50 text-status-warn" title={finding?.risk_accepted_reason ?? ""}>
          risk accepted until {finding?.risk_accepted_until}
        </Badge>
      )}
      {l.acceptedExpired && (
        <Badge variant="outline" className="text-[10px] uppercase border-status-fail/50 text-status-fail">acceptance expired</Badge>
      )}
      {finding?.remediation_status && finding.status === "fail" && (
        <Badge variant="secondary" className="text-[10px]">
          {REMEDIATION_LABEL[finding.remediation_status] ?? finding.remediation_status}
          {finding.remediation_owner ? ` · ${finding.remediation_owner}` : ""}
          {finding.remediation_due ? ` · due ${finding.remediation_due}` : ""}
        </Badge>
      )}
      {l.overdue && <Badge variant="outline" className="text-[10px] uppercase border-status-fail/50 text-status-fail">overdue</Badge>}
    </>
  );
}

export function FindingLifecycleDialog({
  auditId,
  findingId,
  itemTitle,
  itemSeverity,
  finding,
}: {
  auditId: string;
  findingId: string;
  itemTitle: string;
  itemSeverity: string | null;
  finding: LifecycleFields;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [sev, setSev] = useState<string>(finding.severity_override ?? "default");
  const [sevReason, setSevReason] = useState(finding.severity_override_reason ?? "");
  const [accept, setAccept] = useState(!!finding.risk_accepted_at);
  const [accReason, setAccReason] = useState(finding.risk_accepted_reason ?? "");
  const [accBy, setAccBy] = useState(finding.risk_accepted_by ?? "");
  const [accUntil, setAccUntil] = useState(finding.risk_accepted_until ?? "");
  const [owner, setOwner] = useState(finding.remediation_owner ?? "");
  const [due, setDue] = useState(finding.remediation_due ?? "");
  const [rstatus, setRstatus] = useState(finding.remediation_status ?? "none");

  const save = async () => {
    const overriding = sev !== "default";
    if (overriding && sevReason.trim().length < 5) return toast.error("Give a reason for the severity override.");
    if (accept && (accReason.trim().length < 5 || !accBy.trim() || !accUntil)) {
      return toast.error("Accepting a risk needs who accepted it, why, and until when.");
    }
    if (accept && accUntil < todayLocal()) return toast.error("The acceptance date is already in the past.");
    setSaving(true);
    const { error } = await supabase
      .from("audit_findings")
      .update({
        severity_override: overriding ? (sev as any) : null,
        severity_override_reason: overriding ? sevReason.trim() : null,
        risk_accepted_at: accept ? finding.risk_accepted_at ?? new Date().toISOString() : null,
        risk_accepted_reason: accept ? accReason.trim() : null,
        risk_accepted_by: accept ? accBy.trim() : null,
        risk_accepted_until: accept ? accUntil : null,
        remediation_owner: owner.trim() || null,
        remediation_due: due || null,
        remediation_status: rstatus === "none" ? null : rstatus,
      } as any)
      .eq("id", findingId);
    setSaving(false);
    if (error) return toast.error(error.message);
    toast.success("Saved. The change is in the audit trail.");
    setOpen(false);
    qc.invalidateQueries({ queryKey: ["findings", auditId] });
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && setOpen(o)}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1 h-8">
          <SlidersHorizontal className="h-3.5 w-3.5" /> Manage
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Manage finding</DialogTitle>
          <DialogDescription className="line-clamp-2">{itemTitle}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 text-sm">
          <section className="space-y-2">
            <Label className="text-xs font-semibold">Severity for this audit</Label>
            <div className="flex gap-2">
              <Select value={sev} onValueChange={setSev}>
                <SelectTrigger className="h-8 w-[200px] text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">Checklist default ({itemSeverity ?? "medium"})</SelectItem>
                  {["critical", "high", "medium", "low"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
              {sev !== "default" && (
                <Input className="h-8 text-xs" placeholder="Why (required)" value={sevReason} onChange={(e) => setSevReason(e.target.value)} />
              )}
            </div>
          </section>

          <section className="space-y-2 rounded-md border border-border/60 p-3">
            <label className="flex items-center gap-2 text-xs font-semibold">
              <input type="checkbox" checked={accept} onChange={(e) => setAccept(e.target.checked)} />
              <ShieldQuestion className="h-3.5 w-3.5" /> Client accepts this risk
            </label>
            {accept && (
              <div className="grid grid-cols-2 gap-2">
                <Input className="h-8 text-xs" placeholder="Accepted by (name, role)" value={accBy} onChange={(e) => setAccBy(e.target.value)} />
                <Input type="date" className="h-8 text-xs" value={accUntil} onChange={(e) => setAccUntil(e.target.value)} />
                <Textarea rows={2} className="col-span-2 text-xs" placeholder="Why it's accepted, and any compensating control" value={accReason} onChange={(e) => setAccReason(e.target.value)} />
                <p className="col-span-2 text-[11px] text-muted-foreground">It stays a fail. It's listed under accepted risks until the date, then reopens.</p>
              </div>
            )}
          </section>

          <section className="space-y-2">
            <Label className="text-xs font-semibold flex items-center gap-1"><CalendarClock className="h-3.5 w-3.5" /> Remediation</Label>
            <div className="grid grid-cols-3 gap-2">
              <Input className="h-8 text-xs" placeholder="Owner" value={owner} onChange={(e) => setOwner(e.target.value)} />
              <Input type="date" className="h-8 text-xs" value={due} onChange={(e) => setDue(e.target.value)} />
              <Select value={rstatus} onValueChange={setRstatus}>
                <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No status</SelectItem>
                  {Object.entries(REMEDIATION_LABEL).map(([k, v]) => <SelectItem key={k} value={k}>{v}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </section>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={saving}>Cancel</Button>
          <Button onClick={save} disabled={saving}>{saving && <Loader2 className="h-4 w-4 mr-1 animate-spin" />} Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
