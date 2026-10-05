import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { CheckCircle2, ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/fix-tracker")({
  head: () => ({
    meta: [
      { title: "Fix Tracker — AuditKit" },
      { name: "description", content: "Log progress on each generated fix and mark it done once applied." },
      { property: "og:title", content: "Fix Tracker — AuditKit" },
      { property: "og:description", content: "Log progress on each generated fix and mark it done once applied." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: FixTracker,
});

const STAGES = [
  { v: "open", label: "Not started" },
  { v: "in_progress", label: "In progress" },
  { v: "fixed_pending_retest", label: "Applied — needs re-check" },
  { v: "wont_fix", label: "Won't fix" },
] as const;

const SEV: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

type Fix = {
  id: string;
  audit_id: string;
  status: string;
  remediation_status: string | null;
  resolved_at: string | null;
  lovable_prompt: string | null;
  cursor_prompt: string | null;
  claude_prompt: string | null;
  checklist_items: { title: string; severity: string } | null;
  audits: { title: string } | null;
};
type LogRow = { finding_id: string; evidence_text: string | null; created_at: string; event_type: string };

function FixTracker() {
  const qc = useQueryClient();
  const [view, setView] = useState<"active" | "done" | "all">("active");

  const fixes = useQuery({
    queryKey: ["fix-tracker"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audit_findings")
        .select("id, audit_id, status, remediation_status, resolved_at, lovable_prompt, cursor_prompt, claude_prompt, checklist_items(title, severity), audits(title)")
        .or("lovable_prompt.not.is.null,cursor_prompt.not.is.null,claude_prompt.not.is.null");
      if (error) throw error;
      return (data ?? []) as unknown as Fix[];
    },
  });

  const ids = (fixes.data ?? []).map((f) => f.id);
  const logs = useQuery({
    queryKey: ["fix-tracker-logs", ids],
    enabled: ids.length > 0,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("finding_audit_log")
        .select("finding_id, evidence_text, created_at, event_type")
        .in("finding_id", ids)
        .not("evidence_text", "is", null)
        .order("created_at", { ascending: false });
      if (error) throw error;
      return (data ?? []) as LogRow[];
    },
  });

  const notesBy = useMemo(() => {
    const m = new Map<string, LogRow[]>();
    for (const l of logs.data ?? []) m.set(l.finding_id, [...(m.get(l.finding_id) ?? []), l]);
    return m;
  }, [logs.data]);

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["fix-tracker"] });
    qc.invalidateQueries({ queryKey: ["fix-tracker-logs"] });
    qc.invalidateQueries({ queryKey: ["fix-progress"] });
  };

  const setStage = useMutation({
    mutationFn: async ({ id, stage }: { id: string; stage: string }) => {
      const { error } = await supabase.from("audit_findings").update({ remediation_status: stage }).eq("id", id);
      if (error) throw error;
    },
    onSuccess: refresh,
    onError: (e: Error) => toast.error(e.message),
  });

  const addNote = useMutation({
    mutationFn: async ({ f, text }: { f: Fix; text: string }) => {
      const { data: u } = await supabase.auth.getUser();
      const { error } = await supabase.from("finding_audit_log").insert({
        finding_id: f.id, audit_id: f.audit_id, event_type: "fix_submitted",
        evidence_text: text, before_status: f.status, after_status: f.status, performed_by: u.user?.id ?? null,
      });
      if (error) throw error;
      if (!f.remediation_status || f.remediation_status === "open") {
        await supabase.from("audit_findings").update({ remediation_status: "in_progress" }).eq("id", f.id);
      }
    },
    onSuccess: () => { toast.success("Progress logged"); refresh(); },
    onError: (e: Error) => toast.error(e.message),
  });

  const markDone = useMutation({
    mutationFn: async ({ f, text }: { f: Fix; text: string }) => {
      const { error } = await supabase.from("audit_findings").update({
        status: "resolved", resolved_at: new Date().toISOString(), resolved_via: "manual_evidence",
        evidence_text: text || "Fix applied", remediation_status: "verified",
      }).eq("id", f.id);
      if (error) throw error;
    },
    onSuccess: () => { toast.success("Marked as done"); refresh(); },
    onError: (e: Error) => toast.error(e.message),
  });

  const reopen = useMutation({
    mutationFn: async (f: Fix) => {
      const { error } = await supabase.from("audit_findings").update({
        status: "fail", resolved_at: null, resolved_via: null, remediation_status: "in_progress",
      }).eq("id", f.id);
      if (error) throw error;
    },
    onSuccess: refresh,
    onError: (e: Error) => toast.error(e.message),
  });

  const all = (fixes.data ?? []).slice().sort((a, b) =>
    (a.status === "resolved" ? 1 : 0) - (b.status === "resolved" ? 1 : 0) ||
    (SEV[a.checklist_items?.severity ?? "low"] ?? 9) - (SEV[b.checklist_items?.severity ?? "low"] ?? 9));
  const done = all.filter((f) => f.status === "resolved").length;
  const shown = all.filter((f) => view === "all" || (view === "done" ? f.status === "resolved" : f.status !== "resolved"));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Fix Tracker</h1>
        <p className="text-sm text-muted-foreground">
          Every issue you've generated a fix for. Log progress as you go and mark it done once applied.
        </p>
      </div>

      {fixes.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : fixes.error ? (
        <p className="text-sm text-destructive">Couldn't load fixes: {(fixes.error as Error).message}</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <ToggleGroup type="single" value={view} onValueChange={(v) => v && setView(v as typeof view)}>
              <ToggleGroupItem value="active">Active</ToggleGroupItem>
              <ToggleGroupItem value="done">Done</ToggleGroupItem>
              <ToggleGroupItem value="all">All</ToggleGroupItem>
            </ToggleGroup>
            <span className="text-sm text-muted-foreground">{done} of {all.length} done</span>
          </div>

          {shown.length === 0 && (
            <Card className="p-6 text-sm text-muted-foreground">
              {all.length === 0 ? "No fixes generated yet. Click Generate Fix on an issue in any audit." : "Nothing here."}
            </Card>
          )}

          <div className="space-y-4">
            {shown.map((f) => (
              <FixCard
                key={f.id}
                f={f}
                notes={notesBy.get(f.id) ?? []}
                busy={setStage.isPending || addNote.isPending || markDone.isPending || reopen.isPending}
                onStage={(stage) => setStage.mutate({ id: f.id, stage })}
                onNote={(text) => addNote.mutate({ f, text })}
                onDone={(text) => markDone.mutate({ f, text })}
                onReopen={() => reopen.mutate(f)}
              />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function FixCard({ f, notes, busy, onStage, onNote, onDone, onReopen }: {
  f: Fix; notes: LogRow[]; busy: boolean;
  onStage: (s: string) => void; onNote: (t: string) => void; onDone: (t: string) => void; onReopen: () => void;
}) {
  const [text, setText] = useState("");
  const isDone = f.status === "resolved";
  const tools = [f.lovable_prompt && "Lovable", f.cursor_prompt && "Cursor", f.claude_prompt && "Claude"].filter(Boolean).join(" · ");

  return (
    <Card className={cn("p-5", isDone && "opacity-80")}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 font-medium">
            {isDone && <CheckCircle2 className="h-4 w-4 text-status-pass" />}
            <span className={cn(isDone && "line-through text-muted-foreground")}>{f.checklist_items?.title ?? "Finding"}</span>
            <Badge variant="outline" className="capitalize">{f.checklist_items?.severity ?? "—"}</Badge>
          </div>
          <div className="mt-1 text-xs text-muted-foreground">{f.audits?.title} · Fix for {tools}</div>
        </div>
        <Link to="/audits/$id" params={{ id: f.audit_id }} className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
          Open audit <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {isDone ? (
        <div className="mt-4 flex items-center justify-between gap-3 text-sm">
          <span className="text-muted-foreground">
            Done {f.resolved_at ? formatDistanceToNow(new Date(f.resolved_at), { addSuffix: true }) : ""}
          </span>
          <Button size="sm" variant="ghost" disabled={busy} onClick={onReopen}>Reopen</Button>
        </div>
      ) : (
        <div className="mt-4 space-y-3">
          <Select value={f.remediation_status ?? "open"} onValueChange={onStage}>
            <SelectTrigger className="w-64"><SelectValue /></SelectTrigger>
            <SelectContent>
              {STAGES.map((s) => <SelectItem key={s.v} value={s.v}>{s.label}</SelectItem>)}
            </SelectContent>
          </Select>
          <Textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="What did you do? e.g. Pasted the prompt into Lovable, waiting to publish" rows={2} />
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" disabled={busy || !text.trim()} onClick={() => { onNote(text.trim()); setText(""); }}>
              Log progress
            </Button>
            <Button size="sm" disabled={busy} onClick={() => { onDone(text.trim()); setText(""); }}>
              <CheckCircle2 className="mr-1 h-4 w-4" /> Mark as done
            </Button>
          </div>
        </div>
      )}

      {notes.length > 0 && (
        <ul className="mt-4 space-y-2 border-t pt-3">
          {notes.map((n, i) => (
            <li key={i} className="text-sm">
              <span className="text-xs text-muted-foreground">{formatDistanceToNow(new Date(n.created_at), { addSuffix: true })} — </span>
              {n.evidence_text}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
