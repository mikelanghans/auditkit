// Capture inbox (build plan 2e): grab evidence while testing by hand without
// stopping to pick a finding, then attach each item to a checklist item later.
import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Inbox, Loader2, Upload } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EvidenceItem, saveManualEvidence, type EvidenceRowView } from "@/components/evidence-dialog";

const COLS = "id, kind, title, content_text, storage_path, mime_type, size_bytes, sha256, source, captured_at, run_id, purged_at";

export function CaptureInbox({ auditId, items }: { auditId: string; items: { id: string; title: string; category: string }[] }) {
  const qc = useQueryClient();
  const inbox = useQuery({
    queryKey: ["evidence-inbox", auditId],
    queryFn: async (): Promise<EvidenceRowView[]> => {
      const { data, error } = await supabase
        .from("evidence")
        .select(COLS)
        .eq("audit_id", auditId)
        .eq("source", "manual")
        .is("checklist_item_id", null)
        .order("captured_at", { ascending: false });
      if (error) throw new Error(error.message);
      return (data ?? []) as EvidenceRowView[];
    },
  });
  const [title, setTitle] = useState("");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [saving, setSaving] = useState(false);
  const [targetFor, setTargetFor] = useState<Record<string, string>>({});
  const sorted = useMemo(() => [...items].sort((a, b) => a.category.localeCompare(b.category) || a.title.localeCompare(b.title)), [items]);

  const capture = async () => {
    if (!text.trim() && !file) return toast.error("Paste something or choose a file.");
    setSaving(true);
    try {
      await saveManualEvidence({ auditId, checklistItemId: null, title, text, file });
      setTitle(""); setText(""); setFile(null);
      toast.success("Captured to the inbox.");
      qc.invalidateQueries({ queryKey: ["evidence-inbox", auditId] });
    } catch (e: any) {
      toast.error(e?.message ?? "Couldn't save.");
    } finally {
      setSaving(false);
    }
  };

  const attach = async (evidenceId: string) => {
    const itemId = targetFor[evidenceId];
    if (!itemId) return toast.error("Pick the checklist item first.");
    const { error } = await supabase.from("evidence").update({ checklist_item_id: itemId }).eq("id", evidenceId);
    if (error) return toast.error(error.message);
    toast.success("Attached.");
    qc.invalidateQueries({ queryKey: ["evidence-inbox", auditId] });
    qc.invalidateQueries({ queryKey: ["evidence", auditId, itemId] });
  };

  const count = inbox.data?.length ?? 0;
  return (
    <Collapsible defaultOpen={false}>
      <Card className="overflow-hidden">
        <CollapsibleTrigger className="group flex w-full items-center gap-2 px-4 py-3 text-left hover:bg-muted/40 transition-colors">
          <Inbox className="h-4 w-4 text-primary shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold">Capture inbox</div>
            <div className="text-xs text-muted-foreground">Save notes, requests, screenshots or HAR files now; attach them to findings later</div>
          </div>
          {count > 0 && <Badge variant="secondary">{count} to triage</Badge>}
          <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform group-data-[state=closed]:-rotate-90" />
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="space-y-3 p-4 border-t border-border/60">
            <div className="space-y-2 rounded-md bg-muted/30 p-3">
              <Input className="h-8 text-xs" placeholder="Title (optional)" value={title} onChange={(e) => setTitle(e.target.value)} />
              <Textarea rows={3} className="text-xs font-mono" placeholder="Paste a note, a cURL command, a raw request/response…" value={text} onChange={(e) => setText(e.target.value)} />
              <div className="flex items-center gap-2">
                <label className="inline-flex items-center gap-1.5 text-xs cursor-pointer rounded-md border border-border px-2 py-1 hover:bg-muted">
                  <Upload className="h-3.5 w-3.5" />
                  {file ? <span className="truncate max-w-[220px]">{file.name}</span> : "Screenshot, HAR or file"}
                  <input type="file" className="hidden" accept="image/*,.har,.pdf,.txt,.json,.log" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
                </label>
                <span className="text-[11px] text-muted-foreground flex-1">Secrets are redacted before saving.</span>
                <Button size="sm" onClick={capture} disabled={saving}>{saving && <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />} Capture</Button>
              </div>
            </div>

            {inbox.isLoading ? (
              <div className="text-xs text-muted-foreground flex items-center gap-2"><Loader2 className="h-3 w-3 animate-spin" /> Loading…</div>
            ) : inbox.error ? (
              <p className="text-xs text-destructive">{(inbox.error as Error).message}</p>
            ) : count === 0 ? (
              <p className="text-xs text-muted-foreground">Nothing waiting to be triaged.</p>
            ) : (
              <ul className="space-y-2">
                {inbox.data!.map((row) => (
                  <li key={row.id} className="space-y-1.5">
                    <EvidenceItem row={row} />
                    <div className="flex items-center gap-2 pl-1">
                      <Select value={targetFor[row.id] ?? ""} onValueChange={(v) => setTargetFor({ ...targetFor, [row.id]: v })}>
                        <SelectTrigger className="h-8 text-xs flex-1"><SelectValue placeholder="Attach to checklist item…" /></SelectTrigger>
                        <SelectContent className="max-h-80">
                          {sorted.map((it) => (
                            <SelectItem key={it.id} value={it.id} className="text-xs">{it.category} · {it.title}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => attach(row.id)}>Attach</Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
