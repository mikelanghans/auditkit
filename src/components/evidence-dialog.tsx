// Evidence for one checklist item: what the scanners captured, plus anything
// captured by hand (notes, pasted requests, screenshots, HAR files). Phase 2a.
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { format } from "date-fns";
import { FileText, Image as ImageIcon, Loader2, Paperclip, Plus, ShieldCheck, Upload } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { evidenceText, redactHar, sha256Hex, type EvidenceKind } from "@/lib/evidence";

type Row = {
  id: string;
  kind: EvidenceKind;
  title: string;
  content_text: string | null;
  storage_path: string | null;
  mime_type: string | null;
  size_bytes: number;
  sha256: string;
  source: "scanner" | "manual";
  captured_at: string;
  run_id: string | null;
  purged_at?: string | null;
};

const COLS = "id, kind, title, content_text, storage_path, mime_type, size_bytes, sha256, source, captured_at, run_id, purged_at";
const MAX_FILE_BYTES = 25 * 1024 * 1024;

export function useItemEvidence(auditId: string, checklistItemId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["evidence", auditId, checklistItemId],
    enabled,
    queryFn: async (): Promise<Row[]> => {
      // Scanner evidence: from this item's most recent scan results.
      const { data: results, error: rErr } = await supabase
        .from("scan_results")
        .select("evidence_ids, created_at")
        .eq("audit_id", auditId)
        .eq("checklist_item_id", checklistItemId)
        .order("created_at", { ascending: false })
        .limit(5);
      if (rErr) throw new Error(rErr.message);
      const ids = [...new Set((results ?? []).flatMap((r: any) => (r.evidence_ids ?? []) as string[]))];
      const [scanned, manual] = await Promise.all([
        ids.length ? supabase.from("evidence").select(COLS).in("id", ids) : Promise.resolve({ data: [], error: null }),
        supabase.from("evidence").select(COLS).eq("audit_id", auditId).eq("checklist_item_id", checklistItemId),
      ]);
      if (scanned.error) throw new Error(scanned.error.message);
      if (manual.error) throw new Error(manual.error.message);
      return ([...(manual.data ?? []), ...(scanned.data ?? [])] as Row[]).sort((a, b) =>
        b.captured_at.localeCompare(a.captured_at),
      );
    },
  });
}

function safeName(name: string) {
  return name.replace(/[^A-Za-z0-9._-]+/g, "_").slice(-80) || "file";
}

export function EvidenceButton({ auditId, checklistItemId, itemTitle }: { auditId: string; checklistItemId: string; itemTitle: string }) {
  const [open, setOpen] = useState(false);
  const qc = useQueryClient();
  const ev = useItemEvidence(auditId, checklistItemId, open);
  const [title, setTitle] = useState("");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [saving, setSaving] = useState(false);

  const reset = () => { setTitle(""); setText(""); setFile(null); };

  const save = async () => {
    if (!text.trim() && !file) return toast.error("Paste something or choose a file.");
    setSaving(true);
    try {
      const { data: userData } = await supabase.auth.getUser();
      if (!userData.user) throw new Error("Not signed in.");
      if (file) {
        if (file.size > MAX_FILE_BYTES) throw new Error("Files are limited to 25 MB.");
        const isHar = /\.har$/i.test(file.name);
        let body: Blob = file;
        let mime = file.type || "application/octet-stream";
        if (isHar) {
          body = new Blob([redactHar(await file.text())], { type: "application/json" });
          mime = "application/json";
        }
        const bytes = new Uint8Array(await body.arrayBuffer());
        const sha = await sha256Hex(bytes);
        const path = `${auditId}/${crypto.randomUUID()}-${safeName(file.name)}`;
        const up = await supabase.storage.from("evidence").upload(path, body, { contentType: mime, upsert: false });
        if (up.error) throw new Error(up.error.message);
        const kind: EvidenceKind = isHar ? "har" : mime.startsWith("image/") ? "screenshot" : "file";
        const { error } = await supabase.from("evidence").insert({
          audit_id: auditId,
          checklist_item_id: checklistItemId,
          kind,
          title: (title.trim() || file.name).slice(0, 300),
          content_text: text.trim() ? evidenceText(text) : null,
          storage_path: path,
          mime_type: mime,
          size_bytes: bytes.length,
          sha256: sha,
          source: "manual",
        });
        if (error) throw new Error(error.message);
      } else {
        const stored = evidenceText(text);
        const looksHttp = /^(curl\s|GET |POST |PUT |PATCH |DELETE |HTTP\/)/m.test(text.trim());
        const { error } = await supabase.from("evidence").insert({
          audit_id: auditId,
          checklist_item_id: checklistItemId,
          kind: looksHttp ? "http_exchange" : "note",
          title: (title.trim() || (looksHttp ? "Captured request" : "Note")).slice(0, 300),
          content_text: stored,
          mime_type: "text/plain",
          size_bytes: new TextEncoder().encode(stored).length,
          sha256: await sha256Hex(stored),
          source: "manual",
        });
        if (error) throw new Error(error.message);
      }
      toast.success("Evidence saved.");
      reset();
      qc.invalidateQueries({ queryKey: ["evidence", auditId, checklistItemId] });
    } catch (e: any) {
      toast.error(e?.message ?? "Couldn't save evidence.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!saving) { setOpen(o); if (!o) reset(); } }}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1 h-8">
          <Paperclip className="h-3.5 w-3.5" /> Evidence
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Paperclip className="h-4 w-4" /> Evidence</DialogTitle>
          <DialogDescription className="line-clamp-2">{itemTitle}</DialogDescription>
        </DialogHeader>

        <div className="max-h-[45vh] overflow-y-auto space-y-2">
          {ev.isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground py-4 justify-center"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
          ) : ev.error ? (
            <p className="text-sm text-destructive">{(ev.error as Error).message}</p>
          ) : !ev.data?.length ? (
            <p className="text-sm text-muted-foreground py-4 text-center">Nothing captured yet. Scans attach what they saw; add your own below.</p>
          ) : (
            ev.data.map((row) => <EvidenceItem key={row.id} row={row} />)
          )}
        </div>

        <div className="space-y-2 rounded-md border border-border/60 bg-muted/30 p-3">
          <div className="text-xs font-medium flex items-center gap-1"><Plus className="h-3.5 w-3.5" /> Add evidence</div>
          <Input className="h-8 text-xs" placeholder="Title (optional)" value={title} onChange={(e) => setTitle(e.target.value)} />
          <Textarea rows={4} className="text-xs font-mono" placeholder="Paste a note, a cURL command, a raw request/response…" value={text} onChange={(e) => setText(e.target.value)} />
          <div className="flex items-center gap-2">
            <label className="inline-flex items-center gap-1.5 text-xs cursor-pointer rounded-md border border-border px-2 py-1 hover:bg-muted">
              <Upload className="h-3.5 w-3.5" />
              {file ? <span className="truncate max-w-[220px]">{file.name}</span> : "Screenshot, HAR or file"}
              <input type="file" className="hidden" accept="image/*,.har,.pdf,.txt,.json,.log" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
            <span className="text-[11px] text-muted-foreground flex-1">Secrets are redacted before saving. HAR files lose cookies and auth headers.</span>
            <Button size="sm" onClick={save} disabled={saving}>
              {saving && <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />} Save
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function EvidenceItem({ row }: { row: Row }) {
  const [url, setUrl] = useState<string | null>(null);
  const open = async () => {
    if (!row.storage_path) return;
    const { data, error } = await supabase.storage.from("evidence").createSignedUrl(row.storage_path, 300);
    if (error || !data) return toast.error(error?.message ?? "Couldn't open the file.");
    setUrl(data.signedUrl);
    window.open(data.signedUrl, "_blank", "noopener,noreferrer");
  };
  const isImage = row.mime_type?.startsWith("image/");
  return (
    <details className="rounded-md border border-border/60 px-3 py-2">
      <summary className="flex items-center gap-2 cursor-pointer list-none text-sm">
        {isImage ? <ImageIcon className="h-3.5 w-3.5 text-muted-foreground" /> : <FileText className="h-3.5 w-3.5 text-muted-foreground" />}
        <span className="truncate flex-1">{row.title}</span>
        <Badge variant="outline" className="text-[10px]">{row.kind.replace("_", " ")}</Badge>
        <Badge variant="secondary" className="text-[10px]">{row.source}</Badge>
        <span className="text-[11px] text-muted-foreground whitespace-nowrap">{format(new Date(row.captured_at), "MMM d, HH:mm")}</span>
      </summary>
      <div className="mt-2 space-y-2">
        {row.content_text && (
          <pre className="max-h-72 overflow-auto rounded bg-muted/50 p-2 text-[11px] font-mono whitespace-pre-wrap">{row.content_text}</pre>
        )}
        {row.purged_at && (
          <p className="text-xs text-muted-foreground">Purged {format(new Date(row.purged_at), "PP")} under the audit's retention date. The hash below is what was captured.</p>
        )}
        {row.storage_path && !row.purged_at && (
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={open}>Open file</Button>
            {isImage && url && <img src={url} alt={row.title} className="max-h-40 rounded border" />}
          </div>
        )}
        <div className="flex items-center gap-1 text-[10px] text-muted-foreground font-mono break-all">
          <ShieldCheck className="h-3 w-3 shrink-0" /> sha256 {row.sha256} · {row.size_bytes.toLocaleString()} bytes
        </div>
      </div>
    </details>
  );
}
