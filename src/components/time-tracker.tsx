// Time on this audit: a start/stop timer in the header, and a dialog with
// totals, entries, manual add, CSV export, and sessions suggested from my own
// activity in the audit trail that no entry covers yet.
import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { format } from "date-fns";
import { Link } from "@tanstack/react-router";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Clock, Download, Play, Plus, Square, Trash2, Sparkles } from "lucide-react";
import { toast } from "sonner";
import {
  CATEGORY_LABEL,
  billableHours,
  entryMinutes,
  formatDuration,
  sessionsFromActivity,
  timeCsv,
  totals,
  uncoveredSessions,
  type TimeCategory,
  type TimeEntry,
} from "@/lib/time-tracking";

const db = supabase as any;
const COLS = "id, audit_id, category, started_at, ended_at, note, source";
const DAY = 24 * 60 * 60_000;
const CATS = Object.keys(CATEGORY_LABEL) as TimeCategory[];

function useNow(ms = 30_000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(iv);
  }, [ms]);
  return now;
}

function CategorySelect({ value, onChange, className }: { value: TimeCategory; onChange: (c: TimeCategory) => void; className?: string }) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as TimeCategory)}>
      <SelectTrigger className={className ?? "h-8 w-[150px] text-xs"}><SelectValue /></SelectTrigger>
      <SelectContent>
        {CATS.map((c) => <SelectItem key={c} value={c}>{CATEGORY_LABEL[c]}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

export function TimeTracker({ auditId, auditTitle }: { auditId: string; auditTitle: string }) {
  const qc = useQueryClient();
  const [category, setCategory] = useState<TimeCategory>("testing");
  const [busy, setBusy] = useState(false);

  const runningQ = useQuery({
    queryKey: ["time-running"],
    queryFn: async (): Promise<TimeEntry | null> => {
      const { data, error } = await db.from("audit_time_entries").select(COLS).is("ended_at", null).maybeSingle();
      if (error) throw new Error(error.message);
      return data ?? null;
    },
  });
  const running = () => runningQ.data ?? null;
  const now = useNow(runningQ.data ? 15_000 : 60_000);

  const entries = useQuery({
    queryKey: ["time-entries", auditId],
    queryFn: async (): Promise<TimeEntry[]> => {
      const { data, error } = await db.from("audit_time_entries").select(COLS).eq("audit_id", auditId).order("started_at", { ascending: false }).limit(500);
      if (error) throw new Error(error.message);
      return data ?? [];
    },
  });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["time-running"] });
    qc.invalidateQueries({ queryKey: ["time-entries"] });
  };

  const stop = async (e: TimeEntry) => {
    const started = Date.parse(e.started_at);
    const end = Math.min(Date.now(), started + DAY);
    if (end <= started) {
      await db.from("audit_time_entries").delete().eq("id", e.id);
      return;
    }
    const { error } = await db.from("audit_time_entries").update({ ended_at: new Date(end).toISOString() }).eq("id", e.id);
    if (error) throw new Error(error.message);
    if (end < Date.now()) toast.warning("That timer ran over 24 hours, so it was capped at 24h. Adjust it in the Time dialog.");
  };

  const start = async () => {
    setBusy(true);
    try {
      const r = running();
      if (r) await stop(r);
      const { error } = await db.from("audit_time_entries").insert({ audit_id: auditId, category, source: "timer" });
      if (error) throw new Error(error.message);
      if (r && r.audit_id !== auditId) toast.success("Stopped the timer on the other audit and started one here.");
    } catch (e: any) {
      toast.error(e?.message ?? "Couldn't start the timer");
    } finally {
      setBusy(false);
      refresh();
    }
  };

  const stopHere = async () => {
    const r = running();
    if (!r) return;
    setBusy(true);
    try {
      await stop(r);
    } catch (e: any) {
      toast.error(e?.message ?? "Couldn't stop the timer");
    } finally {
      setBusy(false);
      refresh();
    }
  };

  const r = running();
  const here = r?.audit_id === auditId;
  const total = totals(entries.data ?? [], now).total;

  return (
    <div className="inline-flex items-center gap-1">
      {here ? (
        <Button variant="outline" onClick={stopHere} disabled={busy} title="Stop the timer">
          <Square className="h-3.5 w-3.5 mr-1 fill-current text-status-fail" />
          <span className="tabular-nums">{formatDuration(entryMinutes(r!, now))}</span>
        </Button>
      ) : (
        <Button variant="outline" onClick={start} disabled={busy} title={r ? "A timer is running on another audit; this stops it and starts one here" : "Start a timer on this audit"}>
          <Play className="h-3.5 w-3.5 mr-1" /> {r ? "Switch timer here" : "Start timer"}
        </Button>
      )}
      <TimeDialog
        auditId={auditId}
        auditTitle={auditTitle}
        entries={entries.data ?? []}
        now={now}
        total={total}
        category={category}
        setCategory={setCategory}
        onChanged={refresh}
      />
    </div>
  );
}

function TimeDialog({
  auditId,
  auditTitle,
  entries,
  now,
  total,
  category,
  setCategory,
  onChanged,
}: {
  auditId: string;
  auditTitle: string;
  entries: TimeEntry[];
  now: number;
  total: number;
  category: TimeCategory;
  setCategory: (c: TimeCategory) => void;
  onChanged: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [mDate, setMDate] = useState(() => format(new Date(), "yyyy-MM-dd'T'HH:mm"));
  const [mMinutes, setMMinutes] = useState("30");
  const [mCat, setMCat] = useState<TimeCategory>("testing");
  const [mNote, setMNote] = useState("");
  const [sugCat, setSugCat] = useState<TimeCategory>("testing");

  const activity = useQuery({
    queryKey: ["time-activity", auditId],
    enabled: open,
    queryFn: async (): Promise<string[]> => {
      const { data: u } = await supabase.auth.getUser();
      if (!u.user) return [];
      const since = new Date(Date.now() - 60 * DAY).toISOString();
      const { data, error } = await db
        .from("audit_events")
        .select("occurred_at")
        .eq("audit_id", auditId)
        .eq("actor", u.user.id)
        .gte("occurred_at", since)
        .order("occurred_at", { ascending: true })
        .limit(5000);
      if (error) throw new Error(error.message);
      return (data ?? []).map((d: any) => d.occurred_at as string);
    },
  });

  const t = useMemo(() => totals(entries, now), [entries, now]);
  const suggestions = useMemo(
    () => uncoveredSessions(sessionsFromActivity(activity.data ?? []), entries, now).reverse().slice(0, 10),
    [activity.data, entries, now],
  );

  const insert = async (row: Record<string, unknown>) => {
    const { error } = await db.from("audit_time_entries").insert({ audit_id: auditId, ...row });
    if (error) toast.error(error.message);
    onChanged();
  };

  const addManual = async (e: React.FormEvent) => {
    e.preventDefault();
    const start = new Date(mDate);
    const mins = Math.round(Number(mMinutes));
    if (!Number.isFinite(start.getTime()) || !(mins > 0) || mins > 24 * 60) return toast.error("Enter a start time and 1–1440 minutes.");
    await insert({
      category: mCat,
      started_at: start.toISOString(),
      ended_at: new Date(start.getTime() + mins * 60_000).toISOString(),
      note: mNote.trim() || null,
      source: "manual",
    });
    setMNote("");
  };

  const remove = async (id: string) => {
    const { error } = await db.from("audit_time_entries").delete().eq("id", id);
    if (error) toast.error(error.message);
    onChanged();
  };

  const updateEntry = async (id: string, fields: Record<string, unknown>) => {
    const { error } = await db.from("audit_time_entries").update(fields).eq("id", id);
    if (error) toast.error(error.message);
    onChanged();
  };

  const exportCsv = () => {
    const blob = new Blob([timeCsv(entries, now, auditTitle)], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `time-${auditTitle.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "audit"}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" title="Time on this audit">
          <Clock className="h-4 w-4 mr-1" /> <span className="tabular-nums">{formatDuration(total)}</span>
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Clock className="h-4 w-4" /> Time on this audit</DialogTitle>
          <DialogDescription>Internal only; never in the client report.</DialogDescription>
        </DialogHeader>

        <div className="flex items-end justify-between flex-wrap gap-3">
          <div>
            <div className="text-2xl font-semibold tabular-nums">{formatDuration(t.total)}</div>
            <div className="text-xs text-muted-foreground">{billableHours(t.total).toFixed(1)} billable h (6-minute increments)</div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Timer category</span>
            <CategorySelect value={category} onChange={setCategory} />
            <Button variant="outline" size="sm" onClick={exportCsv} disabled={!entries.length}><Download className="h-4 w-4 mr-1" /> CSV</Button>
          </div>
        </div>
        {t.total > 0 && (
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            {CATS.filter((c) => t.byCategory[c]).map((c) => <span key={c}>{CATEGORY_LABEL[c]}: <span className="text-foreground tabular-nums">{formatDuration(t.byCategory[c]!)}</span></span>)}
          </div>
        )}

        {suggestions.length > 0 && (
          <div className="rounded-md border border-border/60 p-3 space-y-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="text-sm font-medium flex items-center gap-1.5"><Sparkles className="h-4 w-4" /> Untracked work, from your activity</div>
              <CategorySelect value={sugCat} onChange={setSugCat} />
            </div>
            <p className="text-xs text-muted-foreground">Times you were active on this audit (scans, findings, evidence) that no entry covers.</p>
            <ul className="space-y-1">
              {suggestions.map((s) => (
                <li key={s.start} className="flex items-center justify-between text-xs gap-2">
                  <span className="tabular-nums">{format(s.start, "EEE MMM d, HH:mm")}–{format(s.end, "HH:mm")} · {formatDuration((s.end - s.start) / 60_000)}</span>
                  <Button size="sm" variant="outline" className="h-7" onClick={() => insert({ category: sugCat, started_at: new Date(s.start).toISOString(), ended_at: new Date(s.end).toISOString(), source: "suggested" })}>
                    <Plus className="h-3.5 w-3.5 mr-1" /> Add
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        )}

        <form onSubmit={addManual} className="grid grid-cols-[1fr_80px_150px] gap-2 items-end">
          <div className="space-y-1"><Label className="text-xs">Started</Label><Input type="datetime-local" className="h-8 text-xs" value={mDate} onChange={(e) => setMDate(e.target.value)} /></div>
          <div className="space-y-1"><Label className="text-xs">Minutes</Label><Input type="number" min={1} max={1440} className="h-8 text-xs" value={mMinutes} onChange={(e) => setMMinutes(e.target.value)} /></div>
          <div className="space-y-1"><Label className="text-xs">Category</Label><CategorySelect value={mCat} onChange={setMCat} className="h-8 w-full text-xs" /></div>
          <Input className="h-8 text-xs col-span-2" placeholder="Note (optional)" maxLength={500} value={mNote} onChange={(e) => setMNote(e.target.value)} />
          <Button type="submit" size="sm" className="h-8"><Plus className="h-4 w-4 mr-1" /> Add entry</Button>
        </form>

        <ul className="divide-y divide-border/60 border-t border-border/60">
          {entries.map((e) => (
            <li key={e.id} className="py-2 flex items-center gap-2 text-xs">
              <span className="tabular-nums w-[150px] shrink-0">{format(new Date(e.started_at), "MMM d, HH:mm")}{e.ended_at ? `–${format(new Date(e.ended_at), "HH:mm")}` : " · running"}</span>
              <span className="tabular-nums w-[60px] shrink-0">{formatDuration(entryMinutes(e, now))}</span>
              <CategorySelect value={e.category} onChange={(c) => updateEntry(e.id, { category: c })} className="h-7 w-[140px] text-xs" />
              <Input
                className="h-7 text-xs flex-1 min-w-0"
                defaultValue={e.note ?? ""}
                placeholder={e.source === "suggested" ? "From activity" : e.source === "manual" ? "Manual entry" : "Note"}
                maxLength={500}
                onBlur={(ev) => { const v = ev.target.value.trim() || null; if (v !== (e.note ?? null)) updateEntry(e.id, { note: v }); }}
              />
              <Button size="icon" variant="ghost" className="h-7 w-7 shrink-0" aria-label="Delete entry" onClick={() => remove(e.id)}><Trash2 className="h-3.5 w-3.5" /></Button>
            </li>
          ))}
          {!entries.length && <li className="py-3 text-xs text-muted-foreground">No time recorded yet.</li>}
        </ul>
      </DialogContent>
    </Dialog>
  );
}

/** Header chip while a timer runs anywhere, so it isn't forgotten. */
export function RunningTimerChip() {
  const q = useQuery({
    queryKey: ["time-running", "shell"],
    queryFn: async () => {
      const { data } = await db.from("audit_time_entries").select("id, audit_id, started_at, ended_at, audit:audits(title)").is("ended_at", null).maybeSingle();
      return (data ?? null) as (Pick<TimeEntry, "id" | "audit_id" | "started_at" | "ended_at"> & { audit: { title: string } | null }) | null;
    },
    refetchInterval: 120_000,
  });
  const now = useNow(30_000);
  if (!q.data) return null;
  return (
    <Link
      to="/audits/$id"
      params={{ id: q.data.audit_id }}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs bg-white/10 text-white hover:bg-white/15 max-w-[220px]"
      title="Timer running"
    >
      <span className="h-2 w-2 rounded-full bg-red-400 animate-pulse shrink-0" />
      <span className="tabular-nums shrink-0">{formatDuration(entryMinutes(q.data, now))}</span>
      <span className="truncate text-white/80">{q.data.audit?.title ?? "Audit"}</span>
    </Link>
  );
}
