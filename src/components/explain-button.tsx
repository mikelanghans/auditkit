import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Sparkles, Loader2, Copy, Check } from "lucide-react";
import { toast } from "sonner";
import { explainFinding } from "@/lib/explain-finding.functions";

export function ExplainButton({
  auditId,
  checklistItemId,
  cached,
  onCached,
}: {
  auditId: string;
  checklistItemId: string;
  cached: string | null;
  onCached: (explanation: string) => void;
}) {
  const gen = useServerFn(explainFinding);
  const [open, setOpen] = useState(false);
  const [text, setText] = useState<string | null>(cached);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const load = async () => {
    setOpen(true);
    if (text) return;
    setLoading(true);
    try {
      const res = await gen({ data: { auditId, checklistItemId } });
      if (!res.ok) { toast.error(res.error); setOpen(false); return; }
      setText(res.explanation);
      onCached(res.explanation);
    } catch (e: any) {
      toast.error(e?.message ?? "Could not generate explanation");
      setOpen(false);
    } finally {
      setLoading(false);
    }
  };

  const copy = async () => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch { /* ignore */ }
  };

  const bullets = (text ?? "")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => l.replace(/^[-*•]\s*/, ""));

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          onClick={load}
          className="h-7 px-2 text-xs text-amber-600 hover:text-amber-700 hover:bg-amber-500/10 dark:text-amber-400 dark:hover:text-amber-300"
        >
          <Sparkles className="h-3 w-3 mr-1" /> Explain
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[360px] p-3">
        <div className="flex items-center justify-between mb-2">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground flex items-center gap-1">
            <Sparkles className="h-3 w-3 text-amber-500" /> AI Explanation
          </div>
          {text && (
            <Button type="button" size="sm" variant="ghost" className="h-6 px-1.5" onClick={copy}>
              {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
            </Button>
          )}
        </div>
        {loading ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground py-3 justify-center">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Asking Claude…
          </div>
        ) : bullets.length ? (
          <ul className="border-l-2 border-amber-500/40 pl-3 space-y-2 text-sm leading-snug">
            {bullets.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-muted-foreground">No explanation yet.</p>
        )}
      </PopoverContent>
    </Popover>
  );
}
