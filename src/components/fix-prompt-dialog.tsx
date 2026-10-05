import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Sparkles, Copy, Check, CheckCircle2, ExternalLink, Loader2, Wand2 } from "lucide-react";
import { toast } from "sonner";
import { generateFixPrompt, type FixTarget } from "@/lib/fix-prompt.functions";

type CachedPrompts = {
  lovable: string | null;
  cursor: string | null;
  claude: string | null;
};

const EMPTY_CACHE: CachedPrompts = { lovable: null, cursor: null, claude: null };

const TARGETS: { id: FixTarget; label: string; openUrl?: string; openLabel?: string }[] = [
  { id: "lovable", label: "Lovable", openUrl: "https://lovable.dev", openLabel: "Open Lovable" },
  { id: "cursor", label: "Cursor", openUrl: "https://cursor.com", openLabel: "Open Cursor" },
  { id: "claude", label: "Claude Code", openUrl: "https://claude.com/product/claude-code", openLabel: "Open Claude Code" },
];

type AdhocContext = {
  notes?: string;
};

export function FixPromptButton({
  auditId,
  checklistItemId,
  cached,
  onCached,
  adhoc,
  buttonLabel,
  buttonClassName,
}: {
  auditId?: string;
  checklistItemId?: string;
  cached?: CachedPrompts;
  onCached?: (target: FixTarget, prompt: string) => void;
  adhoc?: AdhocContext;
  buttonLabel?: string;
  buttonClassName?: string;
}) {
  const gen = useServerFn(generateFixPrompt);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState<FixTarget>("lovable");
  const [prompts, setPrompts] = useState<CachedPrompts>(cached ?? EMPTY_CACHE);
  const [loading, setLoading] = useState<FixTarget | null>(null);
  const [copied, setCopied] = useState<FixTarget | null>(null);

  useEffect(() => {
    if (cached) setPrompts(cached);
  }, [cached]);

  const generatedTargets = TARGETS.filter((target) => Boolean(prompts[target.id]));
  const hasGeneratedPrompt = generatedTargets.length > 0;

  const loadIfNeeded = async (target: FixTarget) => {
    if (prompts[target]) return;
    setLoading(target);
    try {
      const payload = adhoc
        ? { auditId, checklistItemId, target, adhoc }
        : { auditId, checklistItemId, target };
      const res = await gen({ data: payload as any });
      if (!res.ok) { toast.error(res.error); return; }
      setPrompts((p) => ({ ...p, [target]: res.prompt }));
      onCached?.(target, res.prompt);
    } catch (e: any) {
      toast.error(e?.message ?? "Could not generate prompt");
    } finally {
      setLoading(null);
    }
  };

  const openDialog = () => {
    setOpen(true);
    setCopied(null);
  };


  const switchTab = (val: string) => {
    const t = val as FixTarget;
    setActive(t);
    setCopied(null);
  };

  const copy = async (target: FixTarget) => {
    const text = prompts[target];
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(target);
      toast.success("Prompt copied");
      setTimeout(() => setCopied(null), 2000);
    } catch {
      toast.error("Could not copy to clipboard");
    }
  };

  const meta = TARGETS.find((t) => t.id === active) ?? TARGETS[0];

  return (
    <>
      <div className="mt-3 flex flex-col items-start">
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={openDialog}
          className={buttonClassName ?? (hasGeneratedPrompt
            ? "border-status-pass/50 bg-status-pass/10 text-status-pass hover:bg-status-pass/15 hover:text-status-pass"
            : "border-purple-500/40 text-purple-600 hover:bg-purple-500/5 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300")}
        >
          {hasGeneratedPrompt
            ? <CheckCircle2 className="h-3.5 w-3.5 mr-1.5" />
            : <Wand2 className="h-3.5 w-3.5 mr-1.5" />}
          {buttonLabel ?? (hasGeneratedPrompt ? "Fix Generated" : "Generate Fix")}
        </Button>
        <span className="mt-1 text-[10px] uppercase tracking-wide text-muted-foreground flex items-center gap-1">
          {hasGeneratedPrompt ? (
            <><CheckCircle2 className="h-2.5 w-2.5 text-status-pass" /> Ready for {generatedTargets.map((target) => target.label).join(" · ")}</>
          ) : (
            <><Sparkles className="h-2.5 w-2.5" /> AI assisted · Lovable · Cursor · Claude</>
          )}
        </span>
      </div>


      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Wand2 className="h-4 w-4 text-purple-500" /> Remediation prompt
            </DialogTitle>
            <DialogDescription>
              AI-written starting point, not a guaranteed fix. Check what the tool changed, publish, then re-scan: only a passing re-scan closes it.
            </DialogDescription>
          </DialogHeader>

          <Tabs value={active} onValueChange={switchTab}>
            <TabsList className="grid grid-cols-3 w-full">
              {TARGETS.map((t) => (
                <TabsTrigger key={t.id} value={t.id}>{t.label}</TabsTrigger>
              ))}
            </TabsList>
            {TARGETS.map((t) => (
              <TabsContent key={t.id} value={t.id} className="mt-3">
                {loading === t.id ? (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground py-10 justify-center">
                    <Loader2 className="h-4 w-4 animate-spin" /> Generating {t.label} prompt…
                  </div>
                ) : prompts[t.id] ? (
                  <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed bg-muted/60 rounded-md p-3 max-h-[50vh] overflow-auto border border-border">
{prompts[t.id]}
                  </pre>
                ) : (
                  <div className="flex flex-col items-center gap-2 text-sm text-muted-foreground py-10">
                    <span>No prompt yet for {t.label}.</span>
                    <Button type="button" size="sm" variant="outline" onClick={() => loadIfNeeded(t.id)}>
                      <Wand2 className="h-3.5 w-3.5 mr-1.5" /> Generate {t.label} prompt
                    </Button>
                  </div>
                )}
              </TabsContent>
            ))}
          </Tabs>

          <p className="text-[10px] uppercase tracking-wide text-muted-foreground flex items-center gap-1">
            <Sparkles className="h-2.5 w-2.5" /> AI Generated
          </p>

          <DialogFooter className="gap-2 sm:gap-2">
            <Button type="button" variant="outline" onClick={() => copy(active)} disabled={!prompts[active]}>
              {copied === active ? <Check className="h-4 w-4 mr-1.5" /> : <Copy className="h-4 w-4 mr-1.5" />}
              {copied === active ? "Copied" : "Copy prompt"}
            </Button>
            {meta.openUrl && (
              <Button
                type="button"
                asChild
                className="bg-purple-600 hover:bg-purple-700 text-white"
                disabled={!prompts[active]}
              >
                <a href={meta.openUrl} target="_blank" rel="noreferrer">
                  <ExternalLink className="h-4 w-4 mr-1.5" /> {meta.openLabel ?? `Open ${meta.label}`}
                </a>
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
