import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Sparkles, Copy, Check, ExternalLink, Loader2, Wand2 } from "lucide-react";
import { toast } from "sonner";
import { generateLovablePrompt } from "@/lib/lovable-prompt.functions";

export function LovablePromptButton({
  auditId,
  checklistItemId,
  cachedPrompt,
  onCached,
}: {
  auditId: string;
  checklistItemId: string;
  cachedPrompt: string | null;
  onCached: (prompt: string) => void;
}) {
  const gen = useServerFn(generateLovablePrompt);
  const [open, setOpen] = useState(false);
  const [prompt, setPrompt] = useState<string | null>(cachedPrompt);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const openAndLoad = async () => {
    setOpen(true);
    setCopied(false);
    if (prompt) return;
    setLoading(true);
    try {
      const res = await gen({ data: { auditId, checklistItemId } });
      if (!res.ok) { toast.error(res.error); setOpen(false); return; }
      setPrompt(res.prompt);
      onCached(res.prompt);
    } catch (e: any) {
      toast.error(e?.message ?? "Could not generate prompt");
      setOpen(false);
    } finally {
      setLoading(false);
    }
  };

  const copy = async () => {
    if (!prompt) return;
    try {
      await navigator.clipboard.writeText(prompt);
      setCopied(true);
      toast.success("Prompt copied");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Could not copy to clipboard");
    }
  };

  return (
    <>
      <div className="mt-3 flex flex-col items-start">
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={openAndLoad}
          className="border-purple-500/40 text-purple-600 hover:bg-purple-500/5 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300"
        >
          <Wand2 className="h-3.5 w-3.5 mr-1.5" /> Generate Lovable Prompt
        </Button>
        <span className="mt-1 text-[10px] uppercase tracking-wide text-muted-foreground flex items-center gap-1">
          <Sparkles className="h-2.5 w-2.5" /> AI Generated
        </span>
      </div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Wand2 className="h-4 w-4 text-purple-500" /> Lovable remediation prompt
            </DialogTitle>
            <DialogDescription>
              Paste this directly into Lovable to fix the vulnerability.
            </DialogDescription>
          </DialogHeader>

          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground py-8 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" /> Generating prompt…
            </div>
          ) : prompt ? (
            <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed bg-muted/60 rounded-md p-3 max-h-[50vh] overflow-auto border border-border">
{prompt}
            </pre>
          ) : null}

          <p className="text-[10px] uppercase tracking-wide text-muted-foreground flex items-center gap-1">
            <Sparkles className="h-2.5 w-2.5" /> AI Generated
          </p>

          <DialogFooter className="gap-2 sm:gap-2">
            <Button type="button" variant="outline" onClick={copy} disabled={!prompt}>
              {copied ? <Check className="h-4 w-4 mr-1.5" /> : <Copy className="h-4 w-4 mr-1.5" />}
              {copied ? "Copied" : "Copy prompt"}
            </Button>
            <Button
              type="button"
              asChild
              className="bg-purple-600 hover:bg-purple-700 text-white"
              disabled={!prompt}
            >
              <a href="https://lovable.dev" target="_blank" rel="noreferrer">
                <ExternalLink className="h-4 w-4 mr-1.5" /> Open Lovable
              </a>
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
