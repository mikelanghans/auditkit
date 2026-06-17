import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Bot, ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { runAIScan, type AIPayloadResult } from "@/lib/ai-scan.functions";
import { cn } from "@/lib/utils";

export function AIScanDialog({
  auditId,
  onDone,
  onResult,
}: {
  auditId: string;
  onDone: () => void;
  onResult: (s: { passes: number; fails: number; endpoint: string; critical: number; high: number; medium: number; at: string }) => void;
}) {
  const scan = useServerFn(runAIScan);
  const [open, setOpen] = useState(false);
  const [endpointUrl, setEndpointUrl] = useState("");
  const [promptField, setPromptField] = useState("prompt");
  const [authToken, setAuthToken] = useState("");
  const [pending, setPending] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<AIPayloadResult[] | null>(null);
  const [endpointLabel, setEndpointLabel] = useState("");

  useEffect(() => {
    if (!pending) { setProgress(0); return; }
    setProgress(6);
    const iv = setInterval(() => {
      setProgress((p) => (p < 90 ? p + Math.max(0.5, (90 - p) * 0.04) : p));
    }, 250);
    return () => clearInterval(iv);
  }, [pending]);

  const reset = () => {
    setEndpointUrl("");
    setPromptField("prompt");
    setAuthToken("");
    setResults(null);
    setEndpointLabel("");
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!endpointUrl.trim()) {
      toast.error("Endpoint URL is required.");
      return;
    }
    setPending(true);
    setResults(null);
    const tid = toast.loading("Probing AI endpoint…");
    try {
      const res = await scan({
        data: {
          auditId,
          endpointUrl: endpointUrl.trim(),
          promptField: promptField.trim() || "prompt",
          authToken: authToken.trim() || null,
        },
      });
      setProgress(100);
      if (!res.ok) {
        toast.error(res.error, { id: tid });
        return;
      }
      const { counts } = res;
      const headline = counts.critical > 0
        ? `${counts.critical} CRITICAL injection${counts.critical === 1 ? "" : "s"} succeeded`
        : counts.high > 0
          ? `${counts.high} high-severity finding${counts.high === 1 ? "" : "s"}`
          : `${counts.passes} pass, ${counts.fails} fail`;
      toast.success(`AI scan complete — ${headline}`, { id: tid, description: res.endpoint });
      setResults(res.results);
      setEndpointLabel(res.endpoint);
      onResult({
        passes: counts.passes,
        fails: counts.fails,
        endpoint: res.endpoint,
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        at: new Date().toISOString(),
      });
      onDone();
    } catch (err: any) {
      toast.error(err?.message ?? "AI scan failed", { id: tid });
    } finally {
      setTimeout(() => setPending(false), 400);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!pending) { if (!o) reset(); setOpen(o); } }}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Bot className="h-4 w-4 mr-1" /> Scan AI Endpoints
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Bot className="h-4 w-4" /> Scan AI endpoint for prompt injection
            </DialogTitle>
            <DialogDescription>
              Sends 6 prompt-injection probes (instruction extraction, override, mode switch, context overflow) and
              classifies each response for prompt leakage and architecture disclosure.
            </DialogDescription>
          </DialogHeader>

          <div className="rounded-md border border-status-na/50 bg-status-na/5 p-3 text-xs">
            <div className="flex items-center gap-1.5 font-semibold text-foreground/90">
              <AlertTriangle className="h-3.5 w-3.5 text-status-na" /> Authorized testing only
            </div>
            <p className="text-foreground/80 mt-1">
              Only run this against endpoints you have explicit permission to test. Probing third-party AI APIs without
              authorization may violate their terms of service or applicable law.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="ai-url">AI Endpoint URL</Label>
            <Input
              id="ai-url"
              placeholder="https://app.example.com/api/generate"
              value={endpointUrl}
              onChange={(e) => setEndpointUrl(e.target.value)}
              disabled={pending}
              autoFocus
              autoComplete="off"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="ai-field">Prompt field name</Label>
            <Input
              id="ai-field"
              placeholder="prompt"
              value={promptField}
              onChange={(e) => setPromptField(e.target.value)}
              disabled={pending}
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              The JSON body field that carries the user prompt. Request will be <code>{`{"${promptField || "prompt"}": "…"}`}</code>.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="ai-auth">Auth token <span className="text-muted-foreground font-normal">(optional)</span></Label>
            <Input
              id="ai-auth"
              type="password"
              placeholder="Bearer eyJ… or sk-…"
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              disabled={pending}
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">Sent as the Authorization header. "Bearer " prefix added automatically.</p>
          </div>

          {pending && <Progress value={progress} />}

          {results && (
            <div className="space-y-2 pt-2 border-t">
              <div className="text-sm font-medium flex items-center gap-2">
                Results <span className="text-xs text-muted-foreground font-normal truncate">{endpointLabel}</span>
              </div>
              {results.map((r, i) => (
                <ResultRow key={i} r={r} />
              ))}
            </div>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => { reset(); setOpen(false); }} disabled={pending}>
              Close
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? (<><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Probing…</>) : results ? "Re-run scan" : "Run scan"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ResultRow({ r }: { r: AIPayloadResult }) {
  const [open, setOpen] = useState(r.verdict === "critical" || r.verdict === "high");
  const tone =
    r.verdict === "critical" || r.verdict === "high" || r.verdict === "error" ? "fail" :
    r.verdict === "medium" ? "na" : "pass";
  const toneClass = {
    fail: "border-l-status-fail bg-status-fail/[0.04]",
    na: "border-l-status-na bg-status-na/[0.04]",
    pass: "border-l-status-pass bg-status-pass/[0.04]",
  }[tone];
  const badgeVariant = r.verdict === "critical" ? "destructive" : r.verdict === "high" ? "destructive" : r.verdict === "medium" ? "secondary" : r.verdict === "error" ? "outline" : "secondary";

  return (
    <div className={cn("rounded-md border border-l-4 p-2.5 text-xs", toneClass)}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-center gap-2">
        {open ? <ChevronDown className="h-3.5 w-3.5 shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" />}
        <span className="font-medium">{r.label}</span>
        <Badge variant={badgeVariant as any} className="uppercase text-[10px]">{r.verdict}</Badge>
        <span className="text-muted-foreground ml-auto">HTTP {r.httpStatus || "—"} · {r.durationMs}ms</span>
      </button>
      {open && (
        <div className="mt-2 space-y-2 pl-5">
          <div>
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Payload</div>
            <pre className="mt-0.5 whitespace-pre-wrap break-words font-mono text-[11px] bg-muted/60 rounded p-2 max-h-24 overflow-auto">
{r.payload.length > 400 ? r.payload.slice(0, 400) + `…[+${r.payload.length - 400} chars]` : r.payload}
            </pre>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Extracted response</div>
            <pre className="mt-0.5 whitespace-pre-wrap break-words font-mono text-[11px] bg-muted/60 rounded p-2 max-h-48 overflow-auto">
{r.extractedText || "(empty)"}
            </pre>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Verdict reasoning</div>
            <ul className="mt-0.5 list-disc list-inside text-foreground/80">
              {r.reasons.map((reason, i) => <li key={i} className="whitespace-pre-wrap">{reason}</li>)}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
