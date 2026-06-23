import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, ArrowLeft, Bot, ChevronDown, ChevronRight, GitBranch, Loader2, Plus, Sparkles, Wand2 } from "lucide-react";
import { toast } from "sonner";
import { runAIScan, type AIPayloadResult } from "@/lib/ai-scan.functions";
import { detectAIEndpoints, type DetectedEndpoint } from "@/lib/ai-endpoint-detect.functions";
import type { SavedRepo } from "@/components/repo-launcher";
import { supabase } from "@/integrations/supabase/client";
import { useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";

type Mode = "repo-pick" | "detecting" | "endpoint-pick" | "manual";

export type AIScanPreset = { url: string; promptField: string; source?: string };

export function AIScanDialog({
  auditId,
  appUrl,
  savedRepos,
  onDone,
  onResult,
  preset,
  onPresetConsumed,
}: {
  auditId: string;
  appUrl: string | null;
  savedRepos: SavedRepo[];
  onDone: () => void;
  onResult: (s: { passes: number; fails: number; endpoint: string; critical: number; high: number; medium: number; at: string }) => void;
  preset?: AIScanPreset | null;
  onPresetConsumed?: () => void;
}) {
  const scan = useServerFn(runAIScan);
  const detect = useServerFn(detectAIEndpoints);

  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<Mode>("manual");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [promptField, setPromptField] = useState("prompt");
  const [authToken, setAuthToken] = useState("");
  const [pending, setPending] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<AIPayloadResult[] | null>(null);
  const [endpointLabel, setEndpointLabel] = useState("");
  const [detected, setDetected] = useState<DetectedEndpoint[]>([]);
  const [detectMeta, setDetectMeta] = useState<{ repo: string; filesScanned: number; supabaseBaseDetected: boolean; appBaseDetected: boolean } | null>(null);

  const hasRepos = savedRepos.length > 0;
  const qc = useQueryClient();
  const [needTokenFor, setNeedTokenFor] = useState<SavedRepo | null>(null);
  const [pendingToken, setPendingToken] = useState("");
  const [savePendingToken, setSavePendingToken] = useState(true);

  // External preset (from “Test for Injection” buttons) — opens dialog prefilled in manual mode.
  useEffect(() => {
    if (!preset) return;
    setEndpointUrl(preset.url);
    setPromptField(preset.promptField || "prompt");
    setAuthToken("");
    setResults(null);
    setEndpointLabel(preset.source ?? "");
    setMode("manual");
    setOpen(true);
    onPresetConsumed?.();
  }, [preset, onPresetConsumed]);


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
    setDetected([]);
    setDetectMeta(null);
    setMode(hasRepos ? (savedRepos.length === 1 ? "detecting" : "repo-pick") : "manual");
  };

  const runDetect = async (repo: SavedRepo, overrideToken?: string) => {
    const token = overrideToken ?? repo.github_token;
    if (!token) {
      setNeedTokenFor(repo);
      setPendingToken("");
      setSavePendingToken(true);
      setMode("manual");
      return;
    }
    setDetecting(true);
    setMode("detecting");
    const tid = toast.loading(`Scanning ${repo.label} for AI endpoints…`);
    try {
      const res = await detect({ data: { repoUrl: repo.repo_url, token, appUrl } });
      if (!res.ok) {
        toast.error(res.error, { id: tid });
        setMode("manual");
        return;
      }
      setDetected(res.endpoints);
      setDetectMeta({ repo: res.repo, filesScanned: res.filesScanned, supabaseBaseDetected: res.supabaseBaseDetected, appBaseDetected: res.appBaseDetected });
      if (res.endpoints.length === 0) {
        toast.message("No AI endpoints detected — enter one manually.", { id: tid });
        setMode("manual");
      } else {
        toast.success(`Found ${res.endpoints.length} AI endpoint${res.endpoints.length === 1 ? "" : "s"} in ${res.repo}`, { id: tid });
        setMode("endpoint-pick");
      }
    } catch (e: any) {
      toast.error(e?.message ?? "Detection failed", { id: tid });
      setMode("manual");
    } finally {
      setDetecting(false);
    }
  };

  const openDialog = () => {
    reset();
    setOpen(true);
    if (savedRepos.length === 1) {
      void runDetect(savedRepos[0]);
    }
  };

  const pickDetected = (ep: DetectedEndpoint) => {
    setEndpointUrl(ep.url);
    setPromptField(ep.promptField);
    setMode("manual");
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
      if (!res.ok) { toast.error(res.error, { id: tid }); return; }
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
        passes: counts.passes, fails: counts.fails, endpoint: res.endpoint,
        critical: counts.critical, high: counts.high, medium: counts.medium,
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
    <Dialog open={open} onOpenChange={(o) => { if (!pending && !detecting) { if (!o) reset(); setOpen(o); } }}>
      <Button variant="outline" onClick={openDialog}>
        <Bot className="h-4 w-4 mr-1" /> Scan AI Endpoints
        {hasRepos && (
          <span className="ml-1.5 inline-flex items-center" title={`${savedRepos.length} repo${savedRepos.length === 1 ? "" : "s"} available for auto-detect`}>
            <Sparkles className="h-3 w-3 text-status-pass" />
          </span>
        )}
      </Button>

      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Bot className="h-4 w-4" /> Scan AI endpoint for prompt injection
          </DialogTitle>
          <DialogDescription>
            Sends 6 prompt-injection probes (instruction extraction, override, mode switch, context overflow) and classifies each response for prompt leakage and architecture disclosure.
          </DialogDescription>
        </DialogHeader>

        {needTokenFor && (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              const r = needTokenFor;
              const tok = pendingToken.trim();
              if (!tok) return;
              if (savePendingToken) {
                const { error } = await supabase.from("client_repos").update({ github_token: tok }).eq("id", r.id);
                if (error) toast.error(`Could not save token: ${error.message}`);
                else qc.invalidateQueries({ queryKey: ["client-repos"] });
              }
              setNeedTokenFor(null);
              setPendingToken("");
              await runDetect(r, tok);
            }}
            className="space-y-4"
          >
            <div>
              <div className="text-sm font-medium">{needTokenFor.label}</div>
              <div className="text-xs text-muted-foreground break-all">{needTokenFor.repo_url}</div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ai-pending-token">Personal access token</Label>
              <Input
                id="ai-pending-token"
                type="password"
                placeholder="ghp_… or github_pat_…"
                value={pendingToken}
                onChange={(e) => setPendingToken(e.target.value)}
                autoFocus
                autoComplete="off"
              />
              <p className="text-xs text-muted-foreground">Fine-grained PAT: <em>Contents: Read</em> + <em>Metadata: Read</em>.</p>
            </div>
            <label className="flex items-start gap-2 text-sm cursor-pointer select-none">
              <input
                type="checkbox"
                checked={savePendingToken}
                onChange={(e) => setSavePendingToken(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-border accent-navy"
              />
              <span>
                <span className="font-medium">Remember this token</span>
                <span className="block text-xs text-muted-foreground">Saves the PAT on this repo so future scans run with one click.</span>
              </span>
            </label>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => { setNeedTokenFor(null); setPendingToken(""); setMode(savedRepos.length >= 2 ? "repo-pick" : "manual"); }}>
                Cancel
              </Button>
              <Button type="submit" disabled={!pendingToken.trim()}>Detect endpoints</Button>
            </DialogFooter>
          </form>
        )}

        {!needTokenFor && mode === "repo-pick" && (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">Pick a repo to auto-detect AI endpoints:</p>
            <ul className="space-y-1.5">
              {savedRepos.map((r) => (
                <li key={r.id}>
                  <button
                    type="button"
                    disabled={detecting}
                    onClick={() => runDetect(r)}
                    className="w-full flex items-center justify-between gap-3 rounded-md border border-border bg-card px-3 py-2 text-left hover:border-navy/50 hover:bg-muted/40 transition-colors disabled:opacity-50"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <GitBranch className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                        <span className="font-medium text-sm truncate">{r.label}</span>
                        {!r.github_token && <span className="text-[10px] uppercase tracking-wide text-status-fail">no PAT</span>}
                      </div>
                      <div className="text-xs text-muted-foreground truncate">{r.repo_url}</div>
                    </div>
                    <span className="text-xs text-navy shrink-0">Detect →</span>
                  </button>
                </li>
              ))}
            </ul>
            <DialogFooter className="pt-2">
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              <Button type="button" variant="outline" onClick={() => setMode("manual")}>
                <Plus className="h-4 w-4 mr-1" /> Enter manually
              </Button>
            </DialogFooter>
          </div>
        )}

        {mode === "detecting" && (
          <div className="py-6 text-center space-y-3">
            <Loader2 className="h-6 w-6 animate-spin mx-auto text-navy" />
            <p className="text-sm text-muted-foreground">Scanning repo for AI endpoints…</p>
          </div>
        )}

        {mode === "endpoint-pick" && detectMeta && (
          <div className="space-y-3">
            <div className="text-xs text-muted-foreground">
              {detectMeta.repo} · {detectMeta.filesScanned} candidate files scanned · {detected.length} endpoint{detected.length === 1 ? "" : "s"} found
              {!detectMeta.supabaseBaseDetected && detected.some((e) => e.kind === "supabase-function") && (
                <span className="block text-status-na mt-0.5">⚠ Supabase URL not found in repo — edge function URLs will need to be completed manually.</span>
              )}
              {!detectMeta.appBaseDetected && detected.some((e) => e.kind !== "supabase-function") && (
                <span className="block text-status-na mt-0.5">⚠ Client app URL not set — route endpoints are relative paths.</span>
              )}
            </div>
            <ul className="space-y-1.5">
              {detected.map((ep, i) => (
                <li key={`${ep.filePath}-${i}`}>
                  <button
                    type="button"
                    onClick={() => pickDetected(ep)}
                    className="w-full flex items-start justify-between gap-3 rounded-md border border-border bg-card px-3 py-2 text-left hover:border-navy/50 hover:bg-muted/40 transition-colors"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Wand2 className="h-3.5 w-3.5 shrink-0 text-navy" />
                        <span className="font-medium text-sm">{ep.source}</span>
                        {ep.partialUrl && <Badge variant="outline" className="text-[10px] uppercase border-status-na/50 text-status-na">partial URL</Badge>}
                        {ep.requiresAuth && <Badge variant="outline" className="text-[10px] uppercase">auth</Badge>}
                        <Badge variant="secondary" className="text-[10px] font-mono lowercase">field: {ep.promptField}</Badge>
                      </div>
                      <div className="text-xs text-muted-foreground font-mono truncate mt-0.5">{ep.url || "(URL needs to be completed)"}</div>
                      <div className="text-[11px] text-muted-foreground/80 italic truncate mt-0.5">{ep.filePath}</div>
                    </div>
                    <span className="text-xs text-navy shrink-0 self-center">Use →</span>
                  </button>
                </li>
              ))}
            </ul>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              <Button type="button" variant="outline" onClick={() => setMode("manual")}>
                <Plus className="h-4 w-4 mr-1" /> Enter manually
              </Button>
            </DialogFooter>
          </div>
        )}

        {mode === "manual" && (
          <form onSubmit={submit} className="space-y-4">
            <div className="rounded-md border border-status-na/50 bg-status-na/5 p-3 text-xs">
              <div className="flex items-center gap-1.5 font-semibold text-foreground/90">
                <AlertTriangle className="h-3.5 w-3.5 text-status-na" /> Authorized testing only
              </div>
              <p className="text-foreground/80 mt-1">
                Only run this against endpoints you have explicit permission to test.
              </p>
            </div>

            {hasRepos && detected.length === 0 && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={detecting}
                onClick={() => savedRepos.length === 1 ? runDetect(savedRepos[0]) : setMode("repo-pick")}
              >
                {detecting ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Sparkles className="h-3.5 w-3.5 mr-1" />}
                Auto-detect from repo
              </Button>
            )}
            {detected.length > 0 && (
              <Button type="button" variant="ghost" size="sm" onClick={() => setMode("endpoint-pick")}>
                <ArrowLeft className="h-3.5 w-3.5 mr-1" /> Back to detected endpoints
              </Button>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="ai-url">AI Endpoint URL</Label>
              <Input id="ai-url" placeholder="https://app.example.com/api/generate" value={endpointUrl} onChange={(e) => setEndpointUrl(e.target.value)} disabled={pending} autoComplete="off" />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="ai-field">Prompt field name</Label>
              <Input id="ai-field" placeholder="prompt" value={promptField} onChange={(e) => setPromptField(e.target.value)} disabled={pending} autoComplete="off" />
              <p className="text-xs text-muted-foreground">
                The JSON body field that carries the user prompt. Request will be <code>{`{"${promptField || "prompt"}": "…"}`}</code>.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="ai-auth">Auth token <span className="text-muted-foreground font-normal">(optional)</span></Label>
              <Input id="ai-auth" type="password" placeholder="Bearer eyJ… or sk-…" value={authToken} onChange={(e) => setAuthToken(e.target.value)} disabled={pending} autoComplete="off" />
              <p className="text-xs text-muted-foreground">Sent as the Authorization header. "Bearer " prefix added automatically.</p>
            </div>

            {pending && <Progress value={progress} />}

            {results && (
              <div className="space-y-2 pt-2 border-t">
                <div className="text-sm font-medium flex items-center gap-2">
                  Results <span className="text-xs text-muted-foreground font-normal truncate">{endpointLabel}</span>
                </div>
                {results.map((r, i) => <ResultRow key={i} r={r} />)}
              </div>
            )}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => { reset(); setOpen(false); }} disabled={pending}>Close</Button>
              <Button type="submit" disabled={pending}>
                {pending ? (<><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Probing…</>) : results ? "Re-run scan" : "Run scan"}
              </Button>
            </DialogFooter>
          </form>
        )}
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
