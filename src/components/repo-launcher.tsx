import { useEffect, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { GitBranch, Github, Loader2, Plus, ArrowLeft, KeyRound } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";

import { getCachedRepoToken, setCachedRepoToken, clearCachedRepoToken } from "@/lib/repo-token-cache";

export type SavedRepo = {
  id: string;
  label: string;
  repo_url: string;
};

type Mode = "picker" | "form";

export function RepoLauncher({
  trigger,
  clientId,
  savedRepos,
  title,
  description,
  submitLabel,
  runningLabel,
  loadingToast,
  onRun,
  onSaved,
  buttonClassName,
  extraControls,
}: {
  trigger: { label: string; icon: ReactNode; variant?: "outline" | "default" | "ghost"; className?: string };
  clientId: string | null;
  savedRepos: SavedRepo[];
  title: string;
  description: ReactNode;
  submitLabel: string;
  runningLabel: string;
  loadingToast: string;
  /** Runs the actual scan. Returns true on success so saved-creds flow can close. */
  onRun: (args: { repoUrl: string; token: string; loadingToastId: string | number }) => Promise<boolean>;
  /** Called after creds are saved to client_repos so caller can invalidate audit/client queries. */
  onSaved?: () => void;
  buttonClassName?: string;
  /** Optional controls (e.g. scan depth selector) rendered above the picker / form. */
  extraControls?: ReactNode;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<Mode>("picker");
  const [repoUrl, setRepoUrl] = useState("");
  const [token, setToken] = useState("");
  const [label, setLabel] = useState("");
  const [saveForClient, setSaveForClient] = useState(true);
  const [pending, setPending] = useState(false);
  const [runningRepoId, setRunningRepoId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  const hasSaved = savedRepos.length > 0;

  useEffect(() => {
    if (!pending) { setProgress(0); return; }
    setProgress(6);
    const iv = setInterval(() => {
      setProgress((p) => (p < 92 ? p + Math.max(0.5, (92 - p) * 0.04) : p));
    }, 250);
    return () => clearInterval(iv);
  }, [pending]);

  const reset = () => { setRepoUrl(""); setToken(""); setLabel(""); setSaveForClient(true); setMode(savedRepos.length >= 2 ? "picker" : "form"); };

  const runWith = async (rurl: string, tok: string) => {
    setPending(true);
    const tid = toast.loading(loadingToast);
    try {
      const ok = await onRun({ repoUrl: rurl, token: tok, loadingToastId: tid });
      setProgress(100);
      return ok;
    } finally {
      setTimeout(() => setPending(false), 400);
    }
  };

  const handleTriggerClick = async () => {
    if (savedRepos.length === 1) {
      promptToken(savedRepos[0]);
      return;
    }
    if (savedRepos.length >= 2) {
      setMode("picker");
    } else {
      setMode("form");
    }
    setOpen(true);
  };

  const [needTokenFor, setNeedTokenFor] = useState<SavedRepo | null>(null);
  const [pendingToken, setPendingToken] = useState("");
  const [savePendingToken, setSavePendingToken] = useState(true);

  const promptToken = (r: SavedRepo) => {
    setNeedTokenFor(r);
    setPendingToken(getCachedRepoToken(r.id) ?? "");
    setSavePendingToken(true);
    setOpen(true);
  };

  const runSaved = async (r: SavedRepo) => {
    promptToken(r);
  };

  const submitPendingToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!needTokenFor || !pendingToken.trim()) return;
    const r = needTokenFor;
    const tok = pendingToken.trim();
    const ok = await runWith(r.repo_url, tok);
    if (ok) {
      if (savePendingToken && r.id) setCachedRepoToken(r.id, tok);
      else clearCachedRepoToken(r.id);
      setNeedTokenFor(null);
      setPendingToken("");
      setOpen(false);
    }
  };

  const submitForm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim()) {
      toast.error("Enter the repo URL.");
      return;
    }
    if (!token.trim()) {
      toast.error("Enter a GitHub personal access token.");
      return;
    }
    const rurl = repoUrl.trim();
    const tok = token.trim();
    let savedRepoRow: SavedRepo = {
      id: "",
      label: label.trim() || deriveLabel(rurl),
      repo_url: rurl,
    };
    if (saveForClient && clientId) {
      const { data: inserted, error } = await supabase.from("client_repos").insert({
        client_id: clientId,
        label: savedRepoRow.label,
        repo_url: rurl,
        github_token: tok,
      }).select("id, label, repo_url").single();
      if (error) {
        toast.error(`Could not save repo: ${error.message}`);
        return;
      }
      savedRepoRow = inserted as SavedRepo;
      qc.invalidateQueries({ queryKey: ["client-repos", clientId] });
      onSaved?.();
    }
    if (savedRepoRow.id) setCachedRepoToken(savedRepoRow.id, tok);
    const ok = await runWith(rurl, tok);
    if (ok) {
      reset();
      setOpen(false);
    }
  };


  return (
    <Dialog open={open} onOpenChange={(o) => { if (!pending) { if (!o) { reset(); setNeedTokenFor(null); setPendingToken(""); } setOpen(o); } }}>
      <Button
        variant={trigger.variant ?? "outline"}
        onClick={handleTriggerClick}
        disabled={pending}
        className={trigger.className ?? buttonClassName}
      >
        {pending && hasSaved && savedRepos.length === 1 ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : trigger.icon}
        {trigger.label}
        {hasSaved && (
          <span
            className="ml-1.5 inline-flex items-center gap-0.5"
            title={savedRepos.length === 1 ? `Using saved repo: ${savedRepos[0].label}` : `${savedRepos.length} saved repos`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-status-pass" />
            {savedRepos.length > 1 && <span className="text-[10px] font-semibold opacity-70">{savedRepos.length}</span>}
          </span>
        )}
      </Button>

      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Github className="h-4 w-4" /> {needTokenFor ? `PAT required for ${needTokenFor.label}` : title}
          </DialogTitle>
          <DialogDescription>
            {needTokenFor ? "Enter a GitHub Personal Access Token to scan this repo." : description}
          </DialogDescription>
        </DialogHeader>

        {!needTokenFor && extraControls ? <div>{extraControls}</div> : null}

        {needTokenFor ? (
          <form onSubmit={submitPendingToken} className="space-y-4">
            <div className="text-xs text-muted-foreground break-all">{needTokenFor.repo_url}</div>
            <div className="space-y-1.5">
              <Label htmlFor="rl-pending-token">Personal access token</Label>
              <Input
                id="rl-pending-token"
                type="password"
                placeholder="ghp_… or github_pat_…"
                value={pendingToken}
                onChange={(e) => setPendingToken(e.target.value)}
                disabled={pending}
                autoFocus
                autoComplete="off"
              />
              <p className="text-xs text-muted-foreground">
                Fine-grained PAT: <em>Contents: Read</em> + <em>Metadata: Read</em>.
              </p>
            </div>
            <label className="flex items-start gap-2 text-sm cursor-pointer select-none">
              <input
                type="checkbox"
                checked={savePendingToken}
                onChange={(e) => setSavePendingToken(e.target.checked)}
                disabled={pending}
                className="mt-0.5 h-4 w-4 rounded border-border accent-navy"
              />
              <span>
                <span className="font-medium">Remember this token</span>
                <span className="block text-xs text-muted-foreground">Saves the PAT on this repo so future scans run with one click.</span>
              </span>
            </label>
            {pending && (
              <div className="space-y-1.5">
                <Progress value={progress} />
                <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                  <Loader2 className="h-3 w-3 animate-spin" /> {runningLabel}
                </p>
              </div>
            )}
            <DialogFooter>
              <Button type="button" variant="ghost" disabled={pending} onClick={() => { setNeedTokenFor(null); if (savedRepos.length >= 2) setMode("picker"); else setOpen(false); }}>
                Cancel
              </Button>
              <Button type="submit" disabled={pending || !pendingToken.trim()}>
                {pending ? <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> {runningLabel}</> : submitLabel}
              </Button>
            </DialogFooter>
          </form>
        ) : mode === "picker" ? (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">Pick a saved repo to scan:</p>
            <ul className="space-y-1.5">
              {savedRepos.map((r) => (
                <li
                  key={r.id}
                  className="w-full flex items-center justify-between gap-2 rounded-md border border-border bg-card px-3 py-2 hover:border-navy/50 hover:bg-muted/40 transition-colors"
                >
                  <button
                    type="button"
                    disabled={pending}
                    onClick={() => runSaved(r)}
                    className="flex-1 min-w-0 text-left disabled:opacity-50"
                  >
                    <div className="flex items-center gap-2">
                      <GitBranch className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                      <span className="font-medium text-sm truncate">{r.label}</span>
                      {getCachedRepoToken(r.id) && <span className="text-[10px] uppercase tracking-wide text-status-pass">session PAT</span>}
                    </div>
                    <div className="text-xs text-muted-foreground truncate">{r.repo_url}</div>
                  </button>
                  <div className="flex items-center gap-1 shrink-0">
                    {getCachedRepoToken(r.id) && (
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        disabled={pending}
                        title="Forget session token for this repo"
                        onClick={() => {
                          clearCachedRepoToken(r.id);
                          // force re-render of list badges
                          qc.invalidateQueries({ queryKey: ["client-repos", clientId] });
                          toast.success("Session token forgotten");
                        }}
                        className="h-7 px-2 text-muted-foreground hover:text-foreground"
                      >
                        <KeyRound className="h-3.5 w-3.5 mr-1" />
                        <span className="text-xs">Forget</span>
                      </Button>
                    )}
                    {runningRepoId === r.id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <span className="text-xs text-navy">Scan →</span>
                    )}
                  </div>

                </li>
              ))}

            </ul>
            {pending && <Progress value={progress} className="mt-3" />}
            <DialogFooter className="pt-2">
              <Button type="button" variant="ghost" disabled={pending} onClick={() => setOpen(false)}>Cancel</Button>
              <Button type="button" variant="outline" disabled={pending} onClick={() => setMode("form")}>
                <Plus className="h-4 w-4 mr-1" /> Use a new repo
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={submitForm} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="rl-url">Repository URL</Label>
              <Input
                id="rl-url"
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                disabled={pending}
                autoFocus
                autoComplete="off"
              />
            </div>
            <p className="text-xs text-muted-foreground">
              You'll be prompted for a GitHub personal access token after the repo is saved.
            </p>


            {clientId && (
              <>
                <label className="flex items-start gap-2 text-sm cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={saveForClient}
                    onChange={(e) => setSaveForClient(e.target.checked)}
                    disabled={pending}
                    className="mt-0.5 h-4 w-4 rounded border-border accent-navy"
                  />
                  <span>
                    <span className="font-medium">Save for this client</span>
                    <span className="block text-xs text-muted-foreground">Adds to Connected Accounts for one-click reruns.</span>
                  </span>
                </label>
                {saveForClient && (
                  <div className="space-y-1.5">
                    <Label htmlFor="rl-label">Label (optional)</Label>
                    <Input
                      id="rl-label"
                      placeholder={repoUrl ? deriveLabel(repoUrl) : "e.g. Frontend, API, Worker"}
                      value={label}
                      onChange={(e) => setLabel(e.target.value)}
                      disabled={pending}
                    />
                  </div>
                )}
              </>
            )}

            {pending && (
              <div className="space-y-1.5">
                <Progress value={progress} />
                <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                  <Loader2 className="h-3 w-3 animate-spin" /> {runningLabel}
                </p>
              </div>
            )}

            <DialogFooter>
              {savedRepos.length >= 2 && (
                <Button type="button" variant="ghost" disabled={pending} onClick={() => setMode("picker")}>
                  <ArrowLeft className="h-4 w-4 mr-1" /> Back
                </Button>
              )}
              <Button type="button" variant="ghost" disabled={pending} onClick={() => setOpen(false)}>Cancel</Button>
              <Button type="submit" disabled={pending}>
                Continue
              </Button>

            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function deriveLabel(url: string): string {
  try {
    const m = url.match(/github\.com[/:]([^/]+)\/([^/.]+)/i);
    if (m) return `${m[1]}/${m[2]}`;
  } catch { /* ignore */ }
  return "Repo";
}
