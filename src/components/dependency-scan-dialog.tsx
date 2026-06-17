import { useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { Github, Loader2, Package } from "lucide-react";
import { toast } from "sonner";
import { runDependencyScan, type DepFinding } from "@/lib/dependency-scan.functions";

export type DepScanResult = {
  repo: string;
  path: string;
  packagesScanned: number;
  counts: { critical: number; high: number; medium: number; low: number };
  status: "pass" | "fail";
  findings: DepFinding[];
  at: string;
};

export function DependencyScanDialog({
  auditId,
  onDone,
  onResult,
}: {
  auditId: string;
  onDone: () => void;
  onResult: (r: DepScanResult) => void;
}) {
  const scan = useServerFn(runDependencyScan);
  const [open, setOpen] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [token, setToken] = useState("");
  const [pending, setPending] = useState(false);
  const [progress, setProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!pending) { setProgress(0); return; }
    setProgress(6);
    const iv = setInterval(() => {
      setProgress((p) => (p < 92 ? p + Math.max(0.5, (92 - p) * 0.04) : p));
    }, 250);
    return () => clearInterval(iv);
  }, [pending]);

  const reset = () => { setRepoUrl(""); setToken(""); setErrorMsg(null); };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (!repoUrl.trim() || !token.trim()) {
      setErrorMsg("Enter both the repo URL and a personal access token.");
      return;
    }
    setPending(true);
    const tid = toast.loading("Scanning dependencies…");
    try {
      const res = await scan({ data: { auditId, repoUrl: repoUrl.trim(), token: token.trim() } });
      setProgress(100);
      if (!res.ok) {
        setErrorMsg(res.error);
        toast.error(res.error, { id: tid });
        return;
      }
      toast.success(
        `Dependency scan complete — ${res.packagesScanned} packages, ${res.findings.length} flagged`,
        { id: tid, description: `${res.repo} · ${res.path}` },
      );
      onResult({
        repo: res.repo,
        path: res.path,
        packagesScanned: res.packagesScanned,
        counts: res.counts,
        status: res.status,
        findings: res.findings,
        at: new Date().toISOString(),
      });
      onDone();
      reset();
      setOpen(false);
    } catch (err: any) {
      const msg = err?.message ?? "Dependency scan failed";
      setErrorMsg(msg);
      toast.error(msg, { id: tid });
    } finally {
      setTimeout(() => setPending(false), 400);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!pending) setOpen(o); }}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Package className="h-4 w-4 mr-1" /> Scan Dependencies
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Github className="h-4 w-4" /> Scan npm dependencies
            </DialogTitle>
            <DialogDescription>
              Reads <code>package.json</code> from the repo and checks each package against the npm registry and
              advisory database for known CVEs, major-version drift, and stale pins.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-1.5">
            <Label htmlFor="dep-repo-url">Repository URL</Label>
            <Input
              id="dep-repo-url"
              placeholder="https://github.com/owner/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              disabled={pending}
              autoFocus
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="dep-pat">GitHub personal access token</Label>
            <Input
              id="dep-pat"
              type="password"
              placeholder="ghp_… or github_pat_…"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              disabled={pending}
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground leading-relaxed">
              Read-only scope (<em>Contents: Read</em> + <em>Metadata: Read</em>, or classic <code>repo</code>/<code>public_repo</code>).
              The token is <strong>never stored</strong> — used only for this scan and discarded afterward.
            </p>
          </div>

          {pending && (
            <div className="space-y-1.5">
              <Progress value={progress} />
              <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                <Loader2 className="h-3 w-3 animate-spin" /> Fetching package.json and querying npm registry…
              </p>
            </div>
          )}

          <DialogFooter>
            <Button type="button" variant="ghost" disabled={pending} onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" disabled={pending}>
              {pending ? <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Scanning…</> : <><Package className="h-4 w-4 mr-1" /> Start scan</>}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
