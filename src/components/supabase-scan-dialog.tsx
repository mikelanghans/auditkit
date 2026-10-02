import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { AlertTriangle, Database, Loader2, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { runSupabaseScan } from "@/lib/supabase-scan.functions";
import { useAuditScope, useAuditTargets } from "@/hooks/use-audit-targets";
import { firstTarget } from "@/lib/audit-targets";

export function SupabaseScanDialog({
  auditId,
  appUrl,
  onDone,
  onResult,
  hasRun,
}: {
  auditId: string;
  appUrl?: string | null;
  onDone: () => void;
  onResult: (s: { passes: number; fails: number; project: string; leaks: number; publicBuckets: string[]; bundleMatches: number; at: string }) => void;
  hasRun?: boolean;
}) {
  const scan = useServerFn(runSupabaseScan);
  const [open, setOpen] = useState(false);
  const [projectUrl, setProjectUrl] = useState("");
  const [anonKey, setAnonKey] = useState("");
  const [serviceRoleKey, setServiceRoleKey] = useState("");
  const [pat, setPat] = useState("");
  const [pending, setPending] = useState(false);
  const [progress, setProgress] = useState(0);
  const [showRotate, setShowRotate] = useState(false);
  // Off by default: these probes write to the client's project. See
  // SupabaseScanInput.intrusiveProbes.
  const [intrusiveProbes, setIntrusiveProbes] = useState(false);
  const targets = useAuditTargets(auditId);
  const scope = useAuditScope(auditId);
  const writeTestsAllowed = !!scope.data?.write_tests_allowed;

  // Pre-fill the project URL from this audit's Supabase target.
  useEffect(() => {
    if (!open || projectUrl) return;
    const t = firstTarget(targets.data, "supabase");
    if (t) setProjectUrl(t.value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, targets.data]);

  useEffect(() => {
    if (!pending) { setProgress(0); return; }
    setProgress(8);
    const iv = setInterval(() => {
      setProgress((p) => (p < 92 ? p + Math.max(0.5, (92 - p) * 0.04) : p));
    }, 250);
    return () => clearInterval(iv);
  }, [pending]);

  const reset = () => { setProjectUrl(""); setAnonKey(""); setServiceRoleKey(""); setPat(""); setIntrusiveProbes(false); };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectUrl.trim() || !anonKey.trim() || !serviceRoleKey.trim()) {
      toast.error("Project URL, anon key, and service role key are required.");
      return;
    }
    setPending(true);
    const tid = toast.loading("Scanning Supabase project…");
    try {
      const res = await scan({
        data: {
          auditId,
          projectUrl: projectUrl.trim(),
          anonKey: anonKey.trim(),
          serviceRoleKey: serviceRoleKey.trim(),
          managementPat: pat.trim() || null,
          appUrl: appUrl ?? null,
          intrusiveProbes: intrusiveProbes && writeTestsAllowed,
        },
      });
      setProgress(100);
      if (!res.ok) {
        toast.error(res.error, { id: tid });
        return;
      }
      toast.success(
        `Supabase scan complete — ${res.passes} pass, ${res.fails} fail${res.inconclusive ? `, ${res.inconclusive} couldn't verify` : ""}`,
        {
          id: tid,
          description: `${res.project} · ${res.tablesProbed}${res.tablesDiscovered > res.tablesProbed ? ` of ${res.tablesDiscovered}` : ""} tables probed${res.probeErrors ? ` · ${res.probeErrors} probe error(s)` : ""}${res.bundleMatches > 0 ? ` · ⚠ key found in bundle` : ""}`,
        },
      );
      onResult({
        passes: res.passes,
        fails: res.fails,
        project: res.project,
        leaks: res.leaks,
        publicBuckets: res.publicBuckets,
        bundleMatches: res.bundleMatches,
        at: new Date().toISOString(),
      });
      onDone();
      // Discard credentials immediately and block on rotation reminder
      reset();
      setOpen(false);
      setShowRotate(true);
    } catch (err: any) {
      toast.error(err?.message ?? "Supabase scan failed", { id: tid });
    } finally {
      setTimeout(() => setPending(false), 400);
    }
  };

  return (
    <>
      <Dialog open={open} onOpenChange={(o) => { if (!pending) { if (!o) reset(); setOpen(o); } }}>
        <DialogTrigger asChild>
          <Button variant="outline">
            <Database className="h-4 w-4 mr-1" /> {hasRun ? "Re-scan Supabase" : "Scan Supabase"}
          </Button>
        </DialogTrigger>
        <DialogContent className="sm:max-w-lg">
          <form onSubmit={submit} className="space-y-4">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Database className="h-4 w-4" /> Scan Supabase project
              </DialogTitle>
              <DialogDescription>
                Probes the project for RLS gaps, anon-readable tables, weak auth settings, public storage buckets,
                and service-role-key exposure in the live JS bundle.
              </DialogDescription>
            </DialogHeader>

            <div className="rounded-md border border-status-fail/40 bg-status-fail/5 p-3 text-xs space-y-1">
              <div className="flex items-center gap-1.5 font-semibold text-status-fail">
                <ShieldAlert className="h-3.5 w-3.5" /> Service role key handling
              </div>
              <p className="text-foreground/80">
                The service role key is used only to enumerate storage buckets and validate that the key is real.
                It is held in memory for the duration of the scan, never logged, and never written to the database.
              </p>
              <p className="text-foreground/80">
                <strong>Rotate this key immediately after the scan completes</strong> as a security best practice.
              </p>
            </div>

            <div className="rounded-md border border-border bg-muted/40 p-3 text-xs space-y-2">
              <label htmlFor="sb-intrusive" className="flex items-start gap-2 cursor-pointer">
                <input
                  id="sb-intrusive"
                  type="checkbox"
                  className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-current"
                  checked={intrusiveProbes && writeTestsAllowed}
                  onChange={(e) => setIntrusiveProbes(e.target.checked)}
                  disabled={pending || !writeTestsAllowed}
                />
                <span className="space-y-1">
                  <span className="block font-semibold">
                    Enable active probes (needs the client&rsquo;s consent)
                  </span>
                  <span className="block text-foreground/70">
                    Adds two checks that <strong>write to the client&rsquo;s live project</strong>: a signup attempt
                    with a weak password (creates a user record, may send a confirmation email) to test the password
                    policy, and a burst of 8 failed sign-ins to test rate limiting (writes to their auth logs and may
                    trigger alerting).
                  </span>
                  {!writeTestsAllowed && (
                    <span className="block font-medium text-status-warn">
                      Locked: turn on &ldquo;Write and stress tests allowed&rdquo; in Targets &amp; scope first.
                    </span>
                  )}
                  <span className="block text-foreground/70">
                    Leave this off for a passive scan. Both checks are reported as
                    &ldquo;not tested&rdquo; rather than passing.
                  </span>
                </span>
              </label>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="sb-url">Supabase Project URL</Label>
              <Input
                id="sb-url"
                placeholder="https://xyzxyz.supabase.co"
                value={projectUrl}
                onChange={(e) => setProjectUrl(e.target.value)}
                disabled={pending}
                autoFocus
                autoComplete="off"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="sb-anon">Anon Key <span className="text-muted-foreground font-normal">(publishable)</span></Label>
              <Input
                id="sb-anon"
                type="password"
                placeholder="eyJhbGc…"
                value={anonKey}
                onChange={(e) => setAnonKey(e.target.value)}
                disabled={pending}
                autoComplete="off"
              />
              <p className="text-xs text-muted-foreground">Used to probe each table without authentication.</p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="sb-srv">Service Role Key <span className="text-status-fail font-normal">(secret — discarded after scan)</span></Label>
              <Input
                id="sb-srv"
                type="password"
                placeholder="eyJhbGc…"
                value={serviceRoleKey}
                onChange={(e) => setServiceRoleKey(e.target.value)}
                disabled={pending}
                autoComplete="off"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="sb-pat">Management API PAT <span className="text-muted-foreground font-normal">(optional)</span></Label>
              <Input
                id="sb-pat"
                type="password"
                placeholder="sbp_…"
                value={pat}
                onChange={(e) => setPat(e.target.value)}
                disabled={pending}
                autoComplete="off"
              />
              <p className="text-xs text-muted-foreground">
                If provided, enables an authoritative per-table RLS check and pulls the project's auth config.
              </p>
            </div>

            {appUrl ? (
              <p className="text-xs text-muted-foreground">
                Bundle scan target: <code className="text-foreground">{appUrl}</code>
              </p>
            ) : (
              <p className="text-xs text-status-na">
                No website URL provided — bundle scan and service-role-exposure check will be skipped.
              </p>
            )}

            {pending && <Progress value={progress} />}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => { reset(); setOpen(false); }} disabled={pending}>
                Cancel
              </Button>
              <Button type="submit" disabled={pending}>
                {pending ? (<><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Scanning…</>) : (<>Run scan</>)}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={showRotate} onOpenChange={(o) => { if (!o) setShowRotate(false); }}>
        <DialogContent className="sm:max-w-md" onPointerDownOutside={(e) => e.preventDefault()} onEscapeKeyDown={(e) => e.preventDefault()}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-status-fail">
              <AlertTriangle className="h-5 w-5" /> Rotate the service role key now
            </DialogTitle>
            <DialogDescription>
              The scan is complete and your credentials have been discarded from this app. As a security best practice,
              rotate the service role key in the client's Supabase dashboard before continuing.
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-md border border-border bg-muted/40 p-3 text-xs space-y-1.5">
            <p className="font-semibold">How to rotate:</p>
            <ol className="list-decimal list-inside space-y-0.5 text-foreground/80">
              <li>Open the project in Supabase → Settings → API.</li>
              <li>Click <strong>Reset service role key</strong>.</li>
              <li>Update any server-side env vars that depend on it.</li>
            </ol>
          </div>
          <DialogFooter>
            <Button onClick={() => setShowRotate(false)} className="bg-status-fail text-white hover:bg-status-fail/90">
              I've rotated the key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
