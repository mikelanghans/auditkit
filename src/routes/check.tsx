import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { AlertTriangle, CheckCircle2, Loader2, Lock, ShieldCheck, ShieldAlert } from "lucide-react";
import { startPublicCheck, getPublicReport } from "@/lib/public-check.functions";
import type { PublicCheckSummary, PublicCheckTeaser } from "@/lib/public-check-core";
import type { SecretFinding, Severity } from "@/lib/bundle-secrets";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/check")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Is your app leaking API keys? — Free check" },
      {
        name: "description",
        content:
          "Free check for secret keys (Stripe, Supabase service role, OpenAI, AWS and more) exposed in your website's JavaScript.",
      },
    ],
  }),
  component: PublicCheckPage,
});

const BOOKING_URL = import.meta.env.VITE_SAFESHIP_BOOKING_URL as string | undefined;

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100",
};

function SeverityChip({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold capitalize",
        SEVERITY_STYLE[severity],
      )}
    >
      {count !== undefined ? `${count} ` : ""}
      {severity}
    </span>
  );
}

function PublicCheckPage() {
  const start = useServerFn(startPublicCheck);
  const unlock = useServerFn(getPublicReport);

  const [url, setUrl] = useState("");
  const [permission, setPermission] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    id: string;
    summary: PublicCheckSummary;
    teaser: PublicCheckTeaser;
  } | null>(null);

  const [email, setEmail] = useState("");
  const [consent, setConsent] = useState(false);
  const [unlocking, setUnlocking] = useState(false);
  const [report, setReport] = useState<{ findings: SecretFinding[]; coverageNote: string } | null>(
    null,
  );

  async function onCheck(e: React.FormEvent) {
    e.preventDefault();
    if (!permission)
      return setError("Please confirm you own this site or have permission to test it.");
    setError(null);
    setResult(null);
    setReport(null);
    setRunning(true);
    try {
      const res = await start({ data: { url } });
      if (!res.ok) setError(res.error);
      else setResult({ id: res.id, summary: res.summary, teaser: res.teaser });
    } catch {
      setError("Something went wrong running the check. Please try again.");
    } finally {
      setRunning(false);
    }
  }

  async function onUnlock(e: React.FormEvent) {
    e.preventDefault();
    if (!result) return;
    setUnlocking(true);
    setError(null);
    try {
      const res = await unlock({ data: { id: result.id, email, marketingConsent: consent } });
      if (!res.ok) setError(res.error);
      else setReport({ findings: res.findings, coverageNote: res.coverageNote });
    } catch {
      setError("Couldn't load the report. Please try again.");
    } finally {
      setUnlocking(false);
    }
  }

  const s = result?.summary;
  const serious = s ? s.counts.critical + s.counts.high + s.counts.medium : 0;

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <div className="bg-navy text-navy-foreground py-12 px-6 text-center">
        <div className="flex items-center justify-center gap-2 text-sm font-semibold text-white/80">
          <ShieldCheck className="h-5 w-5" />
          AuditKit · SafeShip
        </div>
        <h1 className="mt-3 text-3xl sm:text-4xl font-semibold tracking-tight">
          Is your app leaking API keys?
        </h1>
        <p className="mt-3 text-white/75 max-w-xl mx-auto">
          AI app builders make it easy to ship a secret key to every visitor&apos;s browser. Check
          the JavaScript your site serves for Stripe, Supabase service-role, OpenAI, AWS and other
          keys in under a minute.
        </p>
      </div>

      <div className="flex-1 w-full max-w-2xl mx-auto p-6 space-y-6">
        <form onSubmit={onCheck} className="bg-card border rounded-xl p-6 shadow-sm space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="url">Website address</Label>
            <div className="flex gap-2">
              <Input
                id="url"
                inputMode="url"
                autoComplete="url"
                placeholder="https://yourapp.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
              <Button
                type="submit"
                disabled={running || !url}
                className="bg-navy text-navy-foreground hover:bg-navy/90 shrink-0"
              >
                {running ? <Loader2 className="h-4 w-4 animate-spin" /> : "Check"}
              </Button>
            </div>
          </div>
          <label className="flex items-start gap-2 text-sm text-muted-foreground">
            <Checkbox
              checked={permission}
              onCheckedChange={(v) => setPermission(v === true)}
              className="mt-0.5"
            />
            <span>I own this site or have permission to test it.</span>
          </label>
          {running && (
            <p className="text-sm text-muted-foreground">
              Fetching the page and its JavaScript files. This can take up to a minute.
            </p>
          )}
          {error && (
            <div className="rounded-md border border-red-500/40 bg-red-500/[0.06] p-3 text-sm text-red-700 dark:text-red-300">
              {error}
            </div>
          )}
        </form>

        {s && (
          <div className="bg-card border rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-start gap-3">
              {serious > 0 ? (
                <ShieldAlert className="h-8 w-8 text-red-600 shrink-0" />
              ) : s.complete ? (
                <CheckCircle2 className="h-8 w-8 text-green-600 shrink-0" />
              ) : (
                <AlertTriangle className="h-8 w-8 text-amber-500 shrink-0" />
              )}
              <div>
                <h2 className="text-lg font-semibold">
                  {serious > 0
                    ? `${serious} exposed secret${serious === 1 ? "" : "s"} found on ${s.hostname}`
                    : s.complete
                      ? `No exposed secret keys found on ${s.hostname}`
                      : `No keys found in what we could scan on ${s.hostname}`}
                </h2>
                <p className="text-sm text-muted-foreground mt-1">
                  Scanned the page and {s.filesScanned} of {s.filesFound} JavaScript file
                  {s.filesFound === 1 ? "" : "s"}.
                  {!s.complete &&
                    " Some files couldn't be scanned, so this isn't a clean bill of health."}
                </p>
              </div>
            </div>

            {s.total > 0 && (
              <div className="flex flex-wrap gap-2">
                {(["critical", "high", "medium", "low"] as Severity[])
                  .filter((k) => s.counts[k] > 0)
                  .map((k) => (
                    <SeverityChip key={k} severity={k} count={s.counts[k]} />
                  ))}
              </div>
            )}

            {!report && result.teaser.length > 0 && (
              <ul className="divide-y rounded-md border">
                {result.teaser.map((t, i) => (
                  <li key={i} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                    <span>{t.label}</span>
                    <span className="flex items-center gap-2 text-muted-foreground">
                      <Lock className="h-3.5 w-3.5" />
                      <SeverityChip severity={t.severity} />
                    </span>
                  </li>
                ))}
              </ul>
            )}

            {!report && (
              <form onSubmit={onUnlock} className="rounded-lg bg-muted/50 border p-4 space-y-3">
                <p className="text-sm font-medium">
                  {s.total > 0
                    ? "Get the full report: which file each key is in, what it exposes, and how to fix it."
                    : "Get the full report, including what we scanned and what a code-level audit would add."}
                </p>
                <div className="flex gap-2">
                  <Input
                    type="email"
                    autoComplete="email"
                    placeholder="you@company.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                  <Button type="submit" disabled={unlocking || !email} className="shrink-0">
                    {unlocking ? <Loader2 className="h-4 w-4 animate-spin" /> : "Show report"}
                  </Button>
                </div>
                <label className="flex items-start gap-2 text-xs text-muted-foreground">
                  <Checkbox
                    checked={consent}
                    onCheckedChange={(v) => setConsent(v === true)}
                    className="mt-0.5"
                  />
                  <span>
                    Send me occasional security tips for AI-built apps. Unsubscribe any time.
                  </span>
                </label>
              </form>
            )}

            {report && (
              <div className="space-y-3">
                {report.findings.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No secret keys were found in the files we scanned.
                  </p>
                ) : (
                  report.findings.map((f, i) => (
                    <div key={i} className="rounded-md border p-3 space-y-1.5">
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-medium text-sm">{f.label}</span>
                        <SeverityChip severity={f.severity} />
                      </div>
                      <code className="block text-xs bg-muted rounded px-2 py-1 break-all">
                        {f.masked}
                      </code>
                      <p className="text-xs text-muted-foreground break-all">
                        Found in: {f.urls.join(", ")}
                        {f.occurrences > f.urls.length
                          ? ` (+${f.occurrences - f.urls.length} more)`
                          : ""}
                      </p>
                      <p className="text-sm">{f.advice}</p>
                    </div>
                  ))
                )}
                <details className="text-xs text-muted-foreground">
                  <summary className="cursor-pointer">What was scanned</summary>
                  <pre className="whitespace-pre-wrap mt-2">{report.coverageNote}</pre>
                </details>
              </div>
            )}
          </div>
        )}

        {s && (
          <div className="bg-navy text-navy-foreground rounded-xl p-6 space-y-2">
            <h3 className="font-semibold">
              Keys in the browser are only one way AI-built apps leak data
            </h3>
            <p className="text-sm text-white/75">
              Missing Row Level Security, open storage buckets, and unprotected server functions
              don&apos;t show up in a public scan. A SafeShip SHIELD audit reviews your code,
              database policies and deployment, and gives you a prioritised fix list.
            </p>
            {BOOKING_URL && (
              <a
                href={BOOKING_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex mt-2 items-center rounded-md bg-white px-4 py-2 text-sm font-medium text-navy hover:bg-white/90"
              >
                Book a SHIELD audit
              </a>
            )}
          </div>
        )}

        <p className="text-xs text-muted-foreground text-center">
          This check only reads files your site already sends to every visitor. Keys are masked and
          never stored in full.
        </p>
      </div>
    </div>
  );
}
