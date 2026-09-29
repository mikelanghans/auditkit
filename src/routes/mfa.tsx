import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export const Route = createFileRoute("/mfa")({
  ssr: false,
  head: () => ({ meta: [{ title: "Two-factor verification — AuditKit" }] }),
  component: MfaPage,
});

type Step =
  | { kind: "loading" }
  | { kind: "not_owner" }
  | { kind: "enroll"; factorId: string; qr: string; secret: string }
  | { kind: "verify"; factorId: string };

function MfaPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>({ kind: "loading" });
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const { data: session } = await supabase.auth.getSession();
      if (!session.session) return navigate({ to: "/auth", replace: true });

      const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
      if (aal?.currentLevel === "aal2") return navigate({ to: "/dashboard", replace: true });

      // The database only serves data to the allowlisted owner; say so plainly
      // instead of showing an empty app.
      const { data: owner } = await supabase.rpc("am_i_app_owner");
      if (cancelled) return;
      if (owner !== true) return setStep({ kind: "not_owner" });

      const { data: factors, error } = await supabase.auth.mfa.listFactors();
      if (error) return toast.error(error.message);
      const verified = factors?.totp?.find((f) => f.status === "verified");
      if (verified) return setStep({ kind: "verify", factorId: verified.id });

      // Clear half-finished enrolments, then start a fresh one.
      for (const f of factors?.all ?? []) {
        if (f.status !== "verified") await supabase.auth.mfa.unenroll({ factorId: f.id });
      }
      const { data: enrolled, error: enrollErr } = await supabase.auth.mfa.enroll({
        factorType: "totp",
        friendlyName: "AuditKit",
        issuer: "AuditKit",
      });
      if (cancelled) return;
      if (enrollErr || !enrolled)
        return toast.error(enrollErr?.message ?? "Could not start two-factor setup.");
      setStep({
        kind: "enroll",
        factorId: enrolled.id,
        qr: enrolled.totp.qr_code,
        secret: enrolled.totp.secret,
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  async function onVerify(e: React.FormEvent) {
    e.preventDefault();
    if (step.kind !== "enroll" && step.kind !== "verify") return;
    setBusy(true);
    const { error } = await supabase.auth.mfa.challengeAndVerify({
      factorId: step.factorId,
      code: code.trim(),
    });
    setBusy(false);
    if (error) {
      setCode("");
      return toast.error("That code didn't match. Check your authenticator app and try again.");
    }
    toast.success(step.kind === "enroll" ? "Two-factor login is on." : "Verified.");
    navigate({ to: "/dashboard", replace: true });
  }

  async function signOut() {
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  return (
    <div className="min-h-screen flex flex-col">
      <div className="bg-navy text-navy-foreground py-10 px-6 text-center">
        <div className="flex items-center justify-center gap-2 text-xl font-semibold">
          <ShieldCheck className="h-6 w-6" />
          AuditKit
        </div>
        <p className="mt-1 text-sm text-white/70">Two-factor verification</p>
      </div>
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-card border rounded-xl p-6 shadow-sm space-y-4">
          {step.kind === "loading" && (
            <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground py-6">
              <Loader2 className="h-4 w-4 animate-spin" /> Checking your account…
            </div>
          )}

          {step.kind === "not_owner" && (
            <>
              <h1 className="text-lg font-semibold">This account can&apos;t use AuditKit</h1>
              <p className="text-sm text-muted-foreground">
                AuditKit is private. If this is your account, confirm your email address first, then
                sign in again.
              </p>
              <Button variant="outline" onClick={signOut} className="w-full">
                Sign out
              </Button>
            </>
          )}

          {step.kind === "enroll" && (
            <>
              <h1 className="text-lg font-semibold">Set up two-factor login</h1>
              <p className="text-sm text-muted-foreground">
                Scan this with an authenticator app (1Password, Google Authenticator, Authy), then
                enter the 6-digit code.
              </p>
              <div className="flex justify-center">
                <img
                  src={step.qr}
                  alt="Authenticator QR code"
                  className="h-48 w-48 bg-white p-2 rounded"
                />
              </div>
              <details className="text-xs text-muted-foreground">
                <summary className="cursor-pointer">
                  Can&apos;t scan? Enter this key instead
                </summary>
                <code className="block mt-1 break-all select-all">{step.secret}</code>
              </details>
            </>
          )}

          {step.kind === "verify" && (
            <>
              <h1 className="text-lg font-semibold">Enter your authentication code</h1>
              <p className="text-sm text-muted-foreground">
                Open your authenticator app and enter the 6-digit code for AuditKit.
              </p>
            </>
          )}

          {(step.kind === "enroll" || step.kind === "verify") && (
            <form onSubmit={onVerify} className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="code">Code</Label>
                <Input
                  id="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  autoFocus
                  required
                />
              </div>
              <Button
                type="submit"
                disabled={busy || code.length !== 6}
                className="w-full bg-navy text-navy-foreground hover:bg-navy/90"
              >
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Verify"}
              </Button>
              <button
                type="button"
                onClick={signOut}
                className="text-sm text-muted-foreground hover:text-foreground underline underline-offset-2"
              >
                Sign out
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
