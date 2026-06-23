import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";

export const Route = createFileRoute("/reset-password")({
  ssr: false,
  head: () => ({ meta: [{ title: "Reset password — AuditKit" }] }),
  component: ResetPasswordPage,
});

type ValidationResult = { ok: true } | { ok: false; message: string };

let activeValidation:
  | {
      href: string;
      promise: Promise<ValidationResult>;
    }
  | undefined;

function ResetPasswordPage() {
  const navigate = useNavigate();
  const [ready, setReady] = useState(false);
  const [statusMessage, setStatusMessage] = useState("Validating reset link…");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let mounted = true;

    const markReady = () => {
      if (!mounted) return;
      setReady(true);
      setStatusMessage("Enter and confirm your new password below.");
    };

    const markError = (message: string) => {
      if (!mounted) return;
      setReady(false);
      setStatusMessage(message);
      toast.error(message);
    };

    const { data: sub } = supabase.auth.onAuthStateChange((event) => {
      if (event === "PASSWORD_RECOVERY" || event === "SIGNED_IN" || event === "INITIAL_SESSION") {
        supabase.auth.getSession().then(({ data }) => {
          if (data.session) markReady();
        });
      }
    });

    function cleanUrl() {
      if (window.location.search || window.location.hash) {
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    }

    function readParam(name: string) {
      const query = new URLSearchParams(window.location.search);
      const hash = new URLSearchParams(window.location.hash.replace(/^#/, ""));
      return query.get(name) || hash.get(name);
    }

    async function waitForSession(timeoutMs = 5000) {
      const started = Date.now();
      while (Date.now() - started < timeoutMs) {
        const { data } = await supabase.auth.getSession();
        if (data.session) return data.session;
        await new Promise((resolve) => window.setTimeout(resolve, 250));
      }
      return null;
    }

    async function runValidation(): Promise<ValidationResult> {
      const existing = await supabase.auth.getSession();
      if (existing.data.session) return { ok: true };

      const linkError = readParam("error_description");

      if (linkError) {
        const delayed = await waitForSession();
        if (delayed) return { ok: true };
        return { ok: false, message: linkError };
      }

      const tokenHash = readParam("token_hash");
      const type = readParam("type");
      if (tokenHash && type === "recovery") {
        const { error } = await supabase.auth.verifyOtp({
          token_hash: tokenHash,
          type: "recovery",
        });
        if (error) {
          const after = await supabase.auth.getSession();
          if (after.data.session) return { ok: true };
          return { ok: false, message: error.message };
        }
        return { ok: true };
      }

      const code = readParam("code");
      if (code) {
        const { error } = await supabase.auth.exchangeCodeForSession(code);
        if (error) {
          // Code may have been consumed by a prior run — re-check session.
          const after = await supabase.auth.getSession();
          if (after.data.session) return { ok: true };
          return { ok: false, message: error.message };
        }
        return { ok: true };
      }

      const accessToken = readParam("access_token");
      const refreshToken = readParam("refresh_token");
      if (accessToken && refreshToken) {
        const { error } = await supabase.auth.setSession({
          access_token: accessToken,
          refresh_token: refreshToken,
        });
        if (error) {
          const after = await supabase.auth.getSession();
          if (after.data.session) return { ok: true };
          return { ok: false, message: error.message };
        }
        return { ok: true };
      }

      const delayed = await waitForSession();
      if (delayed) return { ok: true };

      return { ok: false, message: "This reset link is invalid or expired. Request a new password reset email." };
    }

    async function validateResetLink() {
      const href = window.location.href;
      if (!activeValidation || activeValidation.href !== href) {
        activeValidation = { href, promise: runValidation() };
      }

      const result = await activeValidation.promise;
      if (result.ok) {
        markReady();
        cleanUrl();
      } else {
        const after = await supabase.auth.getSession();
        if (after.data.session) {
          markReady();
          cleanUrl();
          return;
        }
        markError(result.message);
      }
    }

    validateResetLink();

    return () => {
      mounted = false;
      sub.subscription.unsubscribe();
    };
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password.length < 6) return toast.error("Password must be at least 6 characters.");
    if (password !== confirm) return toast.error("Passwords do not match.");
    setLoading(true);
    const { error } = await supabase.auth.updateUser({ password });
    setLoading(false);
    if (error) return toast.error(error.message);
    toast.success("Password updated. You're signed in.");
    navigate({ to: "/dashboard", replace: true });
  }

  return (
    <div className="min-h-screen flex flex-col">
      <div className="bg-navy text-navy-foreground py-10 px-6 text-center">
        <div className="flex items-center justify-center gap-2 text-xl font-semibold">
          <ShieldCheck className="h-6 w-6" />
          AuditKit
        </div>
        <p className="mt-1 text-sm text-white/70">Reset your password</p>
      </div>
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-card border rounded-xl p-6 shadow-sm">
          <h1 className="text-lg font-semibold mb-1">Choose a new password</h1>
          <p className="text-sm text-muted-foreground mb-4">{statusMessage}</p>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="pw">New password</Label>
              <Input id="pw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required disabled={!ready} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pw2">Confirm new password</Label>
              <Input id="pw2" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required disabled={!ready} />
            </div>
            <Button type="submit" disabled={loading || !ready} className="w-full bg-navy text-navy-foreground hover:bg-navy/90">
              {loading ? "Updating…" : "Update password"}
            </Button>
          </form>
        </div>
      </div>
    </div>
  );
}
