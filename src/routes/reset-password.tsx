import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { ShieldCheck } from "lucide-react";
import { passwordResetClient } from "@/lib/password-reset-client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";

export const Route = createFileRoute("/reset-password")({
  ssr: false,
  head: () => ({ meta: [{ title: "Reset password — AuditKit" }] }),
  component: ResetPasswordPage,
});

const MIN_PASSWORD_LENGTH = 8;
const invalidLinkMessage =
  "This reset link is invalid or expired. Request a new password reset email.";

function readAuthParams() {
  const url = new URL(window.location.href);
  const params = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
  url.searchParams.forEach((value, key) => params.set(key, value));
  return params;
}

/**
 * Establish the recovery session from the email link, in the isolated reset
 * client only. Nothing here touches the main app's stored login, and a link
 * that is not a recovery link is refused rather than adopted.
 */
async function resolveRecoverySession(): Promise<Session | null> {
  const params = readAuthParams();
  const urlError = params.get("error_description") || params.get("error");
  if (urlError) throw new Error(urlError.replace(/\+/g, " "));

  const tokenHash = params.get("token_hash");
  if (tokenHash) {
    const { data, error } = await passwordResetClient.auth.verifyOtp({
      token_hash: tokenHash,
      type: "recovery",
    });
    if (error) throw error;
    return data.session;
  }

  const code = params.get("code");
  if (code) {
    const { data, error } = await passwordResetClient.auth.exchangeCodeForSession(code);
    if (error) throw error;
    return data.session;
  }

  const accessToken = params.get("access_token");
  const refreshToken = params.get("refresh_token");
  if (accessToken && refreshToken) {
    if (params.get("type") !== "recovery") throw new Error(invalidLinkMessage);
    const { data, error } = await passwordResetClient.auth.setSession({
      access_token: accessToken,
      refresh_token: refreshToken,
    });
    if (error) throw error;
    return data.session;
  }

  // detectSessionInUrl may already have consumed the fragment.
  const { data } = await passwordResetClient.auth.getSession();
  return data.session;
}

function ResetPasswordPage() {
  const navigate = useNavigate();
  const [statusMessage, setStatusMessage] = useState("Preparing secure password reset…");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [ready, setReady] = useState(false);
  const setupRef = useRef<Promise<Session | null> | null>(null);

  const cleanUrl = useCallback(() => {
    if (window.location.search || window.location.hash) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    setupRef.current ??= resolveRecoverySession();
    setupRef.current
      .then((session) => {
        if (!mounted) return;
        cleanUrl();
        if (session) {
          setReady(true);
          setStatusMessage("Enter and confirm your new password below.");
        } else {
          setStatusMessage(invalidLinkMessage);
        }
      })
      .catch(() => {
        if (!mounted) return;
        cleanUrl();
        setStatusMessage(invalidLinkMessage);
      });

    const { data: sub } = passwordResetClient.auth.onAuthStateChange((event, session) => {
      if (!mounted || !session) return;
      if (event === "PASSWORD_RECOVERY") {
        setReady(true);
        setStatusMessage("Enter and confirm your new password below.");
        cleanUrl();
      }
    });

    return () => {
      mounted = false;
      sub.subscription.unsubscribe();
    };
  }, [cleanUrl]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!ready) return toast.error(invalidLinkMessage);
    if (password.length < MIN_PASSWORD_LENGTH) {
      return toast.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    }
    if (password !== confirm) return toast.error("Passwords do not match.");
    setLoading(true);
    try {
      const { error } = await passwordResetClient.auth.updateUser({ password });
      if (error) {
        setLoading(false);
        return toast.error(error.message || invalidLinkMessage);
      }
      // Drop the recovery session. The user signs in with the new password,
      // which is what establishes the app login.
      await passwordResetClient.auth.signOut({ scope: "local" }).catch(() => {});
      setLoading(false);
      toast.success("Password updated. Sign in with your new password.");
      navigate({ to: "/auth", replace: true });
    } catch (error) {
      setLoading(false);
      setStatusMessage(invalidLinkMessage);
      return toast.error(error instanceof Error ? error.message : invalidLinkMessage);
    }
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
              <Input
                id="pw"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pw2">Confirm new password</Label>
              <Input
                id="pw2"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
              />
            </div>
            <Button
              type="submit"
              disabled={loading || !ready}
              className="w-full bg-navy text-navy-foreground hover:bg-navy/90"
            >
              {loading ? "Updating…" : "Update password"}
            </Button>
          </form>
        </div>
      </div>
    </div>
  );
}
