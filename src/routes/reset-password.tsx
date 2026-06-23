import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { ShieldCheck } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";

const resetAccessTokenStorageKey = "auditkit-reset-access-token";
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
const supabasePublishableKey =
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_PUBLISHABLE_KEY;

export const Route = createFileRoute("/reset-password")({
  ssr: false,
  head: () => ({ meta: [{ title: "Reset password — AuditKit" }] }),
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const navigate = useNavigate();
  const invalidLinkMessage =
    "This reset link is invalid or expired. Request a new password reset email.";
  const [statusMessage, setStatusMessage] = useState("Preparing secure password reset…");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [ready, setReady] = useState(false);
  const sessionSetupPromiseRef = useRef<Promise<Session | null> | null>(null);
  const recoveryAccessTokenRef = useRef<string | null>(null);

  const rememberRecoveryAccessToken = useCallback((token?: string | null) => {
    if (!token) return;
    recoveryAccessTokenRef.current = token;
    window.sessionStorage.setItem(resetAccessTokenStorageKey, token);
  }, []);

  const getRecoveryAccessToken = useCallback(() => {
    return recoveryAccessTokenRef.current || window.sessionStorage.getItem(resetAccessTokenStorageKey);
  }, []);

  const clearRecoveryAccessToken = useCallback(() => {
    recoveryAccessTokenRef.current = null;
    window.sessionStorage.removeItem(resetAccessTokenStorageKey);
  }, []);

  const cleanUrl = useCallback(() => {
    if (window.location.search || window.location.hash) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, []);

  const readAuthParams = useCallback(() => {
    const url = new URL(window.location.href);
    const params = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
    url.searchParams.forEach((value, key) => params.set(key, value));
    return params;
  }, []);

  const waitForStoredSession = useCallback(async (timeoutMs = 8000) => {
    const startedAt = Date.now();

    while (Date.now() - startedAt < timeoutMs) {
      const { data } = await supabase.auth.getSession();
      if (data.session) {
        rememberRecoveryAccessToken(data.session.access_token);
        return data.session;
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }

    return null;
  }, [rememberRecoveryAccessToken]);

  const resolveRecoverySession = useCallback(async () => {
    const params = readAuthParams();
    const urlError = params.get("error_description") || params.get("error");
    const tokenHash = params.get("token_hash");
    const code = params.get("code");
    const accessToken = params.get("access_token");
    const refreshToken = params.get("refresh_token");

    if (urlError) throw new Error(urlError.replace(/\+/g, " "));

    if (tokenHash) {
      const { data, error } = await supabase.auth.verifyOtp({
        token_hash: tokenHash,
        type: "recovery",
      });
      if (error) throw error;
      rememberRecoveryAccessToken(data.session?.access_token);
      return data.session;
    }

    if (code) {
      const { data, error } = await supabase.auth.exchangeCodeForSession(code);
      if (error) throw error;
      rememberRecoveryAccessToken(data.session?.access_token);
      return data.session;
    }

    if (accessToken && refreshToken) {
      rememberRecoveryAccessToken(accessToken);
      const { data, error } = await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });
      if (error) throw error;
      rememberRecoveryAccessToken(data.session?.access_token);
      return data.session;
    }

    return waitForStoredSession();
  }, [readAuthParams, rememberRecoveryAccessToken, waitForStoredSession]);

  const ensureRecoverySession = useCallback(async () => {
    if (!sessionSetupPromiseRef.current) {
      sessionSetupPromiseRef.current = resolveRecoverySession();
    }

    try {
      return await sessionSetupPromiseRef.current;
    } catch (error) {
      const session = await waitForStoredSession(1200);
      if (session) return session;
      sessionSetupPromiseRef.current = null;
      throw error;
    }
  }, [resolveRecoverySession, waitForStoredSession]);

  useEffect(() => {
    let mounted = true;

    ensureRecoverySession()
      .then((session) => {
        if (!mounted) return;
        if (session) {
          setReady(true);
          setStatusMessage("Enter and confirm your new password below.");
          cleanUrl();
        } else {
          setStatusMessage("Enter and confirm your new password below.");
        }
      })
      .catch(async () => {
        if (!mounted) return;
        const session = await waitForStoredSession(1200);
        if (!mounted) return;
        if (session) {
          setReady(true);
          setStatusMessage("Enter and confirm your new password below.");
          cleanUrl();
          return;
        }
        setStatusMessage(invalidLinkMessage);
      });

    const { data: sub } = supabase.auth.onAuthStateChange((event, session) => {
      if (!mounted) return;
      if (
        session &&
        (event === "PASSWORD_RECOVERY" ||
          event === "SIGNED_IN" ||
          event === "TOKEN_REFRESHED" ||
          event === "INITIAL_SESSION")
      ) {
        setReady(true);
        setStatusMessage("Enter and confirm your new password below.");
        cleanUrl();
      }
    });

    return () => {
      mounted = false;
      sub.subscription.unsubscribe();
    };
  }, [cleanUrl, ensureRecoverySession, invalidLinkMessage, waitForStoredSession]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password.length < 6) return toast.error("Password must be at least 6 characters.");
    if (password !== confirm) return toast.error("Passwords do not match.");
    setLoading(true);
    try {
      const session = await ensureRecoverySession();
      if (!session) {
        setLoading(false);
        setStatusMessage(invalidLinkMessage);
        return toast.error(invalidLinkMessage);
      }
      setReady(true);
      const { error } = await supabase.auth.updateUser({ password });
      setLoading(false);
      if (error) return toast.error(error.message);
      toast.success("Password updated. You're signed in.");
      navigate({ to: "/dashboard", replace: true });
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
              disabled={loading}
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
