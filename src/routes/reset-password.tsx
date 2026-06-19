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

function ResetPasswordPage() {
  const navigate = useNavigate();
  const [ready, setReady] = useState(false);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Supabase auto-parses the recovery token from the URL hash and creates a session.
    const { data: sub } = supabase.auth.onAuthStateChange((event) => {
      if (event === "PASSWORD_RECOVERY" || event === "SIGNED_IN") setReady(true);
    });
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) setReady(true);
    });
    return () => sub.subscription.unsubscribe();
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
          <p className="text-sm text-muted-foreground mb-4">
            {ready
              ? "Enter and confirm your new password below."
              : "Validating reset link…"}
          </p>
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
