import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { ShieldCheck, LogOut } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";

export function AppShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const path = useRouterState({ select: (s) => s.location.pathname });

  async function signOut() {
    await qc.cancelQueries();
    qc.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  const nav = [
    { to: "/dashboard", label: "Dashboard" },
    { to: "/clients", label: "Clients" },
  ] as const;

  return (
    <div className="min-h-screen bg-background">
      <header className="bg-navy text-navy-foreground border-b border-black/10">
        <div className="mx-auto max-w-7xl px-6 h-14 flex items-center justify-between">
          <Link to="/dashboard" className="flex items-center gap-2 font-semibold tracking-tight">
            <ShieldCheck className="h-5 w-5" />
            AuditKit
          </Link>
          <nav className="flex items-center gap-1">
            {nav.map((n) => (
              <Link
                key={n.to}
                to={n.to}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm transition-colors",
                  path.startsWith(n.to)
                    ? "bg-white/10 text-white"
                    : "text-white/70 hover:text-white hover:bg-white/5",
                )}
              >
                {n.label}
              </Link>
            ))}
            <button
              onClick={signOut}
              className="ml-2 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm text-white/80 hover:text-white hover:bg-white/5"
            >
              <LogOut className="h-4 w-4" />
              Sign out
            </button>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
    </div>
  );
}
