import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { ShieldCheck, LogOut } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import { RunningTimerChip } from "@/components/time-tracker";

export function AppShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const path = useRouterState({ select: (s) => s.location.pathname });

  const pendingCount = useQuery({
    queryKey: ["threat-feed-pending-count"],
    queryFn: async () => {
      const { count } = await supabase
        .from("threat_feed_items")
        .select("*", { count: "exact", head: true })
        .eq("status", "pending_review");
      return count ?? 0;
    },
    refetchInterval: 60_000,
  });

  async function signOut() {
    await qc.cancelQueries();
    qc.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  const nav = [
    { to: "/dashboard", label: "Dashboard" },
    { to: "/clients", label: "Clients" },
    { to: "/threat-feed", label: "Threat Feed" },
    { to: "/leads", label: "Leads" },
  ] as const;

  return (
    <div className="min-h-screen bg-background print:min-h-0 print:bg-transparent">
      <header className="bg-navy text-navy-foreground border-b border-black/10 print:hidden">
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
                  "relative px-3 py-1.5 rounded-md text-sm transition-colors inline-flex items-center gap-1.5",
                  path.startsWith(n.to)
                    ? "bg-white/10 text-white"
                    : "text-white/70 hover:text-white hover:bg-white/5",
                )}
              >
                {n.label}
                {n.to === "/threat-feed" && (pendingCount.data ?? 0) > 0 && (
                  <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full bg-red-500 text-white text-[11px] font-semibold">
                    {pendingCount.data}
                  </span>
                )}
              </Link>
            ))}
            <RunningTimerChip />
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
      <main className="mx-auto max-w-7xl px-6 py-8 print:max-w-none print:p-0">{children}</main>
    </div>
  );
}

