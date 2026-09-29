import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/leads")({
  head: () => ({ meta: [{ title: "Leads — AuditKit" }] }),
  component: LeadsPage,
});

const LEAD_STATUSES = ["new", "contacted", "qualified", "won", "lost", "ignored"] as const;

type Counts = { critical?: number; high?: number; medium?: number; low?: number };

function LeadsPage() {
  const qc = useQueryClient();
  // RLS limits public_checks to admins; anyone else sees an empty list.
  const leads = useQuery({
    queryKey: ["public-check-leads"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("public_checks")
        .select(
          "id, created_at, hostname, url, email, email_captured_at, marketing_consent, lead_status, summary",
        )
        .not("email", "is", null)
        .order("email_captured_at", { ascending: false })
        .limit(300);
      if (error) throw error;
      return data ?? [];
    },
  });

  const stats = useQuery({
    queryKey: ["public-check-stats"],
    queryFn: async () => {
      const since = new Date(Date.now() - 30 * 86400_000).toISOString();
      const { count } = await supabase
        .from("public_checks")
        .select("id", { count: "exact", head: true })
        .gte("created_at", since);
      return { checks30d: count ?? 0 };
    },
  });

  async function setStatus(id: string, lead_status: string) {
    const { error } = await supabase.from("public_checks").update({ lead_status }).eq("id", id);
    if (error) return toast.error(error.message);
    qc.invalidateQueries({ queryKey: ["public-check-leads"] });
  }

  const rows = leads.data ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Leads</h1>
        <p className="text-sm text-muted-foreground mt-1">
          People who ran the free key check at <code>/check</code> and asked for the full report.
          {stats.data &&
            ` ${stats.data.checks30d} checks in the last 30 days, ${rows.length} emails captured.`}
        </p>
      </div>

      {leads.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : rows.length === 0 ? (
        <Card className="p-6 text-sm text-muted-foreground">
          No leads yet. Share <code>/check</code> from the SafeShip site. (Only admins can see this
          list.)
        </Card>
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-muted-foreground border-b">
              <tr>
                <th className="p-3">Site</th>
                <th className="p-3">Email</th>
                <th className="p-3">Found</th>
                <th className="p-3">When</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const c = ((r.summary as any)?.counts ?? {}) as Counts;
                const serious = (c.critical ?? 0) + (c.high ?? 0) + (c.medium ?? 0);
                return (
                  <tr key={r.id} className="border-b last:border-0 align-top">
                    <td className="p-3">
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-medium hover:underline"
                      >
                        {r.hostname}
                      </a>
                    </td>
                    <td className="p-3">
                      <a href={`mailto:${r.email}`} className="hover:underline">
                        {r.email}
                      </a>
                      {r.marketing_consent && (
                        <div className="text-xs text-muted-foreground">OK to email tips</div>
                      )}
                    </td>
                    <td className="p-3">
                      {serious > 0 ? (
                        <span className="font-medium text-red-600">
                          {c.critical ? `${c.critical} critical ` : ""}
                          {c.high ? `${c.high} high ` : ""}
                          {c.medium ? `${c.medium} medium` : ""}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">Nothing serious</span>
                      )}
                    </td>
                    <td className="p-3 text-muted-foreground whitespace-nowrap">
                      {r.email_captured_at
                        ? formatDistanceToNow(new Date(r.email_captured_at), { addSuffix: true })
                        : ""}
                    </td>
                    <td className="p-3">
                      <select
                        value={r.lead_status}
                        onChange={(e) => setStatus(r.id, e.target.value)}
                        className="rounded-md border bg-background px-2 py-1 text-sm capitalize"
                      >
                        {LEAD_STATUSES.map((s) => (
                          <option key={s} value={s}>
                            {s}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
