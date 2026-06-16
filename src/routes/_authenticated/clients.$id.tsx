import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { ArrowLeft, ArrowRight } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { NewAuditDialog } from "./dashboard";

export const Route = createFileRoute("/_authenticated/clients/$id")({
  head: () => ({ meta: [{ title: "Client — AuditKit" }] }),
  component: ClientDetail,
});

function ClientDetail() {
  const { id } = Route.useParams();
  const client = useQuery({
    queryKey: ["client", id],
    queryFn: async () => {
      const { data, error } = await supabase.from("clients").select("*").eq("id", id).single();
      if (error) throw error;
      return data;
    },
  });
  const audits = useQuery({
    queryKey: ["client-audits", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, status, started_at, completed_at")
        .eq("client_id", id)
        .order("started_at", { ascending: false });
      if (error) throw error;
      return data ?? [];
    },
  });

  return (
    <div className="space-y-6">
      <Link to="/clients" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="h-4 w-4 mr-1" /> All clients
      </Link>

      {client.data && (
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">{client.data.name}</h1>
            <p className="text-sm text-muted-foreground">
              {client.data.contact_name || "—"}{client.data.contact_email ? ` · ${client.data.contact_email}` : ""}
            </p>
            {client.data.notes && (
              <p className="text-sm mt-3 max-w-2xl whitespace-pre-wrap">{client.data.notes}</p>
            )}
          </div>
          <NewAuditDialog />
        </div>
      )}

      <section>
        <h2 className="text-lg font-semibold mb-3">Audits</h2>
        {audits.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : audits.data && audits.data.length > 0 ? (
          <div className="grid gap-3">
            {audits.data.map((a) => (
              <Link key={a.id} to="/audits/$id" params={{ id: a.id }} className="group block">
                <Card className="p-4 flex items-center justify-between hover:border-navy/40 transition-colors">
                  <div>
                    <div className="font-medium">{a.title}</div>
                    <div className="text-sm text-muted-foreground capitalize">
                      {a.status.replace("_", " ")} · {formatDistanceToNow(new Date(a.started_at), { addSuffix: true })}
                    </div>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:text-navy transition-colors" />
                </Card>
              </Link>
            ))}
          </div>
        ) : (
          <Card className="p-8 text-center text-sm text-muted-foreground">No audits yet for this client.</Card>
        )}
      </section>
    </div>
  );
}
