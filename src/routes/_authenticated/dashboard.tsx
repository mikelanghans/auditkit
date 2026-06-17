import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Plus, ClipboardList, Users, ArrowRight } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { formatDistanceToNow } from "date-fns";
import { DeleteAuditButton } from "@/components/delete-audit-button";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({ meta: [{ title: "Dashboard — AuditKit" }] }),
  component: Dashboard,
});

function Dashboard() {
  const audits = useQuery({
    queryKey: ["audits", "active"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, status, started_at, client:clients(id, name)")
        .neq("status", "completed")
        .order("started_at", { ascending: false });
      if (error) throw error;
      return data ?? [];
    },
  });

  const completed = useQuery({
    queryKey: ["audits", "completed-count"],
    queryFn: async () => {
      const { count } = await supabase
        .from("audits")
        .select("*", { count: "exact", head: true })
        .eq("status", "completed");
      return count ?? 0;
    },
  });

  const clientsCount = useQuery({
    queryKey: ["clients", "count"],
    queryFn: async () => {
      const { count } = await supabase.from("clients").select("*", { count: "exact", head: true });
      return count ?? 0;
    },
  });

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">Active audits and recent activity.</p>
        </div>
        <NewAuditDialog />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Active audits" value={audits.data?.length ?? 0} icon={<ClipboardList className="h-5 w-5" />} />
        <Stat label="Completed" value={completed.data ?? 0} icon={<ClipboardList className="h-5 w-5" />} />
        <Stat label="Clients" value={clientsCount.data ?? 0} icon={<Users className="h-5 w-5" />} />
      </div>

      <section>
        <h2 className="text-lg font-semibold mb-3">Active audits</h2>
        {audits.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : audits.data && audits.data.length > 0 ? (
          <div className="grid gap-3">
            {audits.data.map((a: any) => (
              <Card key={a.id} className="p-4 flex items-center justify-between gap-3 hover:border-navy/40 transition-colors group">
                <Link
                  to="/audits/$id"
                  params={{ id: a.id }}
                  className="flex items-center justify-between gap-3 flex-1 min-w-0"
                >
                  <div className="min-w-0">
                    <div className="font-medium truncate">{a.title}</div>
                    <div className="text-sm text-muted-foreground truncate">
                      {a.client?.name} · started {formatDistanceToNow(new Date(a.started_at), { addSuffix: true })}
                    </div>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:text-navy transition-colors shrink-0" />
                </Link>
                <DeleteAuditButton auditId={a.id} title={a.title} variant="icon" />
              </Card>
            ))}
          </div>
        ) : (
          <Card className="p-8 text-center text-sm text-muted-foreground">
            No active audits. <NewAuditDialog inline /> to begin.
          </Card>
        )}
      </section>
    </div>
  );
}

function Stat({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between text-muted-foreground">
        <span className="text-sm">{label}</span>
        {icon}
      </div>
      <div className="mt-2 text-3xl font-semibold tracking-tight">{value}</div>
    </Card>
  );
}

export function NewAuditDialog({ inline = false }: { inline?: boolean }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [clientId, setClientId] = useState("");
  const qc = useQueryClient();
  const navigate = useNavigate();

  const clients = useQuery({
    queryKey: ["clients", "list"],
    queryFn: async () => {
      const { data, error } = await supabase.from("clients").select("id, name").order("name");
      if (error) throw error;
      return data ?? [];
    },
    enabled: open,
  });

  const create = useMutation({
    mutationFn: async () => {
      const { data: u } = await supabase.auth.getUser();
      if (!u.user) throw new Error("Not signed in");
      const { data, error } = await supabase
        .from("audits")
        .insert({ title, client_id: clientId, created_by: u.user.id, status: "in_progress" })
        .select("id")
        .single();
      if (error) throw error;
      return data;
    },
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ["audits"] });
      setOpen(false);
      setTitle("");
      setClientId("");
      toast.success("Audit created");
      navigate({ to: "/audits/$id", params: { id: d.id } });
    },
    onError: (e: any) => toast.error(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {inline ? (
          <button className="text-navy underline-offset-2 hover:underline">Create one</button>
        ) : (
          <Button className="bg-navy text-navy-foreground hover:bg-navy/90">
            <Plus className="h-4 w-4 mr-1" /> New audit
          </Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Start a new audit</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>Client</Label>
            <Select value={clientId} onValueChange={setClientId}>
              <SelectTrigger><SelectValue placeholder={clients.data?.length ? "Select a client" : "No clients yet — create one first"} /></SelectTrigger>
              <SelectContent>
                {clients.data?.map((c) => (
                  <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Audit title</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Q2 2026 Security Review" />
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => create.mutate()}
            disabled={!title || !clientId || create.isPending}
            className="bg-navy text-navy-foreground hover:bg-navy/90"
          >
            Start audit
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
