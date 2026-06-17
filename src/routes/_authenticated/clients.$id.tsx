import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { ArrowLeft, ArrowRight, Pencil, Github, Unlink } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { toast } from "sonner";
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
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">{client.data.name}</h1>
            <p className="text-sm text-muted-foreground">
              {client.data.contact_name || "—"}{client.data.contact_email ? ` · ${client.data.contact_email}` : ""}
            </p>
            {client.data.app_url && (
              <p className="text-sm mt-1"><span className="text-muted-foreground">App:</span>{" "}<a href={client.data.app_url} target="_blank" rel="noreferrer" className="text-navy hover:underline">{client.data.app_url}</a></p>
            )}
            {client.data.notes && (
              <p className="text-sm mt-3 max-w-2xl whitespace-pre-wrap">{client.data.notes}</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <EditClientDialog client={client.data} />
            <NewAuditDialog />
          </div>
        </div>
      )}

      {client.data && <ConnectedAccountsSection client={client.data} />}


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

function EditClientDialog({ client }: { client: any }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(client.name ?? "");
  const [contactName, setContactName] = useState(client.contact_name ?? "");
  const [contactEmail, setContactEmail] = useState(client.contact_email ?? "");
  const [appUrl, setAppUrl] = useState(client.app_url ?? "");
  const [githubRepoUrl, setGithubRepoUrl] = useState(client.github_repo_url ?? "");
  const [githubToken, setGithubToken] = useState(client.github_token ?? "");
  const [notes, setNotes] = useState(client.notes ?? "");
  const qc = useQueryClient();

  useEffect(() => {
    if (!open) return;
    setName(client.name ?? "");
    setContactName(client.contact_name ?? "");
    setContactEmail(client.contact_email ?? "");
    setAppUrl(client.app_url ?? "");
    setGithubRepoUrl(client.github_repo_url ?? "");
    setGithubToken(client.github_token ?? "");
    setNotes(client.notes ?? "");
  }, [open, client]);

  const save = useMutation({
    mutationFn: async () => {
      const { error } = await supabase
        .from("clients")
        .update({
          name,
          contact_name: contactName || null,
          contact_email: contactEmail || null,
          app_url: appUrl || null,
          github_repo_url: githubRepoUrl || null,
          github_token: githubToken || null,
          notes: notes || null,
        })
        .eq("id", client.id);
      if (error) throw error;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["client", client.id] });
      qc.invalidateQueries({ queryKey: ["clients"] });
      setOpen(false);
      toast.success("Client updated");
    },
    onError: (e: any) => toast.error(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Pencil className="h-4 w-4 mr-1" /> Edit
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Edit client</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <Field label="Name" value={name} onChange={setName} required />
          <Field label="Contact name" value={contactName} onChange={setContactName} />
          <Field label="Contact email" value={contactEmail} onChange={setContactEmail} type="email" />
          <Field label="App URL" value={appUrl} onChange={setAppUrl} type="url" />
          <div className="space-y-1.5">
            <Label>Notes</Label>
            <Textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} />
          </div>
        </div>
        <DialogFooter>
          <Button disabled={!name || save.isPending} onClick={() => save.mutate()} className="bg-navy text-navy-foreground hover:bg-navy/90">
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, value, onChange, type = "text", required, placeholder }: { label: string; value: string; onChange: (v: string) => void; type?: string; required?: boolean; placeholder?: string }) {
  return (
    <div className="space-y-1.5">
      <Label>{label}{required ? " *" : ""}</Label>
      <Input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  );
}
