import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Plus, ArrowRight } from "lucide-react";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/clients/")({
  head: () => ({ meta: [{ title: "Clients — AuditKit" }] }),
  component: ClientsPage,
});

function ClientsPage() {
  const list = useQuery({
    queryKey: ["clients", "list-full"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("clients")
        .select("id, name, contact_name, contact_email, created_at")
        .order("created_at", { ascending: false });
      if (error) throw error;
      return data ?? [];
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Clients</h1>
          <p className="text-sm text-muted-foreground">Organizations you audit.</p>
        </div>
        <NewClientDialog />
      </div>

      {list.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : list.data && list.data.length > 0 ? (
        <div className="grid gap-3">
          {list.data.map((c) => (
            <Link key={c.id} to="/clients/$id" params={{ id: c.id }} className="group block">
              <Card className="p-4 flex items-center justify-between hover:border-navy/40 transition-colors">
                <div>
                  <div className="font-medium">{c.name}</div>
                  <div className="text-sm text-muted-foreground">
                    {c.contact_name || "—"}{c.contact_email ? ` · ${c.contact_email}` : ""}
                  </div>
                </div>
                <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:text-navy transition-colors" />
              </Card>
            </Link>
          ))}
        </div>
      ) : (
        <Card className="p-10 text-center">
          <p className="text-sm text-muted-foreground mb-4">No clients yet.</p>
          <NewClientDialog />
        </Card>
      )}
    </div>
  );
}

function NewClientDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [contactName, setContactName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [appUrl, setAppUrl] = useState("");
  const [githubRepoUrl, setGithubRepoUrl] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [notes, setNotes] = useState("");
  const qc = useQueryClient();

  const create = useMutation({
    mutationFn: async () => {
      const { data: u } = await supabase.auth.getUser();
      if (!u.user) throw new Error("Not signed in");
      const { error } = await supabase.from("clients").insert({
        name,
        contact_name: contactName || null,
        contact_email: contactEmail || null,
        app_url: appUrl || null,
        github_repo_url: githubRepoUrl || null,
        github_token: githubToken || null,
        notes: notes || null,
        created_by: u.user.id,
      });
      if (error) throw error;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients"] });
      setOpen(false);
      setName(""); setContactName(""); setContactEmail(""); setAppUrl(""); setGithubRepoUrl(""); setGithubToken(""); setNotes("");
      toast.success("Client added");
    },
    onError: (e: any) => toast.error(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="bg-navy text-navy-foreground hover:bg-navy/90">
          <Plus className="h-4 w-4 mr-1" /> New client
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Add client</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <Field label="Name" value={name} onChange={setName} required />
          <Field label="Contact name" value={contactName} onChange={setContactName} />
          <Field label="Contact email" value={contactEmail} onChange={setContactEmail} type="email" />
          <Field label="App URL" value={appUrl} onChange={setAppUrl} type="url" />
          <Field label="GitHub repo URL" value={githubRepoUrl} onChange={setGithubRepoUrl} type="url" placeholder="https://github.com/owner/repo" />
          <Field label="GitHub access token" value={githubToken} onChange={setGithubToken} type="password" placeholder="Fine-grained PAT with repo: read" />
          <div className="space-y-1.5">
            <Label>Notes</Label>
            <Textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} />
          </div>
        </div>
        <DialogFooter>
          <Button disabled={!name || create.isPending} onClick={() => create.mutate()} className="bg-navy text-navy-foreground hover:bg-navy/90">
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
