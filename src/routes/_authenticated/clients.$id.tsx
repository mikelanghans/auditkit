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

function ConnectedAccountsSection({ client }: { client: any }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [repoUrl, setRepoUrl] = useState(client.github_repo_url ?? "");
  const [token, setToken] = useState("");
  const connected = !!(client.github_repo_url && client.github_token);

  useEffect(() => {
    setRepoUrl(client.github_repo_url ?? "");
    setToken("");
  }, [client.id, client.github_repo_url, client.github_token]);

  const save = useMutation({
    mutationFn: async () => {
      const update: any = { github_repo_url: repoUrl.trim() || null };
      if (token.trim()) update.github_token = token.trim();
      const { error } = await supabase.from("clients").update(update).eq("id", client.id);
      if (error) throw error;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["client", client.id] });
      setEditing(false);
      setToken("");
      toast.success("GitHub credentials saved");
    },
    onError: (e: any) => toast.error(e.message),
  });

  const disconnect = useMutation({
    mutationFn: async () => {
      const { error } = await supabase
        .from("clients")
        .update({ github_repo_url: null, github_token: null })
        .eq("id", client.id);
      if (error) throw error;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["client", client.id] });
      setRepoUrl("");
      setToken("");
      toast.success("GitHub disconnected");
    },
    onError: (e: any) => toast.error(e.message),
  });

  return (
    <section>
      <h2 className="text-lg font-semibold mb-3">Connected Accounts</h2>
      <Card className="p-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-start gap-3 min-w-0">
            <div className="rounded-md bg-muted p-2 shrink-0">
              <Github className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium">GitHub</span>
                {connected ? (
                  <span className="inline-flex items-center gap-1 text-xs text-status-pass">
                    <span className="h-1.5 w-1.5 rounded-full bg-status-pass" /> Connected
                  </span>
                ) : (
                  <span className="text-xs text-muted-foreground">Not connected</span>
                )}
              </div>
              {connected && !editing && (
                <a href={client.github_repo_url} target="_blank" rel="noreferrer" className="text-sm text-navy hover:underline break-all">
                  {client.github_repo_url}
                </a>
              )}
              {!connected && !editing && (
                <p className="text-xs text-muted-foreground mt-0.5">
                  Add a repo URL and PAT to enable one-click Scan Repo and AI Assist.
                </p>
              )}
            </div>
          </div>
          {!editing && (
            <div className="flex items-center gap-2 shrink-0">
              <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
                <Pencil className="h-3.5 w-3.5 mr-1" /> {connected ? "Update" : "Connect"}
              </Button>
              {connected && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => disconnect.mutate()}
                  disabled={disconnect.isPending}
                  className="text-status-fail border-status-fail/40 hover:bg-status-fail/5 hover:text-status-fail"
                >
                  <Unlink className="h-3.5 w-3.5 mr-1" /> Disconnect
                </Button>
              )}
            </div>
          )}
        </div>

        {editing && (
          <div className="space-y-3 mt-4">
            <div className="space-y-1.5">
              <Label>Repository URL</Label>
              <Input
                type="url"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
              />
            </div>
            <div className="space-y-1.5">
              <Label>Personal Access Token</Label>
              <Input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder={client.github_token ? "•••••••• (leave blank to keep existing)" : "ghp_… or github_pat_…"}
              />
              <p className="text-xs text-muted-foreground">
                Fine-grained PAT needs <em>Contents: Read</em> + <em>Metadata: Read</em>. Stored on the client and reused for future scans.
              </p>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => { setEditing(false); setRepoUrl(client.github_repo_url ?? ""); setToken(""); }}>
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => save.mutate()}
                disabled={save.isPending || !repoUrl.trim() || (!client.github_token && !token.trim())}
                className="bg-navy text-navy-foreground hover:bg-navy/90"
              >
                Save
              </Button>
            </div>
          </div>
        )}
      </Card>
    </section>
  );
}
