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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ArrowLeft, ArrowRight, Pencil, Github, Unlink, Plus } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { toast } from "sonner";
import { NewAuditDialog } from "./dashboard";
import { WebsitesField } from "./clients.index";

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
            {client.data.websites && client.data.websites.length > 0 && (
              <div className="text-sm mt-1 space-y-0.5">
                <span className="text-muted-foreground">Websites:</span>
                <ul className="space-y-0.5">
                  {client.data.websites.map((w: string) => (
                    <li key={w}>
                      <a href={w} target="_blank" rel="noreferrer" className="text-navy hover:underline break-all">{w}</a>
                    </li>
                  ))}
                </ul>
              </div>
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
  const [websites, setWebsites] = useState<string[]>(
    client.websites && client.websites.length > 0 ? client.websites : [""],
  );
  const [notes, setNotes] = useState(client.notes ?? "");
  const qc = useQueryClient();

  useEffect(() => {
    if (!open) return;
    setName(client.name ?? "");
    setContactName(client.contact_name ?? "");
    setContactEmail(client.contact_email ?? "");
    setWebsites(client.websites && client.websites.length > 0 ? client.websites : [""]);
    setNotes(client.notes ?? "");
  }, [open, client]);

  const save = useMutation({
    mutationFn: async () => {
      const cleaned = websites.map((w) => w.trim()).filter(Boolean);
      const { error } = await supabase
        .from("clients")
        .update({
          name,
          contact_name: contactName || null,
          contact_email: contactEmail || null,
          websites: cleaned,
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
          <WebsitesField websites={websites} setWebsites={setWebsites} />
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
  const repos = useQuery({
    queryKey: ["client-repos", client.id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("client_repos")
        .select("id, label, repo_url, github_token, website_url, updated_at")
        .eq("client_id", client.id)
        .order("created_at", { ascending: true });
      if (error) throw error;
      return data ?? [];
    },
  });

  const websites: string[] = client.websites ?? [];
  const [adding, setAdding] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [websiteUrl, setWebsiteUrl] = useState<string>("");

  const reset = () => { setLabel(""); setRepoUrl(""); setWebsiteUrl(""); setAdding(false); setEditingId(null); };

  const upsert = useMutation({
    mutationFn: async () => {
      if (editingId) {
        const { error } = await supabase.from("client_repos").update({
          label: label.trim() || "Repo",
          repo_url: repoUrl.trim(),
          website_url: websiteUrl || null,
        }).eq("id", editingId);
        if (error) throw error;
      } else {
        const { error } = await supabase.from("client_repos").insert({
          client_id: client.id,
          label: label.trim() || "Repo",
          repo_url: repoUrl.trim(),
          website_url: websiteUrl || null,
        });
        if (error) throw error;
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["client-repos", client.id] });
      toast.success(editingId ? "Repo updated" : "Repo added");
      reset();
    },
    onError: (e: any) => toast.error(e.message),
  });

  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("client_repos").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["client-repos", client.id] });
      toast.success("Repo disconnected");
    },
    onError: (e: any) => toast.error(e.message),
  });

  const startEdit = (r: any) => {
    setEditingId(r.id);
    setAdding(false);
    setLabel(r.label);
    setRepoUrl(r.repo_url);
    setWebsiteUrl(r.website_url ?? "");
  };

  const list = repos.data ?? [];

  return (
    <section>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold">Connected Accounts</h2>
        {!adding && !editingId && (
          <Button variant="outline" size="sm" onClick={() => { reset(); setAdding(true); }}>
            <Plus className="h-3.5 w-3.5 mr-1" /> Add repo
          </Button>
        )}
      </div>
      <Card className="p-4 space-y-3">
        <div className="flex items-center gap-2">
          <div className="rounded-md bg-muted p-1.5"><Github className="h-4 w-4" /></div>
          <span className="font-medium text-sm">GitHub</span>
          {list.length > 0 ? (
            <span className="inline-flex items-center gap-1 text-xs text-status-pass">
              <span className="h-1.5 w-1.5 rounded-full bg-status-pass" /> {list.length} connected
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">Not connected</span>
          )}
        </div>

        {list.length === 0 && !adding && (
          <p className="text-xs text-muted-foreground">
            Add one or more repos to enable one-click Scan Repo and AI Assist.
          </p>
        )}

        {list.length > 0 && (
          <ul className="divide-y divide-border rounded-md border border-border">
            {list.map((r: any) => (
              <li key={r.id} className="p-3">
                {editingId === r.id ? (
                  <RepoForm
                    label={label} setLabel={setLabel}
                    repoUrl={repoUrl} setRepoUrl={setRepoUrl}
                    websiteUrl={websiteUrl} setWebsiteUrl={setWebsiteUrl}
                    websites={websites}
                    onCancel={reset}
                    onSave={() => upsert.mutate()}
                    saving={upsert.isPending}
                    canSave={!!repoUrl.trim()}
                  />
                ) : (
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-sm">{r.label}</span>
                        {r.website_url ? (
                          <span className="text-[10px] uppercase tracking-wide text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                            {r.website_url}
                          </span>
                        ) : (
                          <span className="text-[10px] uppercase tracking-wide text-status-na">unassigned</span>
                        )}
                        {!r.github_token && <span className="text-[10px] uppercase text-status-fail">no PAT</span>}
                      </div>
                      <a href={r.repo_url} target="_blank" rel="noreferrer" className="text-xs text-navy hover:underline break-all">
                        {r.repo_url}
                      </a>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <Button variant="ghost" size="sm" onClick={() => startEdit(r)}>
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => remove.mutate(r.id)}
                        disabled={remove.isPending}
                        className="text-status-fail hover:text-status-fail hover:bg-status-fail/5"
                      >
                        <Unlink className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}

        {adding && (
          <div className="rounded-md border border-border p-3">
            <RepoForm
              label={label} setLabel={setLabel}
              repoUrl={repoUrl} setRepoUrl={setRepoUrl}
              token={token} setToken={setToken}
              websiteUrl={websiteUrl} setWebsiteUrl={setWebsiteUrl}
              websites={websites}
              tokenPlaceholder="ghp_… or github_pat_…"
              onCancel={reset}
              onSave={() => upsert.mutate()}
              saving={upsert.isPending}
              canSave={!!repoUrl.trim() && !!token.trim()}
            />
          </div>
        )}
      </Card>
    </section>
  );
}

function RepoForm({
  label, setLabel, repoUrl, setRepoUrl, token, setToken, tokenPlaceholder,
  websiteUrl, setWebsiteUrl, websites,
  onCancel, onSave, saving, canSave,
}: {
  label: string; setLabel: (v: string) => void;
  repoUrl: string; setRepoUrl: (v: string) => void;
  token: string; setToken: (v: string) => void;
  websiteUrl: string; setWebsiteUrl: (v: string) => void;
  websites: string[];
  tokenPlaceholder: string;
  onCancel: () => void; onSave: () => void; saving: boolean; canSave: boolean;
}) {
  const UNASSIGNED = "__unassigned__";
  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <Label>Label</Label>
        <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Frontend, API, Worker" />
      </div>
      <div className="space-y-1.5">
        <Label>Website</Label>
        {websites.length > 0 ? (
          <Select
            value={websiteUrl || UNASSIGNED}
            onValueChange={(v) => setWebsiteUrl(v === UNASSIGNED ? "" : v)}
          >
            <SelectTrigger><SelectValue placeholder="Select a website" /></SelectTrigger>
            <SelectContent>
              <SelectItem value={UNASSIGNED}>Unassigned</SelectItem>
              {websites.map((w) => (
                <SelectItem key={w} value={w}>{w}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : (
          <p className="text-xs text-muted-foreground">Add websites to this client to link a repo to a specific site.</p>
        )}
      </div>
      <div className="space-y-1.5">
        <Label>Repository URL</Label>
        <Input type="url" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} placeholder="https://github.com/owner/repo" />
      </div>
      <div className="space-y-1.5">
        <Label>Personal Access Token</Label>
        <Input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder={tokenPlaceholder} />
        <p className="text-xs text-muted-foreground">Fine-grained PAT: <em>Contents: Read</em> + <em>Metadata: Read</em>.</p>
      </div>
      <div className="flex justify-end gap-2">
        <Button variant="ghost" size="sm" onClick={onCancel}>Cancel</Button>
        <Button size="sm" onClick={onSave} disabled={saving || !canSave} className="bg-navy text-navy-foreground hover:bg-navy/90">
          Save
        </Button>
      </div>
    </div>
  );
}
