import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Plus, ClipboardList, Users, AlertOctagon, ArrowRight, ExternalLink, ArrowUpDown } from "lucide-react";
import { toast } from "sonner";
import { formatDistanceToNow } from "date-fns";
import { computeSecurityScore, failuresBySeverity, gradeTone } from "@/lib/security-score";
import { cn } from "@/lib/utils";
import { BUILT_WITH_OPTIONS, type BuiltWith } from "@/lib/built-with";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({ meta: [{ title: "Dashboard — AuditKit" }] }),
  component: Dashboard,
});

type EngagementType = "prospect" | "one_time" | "retainer";

const ENGAGEMENT_LABEL: Record<EngagementType, string> = {
  prospect: "Prospect",
  one_time: "One-time audit",
  retainer: "Retainer",
};

type SortKey = "score_asc" | "last_scan_desc" | "name_asc";
type Filter = "all" | "retainer" | "one_time";

function Dashboard() {
  const [sort, setSort] = useState<SortKey>("score_asc");
  const [filter, setFilter] = useState<Filter>("all");

  const clients = useQuery({
    queryKey: ["dashboard", "clients"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("clients")
        .select("id, name, websites, engagement_type, created_at")
        .order("name");
      if (error) throw error;
      return data ?? [];
    },
  });

  const audits = useQuery({
    queryKey: ["dashboard", "audits"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, client_id, status, started_at, completed_at, website_url")
        .order("started_at", { ascending: false });
      if (error) throw error;
      return data ?? [];
    },
  });

  const items = useQuery({
    queryKey: ["dashboard", "checklist-items"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("checklist_items")
        .select("id, severity")
        .eq("is_active", true);
      if (error) throw error;
      return data ?? [];
    },
  });

  const findings = useQuery({
    queryKey: ["dashboard", "findings"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audit_findings")
        .select("audit_id, checklist_item_id, status");
      if (error) throw error;
      return data ?? [];
    },
  });

  // Latest audit per client (status priority gives in_progress preference of newest)
  const latestAuditByClient = useMemo(() => {
    const m = new Map<string, any>();
    for (const a of audits.data ?? []) {
      const prev = m.get(a.client_id);
      if (!prev) { m.set(a.client_id, a); continue; }
      const prevTs = new Date(prev.started_at).getTime();
      const curTs = new Date(a.started_at).getTime();
      if (curTs > prevTs) m.set(a.client_id, a);
    }
    return m;
  }, [audits.data]);

  const findingsByAudit = useMemo(() => {
    const m = new Map<string, Map<string, string>>();
    for (const f of findings.data ?? []) {
      let inner = m.get(f.audit_id);
      if (!inner) { inner = new Map(); m.set(f.audit_id, inner); }
      if (f.status) inner.set(f.checklist_item_id, f.status);
    }
    return m;
  }, [findings.data]);

  const rows = useMemo(() => {
    const itemList = (items.data ?? []) as { id: string; severity: string | null }[];
    return (clients.data ?? []).map((c: any) => {
      const latest = latestAuditByClient.get(c.id);
      const statusMap = latest ? findingsByAudit.get(latest.id) ?? new Map() : new Map();
      const score = computeSecurityScore(itemList, statusMap as Map<string, any>);
      const risk = latest ? failuresBySeverity(itemList, statusMap as Map<string, any>) : { critical: 0, high: 0, medium: 0, low: 0 };
      const lastScanAt: string | null = latest?.completed_at ?? latest?.started_at ?? null;
      return {
        client: c,
        latest,
        score,
        risk,
        lastScanAt,
      };
    });
  }, [clients.data, items.data, latestAuditByClient, findingsByAudit]);

  const filtered = useMemo(() => {
    const f = filter === "all" ? rows : rows.filter((r) => r.client.engagement_type === filter);
    const sorted = [...f].sort((a, b) => {
      if (sort === "name_asc") return a.client.name.localeCompare(b.client.name);
      if (sort === "last_scan_desc") {
        const at = a.lastScanAt ? new Date(a.lastScanAt).getTime() : 0;
        const bt = b.lastScanAt ? new Date(b.lastScanAt).getTime() : 0;
        return bt - at;
      }
      // score_asc: worst first; nulls last
      const as = a.score.score ?? 101;
      const bs = b.score.score ?? 101;
      return as - bs;
    });
    return sorted;
  }, [rows, filter, sort]);

  const activeAuditCount = (audits.data ?? []).filter((a: any) => a.status !== "completed").length;
  const totalCritical = rows.reduce((s, r) => s + r.risk.critical, 0);

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">Security posture across all clients.</p>
        </div>
        <NewAuditDialog />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Total clients" value={clients.data?.length ?? 0} icon={<Users className="h-5 w-5" />} />
        <Stat label="Active audits" value={activeAuditCount} icon={<ClipboardList className="h-5 w-5" />} />
        <Stat
          label="Open critical findings"
          value={totalCritical}
          icon={<AlertOctagon className="h-5 w-5" />}
          tone={totalCritical > 0 ? "danger" : "default"}
        />
      </div>

      <section className="space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <h2 className="text-lg font-semibold">Clients</h2>
          <div className="flex items-center gap-2 flex-wrap">
            <ToggleGroup type="single" value={filter} onValueChange={(v) => v && setFilter(v as Filter)} className="flex-wrap">
              <ToggleGroupItem value="all" className="text-xs">All</ToggleGroupItem>
              <ToggleGroupItem value="retainer" className="text-xs">Retainer</ToggleGroupItem>
              <ToggleGroupItem value="one_time" className="text-xs">One-time</ToggleGroupItem>
            </ToggleGroup>
            <Select value={sort} onValueChange={(v) => setSort(v as SortKey)}>
              <SelectTrigger className="w-[200px] text-sm">
                <ArrowUpDown className="h-3.5 w-3.5 mr-1.5 text-muted-foreground" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="score_asc">Worst score first</SelectItem>
                <SelectItem value="last_scan_desc">Most recent scan</SelectItem>
                <SelectItem value="name_asc">Name (A–Z)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {clients.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : filtered.length === 0 ? (
          <Card className="p-8 text-center text-sm text-muted-foreground">No clients match this filter.</Card>
        ) : (
          <div className="grid gap-3">
            {filtered.map((r) => (
              <ClientRow key={r.client.id} row={r} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function ClientRow({ row }: { row: any }) {
  const { client, latest, score, risk, lastScanAt } = row;
  const tone = gradeTone(score.grade);
  const primaryUrl = (client.websites && client.websites[0]) || latest?.website_url || null;
  const engagement = (client.engagement_type ?? "prospect") as EngagementType;
  return (
    <Card className="p-4">
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
        <div className="md:col-span-4 min-w-0">
          <Link to="/clients/$id" params={{ id: client.id }} className="font-medium hover:underline">
            {client.name}
          </Link>
          <div className="text-xs text-muted-foreground truncate flex items-center gap-1 mt-0.5">
            {primaryUrl ? (
              <a href={primaryUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-foreground truncate">
                <span className="truncate">{primaryUrl}</span>
                <ExternalLink className="h-3 w-3 shrink-0" />
              </a>
            ) : <span>No website set</span>}
          </div>
          <EngagementBadge engagement={engagement} />
        </div>

        <div className="md:col-span-2 text-sm">
          <div className="text-xs text-muted-foreground">Last scan</div>
          <div>{lastScanAt ? formatDistanceToNow(new Date(lastScanAt), { addSuffix: true }) : <span className="text-muted-foreground">—</span>}</div>
        </div>

        <div className="md:col-span-2">
          <div className="text-xs text-muted-foreground">Security score</div>
          <div className="flex items-baseline gap-2">
            <span className={cn(
              "text-2xl font-semibold tabular-nums",
              tone === "pass" && "text-status-pass",
              tone === "warn" && "text-status-na",
              tone === "fail" && "text-status-fail",
              tone === "muted" && "text-muted-foreground",
            )}>{score.score ?? "—"}</span>
            <span className="text-xs text-muted-foreground">{score.grade}</span>
          </div>
        </div>

        <div className="md:col-span-2">
          <div className="text-xs text-muted-foreground mb-1">Open findings</div>
          <div className="flex items-center gap-1.5">
            <CountPill count={risk.critical} label="C" tone="fail" />
            <CountPill count={risk.high} label="H" tone="warn" />
          </div>
        </div>

        <div className="md:col-span-2 flex md:justify-end">
          {latest ? (
            <Link to="/audits/$id" params={{ id: latest.id }}>
              <Button size="sm" variant="outline">
                View Audit <ArrowRight className="h-3.5 w-3.5 ml-1" />
              </Button>
            </Link>
          ) : (
            <Link to="/clients/$id" params={{ id: client.id }}>
              <Button size="sm" variant="ghost">No audit yet</Button>
            </Link>
          )}
        </div>
      </div>
    </Card>
  );
}

function EngagementBadge({ engagement }: { engagement: EngagementType }) {
  const colors: Record<EngagementType, string> = {
    retainer: "bg-emerald-600 text-white hover:bg-emerald-600",
    one_time: "bg-sky-600 text-white hover:bg-sky-600",
    prospect: "bg-muted text-foreground",
  };
  return (
    <Badge className={cn("mt-1.5 text-[10px]", colors[engagement])}>
      {ENGAGEMENT_LABEL[engagement]}
    </Badge>
  );
}

function CountPill({ count, label, tone }: { count: number; label: string; tone: "fail" | "warn" }) {
  if (count === 0) {
    return <span className="text-xs text-muted-foreground">0 {label}</span>;
  }
  return (
    <span className={cn(
      "inline-flex items-center justify-center min-w-[36px] h-6 px-2 rounded-md text-xs font-semibold",
      tone === "fail" && "bg-red-500/15 text-red-600 dark:text-red-400",
      tone === "warn" && "bg-orange-500/15 text-orange-600 dark:text-orange-400",
    )}>
      {count} {label}
    </span>
  );
}

function Stat({
  label, value, icon, tone = "default",
}: { label: string; value: number; icon: React.ReactNode; tone?: "default" | "danger" }) {
  return (
    <Card className={cn("p-5", tone === "danger" && value > 0 && "border-status-fail/40")}>
      <div className="flex items-center justify-between text-muted-foreground">
        <span className="text-sm">{label}</span>
        {icon}
      </div>
      <div className={cn(
        "mt-2 text-3xl font-semibold tracking-tight tabular-nums",
        tone === "danger" && value > 0 && "text-status-fail",
      )}>{value}</div>
    </Card>
  );
}

export function NewAuditDialog({ inline = false }: { inline?: boolean }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [clientId, setClientId] = useState("");
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [builtWith, setBuiltWith] = useState<BuiltWith | "">("");
  const qc = useQueryClient();
  const navigate = useNavigate();

  const clients = useQuery({
    queryKey: ["clients", "list-with-websites"],
    queryFn: async () => {
      const { data, error } = await supabase.from("clients").select("id, name, websites").order("name");
      if (error) throw error;
      return data ?? [];
    },
    enabled: open,
  });

  const selectedClient = clients.data?.find((c) => c.id === clientId);
  const websiteOptions = selectedClient?.websites ?? [];

  const create = useMutation({
    mutationFn: async () => {
      const { data: u } = await supabase.auth.getUser();
      if (!u.user) throw new Error("Not signed in");
      const { data, error } = await supabase
        .from("audits")
        .insert({
          title,
          client_id: clientId,
          created_by: u.user.id,
          status: "in_progress",
          website_url: websiteUrl || null,
          built_with: builtWith || null,
        } as any)
        .select("id")
        .single();
      if (error) throw error;
      return data;
    },
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ["audits"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      setOpen(false);
      setTitle("");
      setClientId("");
      setWebsiteUrl("");
      setBuiltWith("");
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
            <Select value={clientId} onValueChange={(v) => { setClientId(v); setWebsiteUrl(""); }}>
              <SelectTrigger><SelectValue placeholder={clients.data?.length ? "Select a client" : "No clients yet — create one first"} /></SelectTrigger>
              <SelectContent>
                {clients.data?.map((c) => (
                  <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {clientId && (
            <div className="space-y-1.5">
              <Label>Website</Label>
              {websiteOptions.length > 0 ? (
                <Select value={websiteUrl} onValueChange={setWebsiteUrl}>
                  <SelectTrigger><SelectValue placeholder="Select a website" /></SelectTrigger>
                  <SelectContent>
                    {websiteOptions.map((w) => (
                      <SelectItem key={w} value={w}>{w}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <p className="text-xs text-muted-foreground">This client has no websites configured. Add one on the client first.</p>
              )}
            </div>
          )}
          <div className="space-y-1.5">
            <Label>Audit title</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Q2 2026 Security Review" />
          </div>
          <div className="space-y-1.5">
            <Label>Built with <span className="text-muted-foreground font-normal">(optional)</span></Label>
            <Select value={builtWith} onValueChange={(v) => setBuiltWith(v as BuiltWith)}>
              <SelectTrigger><SelectValue placeholder="Which tool built this app?" /></SelectTrigger>
              <SelectContent>
                {BUILT_WITH_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">Tailors remediation prompts and helps track patterns across audits.</p>
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => create.mutate()}
            disabled={!title || !clientId || !websiteUrl || create.isPending}
            className="bg-navy text-navy-foreground hover:bg-navy/90"
          >
            Start audit
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
