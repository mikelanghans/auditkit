import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { ArrowLeft, FileText, Check, X, Minus, CheckCircle2 } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/audits/$id")({
  head: () => ({ meta: [{ title: "Audit — AuditKit" }] }),
  component: AuditView,
});

type Item = {
  id: string;
  category: string;
  title: string;
  description: string | null;
  severity: string;
  sort_order: number;
};
type Finding = { checklist_item_id: string; status: "pass" | "fail" | "na" | null; notes: string | null };

function AuditView() {
  const { id } = Route.useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const audit = useQuery({
    queryKey: ["audit", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, status, started_at, completed_at, summary, client:clients(id, name)")
        .eq("id", id).single();
      if (error) throw error;
      return data;
    },
  });

  const items = useQuery({
    queryKey: ["checklist-items"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("checklist_items")
        .select("id, category, title, description, severity, sort_order")
        .order("sort_order");
      if (error) throw error;
      return (data ?? []) as Item[];
    },
  });

  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audit_findings")
        .select("checklist_item_id, status, notes")
        .eq("audit_id", id);
      if (error) throw error;
      return (data ?? []) as Finding[];
    },
  });

  const findingsMap = useMemo(() => {
    const m = new Map<string, Finding>();
    findings.data?.forEach((f) => m.set(f.checklist_item_id, f));
    return m;
  }, [findings.data]);

  const categories = useMemo(() => {
    if (!items.data) return [];
    const seen = new Map<string, Item[]>();
    items.data.forEach((it) => {
      const arr = seen.get(it.category) ?? [];
      arr.push(it);
      seen.set(it.category, arr);
    });
    return Array.from(seen.entries()).map(([name, list]) => {
      const done = list.filter((it) => findingsMap.get(it.id)?.status).length;
      return { name, items: list, done, total: list.length };
    });
  }, [items.data, findingsMap]);

  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const currentCat = activeCategory ?? categories[0]?.name ?? null;

  const setFinding = useMutation({
    mutationFn: async (payload: { checklist_item_id: string; status: "pass" | "fail" | "na"; notes?: string | null }) => {
      const { error } = await supabase
        .from("audit_findings")
        .upsert(
          {
            audit_id: id,
            checklist_item_id: payload.checklist_item_id,
            status: payload.status,
            notes: payload.notes ?? null,
          },
          { onConflict: "audit_id,checklist_item_id" },
        );
      if (error) throw error;
    },
    onMutate: async (payload) => {
      await qc.cancelQueries({ queryKey: ["findings", id] });
      const prev = qc.getQueryData<Finding[]>(["findings", id]) ?? [];
      const next = prev.filter((f) => f.checklist_item_id !== payload.checklist_item_id);
      next.push({ checklist_item_id: payload.checklist_item_id, status: payload.status, notes: payload.notes ?? null });
      qc.setQueryData(["findings", id], next);
      return { prev };
    },
    onError: (_e, _p, ctx) => {
      if (ctx?.prev) qc.setQueryData(["findings", id], ctx.prev);
      toast.error("Could not save");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["findings", id] }),
  });

  const totalDone = categories.reduce((s, c) => s + c.done, 0);
  const totalItems = categories.reduce((s, c) => s + c.total, 0);
  const pct = totalItems ? Math.round((totalDone / totalItems) * 100) : 0;

  const complete = useMutation({
    mutationFn: async () => {
      const { error } = await supabase
        .from("audits")
        .update({ status: "completed", completed_at: new Date().toISOString() })
        .eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audit", id] });
      qc.invalidateQueries({ queryKey: ["audits"] });
      toast.success("Audit marked complete");
      navigate({ to: "/audits/$id/report", params: { id } });
    },
  });

  const catItems = categories.find((c) => c.name === currentCat)?.items ?? [];

  if (items.data && items.data.length === 0) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Card className="p-10 text-center">
          <h2 className="text-lg font-semibold">No checklist items yet</h2>
          <p className="text-sm text-muted-foreground mt-2">
            Seed the <code className="bg-muted px-1 rounded">checklist_items</code> table with your 35 items to begin auditing.
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <BackLink />
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{audit.data?.title}</h1>
          <p className="text-sm text-muted-foreground">
            {(audit.data as any)?.client?.name} · <span className="capitalize">{audit.data?.status.replace("_", " ")}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/audits/$id/report" params={{ id }}>
            <Button variant="outline"><FileText className="h-4 w-4 mr-1" /> Report</Button>
          </Link>
          {audit.data?.status !== "completed" && (
            <Button
              className="bg-navy text-navy-foreground hover:bg-navy/90"
              onClick={() => complete.mutate()}
              disabled={complete.isPending}
            >
              <CheckCircle2 className="h-4 w-4 mr-1" /> Mark complete
            </Button>
          )}
        </div>
      </div>

      <Card className="p-4">
        <div className="flex items-center justify-between text-sm mb-2">
          <span className="font-medium">Overall progress</span>
          <span className="text-muted-foreground">{totalDone}/{totalItems} · {pct}%</span>
        </div>
        <Progress value={pct} />
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-6">
        <aside className="bg-sidebar border border-sidebar-border rounded-lg p-2 h-fit sticky top-4">
          {categories.map((c) => {
            const p = c.total ? Math.round((c.done / c.total) * 100) : 0;
            const active = c.name === currentCat;
            return (
              <button
                key={c.name}
                onClick={() => setActiveCategory(c.name)}
                className={cn(
                  "w-full text-left px-3 py-2.5 rounded-md transition-colors",
                  active ? "bg-sidebar-accent text-sidebar-accent-foreground" : "hover:bg-sidebar-accent/50",
                )}
              >
                <div className="flex items-center justify-between text-sm font-medium">
                  <span className="truncate">{c.name}</span>
                  <span className={cn("text-xs ml-2", active ? "text-sidebar-accent-foreground" : "text-muted-foreground")}>{p}%</span>
                </div>
                <Progress value={p} className="h-1 mt-2" />
              </button>
            );
          })}
        </aside>

        <div className="space-y-3">
          {catItems.map((it) => (
            <ItemRow
              key={it.id}
              item={it}
              finding={findingsMap.get(it.id)}
              onSet={(status, notes) => setFinding.mutate({ checklist_item_id: it.id, status, notes })}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function BackLink() {
  return (
    <Link to="/dashboard" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
      <ArrowLeft className="h-4 w-4 mr-1" /> Dashboard
    </Link>
  );
}

function ItemRow({
  item, finding, onSet,
}: { item: Item; finding: Finding | undefined; onSet: (status: "pass" | "fail" | "na", notes: string | null) => void }) {
  const [notes, setNotes] = useState(finding?.notes ?? "");
  const status = finding?.status ?? null;
  const showNotes = status === "fail";

  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-medium">{item.title}</h3>
            <SeverityBadge severity={item.severity} />
          </div>
          {item.description && <p className="text-sm text-muted-foreground mt-1">{item.description}</p>}
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <StatusBtn label="Pass" icon={<Check className="h-4 w-4" />} active={status === "pass"} color="pass" onClick={() => onSet("pass", null)} />
          <StatusBtn label="Fail" icon={<X className="h-4 w-4" />} active={status === "fail"} color="fail" onClick={() => onSet("fail", notes || null)} />
          <StatusBtn label="N/A" icon={<Minus className="h-4 w-4" />} active={status === "na"} color="na" onClick={() => onSet("na", null)} />
        </div>
      </div>

      {showNotes && (
        <div className="mt-3 space-y-2">
          <Textarea
            placeholder="Describe the failure, evidence, remediation…"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            onBlur={() => {
              if ((notes || "") !== (finding?.notes || "")) onSet("fail", notes || null);
            }}
            rows={3}
          />
        </div>
      )}
    </Card>
  );
}

function StatusBtn({
  label, icon, active, color, onClick,
}: { label: string; icon: React.ReactNode; active: boolean; color: "pass" | "fail" | "na"; onClick: () => void }) {
  const palette = {
    pass: "border-status-pass/50 text-status-pass bg-status-pass/10",
    fail: "border-status-fail/50 text-status-fail bg-status-fail/10",
    na: "border-status-na/50 text-status-na bg-status-na/10",
  } as const;
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border text-xs font-medium transition-colors",
        active ? palette[color] : "border-border text-muted-foreground hover:bg-muted",
      )}
    >
      {icon}
      {label}
    </button>
  );
}
