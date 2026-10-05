import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { CheckCircle2, CircleAlert, ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/progress")({
  head: () => ({
    meta: [
      { title: "Fix Progress — AuditKit" },
      { name: "description", content: "See which audit findings are fixed and which still need work." },
      { property: "og:title", content: "Fix Progress — AuditKit" },
      { property: "og:description", content: "See which audit findings are fixed and which still need work." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: ProgressPage,
});

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

type Row = {
  id: string;
  audit_id: string;
  status: string;
  resolved_at: string | null;
  checklist_items: { title: string; category: string; severity: string } | null;
  audits: { title: string; website_url: string | null } | null;
};

function pct(fixed: number, open: number) {
  const total = fixed + open;
  return total === 0 ? 100 : Math.round((fixed / total) * 100);
}

function ProgressPage() {
  const [view, setView] = useState<"open" | "fixed" | "all">("open");
  const q = useQuery({
    queryKey: ["fix-progress"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audit_findings")
        .select("id, audit_id, status, resolved_at, checklist_items(title, category, severity), audits(title, website_url)")
        .in("status", ["fail", "resolved"]);
      if (error) throw error;
      return (data ?? []) as unknown as Row[];
    },
  });

  const rows = q.data ?? [];
  const fixed = rows.filter((r) => r.status === "resolved").length;
  const open = rows.length - fixed;

  const perAudit = useMemo(() => {
    const m = new Map<string, { id: string; title: string; site: string | null; fixed: number; open: number; items: Row[] }>();
    for (const r of rows) {
      const a = m.get(r.audit_id) ?? { id: r.audit_id, title: r.audits?.title ?? "Audit", site: r.audits?.website_url ?? null, fixed: 0, open: 0, items: [] };
      if (r.status === "resolved") a.fixed++; else a.open++;
      a.items.push(r);
      m.set(r.audit_id, a);
    }
    for (const a of m.values()) {
      a.items.sort((x, y) =>
        (x.status === "fail" ? 0 : 1) - (y.status === "fail" ? 0 : 1) ||
        (SEV_ORDER[x.checklist_items?.severity ?? "low"] ?? 9) - (SEV_ORDER[y.checklist_items?.severity ?? "low"] ?? 9));
    }
    return [...m.values()].sort((a, b) => pct(a.fixed, a.open) - pct(b.fixed, b.open));
  }, [rows]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Fix Progress</h1>
        <p className="text-sm text-muted-foreground">Issues found across your audits, and how many have been fixed.</p>
      </div>

      {q.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : q.error ? (
        <p className="text-sm text-destructive">Couldn't load findings: {(q.error as Error).message}</p>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            <Card className="p-5">
              <div className="text-sm text-muted-foreground">Overall progress</div>
              <div className="mt-1 text-3xl font-semibold">{pct(fixed, open)}%</div>
              <Progress value={pct(fixed, open)} className="mt-3" />
            </Card>
            <Card className="p-5">
              <div className="flex items-center gap-2 text-sm text-muted-foreground"><CheckCircle2 className="h-4 w-4 text-status-pass" /> Fixed</div>
              <div className="mt-1 text-3xl font-semibold">{fixed}</div>
            </Card>
            <Card className="p-5">
              <div className="flex items-center gap-2 text-sm text-muted-foreground"><CircleAlert className="h-4 w-4 text-destructive" /> Still need work</div>
              <div className="mt-1 text-3xl font-semibold">{open}</div>
            </Card>
          </div>

          <ToggleGroup type="single" value={view} onValueChange={(v) => v && setView(v as any)} className="justify-start">
            <ToggleGroupItem value="open">Needs work</ToggleGroupItem>
            <ToggleGroupItem value="fixed">Fixed</ToggleGroupItem>
            <ToggleGroupItem value="all">All</ToggleGroupItem>
          </ToggleGroup>

          {perAudit.length === 0 && (
            <Card className="p-6 text-sm text-muted-foreground">No issues found yet. Run a scan on an audit to see progress here.</Card>
          )}

          <div className="space-y-4">
            {perAudit.map((a) => {
              const items = a.items.filter((r) => view === "all" || (view === "fixed" ? r.status === "resolved" : r.status === "fail"));
              const p = pct(a.fixed, a.open);
              return (
                <Card key={a.id} className="p-5">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium">{a.title}</div>
                      {a.site && <div className="truncate text-xs text-muted-foreground">{a.site}</div>}
                    </div>
                    <Link to="/audits/$id" params={{ id: a.id }} className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
                      Open audit <ArrowRight className="h-3.5 w-3.5" />
                    </Link>
                  </div>
                  <div className="mt-3 flex items-center gap-3">
                    <Progress value={p} className="flex-1" />
                    <span className="w-28 text-right text-sm tabular-nums">{p}% · {a.fixed}/{a.fixed + a.open}</span>
                  </div>
                  {items.length > 0 ? (
                    <ul className="mt-4 divide-y">
                      {items.map((r) => (
                        <li key={r.id} className="flex items-center gap-3 py-2 text-sm">
                          {r.status === "resolved"
                            ? <CheckCircle2 className="h-4 w-4 shrink-0 text-status-pass" />
                            : <CircleAlert className="h-4 w-4 shrink-0 text-destructive" />}
                          <span className={cn("flex-1", r.status === "resolved" && "text-muted-foreground line-through")}>
                            {r.checklist_items?.title ?? "Finding"}
                          </span>
                          <Badge variant="outline" className="capitalize">{r.checklist_items?.severity ?? "—"}</Badge>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-3 text-xs text-muted-foreground">{view === "open" ? "Everything here is fixed." : "Nothing fixed yet."}</p>
                  )}
                </Card>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
