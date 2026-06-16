import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ArrowLeft, Printer } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { format } from "date-fns";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/audits/$id/report")({
  head: () => ({ meta: [{ title: "Report — AuditKit" }] }),
  component: ReportPage,
});

function ReportPage() {
  const { id } = Route.useParams();

  const audit = useQuery({
    queryKey: ["audit", id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("audits")
        .select("id, title, status, started_at, completed_at, summary, client:clients(name, contact_name, contact_email)")
        .eq("id", id).single();
      if (error) throw error;
      return data as any;
    },
  });

  const items = useQuery({
    queryKey: ["checklist-items"],
    queryFn: async () => {
      const { data } = await supabase
        .from("checklist_items")
        .select("id, category, title, description, severity, sort_order").eq("is_active", true)
        .order("sort_order");
      return data ?? [];
    },
  });

  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: async () => {
      const { data } = await supabase.from("audit_findings").select("checklist_item_id, status, notes").eq("audit_id", id);
      return data ?? [];
    },
  });

  const map = useMemo(() => {
    const m = new Map<string, { status: string | null; notes: string | null }>();
    findings.data?.forEach((f: any) => m.set(f.checklist_item_id, f));
    return m;
  }, [findings.data]);

  const grouped = useMemo(() => {
    if (!items.data) return [];
    const m = new Map<string, any[]>();
    items.data.forEach((it: any) => {
      const arr = m.get(it.category) ?? [];
      arr.push(it);
      m.set(it.category, arr);
    });
    return Array.from(m.entries());
  }, [items.data]);

  const totals = useMemo(() => {
    const t = { pass: 0, fail: 0, na: 0, unanswered: 0, total: items.data?.length ?? 0 };
    items.data?.forEach((it: any) => {
      const s = map.get(it.id)?.status;
      if (s === "pass") t.pass++;
      else if (s === "fail") t.fail++;
      else if (s === "na") t.na++;
      else t.unanswered++;
    });
    return t;
  }, [items.data, map]);

  return (
    <div className="space-y-6 print:space-y-4">
      <div className="flex items-center justify-between print:hidden">
        <Link to="/audits/$id" params={{ id }} className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4 mr-1" /> Back to audit
        </Link>
        <Button onClick={() => window.print()} className="bg-navy text-navy-foreground hover:bg-navy/90">
          <Printer className="h-4 w-4 mr-1" /> Print / Save PDF
        </Button>
      </div>

      <div className="bg-card border rounded-xl p-8 print:border-0 print:p-0">
        <header className="border-b pb-6 mb-6">
          <p className="text-xs uppercase tracking-widest text-muted-foreground">Security Audit Report</p>
          <h1 className="text-3xl font-semibold tracking-tight mt-1">{audit.data?.title}</h1>
          <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <Meta label="Client" value={audit.data?.client?.name} />
            <Meta label="Contact" value={audit.data?.client?.contact_name} />
            <Meta label="Started" value={audit.data?.started_at ? format(new Date(audit.data.started_at), "PP") : "—"} />
            <Meta label="Status" value={<span className="capitalize">{audit.data?.status?.replace("_", " ")}</span>} />
          </div>
        </header>

        <section className="mb-8">
          <h2 className="text-lg font-semibold mb-3">Summary</h2>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Stat label="Total" value={totals.total} />
            <Stat label="Pass" value={totals.pass} tone="pass" />
            <Stat label="Fail" value={totals.fail} tone="fail" />
            <Stat label="N/A" value={totals.na} tone="na" />
            <Stat label="Unanswered" value={totals.unanswered} />
          </div>
        </section>

        {grouped.map(([cat, list]) => (
          <section key={cat} className="mb-6 break-inside-avoid">
            <h2 className="text-lg font-semibold border-b pb-2 mb-3">{cat}</h2>
            <div className="space-y-3">
              {list.map((it: any) => {
                const f = map.get(it.id);
                return (
                  <div key={it.id} className="border rounded-lg p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium">{it.title}</span>
                          <SeverityBadge severity={it.severity} />
                        </div>
                        {it.description && <p className="text-sm text-muted-foreground mt-1">{it.description}</p>}
                      </div>
                      <StatusPill status={f?.status} />
                    </div>
                    {f?.notes && (
                      <div className="mt-2 text-sm bg-muted/50 rounded p-2 whitespace-pre-wrap">{f.notes}</div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>
        ))}
      </div>

      <style>{`
        @media print {
          header.bg-navy, nav, button { display: none !important; }
          body { background: white; }
        }
      `}</style>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="font-medium">{value || "—"}</div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "pass" | "fail" | "na" }) {
  const tones = {
    pass: "text-status-pass",
    fail: "text-status-fail",
    na: "text-status-na",
  } as const;
  return (
    <Card className="p-3">
      <div className="text-xs uppercase text-muted-foreground">{label}</div>
      <div className={cn("text-2xl font-semibold mt-1", tone && tones[tone])}>{value}</div>
    </Card>
  );
}

function StatusPill({ status }: { status: string | null | undefined }) {
  if (!status) return <span className="text-xs text-muted-foreground">—</span>;
  const cls = {
    pass: "bg-status-pass/15 text-status-pass border-status-pass/40",
    fail: "bg-status-fail/15 text-status-fail border-status-fail/40",
    na: "bg-status-na/15 text-status-na border-status-na/40",
  }[status] ?? "";
  return (
    <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold uppercase", cls)}>
      {status}
    </span>
  );
}
