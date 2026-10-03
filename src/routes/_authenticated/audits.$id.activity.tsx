import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useMemo, useState } from "react";
import { ArrowLeft, History, Loader2, ExternalLink, Filter, Download, FileText, FileSpreadsheet } from "lucide-react";
import { format } from "date-fns";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { listAuditActivity, type AuditActivityEvent } from "@/lib/finding-resolution.functions";
import { ScanHistoryPanel } from "@/components/scan-history-panel";
import { AuditTrailPanel } from "@/components/audit-trail-panel";

export const Route = createFileRoute("/_authenticated/audits/$id/activity")({
  head: () => ({ meta: [{ title: "Activity Log — AuditKit" }] }),
  component: ActivityLogPage,
  errorComponent: ({ error }) => (
    <div className="p-6 text-sm text-destructive">Failed to load activity: {error instanceof Error ? error.message : String(error)}</div>
  ),
  notFoundComponent: () => <div className="p-6 text-sm text-muted-foreground">Audit not found.</div>,
});

const EVENT_LABEL: Record<string, string> = {
  flagged: "Flagged",
  fix_submitted: "Fix submitted",
  rescanned: "Re-scanned",
  resolved: "Resolved",
  reopened: "Reopened",
};

const EVENT_TONE: Record<string, string> = {
  flagged: "bg-status-fail/15 text-status-fail border-status-fail/30",
  fix_submitted: "bg-primary/15 text-primary border-primary/30",
  rescanned: "bg-muted text-foreground border-border",
  resolved: "bg-status-pass/15 text-status-pass border-status-pass/30",
  reopened: "bg-status-warn/15 text-status-warn border-status-warn/30",
};

function ActivityLogPage() {
  const { id } = Route.useParams();
  const fetchActivity = useServerFn(listAuditActivity);
  const { data, isLoading, error } = useQuery({
    queryKey: ["audit-activity", id],
    queryFn: () => fetchActivity({ data: { auditId: id } }),
  });

  const [query, setQuery] = useState("");
  const [eventFilter, setEventFilter] = useState<string>("all");

  const filtered = useMemo(() => {
    const rows: AuditActivityEvent[] = data ?? [];
    return rows.filter((r) => {
      if (eventFilter !== "all" && r.event_type !== eventFilter) return false;
      if (!query.trim()) return true;
      const q = query.toLowerCase();
      return (
        r.item_title.toLowerCase().includes(q) ||
        r.item_category.toLowerCase().includes(q) ||
        (r.performer_name ?? "").toLowerCase().includes(q) ||
        (r.evidence_text ?? "").toLowerCase().includes(q)
      );
    });
  }, [data, query, eventFilter]);

  const grouped = useMemo(() => {
    const byDay = new Map<string, AuditActivityEvent[]>();
    for (const row of filtered) {
      const key = format(new Date(row.created_at), "MMM d, yyyy");
      if (!byDay.has(key)) byDay.set(key, []);
      byDay.get(key)!.push(row);
    }
    return Array.from(byDay.entries());
  }, [filtered]);

  const counts = useMemo(() => {
    const rows: AuditActivityEvent[] = data ?? [];
    const c: Record<string, number> = { all: rows.length };
    for (const r of rows) c[r.event_type] = (c[r.event_type] ?? 0) + 1;
    return c;
  }, [data]);

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      <div>
        <Link to="/audits/$id" params={{ id }} className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4 mr-1" /> Back to audit
        </Link>
        <div className="mt-2 flex items-start justify-between gap-3 flex-wrap">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <History className="h-6 w-6" /> Activity Log
            </h1>
            <p className="text-sm text-muted-foreground">Chronological record of every finding status change in this audit.</p>
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" disabled={filtered.length === 0}>
                <Download className="h-4 w-4 mr-1.5" /> Export
                <Badge variant="secondary" className="ml-2 h-4 px-1.5 text-[10px]">{filtered.length}</Badge>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => exportCsv(filtered, id)}>
                <FileSpreadsheet className="h-4 w-4 mr-2" /> Download CSV
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => exportPdf(filtered, id, { query, eventFilter })}>
                <FileText className="h-4 w-4 mr-2" /> Download PDF
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <AuditTrailPanel auditId={id} />

      <ScanHistoryPanel auditId={id} />

      <Card className="p-4 space-y-3">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-[220px]">
            <Filter className="h-4 w-4 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by finding, category, evidence, or auditor…"
              className="pl-8"
            />
          </div>
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          {(["all", "flagged", "fix_submitted", "rescanned", "resolved", "reopened"] as const).map((k) => (
            <Button
              key={k}
              size="sm"
              variant={eventFilter === k ? "default" : "outline"}
              className="h-7 text-xs"
              onClick={() => setEventFilter(k)}
            >
              {k === "all" ? "All" : EVENT_LABEL[k]}
              <Badge variant="secondary" className="ml-1.5 h-4 px-1.5 text-[10px]">
                {counts[k] ?? 0}
              </Badge>
            </Button>
          ))}
        </div>
      </Card>

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-10 justify-center">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading activity…
        </div>
      )}

      {error && !isLoading && (
        <Card className="p-6 text-sm text-destructive">Failed to load activity: {(error as Error).message}</Card>
      )}

      {!isLoading && !error && filtered.length === 0 && (
        <Card className="p-10 text-center text-sm text-muted-foreground">
          {(data?.length ?? 0) === 0 ? "No activity recorded for this audit yet." : "No events match your filters."}
        </Card>
      )}

      {!isLoading && grouped.length > 0 && (
        <div className="space-y-6">
          {grouped.map(([day, rows]) => (
            <section key={day}>
              <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">{day}</h2>
              <ol className="relative border-l border-border ml-3 space-y-3 py-1">
                {rows.map((row) => (
                  <li key={row.id} className="ml-4">
                    <span className="absolute -left-1.5 mt-2 h-3 w-3 rounded-full bg-primary border-2 border-background" />
                    <Card className="p-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant="outline" className={EVENT_TONE[row.event_type] ?? ""}>
                          {EVENT_LABEL[row.event_type] ?? row.event_type}
                        </Badge>
                        <span className="text-xs text-muted-foreground">{row.item_category}</span>
                        <time className="text-xs text-muted-foreground ml-auto">
                          {format(new Date(row.created_at), "h:mm a")}
                        </time>
                      </div>
                      <p className="text-sm font-medium mt-1">{row.item_title}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {row.before_status && row.after_status
                          ? `${row.before_status} → ${row.after_status}`
                          : row.after_status
                            ? `→ ${row.after_status}`
                            : ""}
                        {row.performer_name ? ` · by ${row.performer_name}` : ""}
                      </p>
                      {row.evidence_text && (
                        <p className="text-sm text-muted-foreground mt-2 whitespace-pre-wrap border-l-2 border-border pl-2">
                          {row.evidence_text}
                        </p>
                      )}
                      {row.evidence_url && (
                        <a
                          href={row.evidence_url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-primary hover:underline inline-flex items-center gap-1 mt-1"
                        >
                          <ExternalLink className="h-3 w-3" /> {row.evidence_url}
                        </a>
                      )}
                    </Card>
                  </li>
                ))}
              </ol>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function csvEscape(value: unknown): string {
  let s = value == null ? "" : String(value);
  // Neutralize spreadsheet formula injection (=, +, -, @, tab, CR).
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function exportCsv(rows: AuditActivityEvent[], auditId: string) {
  const headers = [
    "Timestamp",
    "Event",
    "Category",
    "Finding",
    "Before",
    "After",
    "Performed by",
    "Evidence",
    "Evidence URL",
  ];
  const lines = [headers.join(",")];
  for (const r of rows) {
    lines.push(
      [
        format(new Date(r.created_at), "yyyy-MM-dd HH:mm:ss"),
        EVENT_LABEL[r.event_type] ?? r.event_type,
        r.item_category,
        r.item_title,
        r.before_status ?? "",
        r.after_status ?? "",
        r.performer_name ?? "",
        r.evidence_text ?? "",
        r.evidence_url ?? "",
      ]
        .map(csvEscape)
        .join(","),
    );
  }
  const blob = new Blob(["\uFEFF" + lines.join("\n")], { type: "text/csv;charset=utf-8;" });
  downloadBlob(blob, `audit-${auditId}-activity-${format(new Date(), "yyyyMMdd-HHmm")}.csv`);
}

async function exportPdf(
  rows: AuditActivityEvent[],
  auditId: string,
  filters: { query: string; eventFilter: string },
) {
  const [{ default: jsPDF }, autoTableMod] = await Promise.all([
    import("jspdf"),
    import("jspdf-autotable"),
  ]);
  const autoTable = (autoTableMod as { default: (doc: unknown, opts: unknown) => void }).default;
  const doc = new jsPDF({ orientation: "landscape", unit: "pt", format: "letter" });
  doc.setFontSize(14);
  doc.text("Audit Activity Log", 40, 40);
  doc.setFontSize(9);
  doc.setTextColor(120);
  const filterBits: string[] = [`Audit: ${auditId}`, `Events: ${rows.length}`];
  if (filters.eventFilter !== "all") filterBits.push(`Filter: ${EVENT_LABEL[filters.eventFilter] ?? filters.eventFilter}`);
  if (filters.query.trim()) filterBits.push(`Search: "${filters.query.trim()}"`);
  filterBits.push(`Generated: ${format(new Date(), "yyyy-MM-dd HH:mm")}`);
  doc.text(filterBits.join("  ·  "), 40, 56);
  autoTable(doc, {
    startY: 72,
    head: [["Timestamp", "Event", "Category", "Finding", "Status", "By", "Evidence"]],
    body: rows.map((r) => [
      format(new Date(r.created_at), "yyyy-MM-dd HH:mm"),
      EVENT_LABEL[r.event_type] ?? r.event_type,
      r.item_category,
      r.item_title,
      r.before_status && r.after_status
        ? `${r.before_status} → ${r.after_status}`
        : r.after_status
          ? `→ ${r.after_status}`
          : "",
      r.performer_name ?? "",
      [r.evidence_text ?? "", r.evidence_url ?? ""].filter(Boolean).join("\n"),
    ]),
    styles: { fontSize: 8, cellPadding: 4, overflow: "linebreak", valign: "top" },
    headStyles: { fillColor: [30, 30, 30], textColor: 255 },
    columnStyles: {
      0: { cellWidth: 90 },
      1: { cellWidth: 70 },
      2: { cellWidth: 80 },
      3: { cellWidth: 160 },
      4: { cellWidth: 100 },
      5: { cellWidth: 80 },
      6: { cellWidth: "auto" },
    },
    margin: { left: 40, right: 40 },
  });
  doc.save(`audit-${auditId}-activity-${format(new Date(), "yyyyMMdd-HHmm")}.pdf`);
}
