// Tamper-evident audit trail (phase 2b): chain status, recent events, export.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { format } from "date-fns";
import { Download, Link2, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { fetchAuditEvents, useChainStatus } from "@/hooks/use-audit-trail";

const EVENT_LABEL: Record<string, string> = {
  "trail.started": "Trail started",
  "audit.created": "Audit created",
  "audit.updated": "Audit updated",
  "audit.deleted": "Audit deleted",
  "finding.set": "Finding set",
  "finding.cleared": "Finding cleared",
  "scan.started": "Scan started",
  "scan.finished": "Scan finished",
  "evidence.added": "Evidence added",
  "target.added": "Target added",
  "target.changed": "Target changed",
  "target.removed": "Target removed",
  "scope.set": "Scope set",
  "report.exported": "Report exported",
  "code_finding.reviewed": "Code finding reviewed",
};

function describe(e: { event: string; data: any }): string {
  const d = e.data ?? {};
  switch (e.event) {
    case "finding.set": return `${d.from ? `${d.from} → ` : ""}${d.to ?? "?"}`;
    case "scan.started": return [d.scanner, d.target].filter(Boolean).join(" · ");
    case "scan.finished": return `${d.scanner} ${d.status}${d.counts ? ` · ${d.counts.pass ?? 0} pass, ${d.counts.fail ?? 0} fail` : ""}`;
    case "evidence.added": return `${d.title} (${d.kind}, ${String(d.sha256 ?? "").slice(0, 12)}…)`;
    case "target.added": case "target.changed": case "target.removed": return `${d.kind} ${d.value}${d.in_scope === false ? " (out of scope)" : ""}`;
    case "report.exported": return `${d.format}${d.sha256 ? ` · ${String(d.sha256).slice(0, 12)}…` : ""}`;
    case "scope.set": return `${d.environment ?? ""}${d.write_tests_allowed ? " · write tests allowed" : ""}`;
    default: return e.event.startsWith("code_audit.") ? `${e.event.split(".")[1]}${d.confirmed != null ? ` · ${d.confirmed} confirmed` : ""}` : "";
  }
}

export function AuditTrailPanel({ auditId }: { auditId: string }) {
  const chain = useChainStatus(auditId);
  const [showAll, setShowAll] = useState(false);
  const events = useQuery({
    queryKey: ["audit-events", auditId],
    queryFn: () => fetchAuditEvents(auditId),
  });

  const download = () => {
    const payload = {
      audit_id: auditId,
      exported_at: new Date().toISOString(),
      chain: chain.data,
      hash_rule:
        "row_hash = sha256(prev_hash|seq|event|entity|entity_id|actor|occurred_at(UTC, microseconds, ISO)|data as jsonb text); first prev_hash is 64 zeros",
      events: events.data ?? [],
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `audit-trail-${auditId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const rows = [...(events.data ?? [])].reverse();
  const shown = showAll ? rows : rows.slice(0, 25);

  return (
    <Card className="p-4 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <Link2 className="h-4 w-4 text-primary" />
        <h2 className="text-sm font-semibold">Audit trail</h2>
        {chain.isLoading ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
        ) : chain.error ? (
          <Badge variant="outline" className="text-destructive">Couldn't verify: {(chain.error as Error).message}</Badge>
        ) : chain.data?.ok ? (
          <Badge variant="outline" className="border-status-pass/40 text-status-pass gap-1">
            <ShieldCheck className="h-3 w-3" /> Chain verified · {chain.data.events} events
          </Badge>
        ) : chain.data ? (
          <Badge variant="outline" className="border-destructive/50 text-destructive gap-1">
            <ShieldAlert className="h-3 w-3" /> Chain broken at #{chain.data.first_bad_seq}: {chain.data.problem}
          </Badge>
        ) : null}
        <Button variant="ghost" size="sm" className="ml-auto h-7 text-xs" onClick={download} disabled={!events.data?.length}>
          <Download className="h-3.5 w-3.5 mr-1" /> Download trail
        </Button>
      </div>
      {chain.data?.head_hash && (
        <div className="text-[11px] font-mono text-muted-foreground break-all">head {chain.data.head_hash}</div>
      )}
      <p className="text-xs text-muted-foreground">
        Written by the database, not the app: every change to this audit is chained to the one before it, so nothing can be edited or removed without breaking the chain.
      </p>
      {events.isLoading ? null : events.error ? (
        <div className="text-xs text-destructive">{(events.error as Error).message}</div>
      ) : (
        <ol className="text-xs divide-y divide-border/50">
          {shown.map((e: any) => (
            <li key={e.seq} className="flex items-center gap-2 py-1">
              <span className="w-10 text-right tabular-nums text-muted-foreground">#{e.seq}</span>
              <span className="font-medium w-36 shrink-0">{EVENT_LABEL[e.event] ?? e.event}</span>
              <span className="truncate flex-1 text-muted-foreground">{describe(e)}</span>
              <span className="text-muted-foreground whitespace-nowrap">{format(new Date(e.occurred_at), "MMM d, HH:mm:ss")}</span>
            </li>
          ))}
        </ol>
      )}
      {rows.length > 25 && (
        <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setShowAll(!showAll)}>
          {showAll ? "Show fewer" : `Show all ${rows.length}`}
        </Button>
      )}
    </Card>
  );
}
