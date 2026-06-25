import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { toast } from "sonner";
import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { RefreshCw, CheckCircle2, XCircle, ExternalLink } from "lucide-react";
import {
  runThreatFeedCheck,
  approveThreatFeedItem,
  rejectThreatFeedItem,
} from "@/lib/threat-feed.functions";

export const Route = createFileRoute("/_authenticated/threat-feed")({
  head: () => ({ meta: [{ title: "Threat Feed — AuditKit" }] }),
  component: ThreatFeed,
});

type Status = "pending_review" | "approved" | "rejected";

function ThreatFeed() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<Status>("pending_review");

  const items = useQuery({
    queryKey: ["threat-feed", tab],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("threat_feed_items")
        .select("*")
        .eq("status", tab)
        .order("created_at", { ascending: false })
        .limit(200);
      if (error) throw error;
      return data ?? [];
    },
  });

  const runFn = useServerFn(runThreatFeedCheck);
  const approveFn = useServerFn(approveThreatFeedItem);
  const rejectFn = useServerFn(rejectThreatFeedItem);

  const runCheck = useMutation({
    mutationFn: async () => runFn(),
    onSuccess: (r: any) => {
      if (r?.ok === false) toast.error(r.error ?? "Failed.");
      else toast.success(`Fetched ${r.fetched}, added ${r.inserted}, skipped ${r.skipped}.`);
      qc.invalidateQueries({ queryKey: ["threat-feed"] });
      qc.invalidateQueries({ queryKey: ["threat-feed-pending-count"] });
    },
    onError: (e: any) => toast.error(e?.message ?? "Failed."),
  });

  const approve = useMutation({
    mutationFn: async (id: string) => approveFn({ data: { id } }),
    onSuccess: (r: any) => {
      if (r?.ok === false) toast.error(r.error ?? "Failed.");
      else toast.success("Approved and added to checklist.");
      qc.invalidateQueries({ queryKey: ["threat-feed"] });
      qc.invalidateQueries({ queryKey: ["threat-feed-pending-count"] });
    },
    onError: (e: any) => toast.error(e?.message ?? "Failed."),
  });

  const reject = useMutation({
    mutationFn: async (id: string) => rejectFn({ data: { id } }),
    onSuccess: (r: any) => {
      if (r?.ok === false) toast.error(r.error ?? "Failed.");
      else toast.success("Rejected.");
      qc.invalidateQueries({ queryKey: ["threat-feed"] });
      qc.invalidateQueries({ queryKey: ["threat-feed-pending-count"] });
    },
    onError: (e: any) => toast.error(e?.message ?? "Failed."),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Threat Feed</h1>
          <p className="text-sm text-muted-foreground">
            Daily-ingested security advisories from GitHub and NVD, drafted into checklist items by AI.
          </p>
        </div>
        <Button onClick={() => runCheck.mutate()} disabled={runCheck.isPending}>
          <RefreshCw className={`h-4 w-4 mr-2 ${runCheck.isPending ? "animate-spin" : ""}`} />
          Run check now
        </Button>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as Status)}>
        <TabsList>
          <TabsTrigger value="pending_review">Pending</TabsTrigger>
          <TabsTrigger value="approved">Approved</TabsTrigger>
          <TabsTrigger value="rejected">Rejected</TabsTrigger>
        </TabsList>

        <TabsContent value={tab} className="mt-4 space-y-3">
          {items.isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
          {!items.isLoading && (items.data ?? []).length === 0 && (
            <p className="text-sm text-muted-foreground">No items.</p>
          )}
          {(items.data ?? []).map((it: any) => (
            <Card key={it.id} className="p-4 space-y-3">
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="outline">{it.source.toUpperCase()}</Badge>
                    {it.suggested_severity && (
                      <Badge variant={it.suggested_severity === "critical" || it.suggested_severity === "high" ? "destructive" : "secondary"}>
                        {it.suggested_severity}
                      </Badge>
                    )}
                    {it.is_relevant ? (
                      <Badge className="bg-emerald-600 text-white hover:bg-emerald-600">Relevant</Badge>
                    ) : (
                      <Badge variant="secondary">Low relevance</Badge>
                    )}
                    {it.suggested_category && (
                      <Badge variant="outline">{it.suggested_category}</Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">{it.raw_title}</p>
                </div>
                {it.advisory_url && (
                  <a
                    href={it.advisory_url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
                  >
                    Source <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>

              <div className="rounded-md border bg-muted/30 p-3 space-y-1.5">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Drafted checklist item</div>
                <div className="font-medium">{it.suggested_title ?? "—"}</div>
                {it.suggested_risk && (
                  <div className="text-sm"><span className="text-muted-foreground">Risk: </span>{it.suggested_risk}</div>
                )}
                {it.suggested_fix && (
                  <div className="text-sm"><span className="text-muted-foreground">Fix: </span>{it.suggested_fix}</div>
                )}
              </div>

              {tab === "pending_review" && (
                <div className="flex justify-end gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => reject.mutate(it.id)}
                    disabled={reject.isPending}
                  >
                    <XCircle className="h-4 w-4 mr-1.5" /> Reject
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => approve.mutate(it.id)}
                    disabled={approve.isPending || !it.suggested_title || !it.suggested_category || !it.suggested_severity}
                  >
                    <CheckCircle2 className="h-4 w-4 mr-1.5" /> Approve & add to checklist
                  </Button>
                </div>
              )}
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}
