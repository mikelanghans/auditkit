// Phase 4: run due schedules. Called by the signed hook
// /api/public/hooks/scheduled-scans (from a cron: see
// .github/workflows/scheduled-scans.yml). Server-only, service role.
//
// Only passive scanners run here (website, attack surface, an OSV re-check
// of the package list recorded by the last repo scan): no client
// credentials, nothing that writes to the client's systems. Each run is a
// "schedule" parent run owned by the audit's owner, so it shows in scan
// history, the report and the audit trail like any other run.
import { websiteScanCore } from "./scan.functions";
import { surfaceScanCore } from "./attack-surface.functions";
import { recheckStoredPackages } from "./dep-scan-core";
import { summarizeFullAudit, type FullAuditStep } from "./full-audit.functions";
import { emailConfigured, sendEmail } from "./email.server";

const MAX_PER_CALL = 3;
const CADENCE_MS: Record<string, number> = { daily: 24 * 3600_000, weekly: 7 * 24 * 3600_000 };

export type ScheduleOutcome = {
  audit_id: string;
  run_id: string | null;
  status: string;
  alerts: number;
  error?: string;
};

/** Checks that newly failed or came back since the previous result. Exported for tests. */
export function alertWorthy(results: { status: string; change: string | null }[]) {
  return results.filter((r) => r.status === "fail" && (r.change === "new" || r.change === "regressed"));
}

export async function runDueSchedules(admin: any, now = new Date()): Promise<{ ran: ScheduleOutcome[] }> {
  const { data: due, error } = await admin
    .from("audit_schedules")
    .select("audit_id, cadence, scanners, alert_email, audit:audits(id, title, created_by, website_url)")
    .eq("enabled", true)
    .lte("next_run_at", now.toISOString())
    .order("next_run_at", { ascending: true })
    .limit(MAX_PER_CALL);
  if (error) throw new Error(error.message);

  const ran: ScheduleOutcome[] = [];
  for (const s of (due ?? []) as any[]) {
    const audit = s.audit;
    const next = new Date(now.getTime() + (CADENCE_MS[s.cadence] ?? CADENCE_MS.weekly)).toISOString();
    if (!audit) continue;
    let runId: string | null = null;
    try {
      const { data: parent, error: pErr } = await admin
        .from("scan_runs")
        .insert({ audit_id: audit.id, scanner: "full", trigger: "schedule", status: "running", target: audit.title, created_by: audit.created_by })
        .select("id")
        .single();
      if (pErr || !parent) throw new Error(pErr?.message ?? "could not open run");
      runId = parent.id as string;

      const steps: FullAuditStep[] = [];
      const opts = { checkQuota: false, trigger: "schedule" as const, createdBy: audit.created_by as string };
      for (const scanner of (s.scanners ?? []) as string[]) {
        try {
          if (scanner === "website") {
            if (!audit.website_url) {
              steps.push({ scanner: "website", target: null, outcome: "not_run", reason: "This audit has no website set." });
              continue;
            }
            await websiteScanCore(admin, { auditId: audit.id, parentRunId: runId }, opts);
            steps.push({ scanner: "website", target: audit.website_url, outcome: "done" });
          } else if (scanner === "dependencies") {
            const r = await recheckStoredPackages(admin, audit.id, { parentRunId: runId, trigger: "schedule", createdBy: audit.created_by });
            steps.push(r.ok
              ? { scanner: "repo", target: `${r.packages} recorded packages`, outcome: "done" }
              : { scanner: "repo", target: null, outcome: "not_run", reason: r.error });
          } else if (scanner === "surface") {
            const r: any = await surfaceScanCore(admin, { auditId: audit.id, parentRunId: runId }, opts);
            steps.push({ scanner: "surface", target: r?.domain ?? audit.website_url, outcome: r?.ok ? "done" : "failed", reason: r?.ok ? null : r?.error });
          }
        } catch (e: any) {
          steps.push({ scanner: scanner as any, target: audit.website_url, outcome: "failed", reason: e?.message ?? String(e) });
        }
      }

      const { data: children } = await admin.from("scan_runs").select("id, scanner, status, summary").eq("parent_run_id", runId);
      const gaps = steps.filter((x) => x.outcome !== "done");
      if (gaps.length) {
        await admin.from("scan_results").insert(
          gaps.map((g) => ({
            run_id: runId,
            audit_id: audit.id,
            checklist_key: `step:${g.scanner}`,
            scanner: g.scanner,
            status: "not_run",
            stored: false,
            notes: `${g.outcome === "failed" ? "Failed" : "Not run"}: ${g.reason ?? "no reason given"}`,
          })),
        );
      }
      const { status, summary } = summarizeFullAudit(steps, (children ?? []) as any[]);
      await admin.from("scan_runs").update({ status, finished_at: new Date().toISOString(), summary }).eq("id", runId);

      // Alert on checks that newly fail or came back.
      const childIds = ((children ?? []) as any[]).map((c) => c.id);
      let alerts: any[] = [];
      if (childIds.length) {
        const { data: res } = await admin
          .from("scan_results")
          .select("status, change, checklist_key, item:checklist_items(title, severity)")
          .in("run_id", childIds);
        alerts = alertWorthy((res ?? []) as any[]);
      }
      const to = process.env.ALERT_EMAIL || process.env.OWNER_NOTIFY_EMAIL;
      if (alerts.length && s.alert_email && to && emailConfigured()) {
        const lines = alerts.map((a: any) => `• [${a.item?.severity ?? "?"}] ${a.item?.title ?? a.checklist_key} (${a.change})`);
        const appUrl = process.env.PUBLIC_APP_URL ?? "";
        const link = appUrl ? `${appUrl}/audits/${audit.id}/activity` : "";
        await sendEmail({
          to,
          subject: `AuditKit: ${alerts.length} new or regressed issue(s) on ${audit.title}`,
          text: `The scheduled scan of "${audit.title}" found:\n\n${lines.join("\n")}\n\n${link}`,
          html: `<p>The scheduled scan of <strong>${escapeHtml(audit.title)}</strong> found:</p><ul>${alerts
            .map((a: any) => `<li>[${escapeHtml(a.item?.severity ?? "?")}] ${escapeHtml(a.item?.title ?? a.checklist_key ?? "")} (${escapeHtml(a.change)})</li>`)
            .join("")}</ul>${link ? `<p><a href="${escapeHtml(link)}">Open the audit</a></p>` : ""}`,
        });
      }

      await admin.from("audit_schedules").update({ last_run_at: now.toISOString(), last_run_id: runId, last_error: null, next_run_at: next }).eq("audit_id", audit.id);
      ran.push({ audit_id: audit.id, run_id: runId, status, alerts: alerts.length });
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      if (runId) await admin.from("scan_runs").update({ status: "failed", finished_at: new Date().toISOString(), summary: { error: msg } }).eq("id", runId);
      // Push the next attempt out so one broken audit can't block the queue.
      await admin.from("audit_schedules").update({ last_run_at: now.toISOString(), last_error: msg.slice(0, 1000), next_run_at: next }).eq("audit_id", audit.id);
      ran.push({ audit_id: audit.id, run_id: runId, status: "failed", alerts: 0, error: msg });
    }
  }
  return { ran };
}

function escapeHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}
