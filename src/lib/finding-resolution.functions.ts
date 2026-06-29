import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { runAutoScan } from "@/lib/scan.functions";

/**
 * Resolve a finding via one of two enforced paths:
 *   - automated: the finding was produced by an automatic scanner; we re-run
 *     the scan and only allow the transition to `resolved` if the new result
 *     comes back `pass`. We log a `rescanned` event with before/after data.
 *   - manual: requires non-empty evidence_text (optional evidence_url). We log
 *     a `fix_submitted` event with the evidence attached.
 *
 * The DB trigger writes the matching `resolved` row automatically once the
 * status flips, so the timeline reads: flagged → fix_submitted/rescanned → resolved.
 */
export const resolveFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator(
    (data: {
      auditId: string;
      checklistItemId: string;
      mode: "automated" | "manual";
      evidenceText?: string | null;
      evidenceUrl?: string | null;
    }) => data,
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { auditId, checklistItemId, mode } = data;

    const { data: finding, error: fErr } = await supabase
      .from("audit_findings")
      .select("id, status, auto_scanned, checklist_item:checklist_items(checklist_key, title)")
      .eq("audit_id", auditId)
      .eq("checklist_item_id", checklistItemId)
      .maybeSingle();
    if (fErr) throw new Error(fErr.message);
    if (!finding) throw new Error("Finding not found");
    if (finding.status === "resolved") {
      return { ok: true, alreadyResolved: true as const };
    }

    if (mode === "automated") {
      if (!finding.auto_scanned) {
        throw new Error("This finding was not produced by the automated scanner — use the manual evidence path.");
      }
      const before = finding.status;
      // Re-run the surface scanner; it upserts results for this audit.
      const scanResult = await runAutoScan({ data: { auditId } });

      // Re-read the finding after the scan.
      const { data: after, error: aErr } = await supabase
        .from("audit_findings")
        .select("id, status")
        .eq("id", finding.id)
        .maybeSingle();
      if (aErr) throw new Error(aErr.message);

      // Log the rescan event regardless of outcome (tamper-resistant evidence).
      await supabase.from("finding_audit_log").insert({
        finding_id: finding.id,
        audit_id: auditId,
        event_type: "rescanned",
        before_status: before,
        after_status: after?.status ?? null,
        scan_result: { passes: scanResult.passes, fails: scanResult.fails, warnings: scanResult.warnings, target: scanResult.target } as never,
        performed_by: userId,
      });

      if (after?.status !== "pass") {
        return { ok: false as const, reason: "Re-scan did not return pass; the finding remains open." };
      }

      const { error: upErr } = await supabase
        .from("audit_findings")
        .update({
          status: "resolved",
          resolved_at: new Date().toISOString(),
          resolved_via: "automated_rescan",
        })
        .eq("id", finding.id);
      if (upErr) throw new Error(upErr.message);

      return { ok: true as const, mode: "automated" as const };
    }

    // Manual path
    const evidenceText = (data.evidenceText ?? "").trim();
    const evidenceUrl = (data.evidenceUrl ?? "").trim() || null;
    if (!evidenceText) {
      throw new Error("Evidence description is required to manually resolve a finding.");
    }

    // Write the explicit fix_submitted log row first.
    await supabase.from("finding_audit_log").insert({
      finding_id: finding.id,
      audit_id: auditId,
      event_type: "fix_submitted",
      before_status: finding.status,
      after_status: "resolved",
      evidence_text: evidenceText,
      evidence_url: evidenceUrl,
      performed_by: userId,
    });

    const { error: upErr } = await supabase
      .from("audit_findings")
      .update({
        status: "resolved",
        evidence_text: evidenceText,
        evidence_url: evidenceUrl,
        resolved_at: new Date().toISOString(),
        resolved_via: "manual_evidence",
      })
      .eq("id", finding.id);
    if (upErr) throw new Error(upErr.message);

    return { ok: true as const, mode: "manual" as const };
  });

export type FindingHistoryEvent = {
  id: string;
  event_type: "flagged" | "fix_submitted" | "rescanned" | "resolved" | "reopened";
  before_status: string | null;
  after_status: string | null;
  evidence_text: string | null;
  evidence_url: string | null;
  scan_result: { passes?: number; fails?: number; warnings?: number; target?: string } | null;
  performed_by: string | null;
  performer_name: string | null;
  created_at: string;
};

export const listFindingHistory = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { findingId: string }) => data)
  .handler(async ({ data, context }): Promise<FindingHistoryEvent[]> => {
    const { supabase } = context;
    const { data: rows, error } = await supabase
      .from("finding_audit_log")
      .select("id, event_type, before_status, after_status, evidence_text, evidence_url, scan_result, performed_by, created_at")
      .eq("finding_id", data.findingId)
      .order("created_at", { ascending: true });
    if (error) throw new Error(error.message);

    const actorIds = Array.from(new Set((rows ?? []).map((r) => r.performed_by).filter(Boolean) as string[]));
    const nameById = new Map<string, string>();
    if (actorIds.length) {
      const { data: profs } = await supabase
        .from("profiles")
        .select("id, full_name, email")
        .in("id", actorIds);
      (profs ?? []).forEach((p: any) => nameById.set(p.id, p.full_name ?? p.email ?? "Auditor"));
    }

    return (rows ?? []).map((r: any) => ({
      id: r.id,
      event_type: r.event_type,
      before_status: r.before_status,
      after_status: r.after_status,
      evidence_text: r.evidence_text,
      evidence_url: r.evidence_url,
      scan_result: r.scan_result,
      performed_by: r.performed_by,
      performer_name: r.performed_by ? nameById.get(r.performed_by) ?? null : null,
      created_at: r.created_at,
    }));
  });

/** Lists every resolved finding for an audit, used by the SHIELD report appendix. */
export type ResolvedFindingAppendixEntry = {
  finding_id: string;
  checklist_item_id: string;
  title: string;
  category: string;
  resolved_at: string | null;
  resolved_via: "automated_rescan" | "manual_evidence" | null;
  evidence_text: string | null;
  evidence_url: string | null;
};

export const listResolvedFindings = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { auditId: string }) => data)
  .handler(async ({ data, context }): Promise<ResolvedFindingAppendixEntry[]> => {
    const { supabase } = context;
    const { data: rows, error } = await supabase
      .from("audit_findings")
      .select("id, checklist_item_id, resolved_at, resolved_via, evidence_text, evidence_url, checklist_item:checklist_items(title, category)")
      .eq("audit_id", data.auditId)
      .eq("status", "resolved")
      .order("resolved_at", { ascending: false });
    if (error) throw new Error(error.message);

    return (rows ?? []).map((r: any) => ({
      finding_id: r.id,
      checklist_item_id: r.checklist_item_id,
      title: r.checklist_item?.title ?? "(untitled)",
      category: r.checklist_item?.category ?? "Uncategorized",
      resolved_at: r.resolved_at,
      resolved_via: r.resolved_via,
      evidence_text: r.evidence_text,
      evidence_url: r.evidence_url,
    }));
  });

/** Audit-wide activity log: every status change for every finding in an audit. */
export type AuditActivityEvent = {
  id: string;
  finding_id: string;
  checklist_item_id: string | null;
  item_title: string;
  item_category: string;
  event_type: "flagged" | "fix_submitted" | "rescanned" | "resolved" | "reopened";
  before_status: string | null;
  after_status: string | null;
  evidence_text: string | null;
  evidence_url: string | null;
  performed_by: string | null;
  performer_name: string | null;
  created_at: string;
};

export const listAuditActivity = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { auditId: string }) => data)
  .handler(async ({ data, context }): Promise<AuditActivityEvent[]> => {
    const { supabase } = context;
    const { data: rows, error } = await supabase
      .from("finding_audit_log")
      .select("id, finding_id, event_type, before_status, after_status, evidence_text, evidence_url, performed_by, created_at, finding:audit_findings(checklist_item_id, checklist_item:checklist_items(title, category))")
      .eq("audit_id", data.auditId)
      .order("created_at", { ascending: false });
    if (error) throw new Error(error.message);

    const actorIds = Array.from(new Set((rows ?? []).map((r: any) => r.performed_by).filter(Boolean) as string[]));
    const nameById = new Map<string, string>();
    if (actorIds.length) {
      const { data: profs } = await supabase
        .from("profiles")
        .select("id, full_name, email")
        .in("id", actorIds);
      (profs ?? []).forEach((p: any) => nameById.set(p.id, p.full_name ?? p.email ?? "Auditor"));
    }

    return (rows ?? []).map((r: any) => ({
      id: r.id,
      finding_id: r.finding_id,
      checklist_item_id: r.finding?.checklist_item_id ?? null,
      item_title: r.finding?.checklist_item?.title ?? "(untitled)",
      item_category: r.finding?.checklist_item?.category ?? "Uncategorized",
      event_type: r.event_type,
      before_status: r.before_status,
      after_status: r.after_status,
      evidence_text: r.evidence_text,
      evidence_url: r.evidence_url,
      performed_by: r.performed_by,
      performer_name: r.performed_by ? nameById.get(r.performed_by) ?? null : null,
      created_at: r.created_at,
    }));
  });
