// Draft the report's executive summary with Claude (build plan, phase 2c).
// The draft is saved unapproved; the report prints it only after the auditor
// edits and approves it.
//
// Only structured facts go to the model: check titles, categories, severities,
// statuses, counts and scope. Finding notes (which hold evidence from the
// client's systems) are never sent.
import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { consumeQuota } from "./quota";

const SYSTEM = [
  "You write the executive summary of a security audit report for a SaaS founder who is not a security specialist.",
  "Use only the facts given. Do not invent findings, numbers, dates or company details.",
  "3 short paragraphs, under 220 words, plain language, no headings, no bullet lists, no marketing tone.",
  "Paragraph 1: what was assessed and how (scope, environment, which checks ran).",
  "Paragraph 2: the most important issues, by business impact, highest severity first; name at most four.",
  "Paragraph 3: what was not tested or couldn't be verified, and the recommended next step.",
  "If there are no open issues, say so plainly and still state the limits of the testing.",
].join(" ");

export const draftExecutiveSummary = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string }) => {
    if (!input || typeof input.auditId !== "string") throw new Error("auditId required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: audit } = await supabase
      .from("audits")
      .select("id, created_by, title, website_url, client:clients(name)")
      .eq("id", data.auditId)
      .maybeSingle();
    if (!audit || (audit as any).created_by !== userId) return { ok: false as const, error: "Audit not found or access denied." };

    const [{ data: items }, { data: findings }, { data: scope }, { data: targets }, { data: runs }] = await Promise.all([
      supabase.from("checklist_items").select("id, title, category, severity").eq("is_active", true),
      supabase.from("audit_findings").select("checklist_item_id, status").eq("audit_id", data.auditId),
      supabase.from("audit_scope").select("environment, write_tests_allowed, out_of_scope").eq("audit_id", data.auditId).maybeSingle(),
      supabase.from("audit_targets").select("kind, value, in_scope").eq("audit_id", data.auditId),
      supabase.from("scan_runs").select("scanner, status").eq("audit_id", data.auditId),
    ]);
    const status = new Map((findings ?? []).map((f: any) => [f.checklist_item_id, f.status as string]));
    const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const failed = (items ?? [])
      .filter((it: any) => status.get(it.id) === "fail")
      .sort((a: any, b: any) => (sevRank[a.severity] ?? 2) - (sevRank[b.severity] ?? 2));
    const unverified = (items ?? []).filter((it: any) => status.get(it.id) === "inconclusive");
    const counts = { pass: 0, fail: 0, na: 0, inconclusive: 0, resolved: 0, unanswered: 0 };
    for (const it of items ?? []) {
      const s = status.get((it as any).id);
      if (s && s in counts) (counts as any)[s]++;
      else counts.unanswered++;
    }
    const scanners = [...new Set((runs ?? []).map((r: any) => r.scanner).filter((s: string) => s !== "full"))];

    const facts = {
      audit: (audit as any).title,
      client: (audit as any).client?.name ?? null,
      website: (audit as any).website_url ?? null,
      environment: (scope as any)?.environment ?? "not recorded",
      write_tests_performed: !!(scope as any)?.write_tests_allowed,
      out_of_scope: (scope as any)?.out_of_scope ?? null,
      targets: (targets ?? []).filter((t: any) => t.in_scope).map((t: any) => `${t.kind}: ${t.value}`),
      automated_checks_run: scanners,
      counts,
      open_issues: failed.slice(0, 25).map((it: any) => ({ title: it.title, category: it.category, severity: it.severity })),
      could_not_verify: unverified.slice(0, 15).map((it: any) => it.title),
    };

    const quota = await consumeQuota(supabase, "llm", 1);
    if (!quota.ok) return { ok: false as const, error: quota.error };
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return { ok: false as const, error: "ANTHROPIC_API_KEY is not configured." };
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-haiku-4-5",
        max_tokens: 1200,
        system: SYSTEM,
        messages: [{ role: "user", content: `Audit facts (JSON):\n${JSON.stringify(facts, null, 2)}` }],
      }),
    });
    const raw = await res.text();
    if (!res.ok) return { ok: false as const, error: `Claude ${res.status}` };
    const text = (JSON.parse(raw).content ?? []).map((c: any) => c?.text ?? "").join("\n").trim();
    if (!text) return { ok: false as const, error: "Claude returned an empty draft." };

    const { error } = await supabase
      .from("audits")
      .update({ summary: text, summary_approved_at: null })
      .eq("id", data.auditId);
    if (error) return { ok: false as const, error: error.message };
    return { ok: true as const, text };
  });
