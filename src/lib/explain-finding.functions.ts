import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const SYSTEM_PROMPT =
  "You are a security expert who explains findings to non-technical founders. " +
  "Given a security checklist finding, produce a plain-English explanation in 3-5 short bullet points (one sentence each). " +
  "Cover: 1) what is currently true about the application, 2) why that matters in concrete terms, " +
  "3) the realistic risk, 4) (optional) why this is common in AI-generated apps. " +
  "Do not propose a fix — another tool does that. Do not use jargon without defining it. " +
  "Output ONLY the bullets, one per line, each starting with '- '. No preamble, no headers.";

export type ExplainFindingInput = {
  auditId: string;
  checklistItemId: string;
  force?: boolean;
};

export const explainFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: ExplainFindingInput) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;

    const { data: auditRow, error: aerr } = await supabase
      .from("audits").select("id, created_by").eq("id", data.auditId).single();
    if (aerr || !auditRow || auditRow.created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }

    const { data: finding, error: ferr } = await supabase
      .from("audit_findings")
      .select("notes, status, explanation")
      .eq("audit_id", data.auditId)
      .eq("checklist_item_id", data.checklistItemId)
      .maybeSingle();
    if (ferr) return { ok: false as const, error: ferr.message };

    if (!data.force && finding?.explanation && finding.explanation.trim()) {
      return { ok: true as const, explanation: finding.explanation, cached: true };
    }

    const { data: item, error: ierr } = await supabase
      .from("checklist_items")
      .select("title, category, description, what_to_look_for, severity")
      .eq("id", data.checklistItemId).single();
    if (ierr || !item) return { ok: false as const, error: "Checklist item not found." };

    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return { ok: false as const, error: "ANTHROPIC_API_KEY is not configured." };

    const userMessage =
      `Finding: ${item.title}\n` +
      `Category: ${item.category}\n` +
      `Severity: ${item.severity}\n` +
      `Status: ${finding?.status ?? "unrated"}\n` +
      (item.description ? `Description: ${item.description}\n` : "") +
      (item.what_to_look_for ? `What to look for: ${item.what_to_look_for}\n` : "") +
      (finding?.notes ? `\nAuditor notes:\n${finding.notes}` : "");

    let res: Response;
    try {
      res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": key,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-haiku-4-5",
          max_tokens: 600,
          system: SYSTEM_PROMPT,
          messages: [{ role: "user", content: userMessage }],
        }),
      });
    } catch (e: any) {
      return { ok: false as const, error: e?.message ?? "Claude request failed." };
    }
    const text = await res.text();
    if (!res.ok) return { ok: false as const, error: `Claude ${res.status}: ${text.slice(0, 300)}` };

    let explanation = "";
    try {
      const body = JSON.parse(text);
      explanation = Array.isArray(body.content)
        ? body.content.map((c: any) => c?.text ?? "").join("\n").trim()
        : "";
    } catch {
      return { ok: false as const, error: "Could not parse Claude response." };
    }
    if (!explanation) return { ok: false as const, error: "Claude returned an empty response." };

    if (finding) {
      await supabase
        .from("audit_findings")
        .update({ explanation })
        .eq("audit_id", data.auditId)
        .eq("checklist_item_id", data.checklistItemId);
    }

    return { ok: true as const, explanation, cached: false };
  });
