import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const SYSTEM_PROMPT =
  "You are a security remediation expert who writes precise, actionable prompts for Lovable, an AI-powered app builder. " +
  "Given a security finding, generate a single clear prompt that a founder can paste directly into Lovable to fix the vulnerability. " +
  "The prompt must: 1) Identify the exact file or component to change, 2) Describe the specific code change needed, " +
  "3) Include verification steps so the founder knows the fix worked, 4) Be written in plain language a non-security expert can understand, " +
  "5) Be under 200 words. Do not include explanations or preamble — just the prompt text ready to paste.";

export type GenerateLovablePromptInput = {
  auditId: string;
  checklistItemId: string;
  force?: boolean;
};

export const generateLovablePrompt = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: GenerateLovablePromptInput) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;

    const { data: auditRow, error: aerr } = await supabase
      .from("audits").select("id, created_by").eq("id", data.auditId).single();
    if (aerr || !auditRow || auditRow.created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }

    const { data: finding, error: ferr } = await supabase
      .from("audit_findings")
      .select("notes, status, lovable_prompt")
      .eq("audit_id", data.auditId)
      .eq("checklist_item_id", data.checklistItemId)
      .maybeSingle();
    if (ferr) return { ok: false as const, error: ferr.message };
    if (!finding) return { ok: false as const, error: "Finding not found." };
    if (finding.status !== "fail") return { ok: false as const, error: "Only failing findings can be remediated." };

    if (!data.force && finding.lovable_prompt && finding.lovable_prompt.trim()) {
      return { ok: true as const, prompt: finding.lovable_prompt, cached: true };
    }

    const { data: item, error: ierr } = await supabase
      .from("checklist_items")
      .select("title, category, description, what_to_look_for")
      .eq("id", data.checklistItemId).single();
    if (ierr || !item) return { ok: false as const, error: "Checklist item not found." };

    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return { ok: false as const, error: "ANTHROPIC_API_KEY is not configured." };

    const userMessage =
      `Finding title: ${item.title}\n` +
      `Category: ${item.category}\n` +
      (item.description ? `Description: ${item.description}\n` : "") +
      (item.what_to_look_for ? `What to look for: ${item.what_to_look_for}\n` : "") +
      `\nAuditor notes & evidence:\n${(finding.notes ?? "").trim() || "(no notes provided)"}`;

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
          max_tokens: 1024,
          system: SYSTEM_PROMPT,
          messages: [{ role: "user", content: userMessage }],
        }),
      });
    } catch (e: any) {
      return { ok: false as const, error: e?.message ?? "Claude request failed." };
    }
    const text = await res.text();
    if (!res.ok) return { ok: false as const, error: `Claude ${res.status}: ${text.slice(0, 300)}` };

    let prompt = "";
    try {
      const body = JSON.parse(text);
      prompt = Array.isArray(body.content)
        ? body.content.map((c: any) => c?.text ?? "").join("\n").trim()
        : "";
    } catch {
      return { ok: false as const, error: "Could not parse Claude response." };
    }
    if (!prompt) return { ok: false as const, error: "Claude returned an empty response." };

    const { error: uerr } = await supabase
      .from("audit_findings")
      .update({ lovable_prompt: prompt })
      .eq("audit_id", data.auditId)
      .eq("checklist_item_id", data.checklistItemId);
    if (uerr) return { ok: true as const, prompt, cached: false, warning: uerr.message };

    return { ok: true as const, prompt, cached: false };
  });
