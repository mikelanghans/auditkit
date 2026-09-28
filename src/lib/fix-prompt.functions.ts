import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { redactSourceFile } from "./secret-redaction";
import { consumeQuota } from "./quota";

export type FixTarget = "lovable" | "cursor" | "claude";

// Anti-fabrication rule shared by every target. A remediation prompt that invents
// integrations the app doesn't have (e.g. telling a founder to "preserve your Stripe
// integration" when there is no Stripe) is both embarrassing and dangerous — a
// fabricated CSP allowlist either widens the attack surface or breaks the live app.
// So the model must ground its output only in the finding evidence, and stay generic
// where it lacks real data rather than guessing a "typical" stack.
const GROUNDING_RULE =
  "CRITICAL — do not fabricate. Base the prompt ONLY on the finding evidence provided. " +
  "Never invent, assume, or name specific third-party services, providers, integrations, " +
  "SDKs, CDNs, or file paths (for example Stripe, analytics, or particular script hosts) " +
  "unless they explicitly appear in the finding evidence. When a fix depends on the app's " +
  "actual resources — most importantly a Content-Security-Policy allowlist — do NOT output a " +
  "pre-filled list of origins; instead instruct the reader to inventory the origins their app " +
  "genuinely loads (scripts, styles, fonts, API/connect targets) and allowlist only those, " +
  "and warn that an over-broad or guessed policy can break the app. If you are unsure what the " +
  "app uses, say so and keep the instruction generic rather than naming providers.";

const SYSTEM_PROMPTS: Record<FixTarget, string> = {
  lovable:
    "You are a security remediation expert who writes precise, actionable prompts for Lovable, an AI-powered app builder. " +
    "Given a security finding, generate a single clear prompt that a founder can paste directly into Lovable to fix the vulnerability. " +
    "The prompt must: 1) Identify the exact file or component to change, 2) Describe the specific code change needed, " +
    "3) Include verification steps so the founder knows the fix worked, 4) Be written in plain language a non-security expert can understand, " +
    "5) Preserve the app's existing behavior and integrations without breaking legitimate functionality, " +
    "6) Be under 220 words. " +
    GROUNDING_RULE +
    " Do not include explanations or preamble — just the prompt text ready to paste.",
  cursor:
    "You are a security remediation expert who writes precise prompts for Cursor, an AI code editor. " +
    "Given a security finding, generate a single prompt the developer can paste into Cursor's composer. " +
    "The prompt must: 1) Reference the likely file paths and frameworks, 2) Specify exact code changes (imports, headers, config), " +
    "3) Note any tests or build commands to run, 4) Tell Cursor to return only modified files with diffs, " +
    "5) Preserve unrelated integrations and existing behavior, 6) Be under 220 words. " +
    GROUNDING_RULE +
    " Output only the prompt text — no preamble.",
  claude:
    "You are a security remediation expert who writes precise prompts for Claude Code, Anthropic's CLI coding agent. " +
    "Given a security finding, generate a single prompt the developer can paste into Claude Code. " +
    "The prompt must: 1) Tell Claude which files to read first, 2) Specify the exact remediation with code, " +
    "3) Ask Claude to run the relevant tests/build, 4) Ask for a concise summary of changes, " +
    "5) Preserve existing integrations and behavior, 6) Be under 220 words. " +
    GROUNDING_RULE +
    " Output only the prompt text — no preamble.",
};

const COLUMN: Record<FixTarget, "lovable_prompt" | "cursor_prompt" | "claude_prompt"> = {
  lovable: "lovable_prompt",
  cursor: "cursor_prompt",
  claude: "claude_prompt",
};

const MAX_ADHOC_NOTES = 6_000;

export type GenerateFixPromptInput = {
  auditId?: string;
  checklistItemId?: string;
  target: FixTarget;
  force?: boolean;
  // Ad-hoc mode, for AI Assist suggestions that aren't saved as findings yet.
  // Still requires auditId + checklistItemId: the finding's title and guidance
  // come from our own checklist, and only the evidence text comes from the caller.
  adhoc?: {
    notes?: string;
  };
};

export const generateFixPrompt = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: GenerateFixPromptInput) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const target: FixTarget = data.target;
    const column = COLUMN[target];
    if (!column) return { ok: false as const, error: "Invalid target." };

    if (!data.auditId || !data.checklistItemId) {
      return { ok: false as const, error: "Missing auditId/checklistItemId." };
    }

    const { data: auditRow, error: aerr } = await supabase
      .from("audits").select("id, created_by, built_with").eq("id", data.auditId).single();
    if (aerr || !auditRow || auditRow.created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }

    // Ad-hoc mode: an AI Assist suggestion that isn't a saved finding yet.
    // The item's title and guidance come from our checklist, not the request,
    // and the caller's evidence text is capped and redacted. No caching.
    if (data.adhoc) {
      const { data: adhocItem, error: aiErr } = await supabase
        .from("checklist_items")
        .select("title, category, description, what_to_look_for")
        .eq("id", data.checklistItemId).single();
      if (aiErr || !adhocItem) return { ok: false as const, error: "Checklist item not found." };
      const evidence = redactSourceFile(String(data.adhoc.notes ?? "").slice(0, MAX_ADHOC_NOTES).trim());
      const quota = await consumeQuota(supabase, "llm", 1);
      if (!quota.ok) return { ok: false as const, error: quota.error };
      const userMessage =
        `Finding title: ${adhocItem.title}\n` +
        `Category: ${adhocItem.category}\n` +
        (adhocItem.description ? `Description: ${adhocItem.description}\n` : "") +
        (adhocItem.what_to_look_for ? `What to look for: ${adhocItem.what_to_look_for}\n` : "") +
        `\nAI Assist evidence (unverified, from the client's code):\n${evidence || "(no evidence provided)"}`;
      return await callClaude(target, userMessage);
    }
    const builtWith = (auditRow as any).built_with as string | null;

    const { data: finding, error: ferr } = await supabase
      .from("audit_findings")
      .select("notes, status, lovable_prompt, cursor_prompt, claude_prompt")
      .eq("audit_id", data.auditId)
      .eq("checklist_item_id", data.checklistItemId)
      .maybeSingle();
    if (ferr) return { ok: false as const, error: ferr.message };
    if (!finding) return { ok: false as const, error: "Finding not found." };
    if (finding.status !== "fail") return { ok: false as const, error: "Only failing findings can be remediated." };

    const cached = (finding as any)[column] as string | null | undefined;
    if (!data.force && cached && cached.trim()) {
      return { ok: true as const, prompt: cached, target, cached: true };
    }

    const { data: item, error: ierr } = await supabase
      .from("checklist_items")
      .select("title, category, description, what_to_look_for")
      .eq("id", data.checklistItemId).single();
    if (ierr || !item) return { ok: false as const, error: "Checklist item not found." };


    const BUILT_WITH_LABEL: Record<string, string> = {
      lovable: "Lovable", cursor: "Cursor", claude_code: "Claude Code",
      v0: "v0", bolt: "Bolt", windsurf: "Windsurf", replit: "Replit Agent",
      chatgpt: "ChatGPT", other: "another AI tool", hand_coded: "hand-coded (no AI)",
    };
    const builtWithHint = builtWith && BUILT_WITH_LABEL[builtWith]
      ? `\nApp origin: this codebase was built with ${BUILT_WITH_LABEL[builtWith]}. Tailor file paths, conventions, and phrasing to that toolchain when relevant.\n`
      : "";

    const userMessage =
      `Finding title: ${item.title}\n` +
      `Category: ${item.category}\n` +
      (item.description ? `Description: ${item.description}\n` : "") +
      (item.what_to_look_for ? `What to look for: ${item.what_to_look_for}\n` : "") +
      builtWithHint +
      // Notes can hold evidence pasted from the client's code or scan output.
      `\nAuditor notes & evidence:\n${redactSourceFile((finding.notes ?? "").trim()) || "(no notes provided)"}`;

    const quota = await consumeQuota(supabase, "llm", 1);
    if (!quota.ok) return { ok: false as const, error: quota.error };
    const result = await callClaude(target, userMessage);
    if (!result.ok) return result;

    const { error: uerr } = await supabase
      .from("audit_findings")
      .update({ [column]: result.prompt } as any)
      .eq("audit_id", data.auditId)
      .eq("checklist_item_id", data.checklistItemId);
    if (uerr) return { ok: true as const, prompt: result.prompt, target, cached: false, warning: uerr.message };

    return { ok: true as const, prompt: result.prompt, target, cached: false };
  });

async function callClaude(target: FixTarget, userMessage: string) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return { ok: false as const, error: "ANTHROPIC_API_KEY is not configured." };

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
        system: SYSTEM_PROMPTS[target],
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
  return { ok: true as const, prompt, target, cached: false };
}

