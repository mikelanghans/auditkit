import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { redactSourceFile } from "./secret-redaction";
import { consumeQuota } from "./quota";
import { playbookFor } from "./fix-playbooks";

export type FixTarget = "lovable" | "cursor" | "claude";

// Anti-fabrication rule shared by every target. A remediation prompt that invents
// integrations the app doesn't have (e.g. telling a founder to "preserve your Stripe
// integration" when there is no Stripe) is both embarrassing and dangerous — a
// fabricated CSP allowlist either widens the attack surface or breaks the live app.
// So the model must ground its output only in the finding evidence, and stay generic
// where it lacks real data rather than guessing a "typical" stack.
// Extra guidance applied whenever the finding concerns Content-Security-Policy.
const CSP_RULE =
  "If the finding is about a Content-Security-Policy header, the prompt MUST also: " +
  "(a) say where the header goes using the playbook's rules: the server code that responds to every page request when the app has one (e.g. the SSR/server entry), or the host's header config for a static build. Never vague 'deployment settings' and never a <meta> tag; " +
  "(b) include these directives in the example policy: default-src 'self'; script-src; style-src; img-src; font-src; connect-src; " +
  "object-src 'none'; base-uri 'self'; frame-ancestors 'none' (or 'self'); form-action 'self'; " +
  "(c) forbid script-src 'unsafe-inline' and wildcards, but instruct that any inline scripts the framework needs for hydration " +
  "must be allowed via per-request nonces or SHA-256 hashes instead — warn that banning unsafe-inline without nonces/hashes can blank the page; " +
  "(d) note style-src may keep 'unsafe-inline' if inline styles are required (lower risk); " +
  "(e) roll out safely: ship first as Content-Security-Policy-Report-Only, check the browser console for violations, adjust the allowlist, " +
  "then switch to the enforcing Content-Security-Policy header, and say the AuditKit scan keeps failing CSP until that switch. Word budget for CSP prompts may extend to 300 words.";

const GROUNDING_RULE =
  "CRITICAL — do not fabricate. Base the prompt ONLY on the finding evidence provided. " +
  "Never invent, assume, or name specific third-party services, providers, integrations, " +
  "SDKs, CDNs, or file paths (for example Stripe, analytics, or particular script hosts) " +
  "unless they explicitly appear in the finding evidence. When a fix depends on the app's " +
  "actual resources — most importantly a Content-Security-Policy allowlist — do NOT output a " +
  "pre-filled list of origins; instead instruct the reader to inventory the origins their app " +
  "genuinely loads (scripts, styles, fonts, API/connect targets) and allowlist only those, " +
  "and warn that an over-broad or guessed policy can break the app. If you are unsure what the " +
  "app uses, say so and keep the instruction generic rather than naming providers. " +
  CSP_RULE;


const SYSTEM_PROMPTS: Record<FixTarget, string> = {
  lovable:
    "You are a security remediation expert who writes prompts that a founder pastes into Lovable, an AI app builder, to fix a security finding. " +
    'Lovable is the one doing the work, so write the prompt as direct instructions TO Lovable, in the imperative ("Add…", "Find…", "Check…"). ' +
    "Rules: 1) Lovable does all investigation: finding the right files, reading the code, working out what the app uses. Never ask the founder to locate files, read code, open DevTools, run commands, or edit anything by hand. " +
    "2) Where the fix depends on what the app uses, tell Lovable to check the code first and list what it found before changing anything. " +
    "3) Describe the exact change and the constraints (what must never be done, what must keep working). " +
    "4) Steps only a person can do outside the code (for example rotating a key in a provider's dashboard or changing a hosting setting) go in as an instruction for Lovable to tell the founder at the end, e.g. \"When you're done, remind me to rotate the key in the Stripe dashboard.\" " +
    "Any fix that changes what the live site sends (response headers, redirects, build output, served files) only takes effect after publishing, so always end by telling Lovable to remind the founder to click Publish → Update and then re-scan in AuditKit. " +
    '5) End with what Lovable should report back (the final values it set, what it kept enabled and why) and at most one simple check the founder can do in the app itself (e.g. "log in and complete a test payment"). ' +
    "6) Tell Lovable not to change unrelated code. " +
    '7) Plain text: no title or markdown headings, no "you need to", no explanation of the vulnerability. ' +
    "8) Under 220 words, or up to 380 words when a remediation playbook is provided. " +
    GROUNDING_RULE +
    " Output only the prompt text, ready to paste.",
  cursor:
    "You are a security remediation expert who writes precise prompts for Cursor, an AI code editor. " +
    "Given a security finding, generate a single prompt the developer can paste into Cursor's composer. " +
    "The prompt must: 1) Reference the likely file paths and frameworks, 2) Specify exact code changes (imports, headers, config), " +
    "3) Note any tests or build commands to run, 4) Tell Cursor to return only modified files with diffs, " +
    "5) Preserve unrelated integrations and existing behavior, 6) Be under 220 words, or up to 380 words when a remediation playbook is provided. " +
    GROUNDING_RULE +
    " Output only the prompt text — no preamble.",
  claude:
    "You are a security remediation expert who writes precise prompts for Claude Code, Anthropic's CLI coding agent. " +
    "Given a security finding, generate a single prompt the developer can paste into Claude Code. " +
    "The prompt must: 1) Tell Claude which files to read first, 2) Specify the exact remediation with code, " +
    "3) Ask Claude to run the relevant tests/build, 4) Ask for a concise summary of changes, " +
    "5) Preserve existing integrations and behavior, 6) Be under 220 words, or up to 380 words when a remediation playbook is provided. " +
    GROUNDING_RULE +
    " Output only the prompt text — no preamble.",
};

// When the finding has a playbook, it is appended to the user message. Its
// requirements override generic advice; conditional parts stay conditional.
const PLAYBOOK_RULE =
  " If the input includes a REMEDIATION PLAYBOOK, the prompt you write MUST follow every requirement in it " +
  "(order of steps, what never to do, rollout and verification). Adapt it to the app described in the evidence, " +
  'keep its conditional parts conditional ("if the app uses X"), and do not drop steps to save words.';
for (const k of Object.keys(SYSTEM_PROMPTS) as FixTarget[]) SYSTEM_PROMPTS[k] += PLAYBOOK_RULE;

function playbookSection(item: { checklist_key?: string | null; title?: string | null }): string {
  const pb = playbookFor(item);
  return pb ? `\n\nREMEDIATION PLAYBOOK (${pb.id}):\n${pb.text}\n` : "";
}

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
      .from("audits")
      .select("id, created_by, built_with")
      .eq("id", data.auditId)
      .single();
    if (aerr || !auditRow || auditRow.created_by !== userId) {
      return { ok: false as const, error: "Audit not found or access denied." };
    }

    // Ad-hoc mode: an AI Assist suggestion that isn't a saved finding yet.
    // The item's title and guidance come from our checklist, not the request,
    // and the caller's evidence text is capped and redacted. No caching.
    if (data.adhoc) {
      const { data: adhocItem, error: aiErr } = await supabase
        .from("checklist_items")
        .select("title, category, description, what_to_look_for, checklist_key")
        .eq("id", data.checklistItemId)
        .single();
      if (aiErr || !adhocItem) return { ok: false as const, error: "Checklist item not found." };
      const evidence = redactSourceFile(
        String(data.adhoc.notes ?? "")
          .slice(0, MAX_ADHOC_NOTES)
          .trim(),
      );
      const quota = await consumeQuota(supabase, "llm", 1);
      if (!quota.ok) return { ok: false as const, error: quota.error };
      const userMessage =
        `Finding title: ${adhocItem.title}\n` +
        `Category: ${adhocItem.category}\n` +
        (adhocItem.description ? `Description: ${adhocItem.description}\n` : "") +
        (adhocItem.what_to_look_for ? `What to look for: ${adhocItem.what_to_look_for}\n` : "") +
        `\nAI Assist evidence (unverified, from the client's code):\n${evidence || "(no evidence provided)"}` +
        playbookSection(adhocItem);
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
    if (finding.status !== "fail")
      return { ok: false as const, error: "Only failing findings can be remediated." };

    const cached = (finding as any)[column] as string | null | undefined;
    if (!data.force && cached && cached.trim()) {
      return { ok: true as const, prompt: cached, target, cached: true };
    }

    const { data: item, error: ierr } = await supabase
      .from("checklist_items")
      .select("title, category, description, what_to_look_for, checklist_key")
      .eq("id", data.checklistItemId)
      .single();
    if (ierr || !item) return { ok: false as const, error: "Checklist item not found." };

    const BUILT_WITH_LABEL: Record<string, string> = {
      lovable: "Lovable",
      cursor: "Cursor",
      claude_code: "Claude Code",
      v0: "v0",
      bolt: "Bolt",
      windsurf: "Windsurf",
      replit: "Replit Agent",
      chatgpt: "ChatGPT",
      other: "another AI tool",
      hand_coded: "hand-coded (no AI)",
    };
    const builtWithHint =
      builtWith && BUILT_WITH_LABEL[builtWith]
        ? `\nApp origin: this codebase was built with ${BUILT_WITH_LABEL[builtWith]}. Tailor file paths, conventions, and phrasing to that toolchain when relevant.\n`
        : "";

    const userMessage =
      `Finding title: ${item.title}\n` +
      `Category: ${item.category}\n` +
      (item.description ? `Description: ${item.description}\n` : "") +
      (item.what_to_look_for ? `What to look for: ${item.what_to_look_for}\n` : "") +
      builtWithHint +
      // Notes can hold evidence pasted from the client's code or scan output.
      `\nAuditor notes & evidence:\n${redactSourceFile((finding.notes ?? "").trim()) || "(no notes provided)"}` +
      playbookSection(item);

    const quota = await consumeQuota(supabase, "llm", 1);
    if (!quota.ok) return { ok: false as const, error: quota.error };
    const result = await callClaude(target, userMessage);
    if (!result.ok) return result;

    const { error: uerr } = await supabase
      .from("audit_findings")
      .update({ [column]: result.prompt } as any)
      .eq("audit_id", data.auditId)
      .eq("checklist_item_id", data.checklistItemId);
    if (uerr)
      return {
        ok: true as const,
        prompt: result.prompt,
        target,
        cached: false,
        warning: uerr.message,
      };

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
        max_tokens: 1500,
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
      ? body.content
          .map((c: any) => c?.text ?? "")
          .join("\n")
          .trim()
      : "";
  } catch {
    return { ok: false as const, error: "Could not parse Claude response." };
  }
  if (!prompt) return { ok: false as const, error: "Claude returned an empty response." };
  return { ok: true as const, prompt, target, cached: false };
}
