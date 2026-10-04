// Server side of the deeper AI tests (build plan 3.8). The tests themselves
// live in ai-deep-tests.ts. This file gates them, sends the requests through
// the SSRF guard, and records findings, history and evidence.
import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { assertSafeOutboundUrl, safeFetch, SSRFBlockedError, describeBlockedUrl } from "./ssrf-guard";
import { upsertScanFinding } from "./finding-writer";
import { saveScanRun, type RecordedResult } from "./scan-history";
import type { EvidenceInput } from "./evidence";
import { consumeQuota } from "./quota";
import { checkWriteTestsAllowed } from "./audit-targets";
import { runDeepAiTests, DEFAULT_BUDGET, MAX_BUDGET, DEEP_TEST_LABEL, type Exchange, type Sender } from "./ai-deep-tests";

export type AIDeepInput = {
  auditId: string;
  endpointUrl: string;
  promptField: string;
  messagesField?: string | null;
  authToken?: string | null;
  budget?: number | null;
  parentRunId?: string | null;
};

const fieldName = (s: string | null | undefined) => (s ?? "").trim().replace(/[^a-zA-Z0-9_]/g, "");

export const runAIDeepTests = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: AIDeepInput) => {
    if (!input || typeof input.auditId !== "string" || typeof input.endpointUrl !== "string") throw new Error("Invalid input");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const url = data.endpointUrl.trim();
    try {
      const u = new URL(url);
      if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error();
    } catch {
      return { ok: false as const, error: "Endpoint URL must be a valid http(s) URL." };
    }
    try {
      await assertSafeOutboundUrl(url);
    } catch (e) {
      if (e instanceof SSRFBlockedError) return { ok: false as const, error: describeBlockedUrl(e) };
      throw e;
    }
    const promptField = fieldName(data.promptField) || "prompt";
    const messagesField = fieldName(data.messagesField) || null;
    const budget = Math.max(10, Math.min(MAX_BUDGET, Math.floor(data.budget ?? DEFAULT_BUDGET)));
    const authToken = data.authToken?.trim() || null;

    const { data: auditRow } = await supabase.from("audits").select("id, created_by").eq("id", data.auditId).maybeSingle();
    if (!auditRow || auditRow.created_by !== userId) return { ok: false as const, error: "Audit not found or access denied." };

    // These send real traffic that costs the client money, including a burst
    // for the rate-limit test: only with written authorization on file.
    const gate = await checkWriteTestsAllowed(supabase, data.auditId);
    if (!gate.ok) return { ok: false as const, error: gate.error };

    const quota = await consumeQuota(supabase, "scan", 1);
    if (!quota.ok) return { ok: false as const, error: quota.error };

    const baseHeaders: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/plain;q=0.9, */*;q=0.8",
      "user-agent": "AuditKit-AIDeep/1.0",
    };
    const send: Sender = async ({ body, withAuth }) => {
      const headers = { ...baseHeaders };
      if (withAuth && authToken) headers.authorization = authToken.startsWith("Bearer ") ? authToken : `Bearer ${authToken}`;
      const start = Date.now();
      try {
        const res = await safeFetch(url, { method: "POST", headers, body: JSON.stringify(body) }, { timeoutMs: 30_000, maxBodyBytes: 500_000 });
        const text = await res.text();
        const h: Record<string, string> = {};
        res.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
        return { status: res.status, headers: h, body: text.slice(0, 200_000), ms: Date.now() - start } satisfies Exchange;
      } catch (e: any) {
        return { status: 0, headers: {}, body: "", ms: Date.now() - start, error: e?.message ?? "request failed" };
      }
    };

    const result = await runDeepAiTests(send, { promptField, messagesField, hasAuth: !!authToken, budget });

    const { data: items } = await supabase.from("checklist_items").select("id, checklist_key").in("checklist_key", result.checks.map((c) => c.key));
    const byKey = new Map<string, string>((items ?? []).map((it: any) => [it.checklist_key as string, it.id as string]));
    const stamp = new Date().toISOString();
    const header = `[Deeper AI tests ${stamp}]\nEndpoint: ${url}\nRequests sent: ${result.requestsUsed} of a ${result.budget} budget\n\n`;

    const evidence: EvidenceInput[] = result.checks.map((c) => ({
      ref: c.key,
      kind: "ai_exchange" as const,
      title: `${DEEP_TEST_LABEL[c.key]}: requests sent to ${url}`,
      content: {
        endpoint: url,
        prompt_field: promptField,
        messages_field: messagesField,
        authenticated: !!authToken,
        exchanges: result.probes.filter((p) => p.test === c.key),
      },
    }));

    const recorded: RecordedResult[] = [];
    const counts = { pass: 0, fail: 0, inconclusive: 0, not_run: 0 };
    for (const c of result.checks) {
      counts[c.status]++;
      const itemId = byKey.get(c.key) ?? null;
      const notes = header + c.notes;
      let stored = false;
      if (itemId && c.status !== "not_run") {
        const w = await upsertScanFinding(supabase, { audit_id: data.auditId, checklist_item_id: itemId, status: c.status, notes });
        stored = w.written;
      }
      recorded.push({ checklist_item_id: itemId, checklist_key: c.key, status: c.status, notes, stored, evidence: [c.key] });
    }

    const history = await saveScanRun(
      supabase,
      { auditId: data.auditId, scanner: "ai_deep", target: url, trigger: data.parentRunId ? "full" : "manual", parentRunId: data.parentRunId ?? null, createdBy: userId },
      recorded,
      { evidence },
    );

    return {
      ok: true as const,
      endpoint: url,
      checks: result.checks.map((c) => ({ ...c, label: DEEP_TEST_LABEL[c.key] })),
      requestsUsed: result.requestsUsed,
      budget: result.budget,
      counts,
      history,
    };
  });
