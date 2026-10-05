import { createFileRoute } from "@tanstack/react-router";

// Called by FullAuditWorkflow (exports.cloudflare.ts) through its service
// binding to this Worker: runs the next stage of one full-audit run. Each call
// is its own request, so every stage gets a fresh Worker budget.
// Auth: x-pipeline-token = HMAC of the run id (src/lib/pipeline-auth.ts).

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

export const Route = createFileRoute("/api/public/hooks/pipeline-advance")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env.FULL_AUDIT_SECRETS_KEY;
        if (!secret || secret.length < 32) return json(503, { ok: false, error: "not configured" });
        let body: any;
        try {
          body = await request.json();
        } catch {
          return json(400, { ok: false, error: "invalid body" });
        }
        const runId = String(body?.runId ?? "");
        const profile = ["quick", "standard", "deep"].includes(body?.profile) ? body.profile : "standard";
        if (!RUN_ID.test(runId)) return json(400, { ok: false, error: "invalid runId" });
        const { verifyPipelineStepToken } = await import("@/lib/pipeline-auth");
        const ok = await verifyPipelineStepToken(runId, request.headers.get("x-pipeline-token") ?? "", secret).catch(() => false);
        if (!ok) return json(401, { ok: false, error: "unauthorized" });
        try {
          const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
          const eng = await import("@/lib/pipeline-engine.server");
          const creds = await eng.loadRunSecrets(supabaseAdmin, runId);
          const res = await eng.advancePipeline(supabaseAdmin, runId, creds, { profile });
          return json(200, { ok: true, ...res });
        } catch (e: any) {
          console.error("[pipeline-advance] error", e?.message ?? e);
          return json(500, { ok: false, error: "internal error" });
        }
      },
    },
  },
});
