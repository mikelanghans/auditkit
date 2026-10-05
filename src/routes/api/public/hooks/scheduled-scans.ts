import { createFileRoute } from "@tanstack/react-router";

// Runs due scheduled scans. Called hourly by .github/workflows/scheduled-scans.yml
// (or any cron) with the SCHEDULED_SCANS_SECRET in x-hook-secret or a bearer token.

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export const Route = createFileRoute("/api/public/hooks/scheduled-scans")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env.SCHEDULED_SCANS_SECRET;
        if (!secret || secret.length < 32) {
          console.error("[scheduled-scans hook] SCHEDULED_SCANS_SECRET not configured (needs 32+ characters)");
          return new Response("Server not configured", { status: 503 });
        }
        const auth = request.headers.get("authorization") ?? "";
        const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
        const provided = bearer || (request.headers.get("x-hook-secret") ?? "");
        if (!provided || !timingSafeEqualStr(provided, secret)) {
          return new Response("Unauthorized", { status: 401 });
        }
        try {
          const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
          const { runDueSchedules } = await import("@/lib/scheduled-scans.server");
          const result = await runDueSchedules(supabaseAdmin);
          // Close out full-audit pipelines nobody is driving any more.
          await import("@/lib/pipeline-engine.server")
            .then((m) => m.sweepStalePipelines(supabaseAdmin))
            .catch((e) => console.error("[scheduled-scans hook] pipeline sweep failed", e?.message ?? e));
          return new Response(
            JSON.stringify({ ok: true, ran: result.ran.map((r) => ({ status: r.status, alerts: r.alerts, failed: !!r.error })) }),
            { headers: { "content-type": "application/json" } },
          );
        } catch (e: any) {
          console.error("[scheduled-scans hook] error", e);
          return new Response(JSON.stringify({ ok: false, error: "internal error" }), {
            status: 500,
            headers: { "content-type": "application/json" },
          });
        }
      },
    },
  },
});
