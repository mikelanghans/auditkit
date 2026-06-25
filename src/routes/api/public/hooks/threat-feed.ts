import { createFileRoute } from "@tanstack/react-router";

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export const Route = createFileRoute("/api/public/hooks/threat-feed")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env.THREAT_FEED_WEBHOOK_SECRET;
        if (!secret) {
          console.error("[threat-feed hook] THREAT_FEED_WEBHOOK_SECRET not configured");
          return new Response("Server not configured", { status: 503 });
        }
        const auth = request.headers.get("authorization") ?? "";
        const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
        const headerSecret = request.headers.get("x-hook-secret") ?? "";
        const provided = bearer || headerSecret;
        if (!provided || !timingSafeEqualStr(provided, secret)) {
          return new Response("Unauthorized", { status: 401 });
        }

        try {
          const { runThreatFeed } = await import("@/lib/threat-feed.server");
          const result = await runThreatFeed();
          return new Response(JSON.stringify(result), {
            headers: { "content-type": "application/json" },
          });
        } catch (e: any) {
          console.error("[threat-feed hook] error", e);
          return new Response(
            JSON.stringify({ ok: false, error: e?.message ?? "Unknown error" }),
            { status: 500, headers: { "content-type": "application/json" } },
          );
        }
      },
    },
  },
});
