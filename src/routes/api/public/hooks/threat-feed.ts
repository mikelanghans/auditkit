import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/public/hooks/threat-feed")({
  server: {
    handlers: {
      POST: async () => {
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
