import { createFileRoute } from "@tanstack/react-router";

// Callbacks from the deep-audit runner. Authenticated by an HMAC signature over
// the timestamp and raw body (see code-audit-contract.ts); anything unsigned,
// stale or oversized is rejected before it is parsed.
const MAX_BODY_BYTES = 6 * 1024 * 1024;

async function readCapped(request: Request): Promise<string | null> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return null;
  const reader = request.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

export const Route = createFileRoute("/api/public/hooks/code-audit")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env.CODE_AUDIT_WEBHOOK_SECRET;
        if (!secret) return json(503, { ok: false, error: "not configured" });

        const body = await readCapped(request);
        if (body === null) return json(413, { ok: false, error: "body too large" });

        // Each run signs with its own key, derived from the run id; a runner
        // can only ever speak for the run it was given.
        const { verifyRunCallback } = await import("@/lib/code-audit-contract");
        const verified = await verifyRunCallback(
          body,
          {
            run: request.headers.get("x-auditkit-run"),
            timestamp: request.headers.get("x-auditkit-timestamp"),
            signature: request.headers.get("x-auditkit-signature"),
          },
          secret,
        ).catch(() => null);
        if (!verified) return json(401, { ok: false, error: "unauthorized" });
        const payload = verified.payload;

        try {
          const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
          const { applyCallback } = await import("@/lib/code-audit-import");
          const res = await applyCallback(payload, { db: supabaseAdmin as any });
          return json(res.status, res);
        } catch (e: any) {
          console.error("[code-audit hook] error", e?.message ?? e);
          return json(500, { ok: false, error: "internal error" });
        }
      },
    },
  },
});
