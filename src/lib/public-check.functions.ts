// Server functions for the public /check page. No login: visitors are
// anonymous, so these use the service-role client, and every limit that
// matters is enforced in the database (begin_public_check).
import { createServerFn } from "@tanstack/react-start";
import { runPublicCheck, unlockPublicReport } from "./public-check-core";

/** Keyed hash of the requester's IP, so rate limits work without storing IPs. */
async function requesterHash(): Promise<string> {
  const { getRequest } = await import("@tanstack/react-start/server");
  const req = getRequest();
  const h = req.headers;
  // cf-connecting-ip is set by Cloudflare and can't be spoofed through it.
  const ip =
    h.get("cf-connecting-ip") ||
    h.get("x-real-ip") ||
    (h.get("x-forwarded-for") ?? "").split(",")[0].trim() ||
    "unknown";
  const secret = process.env.PUBLIC_CHECK_SALT || process.env.SUPABASE_SERVICE_ROLE_KEY || "";
  if (!secret) throw new Error("PUBLIC_CHECK_SALT is not configured.");
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`public-check:${ip}`));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
}

export const startPublicCheck = createServerFn({ method: "POST" })
  .inputValidator((input: { url: string }) => {
    if (!input || typeof input.url !== "string" || input.url.length > 2048)
      throw new Error("url required");
    return { url: input.url };
  })
  .handler(async ({ data }) => {
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const ipHash = await requesterHash();
    return runPublicCheck(data.url, { db: supabaseAdmin as any, ipHash });
  });

export const getPublicReport = createServerFn({ method: "POST" })
  .inputValidator((input: { id: string; email: string; marketingConsent?: boolean }) => {
    if (!input || typeof input.id !== "string" || typeof input.email !== "string")
      throw new Error("id and email required");
    return {
      id: input.id,
      email: input.email.slice(0, 254),
      marketingConsent: input.marketingConsent === true,
    };
  })
  .handler(async ({ data }) => {
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { emailConfigured, sendEmail } = await import("./email.server");
    const mailer = emailConfigured()
      ? {
          send: sendEmail,
          ownerEmail: process.env.OWNER_NOTIFY_EMAIL || null,
          bookingUrl: process.env.SAFESHIP_BOOKING_URL || process.env.VITE_SAFESHIP_BOOKING_URL || null,
        }
      : null;
    return unlockPublicReport(data, { db: supabaseAdmin as any, mailer });
  });
