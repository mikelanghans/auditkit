// Outgoing email through Resend. Server-only.
//   RESEND_API_KEY     API key
//   CHECK_FROM_EMAIL   verified sender, e.g. "SafeShip <reports@yourdomain.com>"
import type { OutgoingEmail } from "./public-check-email";

export function emailConfigured(): boolean {
  return !!(process.env.RESEND_API_KEY && process.env.CHECK_FROM_EMAIL);
}

export async function sendEmail(
  msg: OutgoingEmail,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: process.env.CHECK_FROM_EMAIL,
      to: [msg.to],
      subject: msg.subject,
      html: msg.html,
      text: msg.text,
    }),
  });
  if (res.ok) return { ok: true };
  const body = await res.text().catch(() => "");
  return { ok: false, error: `Resend ${res.status}: ${body.slice(0, 200)}` };
}
