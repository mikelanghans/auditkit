// Sends /check leads to Connect Hub (Mike's CRM) through its signed intake
// endpoint: POST <CONNECT_HUB_INTAKE_URL>/auditkit_check with an HMAC-SHA256
// hex signature of the body in x-webhook-signature.
//
// Kept free of the TanStack runtime (and of node:crypto) so it runs in the
// Worker and in the node:test harness alike.

export type CrmLead = {
  name: string;
  email: string;
  external_id: string;
  marketing_consent: boolean;
  notes?: string;
  metadata?: Record<string, string | number | boolean | null>;
};

export type CrmNotifier = { send: (lead: CrmLead) => Promise<{ ok: boolean; error?: string }> };

async function hmacHex(secret: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Notifier for Connect Hub. `baseUrl` is the intake root, e.g.
 * https://heart-of-contacts.lovable.app/api/public/webhooks/intake
 * Returns null unless both the URL and the secret are configured.
 */
export function connectHubNotifier(
  baseUrl: string | undefined | null,
  secret: string | undefined | null,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 5000,
): CrmNotifier | null {
  if (!baseUrl || !secret) return null;
  const url = `${baseUrl.replace(/\/+$/, "")}/auditkit_check`;
  return {
    async send(lead) {
      const body = JSON.stringify(lead);
      try {
        const res = await fetchImpl(url, {
          method: "POST",
          headers: { "content-type": "application/json", "x-webhook-signature": await hmacHex(secret, body) },
          body,
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) return { ok: false, error: `Connect Hub returned ${res.status}` };
        return { ok: true };
      } catch (e) {
        return { ok: false, error: String(e) };
      }
    },
  };
}
