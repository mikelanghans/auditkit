// Authenticates the full-audit Workflow's calls back into the app. No imports,
// so exports.cloudflare.ts can use it without pulling in the app.
//
// The Workflow sends HMAC-SHA256(key, "pipeline-advance:<runId>") where the key
// is derived from FULL_AUDIT_SECRETS_KEY. A token is good for one run only.

const enc = new TextEncoder();

async function hmacKey(secret: string) {
  if (!secret || secret.length < 32) throw new Error("FULL_AUDIT_SECRETS_KEY must be at least 32 characters.");
  const raw = await crypto.subtle.digest("SHA-256", enc.encode(`auditkit-pipeline:advance-hmac:${secret}`));
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

const hex = (buf: ArrayBuffer) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");

export async function pipelineStepToken(runId: string, secret: string): Promise<string> {
  return hex(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(`pipeline-advance:${runId}`)));
}

export async function verifyPipelineStepToken(runId: string, token: string, secret: string): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(token)) return false;
  const bytes = new Uint8Array(token.match(/../g)!.map((h) => parseInt(h, 16)));
  return crypto.subtle.verify("HMAC", await hmacKey(secret), bytes, enc.encode(`pipeline-advance:${runId}`));
}
