// The contract between AuditKit and the deep-audit runner. Shared shape and
// crypto only; no imports, so tests and the runner can load it directly.
//
// Two secrets, so a compromised runner can't speak for other runs:
//   CODE_AUDIT_JOB_KEY         shared with the runner; decrypts job blobs only.
//   CODE_AUDIT_WEBHOOK_SECRET  AuditKit only, never on the runner. Each run's
//                              callback key is derived from it and the run id.
//
// Job (AuditKit → runner): the whole job spec, including the client's GitHub
// token and that run's callback key, is encrypted with AES-256-GCM before it is
// put in the Fly machine's environment.
//
// Callback (runner → AuditKit): X-AuditKit-Run names the run; HMAC-SHA256 with
// that run's key over `${timestamp}.${body}` goes in X-AuditKit-Signature;
// timestamps older than 5 minutes are rejected.

export type CodeAuditProfile = "quick" | "standard" | "deep";

/** Strict agent-invocation budgets passed to the skill, per profile. */
export const PROFILE_BUDGETS: Record<CodeAuditProfile, number> = {
  quick: 30,
  standard: 80,
  deep: 200,
};

export type CodeAuditJob = {
  runId: string;
  repoUrl: string;
  gitRef: string | null;
  githubToken: string | null;
  profile: CodeAuditProfile;
  budget: number;
  callbackUrl: string;
  /** This run's callback signing key (hex). Signs callbacks for this run only. */
  callbackKey: string;
  issuedAt: string;
};

/** Stages the runner reports, in order. */
export const PROGRESS_PHASES = ["starting", "cloning", "auditing", "validating", "reporting"] as const;
export type ProgressPhase = (typeof PROGRESS_PHASES)[number];

export type RunProgress = {
  phase: ProgressPhase;
  /** What the agent is doing now, e.g. its current to-do item. */
  detail?: string | null;
  /** Sub-agents launched so far (counts against the budget). */
  agents?: number | null;
  /** Tool calls made so far. */
  steps?: number | null;
  todosDone?: number | null;
  todosTotal?: number | null;
};

export type CallbackEvent =
  | { runId: string; event: "started"; machineId?: string }
  | ({ runId: string; event: "progress" } & RunProgress)
  | { runId: string; event: "failed"; error: string; agentsUsed?: number }
  | {
      runId: string;
      event: "completed";
      runStatus: "complete" | "incomplete";
      incompleteReason?: string | null;
      sourceCommit?: string | null;
      agentsUsed?: number | null;
      /** Output of the skill's own validators, run on the runner. */
      validators: { findings: string; ledger: string };
      findings: unknown[];
      coverageLedger: unknown[];
      reportMd?: string;
      findingsDetailMd?: string;
      needsValidationMd?: string;
    };

const enc = new TextEncoder();

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveBytes(secret: string, label: string): Promise<ArrayBuffer> {
  if (!secret || secret.length < 32)
    throw new Error("Code-audit secrets must be at least 32 characters.");
  return crypto.subtle.digest("SHA-256", enc.encode(`auditkit-code-audit:${label}:${secret}`));
}

async function hmacKey(secret: string) {
  return crypto.subtle.importKey(
    "raw",
    await deriveBytes(secret, "callback-hmac"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function aesKey(secret: string) {
  return crypto.subtle.importKey(
    "raw",
    await deriveBytes(secret, "job-aes"),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * The callback key for one run. Only AuditKit can compute it (it needs the
 * webhook secret); the runner receives it inside that run's encrypted job.
 */
export async function deriveCallbackKey(webhookSecret: string, runId: string): Promise<string> {
  const root = await crypto.subtle.importKey(
    "raw",
    await deriveBytes(webhookSecret, "callback-root"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", root, enc.encode(`run:${runId}`)));
}

export async function encryptJob(job: CodeAuditJob, secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await aesKey(secret),
    enc.encode(JSON.stringify(job)),
  );
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.length);
  return b64encode(out);
}

export async function decryptJob(blob: string, secret: string): Promise<CodeAuditJob> {
  const bytes = b64decode(blob);
  const iv = bytes.slice(0, 12);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    await aesKey(secret),
    bytes.slice(12),
  );
  return JSON.parse(new TextDecoder().decode(pt)) as CodeAuditJob;
}

export async function signCallback(
  body: string,
  secret: string,
  timestamp = Math.floor(Date.now() / 1000),
): Promise<{
  timestamp: string;
  signature: string;
}> {
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(secret),
    enc.encode(`${timestamp}.${body}`),
  );
  return { timestamp: String(timestamp), signature: toHex(sig) };
}

export const CALLBACK_MAX_SKEW_SECONDS = 300;

const RUN_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Verify a runner callback against the key for the run it names
 * (X-AuditKit-Run), and check the body is about that same run.
 * Returns the parsed payload, or null if anything doesn't match.
 */
export async function verifyRunCallback(
  body: string,
  headers: { run: string | null; timestamp: string | null; signature: string | null },
  webhookSecret: string,
  now = Math.floor(Date.now() / 1000),
): Promise<{ runId: string; payload: any } | null> {
  const runId = headers.run ?? "";
  if (!RUN_ID_RE.test(runId)) return null;
  const key = await deriveCallbackKey(webhookSecret, runId);
  if (!(await verifyCallback(body, headers.timestamp, headers.signature, key, now))) return null;
  let payload: any;
  try {
    payload = JSON.parse(body);
  } catch {
    return null;
  }
  if (!payload || typeof payload !== "object" || payload.runId !== runId) return null;
  return { runId, payload };
}

/** Constant-time check of the callback signature and freshness. */
export async function verifyCallback(
  body: string,
  timestamp: string | null,
  signature: string | null,
  secret: string,
  now = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  if (
    !timestamp ||
    !signature ||
    !/^\d{9,11}$/.test(timestamp) ||
    !/^[0-9a-f]{64}$/.test(signature)
  )
    return false;
  if (Math.abs(now - Number(timestamp)) > CALLBACK_MAX_SKEW_SECONDS) return false;
  const bytes = new Uint8Array(signature.match(/../g)!.map((h) => parseInt(h, 16)));
  // crypto.subtle.verify compares in constant time and needs no length leak.
  return crypto.subtle.verify(
    "HMAC",
    await hmacKey(secret),
    bytes,
    enc.encode(`${timestamp}.${body}`),
  );
}
