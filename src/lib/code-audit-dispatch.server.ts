// Starts one Fly.io machine per deep-audit job. The machine runs the runner
// image, posts results to our webhook and is destroyed when it exits.
//
// Server-only. Required env:
//   FLY_API_TOKEN               deploy token scoped to the runner app
//   CODE_AUDIT_FLY_APP          runner app name
//   CODE_AUDIT_RUNNER_IMAGE     image ref, e.g. registry.fly.io/<app>:<tag>
//   CODE_AUDIT_WEBHOOK_SECRET   shared with the runner (fly secrets)
//   PUBLIC_APP_URL              this app's public origin, for the callback URL
import { encryptJob, type CodeAuditJob } from "./code-audit-contract";

const MACHINE_SIZES = {
  quick: { cpus: 2, memory_mb: 4096 },
  standard: { cpus: 4, memory_mb: 8192 },
  deep: { cpus: 4, memory_mb: 8192 },
} as const;

export function codeAuditRunnerConfigured(): boolean {
  return !!(
    process.env.FLY_API_TOKEN &&
    process.env.CODE_AUDIT_FLY_APP &&
    process.env.CODE_AUDIT_RUNNER_IMAGE &&
    process.env.CODE_AUDIT_WEBHOOK_SECRET &&
    process.env.PUBLIC_APP_URL
  );
}

/**
 * `fly tokens create` prints macaroon tokens as "FlyV1 fm2_…", which is already
 * a full Authorization value; older personal tokens take "Bearer".
 */
export function flyAuthHeader(token: string): string {
  const t = token.trim();
  return /^FlyV1\s/.test(t) ? t : `Bearer ${t}`;
}

export function callbackUrl(): string {
  return `${String(process.env.PUBLIC_APP_URL).replace(/\/+$/, "")}/api/public/hooks/code-audit`;
}

export async function dispatchCodeAudit(
  job: CodeAuditJob,
): Promise<{ ok: true; machineId: string } | { ok: false; error: string }> {
  const app = process.env.CODE_AUDIT_FLY_APP!;
  const blob = await encryptJob(job, process.env.CODE_AUDIT_WEBHOOK_SECRET!);
  const res = await fetch(`https://api.machines.dev/v1/apps/${encodeURIComponent(app)}/machines`, {
    method: "POST",
    headers: {
      authorization: flyAuthHeader(String(process.env.FLY_API_TOKEN)),
      "content-type": "application/json",
    },
    body: JSON.stringify({
      name: `audit-${job.runId.slice(0, 8)}`,
      config: {
        image: process.env.CODE_AUDIT_RUNNER_IMAGE,
        env: { AUDITKIT_JOB: blob },
        auto_destroy: true,
        restart: { policy: "no" },
        guest: { cpu_kind: "shared", ...MACHINE_SIZES[job.profile] },
        metadata: { auditkit_run: job.runId },
      },
    }),
  });
  const text = await res.text();
  if (!res.ok) return { ok: false, error: `Fly API ${res.status}: ${text.slice(0, 300)}` };
  try {
    const body = JSON.parse(text);
    return { ok: true, machineId: String(body.id ?? "") };
  } catch {
    return { ok: true, machineId: "" };
  }
}
