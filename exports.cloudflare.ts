// Extra Worker exports, picked up by Nitro's Cloudflare preset at build time.
//
// FullAuditWorkflow drives a server-side "Run full audit": one durable step per
// pipeline stage, so a run survives the browser tab closing and is retried if
// the Worker is restarted mid-run. Each step calls back into this Worker over
// the SELF service binding (/api/public/hooks/pipeline-advance), so the stage
// runs in the normal app runtime with a fresh request budget. Nothing from the
// app is imported here except the token helper.
import { WorkflowEntrypoint } from "cloudflare:workers";
import type { WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import { pipelineStepToken } from "./src/lib/pipeline-auth";

type Env = {
  SELF: { fetch: (input: string, init?: RequestInit) => Promise<Response> };
  FULL_AUDIT_SECRETS_KEY: string;
};
type Params = { runId: string; profile: string };

// Upper bound on stages in one run (targets × scanners, plus synthesis).
const MAX_STEPS = 60;

export class FullAuditWorkflow extends WorkflowEntrypoint<Env, Params> {
  async run(event: WorkflowEvent<Params>, step: WorkflowStep) {
    const { runId, profile } = event.payload;
    for (let i = 0; i < MAX_STEPS; i++) {
      const r = await step.do(
        `stage ${i + 1}`,
        { retries: { limit: 2, delay: "20 seconds", backoff: "exponential" }, timeout: "15 minutes" },
        async () => {
          const token = await pipelineStepToken(runId, this.env.FULL_AUDIT_SECRETS_KEY);
          const res = await this.env.SELF.fetch("https://auditkit.internal/api/public/hooks/pipeline-advance", {
            method: "POST",
            headers: { "content-type": "application/json", "x-pipeline-token": token },
            body: JSON.stringify({ runId, profile }),
          });
          const body = (await res.json().catch(() => null)) as { ok?: boolean; more?: boolean; stage?: { key: string; status: string } | null } | null;
          // Throwing lets the Workflow retry; the engine won't re-run a stage
          // that already started.
          if (!res.ok || !body?.ok) throw new Error(`pipeline-advance HTTP ${res.status}`);
          return { more: !!body.more, key: body.stage?.key ?? null, status: body.stage?.status ?? null };
        },
      );
      if (!r.more) break;
    }
  }
}
