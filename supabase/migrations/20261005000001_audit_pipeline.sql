-- Full audit as a pipeline: stages in a fixed order (recon → config → code →
-- ai → deep → report, where report merges every scanner's findings), each with its own status, timing and output, so a run can be
-- driven on the server (Cloudflare Workflow) or from the browser, show live
-- progress, skip stages whose inputs failed, and retry one stage on its own.
--
-- Written by the server only (service role). The owner can read their stages.

ALTER TABLE public.scan_runs
  ADD COLUMN IF NOT EXISTS pipeline_driver text CHECK (pipeline_driver IN ('browser', 'workflow')),
  ADD COLUMN IF NOT EXISTS workflow_instance text CHECK (workflow_instance IS NULL OR length(workflow_instance) <= 200);

CREATE TABLE IF NOT EXISTS public.pipeline_stages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id uuid NOT NULL REFERENCES public.scan_runs(id) ON DELETE CASCADE,
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  -- Unique within the run, e.g. "repo:<target id>".
  key text NOT NULL CHECK (length(key) BETWEEN 1 AND 200),
  stage text NOT NULL CHECK (stage IN ('recon', 'config', 'code', 'ai', 'deep', 'report')),
  position int NOT NULL,
  scanner text NOT NULL CHECK (scanner IN ('website', 'surface', 'supabase', 'repo', 'ai_endpoint', 'ai_deep', 'code_audit', 'synthesis')),
  target text CHECK (target IS NULL OR length(target) <= 2048),
  meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- Keys of stages that must finish as "done" before this one may run.
  depends_on text[] NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'waiting', 'done', 'failed', 'skipped')),
  reason text CHECK (reason IS NULL OR length(reason) <= 2000),
  -- What later stages may use (e.g. the repo stage's leads for the deep audit).
  output jsonb NOT NULL DEFAULT '{}'::jsonb,
  attempts int NOT NULL DEFAULT 0,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, key)
);
CREATE INDEX IF NOT EXISTS pipeline_stages_run ON public.pipeline_stages (run_id, position);
-- Deep-audit stages waiting on the runner, for the callback and the stale sweep.
CREATE INDEX IF NOT EXISTS pipeline_stages_waiting ON public.pipeline_stages (status) WHERE status = 'waiting';

ALTER TABLE public.pipeline_stages ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.pipeline_stages FROM anon, authenticated;
GRANT SELECT ON public.pipeline_stages TO authenticated;
GRANT ALL ON public.pipeline_stages TO service_role;
CREATE POLICY pipeline_stages_owner_select ON public.pipeline_stages FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY owner_mfa_required ON public.pipeline_stages AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));

-- Credentials for a server-driven run: AES-256-GCM sealed with a Worker secret
-- (FULL_AUDIT_SECRETS_KEY), readable only by the service role, deleted when
-- the run's last scanner stage has run and expired after a few hours at most.
CREATE TABLE IF NOT EXISTS public.pipeline_secrets (
  run_id uuid PRIMARY KEY REFERENCES public.scan_runs(id) ON DELETE CASCADE,
  sealed text NOT NULL CHECK (length(sealed) <= 20000),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.pipeline_secrets ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.pipeline_secrets FROM anon, authenticated;
GRANT ALL ON public.pipeline_secrets TO service_role;
