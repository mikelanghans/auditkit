CREATE TABLE IF NOT EXISTS public.scan_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  created_by uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  scanner text NOT NULL CHECK (scanner IN ('website', 'supabase', 'repo', 'dependencies', 'ai_endpoint', 'code_audit', 'full')),
  trigger text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'full', 'schedule', 'retest')),
  parent_run_id uuid REFERENCES public.scan_runs(id) ON DELETE SET NULL,
  target text CHECK (target IS NULL OR length(target) <= 2048),
  status text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'partial', 'failed')),
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS scan_runs_audit ON public.scan_runs (audit_id, started_at DESC);
CREATE INDEX IF NOT EXISTS scan_runs_parent ON public.scan_runs (parent_run_id) WHERE parent_run_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.scan_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id uuid NOT NULL REFERENCES public.scan_runs(id) ON DELETE CASCADE,
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  checklist_item_id uuid REFERENCES public.checklist_items(id) ON DELETE SET NULL,
  checklist_key text CHECK (checklist_key IS NULL OR length(checklist_key) <= 200),
  scanner text NOT NULL,
  status text NOT NULL CHECK (status IN ('pass', 'fail', 'warn', 'na', 'inconclusive', 'not_run')),
  change text CHECK (change IN ('new', 'regressed', 'unchanged', 'fixed', 'unverified')),
  previous_status text,
  previous_run_id uuid REFERENCES public.scan_runs(id) ON DELETE SET NULL,
  stored boolean NOT NULL DEFAULT false,
  notes text CHECK (notes IS NULL OR length(notes) <= 20000),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scan_results_run ON public.scan_results (run_id);
CREATE INDEX IF NOT EXISTS scan_results_item ON public.scan_results (audit_id, checklist_item_id, created_at DESC);

ALTER TABLE public.scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_results ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.scan_runs, public.scan_results FROM anon, authenticated;
GRANT ALL ON public.scan_runs, public.scan_results TO service_role;
GRANT SELECT, INSERT ON public.scan_runs, public.scan_results TO authenticated;
GRANT UPDATE (status, finished_at, summary) ON public.scan_runs TO authenticated;

CREATE POLICY scan_runs_owner_select ON public.scan_runs FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY scan_runs_owner_insert ON public.scan_runs FOR INSERT TO authenticated
  WITH CHECK (created_by = auth.uid() AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY scan_runs_owner_close ON public.scan_runs FOR UPDATE TO authenticated
  USING (created_by = auth.uid() AND status = 'running') WITH CHECK (created_by = auth.uid());
CREATE POLICY scan_results_owner_select ON public.scan_results FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY scan_results_owner_insert ON public.scan_results FOR INSERT TO authenticated
  WITH CHECK (EXISTS (SELECT 1 FROM public.scan_runs r WHERE r.id = run_id AND r.audit_id = scan_results.audit_id AND r.created_by = auth.uid() AND r.status = 'running'));
CREATE POLICY owner_mfa_required ON public.scan_runs AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));
CREATE POLICY owner_mfa_required ON public.scan_results AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));