ALTER TABLE public.scan_runs DROP CONSTRAINT IF EXISTS scan_runs_scanner_check;
ALTER TABLE public.scan_runs ADD CONSTRAINT scan_runs_scanner_check
  CHECK (scanner IN ('website', 'surface', 'supabase', 'repo', 'dependencies', 'ai_endpoint', 'ai_deep', 'code_audit', 'full'));

CREATE TABLE IF NOT EXISTS public.audit_schedules (
  audit_id uuid PRIMARY KEY REFERENCES public.audits(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT true,
  cadence text NOT NULL DEFAULT 'weekly' CHECK (cadence IN ('daily', 'weekly')),
  scanners text[] NOT NULL DEFAULT ARRAY['website', 'surface', 'dependencies'],
  alert_email boolean NOT NULL DEFAULT true,
  last_run_at timestamptz,
  last_run_id uuid REFERENCES public.scan_runs(id) ON DELETE SET NULL,
  last_error text,
  next_run_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT audit_schedules_scanners_check CHECK (scanners <@ ARRAY['website', 'surface', 'dependencies']::text[] AND cardinality(scanners) > 0)
);
CREATE INDEX IF NOT EXISTS audit_schedules_due ON public.audit_schedules (next_run_at) WHERE enabled;
CREATE TRIGGER audit_schedules_updated_at BEFORE UPDATE ON public.audit_schedules
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
ALTER TABLE public.audit_schedules ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.audit_schedules FROM anon, authenticated;
GRANT SELECT, INSERT, DELETE ON public.audit_schedules TO authenticated;
GRANT UPDATE (enabled, cadence, scanners, alert_email, next_run_at) ON public.audit_schedules TO authenticated;
GRANT ALL ON public.audit_schedules TO service_role;
CREATE POLICY audit_schedules_owner_all ON public.audit_schedules FOR ALL TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()))
  WITH CHECK (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY owner_mfa_required ON public.audit_schedules AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));

CREATE OR REPLACE FUNCTION public._trail_schedule() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
DECLARE r record := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
BEGIN
  IF NOT _audit_alive(r.audit_id) THEN RETURN NULL; END IF;
  IF TG_OP = 'UPDATE' AND (NEW.enabled, NEW.cadence, NEW.scanners, NEW.alert_email)
     IS NOT DISTINCT FROM (OLD.enabled, OLD.cadence, OLD.scanners, OLD.alert_email) THEN
    RETURN NULL;
  END IF;
  PERFORM _append_audit_event(r.audit_id, CASE TG_OP WHEN 'DELETE' THEN 'schedule.removed' ELSE 'schedule.set' END,
    'schedule', r.audit_id::text,
    CASE WHEN TG_OP = 'DELETE' THEN '{}'::jsonb
         ELSE jsonb_build_object('enabled', NEW.enabled, 'cadence', NEW.cadence, 'scanners', NEW.scanners, 'alert_email', NEW.alert_email) END);
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public._trail_schedule() FROM PUBLIC, anon, authenticated;
DROP TRIGGER IF EXISTS trail ON public.audit_schedules;
CREATE TRIGGER trail AFTER INSERT OR UPDATE OR DELETE ON public.audit_schedules
  FOR EACH ROW EXECUTE FUNCTION public._trail_schedule();

CREATE TABLE IF NOT EXISTS public.audit_packages (
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  source text NOT NULL CHECK (length(source) <= 300),
  name text NOT NULL CHECK (length(name) <= 300),
  version text NOT NULL CHECK (length(version) <= 100),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (audit_id, source, name, version)
);
ALTER TABLE public.audit_packages ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.audit_packages FROM anon, authenticated;
GRANT SELECT, INSERT, DELETE ON public.audit_packages TO authenticated;
GRANT ALL ON public.audit_packages TO service_role;
CREATE POLICY audit_packages_owner_all ON public.audit_packages FOR ALL TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()))
  WITH CHECK (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY owner_mfa_required ON public.audit_packages AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));

CREATE TABLE IF NOT EXISTS public.audit_time_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  category text NOT NULL DEFAULT 'testing' CHECK (category IN ('testing', 'scanning', 'reporting', 'client', 'admin')),
  started_at timestamptz NOT NULL DEFAULT now(),
  ended_at timestamptz,
  note text CHECK (note IS NULL OR length(note) <= 500),
  source text NOT NULL DEFAULT 'timer' CHECK (source IN ('timer', 'manual', 'suggested')),
  created_by uuid NOT NULL DEFAULT auth.uid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (ended_at IS NULL OR ended_at > started_at),
  CHECK (ended_at IS NULL OR ended_at - started_at <= interval '24 hours')
);
CREATE INDEX IF NOT EXISTS audit_time_entries_audit ON public.audit_time_entries (audit_id, started_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS audit_time_entries_one_running ON public.audit_time_entries (created_by) WHERE ended_at IS NULL;
ALTER TABLE public.audit_time_entries ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.audit_time_entries FROM anon, authenticated;
GRANT SELECT, INSERT, DELETE ON public.audit_time_entries TO authenticated;
GRANT UPDATE (category, started_at, ended_at, note) ON public.audit_time_entries TO authenticated;
GRANT ALL ON public.audit_time_entries TO service_role;
CREATE POLICY audit_time_entries_owner_all ON public.audit_time_entries FOR ALL TO authenticated
  USING (created_by = auth.uid() AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()))
  WITH CHECK (created_by = auth.uid() AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY owner_mfa_required ON public.audit_time_entries AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));

ALTER TABLE public.audits
  ADD COLUMN IF NOT EXISTS confirmed_repos text[] NOT NULL DEFAULT '{}' CHECK (cardinality(confirmed_repos) <= 50);

ALTER TABLE public.scan_runs
  ADD COLUMN IF NOT EXISTS pipeline_driver text CHECK (pipeline_driver IN ('browser', 'workflow')),
  ADD COLUMN IF NOT EXISTS workflow_instance text CHECK (workflow_instance IS NULL OR length(workflow_instance) <= 200);

CREATE TABLE IF NOT EXISTS public.pipeline_stages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id uuid NOT NULL REFERENCES public.scan_runs(id) ON DELETE CASCADE,
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  key text NOT NULL CHECK (length(key) BETWEEN 1 AND 200),
  stage text NOT NULL CHECK (stage IN ('recon', 'config', 'code', 'ai', 'deep', 'report')),
  position int NOT NULL,
  scanner text NOT NULL CHECK (scanner IN ('website', 'surface', 'supabase', 'repo', 'ai_endpoint', 'ai_deep', 'code_audit', 'synthesis')),
  target text CHECK (target IS NULL OR length(target) <= 2048),
  meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  depends_on text[] NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'waiting', 'done', 'failed', 'skipped')),
  reason text CHECK (reason IS NULL OR length(reason) <= 2000),
  output jsonb NOT NULL DEFAULT '{}'::jsonb,
  attempts int NOT NULL DEFAULT 0,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, key)
);
CREATE INDEX IF NOT EXISTS pipeline_stages_run ON public.pipeline_stages (run_id, position);
CREATE INDEX IF NOT EXISTS pipeline_stages_waiting ON public.pipeline_stages (status) WHERE status = 'waiting';
ALTER TABLE public.pipeline_stages ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.pipeline_stages FROM anon, authenticated;
GRANT SELECT ON public.pipeline_stages TO authenticated;
GRANT ALL ON public.pipeline_stages TO service_role;
CREATE POLICY pipeline_stages_owner_select ON public.pipeline_stages FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY owner_mfa_required ON public.pipeline_stages AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));

CREATE TABLE IF NOT EXISTS public.pipeline_secrets (
  run_id uuid PRIMARY KEY REFERENCES public.scan_runs(id) ON DELETE CASCADE,
  sealed text NOT NULL CHECK (length(sealed) <= 20000),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.pipeline_secrets ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.pipeline_secrets FROM anon, authenticated;
GRANT ALL ON public.pipeline_secrets TO service_role;