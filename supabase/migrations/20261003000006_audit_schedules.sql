-- Phase 4: scheduled passive rescans. An enabled schedule reruns the
-- passive scanners (website, attack surface) on a cadence, as a "schedule"
-- run owned by the audit's owner, and emails an alert when a check newly
-- fails or regresses. Nothing that needs client credentials or writes to the
-- client's systems runs on a schedule.

CREATE TABLE IF NOT EXISTS public.audit_schedules (
  audit_id uuid PRIMARY KEY REFERENCES public.audits(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT true,
  cadence text NOT NULL DEFAULT 'weekly' CHECK (cadence IN ('daily', 'weekly')),
  scanners text[] NOT NULL DEFAULT ARRAY['website', 'surface']
    CHECK (scanners <@ ARRAY['website', 'surface']::text[] AND cardinality(scanners) > 0),
  alert_email boolean NOT NULL DEFAULT true,
  last_run_at timestamptz,
  last_run_id uuid REFERENCES public.scan_runs(id) ON DELETE SET NULL,
  last_error text,
  next_run_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
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
    RETURN NULL; -- run bookkeeping (last_run_at, next_run_at) isn't a settings change
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

-- Scheduled runs may also re-check the package list recorded by the last
-- repo scan against new advisories (no GitHub token needed).
ALTER TABLE public.audit_schedules DROP CONSTRAINT IF EXISTS audit_schedules_scanners_check;
ALTER TABLE public.audit_schedules ADD CONSTRAINT audit_schedules_scanners_check
  CHECK (scanners <@ ARRAY['website', 'surface', 'dependencies']::text[] AND cardinality(scanners) > 0);
ALTER TABLE public.audit_schedules ALTER COLUMN scanners SET DEFAULT ARRAY['website', 'surface', 'dependencies'];

-- Exact package versions from the audit's lockfiles, replaced on each repo scan.
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
