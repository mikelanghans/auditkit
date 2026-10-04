-- Time spent on each audit: a start/stop timer, manual entries, and entries
-- accepted from the activity-based suggestions. Internal only; never in the
-- client report.

CREATE TABLE IF NOT EXISTS public.audit_time_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  category text NOT NULL DEFAULT 'testing'
    CHECK (category IN ('testing', 'scanning', 'reporting', 'client', 'admin')),
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
-- One running timer per person.
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
