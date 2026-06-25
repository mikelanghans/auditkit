
-- 1. Extend finding_status enum with 'resolved'
ALTER TYPE public.finding_status ADD VALUE IF NOT EXISTS 'resolved';

-- 2. Add evidence + verification columns to audit_findings
ALTER TABLE public.audit_findings
  ADD COLUMN IF NOT EXISTS evidence_text TEXT,
  ADD COLUMN IF NOT EXISTS evidence_url TEXT,
  ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS resolved_via TEXT CHECK (resolved_via IN ('automated_rescan','manual_evidence'));

-- 3. Create finding_audit_log (insert-only at the app layer)
CREATE TABLE IF NOT EXISTS public.finding_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID NOT NULL REFERENCES public.audit_findings(id) ON DELETE CASCADE,
  audit_id UUID NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL CHECK (event_type IN ('flagged','fix_submitted','rescanned','resolved','reopened')),
  evidence_text TEXT,
  evidence_url TEXT,
  before_status TEXT,
  after_status TEXT,
  scan_result JSONB,
  performed_by UUID REFERENCES auth.users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS finding_audit_log_finding_idx ON public.finding_audit_log(finding_id, created_at);
CREATE INDEX IF NOT EXISTS finding_audit_log_audit_idx   ON public.finding_audit_log(audit_id, created_at);

GRANT SELECT, INSERT ON public.finding_audit_log TO authenticated;
GRANT ALL ON public.finding_audit_log TO service_role;

ALTER TABLE public.finding_audit_log ENABLE ROW LEVEL SECURITY;

-- Auditors can read log rows for audits they can see (any authenticated user has read access to audits in this app)
CREATE POLICY "Auditors read finding_audit_log"
  ON public.finding_audit_log
  FOR SELECT
  TO authenticated
  USING (true);

-- Inserts allowed for any authenticated user; performed_by must match auth.uid()
CREATE POLICY "Auditors insert finding_audit_log"
  ON public.finding_audit_log
  FOR INSERT
  TO authenticated
  WITH CHECK (performed_by = auth.uid() OR performed_by IS NULL);

-- No UPDATE or DELETE policies → blocked from the application layer.

-- 4. Auto-log status transitions on audit_findings
CREATE OR REPLACE FUNCTION public.log_finding_status_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_event TEXT;
  v_actor UUID;
BEGIN
  v_actor := auth.uid();

  IF TG_OP = 'INSERT' THEN
    IF NEW.status = 'fail' THEN
      v_event := 'flagged';
    ELSIF NEW.status = 'resolved' THEN
      v_event := 'resolved';
    ELSE
      RETURN NEW; -- pass/na on first insert: no event worth logging
    END IF;

    INSERT INTO public.finding_audit_log(finding_id, audit_id, event_type, before_status, after_status, evidence_text, evidence_url, performed_by)
    VALUES (NEW.id, NEW.audit_id, v_event, NULL, NEW.status::text, NEW.evidence_text, NEW.evidence_url, v_actor);
    RETURN NEW;
  END IF;

  -- UPDATE
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'resolved' THEN
      v_event := 'resolved';
    ELSIF OLD.status = 'resolved' AND NEW.status = 'fail' THEN
      v_event := 'reopened';
    ELSIF NEW.status = 'fail' THEN
      v_event := 'flagged';
    ELSE
      v_event := 'resolved'; -- fallback labeling for pass/na transitions away from fail
      IF NEW.status IN ('pass','na') AND OLD.status <> 'fail' THEN
        RETURN NEW;
      END IF;
    END IF;

    INSERT INTO public.finding_audit_log(finding_id, audit_id, event_type, before_status, after_status, evidence_text, evidence_url, performed_by)
    VALUES (NEW.id, NEW.audit_id, v_event, OLD.status::text, NEW.status::text, NEW.evidence_text, NEW.evidence_url, v_actor);
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_log_finding_status_change ON public.audit_findings;
CREATE TRIGGER trg_log_finding_status_change
AFTER INSERT OR UPDATE OF status ON public.audit_findings
FOR EACH ROW EXECUTE FUNCTION public.log_finding_status_change();
