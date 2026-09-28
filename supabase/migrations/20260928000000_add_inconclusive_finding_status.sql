-- Scanners need a way to say "I could not check this" that is distinct from
-- "not applicable". Until now they wrote 'na' for both, and 'na' counts as
-- assessed coverage, so an audit whose database checks never ran could still
-- reach a "Ready to launch" verdict. 'inconclusive' is never counted as assessed.
ALTER TYPE public.finding_status ADD VALUE IF NOT EXISTS 'inconclusive';

-- Status-change log: an inconclusive result is not a resolution or a flag, so
-- it must not be logged as either. (Previously any move away from 'fail' was
-- labelled 'resolved'.)
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

  IF NEW.status::text = 'inconclusive' THEN
    RETURN NEW;
  END IF;

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

REVOKE EXECUTE ON FUNCTION public.log_finding_status_change() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.log_finding_status_change() FROM anon, authenticated;
