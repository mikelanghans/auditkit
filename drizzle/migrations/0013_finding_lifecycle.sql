ALTER TABLE public.audit_findings
  ADD COLUMN IF NOT EXISTS risk_accepted_reason text CHECK (risk_accepted_reason IS NULL OR length(risk_accepted_reason) BETWEEN 5 AND 4000),
  ADD COLUMN IF NOT EXISTS risk_accepted_by text CHECK (risk_accepted_by IS NULL OR length(risk_accepted_by) <= 200),
  ADD COLUMN IF NOT EXISTS risk_accepted_at timestamptz,
  ADD COLUMN IF NOT EXISTS risk_accepted_until date,
  ADD COLUMN IF NOT EXISTS severity_override public.severity,
  ADD COLUMN IF NOT EXISTS severity_override_reason text CHECK (severity_override_reason IS NULL OR length(severity_override_reason) BETWEEN 5 AND 2000),
  ADD COLUMN IF NOT EXISTS remediation_owner text CHECK (remediation_owner IS NULL OR length(remediation_owner) <= 200),
  ADD COLUMN IF NOT EXISTS remediation_due date,
  ADD COLUMN IF NOT EXISTS remediation_status text
    CHECK (remediation_status IS NULL OR remediation_status IN ('open', 'in_progress', 'fixed_pending_retest', 'verified', 'wont_fix'));

DO $$ BEGIN
  ALTER TABLE public.audit_findings ADD CONSTRAINT audit_findings_risk_acceptance_complete
    CHECK (risk_accepted_at IS NULL OR (risk_accepted_reason IS NOT NULL AND risk_accepted_by IS NOT NULL AND risk_accepted_until IS NOT NULL));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TABLE public.audit_findings ADD CONSTRAINT audit_findings_override_has_reason
    CHECK (severity_override IS NULL OR severity_override_reason IS NOT NULL);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE OR REPLACE FUNCTION public._trail_findings() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
DECLARE
  r record := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  v_life_changed boolean := false;
BEGIN
  IF NOT _audit_alive(r.audit_id) THEN RETURN NULL; END IF;
  IF TG_OP = 'UPDATE' THEN
    v_life_changed := (NEW.risk_accepted_at, NEW.risk_accepted_until, NEW.risk_accepted_reason, NEW.severity_override,
                       NEW.severity_override_reason, NEW.remediation_owner, NEW.remediation_due, NEW.remediation_status)
      IS DISTINCT FROM (OLD.risk_accepted_at, OLD.risk_accepted_until, OLD.risk_accepted_reason, OLD.severity_override,
                        OLD.severity_override_reason, OLD.remediation_owner, OLD.remediation_due, OLD.remediation_status);
    IF (NEW.status, NEW.notes) IS NOT DISTINCT FROM (OLD.status, OLD.notes) AND NOT v_life_changed THEN RETURN NULL; END IF;
  END IF;
  IF TG_OP <> 'UPDATE' OR (NEW.status, NEW.notes) IS DISTINCT FROM (OLD.status, OLD.notes) THEN
    PERFORM _append_audit_event(r.audit_id,
      CASE TG_OP WHEN 'DELETE' THEN 'finding.cleared' ELSE 'finding.set' END,
      'finding', r.checklist_item_id::text,
      jsonb_strip_nulls(jsonb_build_object(
        'from', CASE WHEN TG_OP = 'UPDATE' THEN OLD.status::text END,
        'to', CASE WHEN TG_OP <> 'DELETE' THEN NEW.status::text END,
        'notes_sha256', CASE WHEN TG_OP <> 'DELETE' THEN encode(sha256(convert_to(coalesce(NEW.notes, ''), 'UTF8')), 'hex') END,
        'auto_scanned', CASE WHEN TG_OP <> 'DELETE' THEN NEW.auto_scanned END)));
  END IF;
  IF v_life_changed THEN
    PERFORM _append_audit_event(r.audit_id, 'finding.lifecycle', 'finding', r.checklist_item_id::text, jsonb_strip_nulls(jsonb_build_object(
      'risk_accepted_by', NEW.risk_accepted_by,
      'risk_accepted_until', NEW.risk_accepted_until,
      'risk_accepted_reason', NEW.risk_accepted_reason,
      'risk_acceptance_revoked', CASE WHEN OLD.risk_accepted_at IS NOT NULL AND NEW.risk_accepted_at IS NULL THEN true END,
      'severity_override', NEW.severity_override::text,
      'severity_override_reason', NEW.severity_override_reason,
      'remediation_owner', NEW.remediation_owner,
      'remediation_due', NEW.remediation_due,
      'remediation_status', NEW.remediation_status)));
  END IF;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public._trail_findings() FROM PUBLIC, anon, authenticated;

ALTER TABLE public.audits
  ADD COLUMN IF NOT EXISTS checklist_snapshot jsonb,
  ADD COLUMN IF NOT EXISTS checklist_version text,
  ADD COLUMN IF NOT EXISTS checklist_frozen_at timestamptz;

CREATE OR REPLACE FUNCTION public._checklist_snapshot()
RETURNS jsonb LANGUAGE sql STABLE SET search_path = public AS $$
  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'id', ci.id, 'key', ci.checklist_key, 'category', ci.category, 'title', ci.title,
           'severity', ci.severity::text, 'sort_order', ci.sort_order)
         ORDER BY ci.category, ci.sort_order, ci.title), '[]'::jsonb)
    FROM public.checklist_items ci WHERE ci.is_active;
$$;

CREATE OR REPLACE FUNCTION public._freeze_checklist_on_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_catalog AS $$
BEGIN
  IF NEW.status::text = 'completed' AND OLD.status IS DISTINCT FROM NEW.status AND NEW.checklist_snapshot IS NULL THEN
    NEW.checklist_snapshot := public._checklist_snapshot();
    NEW.checklist_version := encode(sha256(convert_to(NEW.checklist_snapshot::text, 'UTF8')), 'hex');
    NEW.checklist_frozen_at := now();
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS freeze_checklist ON public.audits;
CREATE TRIGGER freeze_checklist BEFORE UPDATE OF status ON public.audits
  FOR EACH ROW EXECUTE FUNCTION public._freeze_checklist_on_complete();

CREATE OR REPLACE FUNCTION public.freeze_audit_checklist(p_audit uuid)
RETURNS text LANGUAGE plpgsql SECURITY INVOKER SET search_path = public, pg_catalog AS $$
DECLARE v_snap jsonb := public._checklist_snapshot(); v_ver text;
BEGIN
  v_ver := encode(sha256(convert_to(v_snap::text, 'UTF8')), 'hex');
  UPDATE public.audits
     SET checklist_snapshot = v_snap, checklist_version = v_ver, checklist_frozen_at = now()
   WHERE id = p_audit;
  IF NOT FOUND THEN RAISE EXCEPTION 'audit not found'; END IF;
  RETURN v_ver;
END $$;
REVOKE ALL ON FUNCTION public.freeze_audit_checklist(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.freeze_audit_checklist(uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public._trail_audits() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM _append_audit_event(NEW.id, 'audit.created', 'audit', NEW.id::text,
      jsonb_build_object('title', NEW.title, 'client_id', NEW.client_id, 'website_url', NEW.website_url));
  ELSIF TG_OP = 'UPDATE' THEN
    IF (NEW.title, NEW.status, NEW.website_url, NEW.summary, NEW.completed_at, NEW.checklist_version, NEW.summary_approved_at)
       IS DISTINCT FROM (OLD.title, OLD.status, OLD.website_url, OLD.summary, OLD.completed_at, OLD.checklist_version, OLD.summary_approved_at) THEN
      PERFORM _append_audit_event(NEW.id, 'audit.updated', 'audit', NEW.id::text, jsonb_strip_nulls(jsonb_build_object(
        'title', CASE WHEN NEW.title IS DISTINCT FROM OLD.title THEN NEW.title END,
        'status', CASE WHEN NEW.status IS DISTINCT FROM OLD.status THEN NEW.status::text END,
        'website_url', CASE WHEN NEW.website_url IS DISTINCT FROM OLD.website_url THEN NEW.website_url END,
        'summary_sha256', CASE WHEN NEW.summary IS DISTINCT FROM OLD.summary THEN encode(sha256(convert_to(coalesce(NEW.summary, ''), 'UTF8')), 'hex') END,
        'summary_approved_at', CASE WHEN NEW.summary_approved_at IS DISTINCT FROM OLD.summary_approved_at THEN NEW.summary_approved_at END,
        'completed_at', CASE WHEN NEW.completed_at IS DISTINCT FROM OLD.completed_at THEN NEW.completed_at END,
        'checklist_version', CASE WHEN NEW.checklist_version IS DISTINCT FROM OLD.checklist_version THEN NEW.checklist_version END)));
    END IF;
  ELSE
    PERFORM _append_audit_event(OLD.id, 'audit.deleted', 'audit', OLD.id::text, jsonb_build_object('title', OLD.title));
  END IF;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public._trail_audits() FROM PUBLIC, anon, authenticated;

UPDATE public.audits
   SET checklist_snapshot = public._checklist_snapshot(),
       checklist_version = encode(sha256(convert_to(public._checklist_snapshot()::text, 'UTF8')), 'hex'),
       checklist_frozen_at = now()
 WHERE status::text = 'completed' AND checklist_snapshot IS NULL;