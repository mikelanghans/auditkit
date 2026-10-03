-- Build plan 2e: capture inbox. Evidence captured by hand without a finding
-- (checklist_item_id NULL) waits in the audit's inbox. Triage attaches it to
-- a checklist item, once: the only change ever allowed on an evidence row,
-- and it's logged in the audit trail.

GRANT UPDATE (checklist_item_id) ON public.evidence TO authenticated;

DROP POLICY IF EXISTS evidence_owner_triage ON public.evidence;
CREATE POLICY evidence_owner_triage ON public.evidence FOR UPDATE TO authenticated
  USING (
    checklist_item_id IS NULL AND source = 'manual' AND purged_at IS NULL
    AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid())
  )
  WITH CHECK (
    checklist_item_id IS NOT NULL
    AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid())
  );

CREATE OR REPLACE FUNCTION public._trail_evidence_triage() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  IF NEW.checklist_item_id IS DISTINCT FROM OLD.checklist_item_id THEN
    PERFORM _append_audit_event(NEW.audit_id, 'evidence.triaged', 'evidence', NEW.id::text, jsonb_build_object(
      'title', NEW.title, 'sha256', NEW.sha256, 'checklist_item_id', NEW.checklist_item_id));
  END IF;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public._trail_evidence_triage() FROM PUBLIC, anon, authenticated;
DROP TRIGGER IF EXISTS trail_triage ON public.evidence;
CREATE TRIGGER trail_triage AFTER UPDATE OF checklist_item_id ON public.evidence
  FOR EACH ROW EXECUTE FUNCTION public._trail_evidence_triage();
