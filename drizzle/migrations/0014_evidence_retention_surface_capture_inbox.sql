ALTER TABLE public.audits ADD COLUMN IF NOT EXISTS evidence_retain_until date;
ALTER TABLE public.evidence ADD COLUMN IF NOT EXISTS purged_at timestamptz;
ALTER TABLE public.evidence DROP CONSTRAINT IF EXISTS evidence_check;
DO $$ BEGIN
  ALTER TABLE public.evidence ADD CONSTRAINT evidence_has_content
    CHECK (content_text IS NOT NULL OR storage_path IS NOT NULL OR purged_at IS NOT NULL);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE OR REPLACE FUNCTION public.purge_audit_evidence(p_audit uuid)
RETURNS TABLE (storage_path text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
DECLARE v_until date; v_items integer; v_notes integer;
BEGIN
  IF NOT public.is_app_owner_session() THEN RAISE EXCEPTION 'not allowed'; END IF;
  SELECT a.evidence_retain_until INTO v_until FROM public.audits a WHERE a.id = p_audit AND a.created_by = auth.uid();
  IF NOT FOUND THEN RAISE EXCEPTION 'audit not found'; END IF;
  IF v_until IS NULL THEN RAISE EXCEPTION 'no retention date is set for this audit'; END IF;
  IF v_until >= current_date THEN RAISE EXCEPTION 'evidence is kept until %', v_until; END IF;
  UPDATE public.evidence e SET content_text = NULL, purged_at = now() WHERE e.audit_id = p_audit AND e.purged_at IS NULL;
  GET DIAGNOSTICS v_items = ROW_COUNT;
  UPDATE public.scan_results r SET notes = NULL WHERE r.audit_id = p_audit AND r.notes IS NOT NULL;
  GET DIAGNOSTICS v_notes = ROW_COUNT;
  PERFORM public._append_audit_event(p_audit, 'evidence.purged', 'audit', p_audit::text, jsonb_build_object(
    'retain_until', v_until, 'evidence_items', v_items, 'scan_notes', v_notes,
    'files', (SELECT count(*) FROM public.evidence e WHERE e.audit_id = p_audit AND e.storage_path IS NOT NULL)));
  RETURN QUERY SELECT e.storage_path FROM public.evidence e WHERE e.audit_id = p_audit AND e.storage_path IS NOT NULL;
END;
$$;
REVOKE ALL ON FUNCTION public.purge_audit_evidence(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.purge_audit_evidence(uuid) TO authenticated;

DROP POLICY IF EXISTS evidence_files_owner_delete_purged ON storage.objects;
CREATE POLICY evidence_files_owner_delete_purged ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'evidence' AND (SELECT public.is_app_owner_session())
    AND EXISTS (SELECT 1 FROM public.evidence e JOIN public.audits a ON a.id = e.audit_id
       WHERE e.storage_path = storage.objects.name AND e.purged_at IS NOT NULL AND a.created_by = auth.uid()));

ALTER TABLE public.scan_runs DROP CONSTRAINT IF EXISTS scan_runs_scanner_check;
ALTER TABLE public.scan_runs ADD CONSTRAINT scan_runs_scanner_check
  CHECK (scanner IN ('website', 'surface', 'supabase', 'repo', 'dependencies', 'ai_endpoint', 'code_audit', 'full'));

GRANT UPDATE (checklist_item_id) ON public.evidence TO authenticated;
DROP POLICY IF EXISTS evidence_owner_triage ON public.evidence;
CREATE POLICY evidence_owner_triage ON public.evidence FOR UPDATE TO authenticated
  USING (checklist_item_id IS NULL AND source = 'manual' AND purged_at IS NULL
    AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()))
  WITH CHECK (checklist_item_id IS NOT NULL
    AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));

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