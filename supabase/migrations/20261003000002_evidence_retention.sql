-- Evidence retention: client data AuditKit captured (responses, HAR files,
-- screenshots, config snapshots, scan notes) is kept until a date set per
-- audit, then purged. What stays: each evidence item's title, kind, size and
-- SHA-256, the findings, and the audit trail, so the record of what was found
-- and proven survives without keeping the client's data.

ALTER TABLE public.audits ADD COLUMN IF NOT EXISTS evidence_retain_until date;

ALTER TABLE public.evidence ADD COLUMN IF NOT EXISTS purged_at timestamptz;
ALTER TABLE public.evidence DROP CONSTRAINT IF EXISTS evidence_check;
DO $$ BEGIN
  ALTER TABLE public.evidence ADD CONSTRAINT evidence_has_content
    CHECK (content_text IS NOT NULL OR storage_path IS NOT NULL OR purged_at IS NOT NULL);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Purge one audit's evidence once its retention date has passed. Returns the
-- storage paths to delete; the caller removes the files (allowed only for
-- purged evidence, see the storage policy below).
CREATE OR REPLACE FUNCTION public.purge_audit_evidence(p_audit uuid)
RETURNS TABLE (storage_path text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
DECLARE
  v_until date;
  v_items integer;
  v_notes integer;
BEGIN
  IF NOT public.is_app_owner_session() THEN RAISE EXCEPTION 'not allowed'; END IF;
  SELECT a.evidence_retain_until INTO v_until FROM public.audits a WHERE a.id = p_audit AND a.created_by = auth.uid();
  IF NOT FOUND THEN RAISE EXCEPTION 'audit not found'; END IF;
  IF v_until IS NULL THEN RAISE EXCEPTION 'no retention date is set for this audit'; END IF;
  IF v_until >= current_date THEN RAISE EXCEPTION 'evidence is kept until %', v_until; END IF;

  UPDATE public.evidence e SET content_text = NULL, purged_at = now()
   WHERE e.audit_id = p_audit AND e.purged_at IS NULL;
  GET DIAGNOSTICS v_items = ROW_COUNT;
  UPDATE public.scan_results r SET notes = NULL WHERE r.audit_id = p_audit AND r.notes IS NOT NULL;
  GET DIAGNOSTICS v_notes = ROW_COUNT;

  PERFORM public._append_audit_event(p_audit, 'evidence.purged', 'audit', p_audit::text, jsonb_build_object(
    'retain_until', v_until, 'evidence_items', v_items, 'scan_notes', v_notes,
    'files', (SELECT count(*) FROM public.evidence e WHERE e.audit_id = p_audit AND e.storage_path IS NOT NULL)));

  RETURN QUERY SELECT e.storage_path FROM public.evidence e
    WHERE e.audit_id = p_audit AND e.storage_path IS NOT NULL;
END;
$$;
REVOKE ALL ON FUNCTION public.purge_audit_evidence(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.purge_audit_evidence(uuid) TO authenticated;

-- Files can be deleted only once their evidence row has been purged.
DROP POLICY IF EXISTS evidence_files_owner_delete_purged ON storage.objects;
CREATE POLICY evidence_files_owner_delete_purged ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'evidence'
    AND (SELECT public.is_app_owner_session())
    AND EXISTS (
      SELECT 1 FROM public.evidence e
        JOIN public.audits a ON a.id = e.audit_id
       WHERE e.storage_path = storage.objects.name
         AND e.purged_at IS NOT NULL
         AND a.created_by = auth.uid()
    )
  );
