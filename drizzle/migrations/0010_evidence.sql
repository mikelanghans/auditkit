CREATE TABLE IF NOT EXISTS public.evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  run_id uuid REFERENCES public.scan_runs(id) ON DELETE CASCADE,
  checklist_item_id uuid REFERENCES public.checklist_items(id) ON DELETE SET NULL,
  kind text NOT NULL CHECK (kind IN ('http_exchange','probe_set','query_result','config','code','ai_exchange','note','file','screenshot','har')),
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  content_text text CHECK (content_text IS NULL OR length(content_text) <= 70000),
  storage_path text CHECK (storage_path IS NULL OR length(storage_path) <= 500),
  mime_type text CHECK (mime_type IS NULL OR length(mime_type) <= 100),
  size_bytes bigint NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  source text NOT NULL DEFAULT 'scanner' CHECK (source IN ('scanner', 'manual')),
  created_by uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  captured_at timestamptz NOT NULL DEFAULT now(),
  CHECK (content_text IS NOT NULL OR storage_path IS NOT NULL),
  CHECK (storage_path IS NULL OR storage_path LIKE audit_id::text || '/%')
);
CREATE INDEX IF NOT EXISTS evidence_audit ON public.evidence (audit_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS evidence_run ON public.evidence (run_id) WHERE run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS evidence_item ON public.evidence (audit_id, checklist_item_id) WHERE checklist_item_id IS NOT NULL;

ALTER TABLE public.scan_results ADD COLUMN IF NOT EXISTS evidence_ids uuid[] NOT NULL DEFAULT '{}';

ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.evidence FROM anon, authenticated;
GRANT ALL ON public.evidence TO service_role;
GRANT SELECT, INSERT ON public.evidence TO authenticated;

CREATE POLICY evidence_owner_select ON public.evidence FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY evidence_owner_insert ON public.evidence FOR INSERT TO authenticated
  WITH CHECK (
    created_by = auth.uid()
    AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid())
    AND ((run_id IS NULL AND source = 'manual')
      OR EXISTS (SELECT 1 FROM public.scan_runs r WHERE r.id = run_id AND r.audit_id = evidence.audit_id AND r.created_by = auth.uid() AND r.status = 'running'))
  );
CREATE POLICY owner_mfa_required ON public.evidence AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));

DROP POLICY IF EXISTS evidence_files_owner_read ON storage.objects;
CREATE POLICY evidence_files_owner_read ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'evidence' AND (SELECT public.is_app_owner_session())
    AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id::text = (storage.foldername(name))[1] AND a.created_by = auth.uid()));
DROP POLICY IF EXISTS evidence_files_owner_insert ON storage.objects;
CREATE POLICY evidence_files_owner_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'evidence' AND (SELECT public.is_app_owner_session())
    AND EXISTS (SELECT 1 FROM public.audits a WHERE a.id::text = (storage.foldername(name))[1] AND a.created_by = auth.uid()));