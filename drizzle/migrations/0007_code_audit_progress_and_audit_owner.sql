ALTER TABLE public.code_audit_runs
  ADD COLUMN IF NOT EXISTS progress jsonb,
  ADD COLUMN IF NOT EXISTS progress_at timestamptz;

DROP POLICY IF EXISTS "audits_owner_all" ON public.audits;
CREATE POLICY "audits_owner_all" ON public.audits FOR ALL TO authenticated
  USING (auth.uid() = created_by)
  WITH CHECK (
    auth.uid() = created_by
    AND EXISTS (SELECT 1 FROM public.clients c WHERE c.id = client_id AND c.created_by = auth.uid())
  );