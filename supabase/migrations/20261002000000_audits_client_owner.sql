-- Launch review (Low): the audits policy checked only created_by, so an audit
-- could be attached to a client row that belongs to someone else. Require the
-- client to be the caller's too. The restrictive owner_mfa_required policy
-- added in 20260929000002 still applies on top of this.
DROP POLICY IF EXISTS "audits_owner_all" ON public.audits;
CREATE POLICY "audits_owner_all" ON public.audits FOR ALL TO authenticated
  USING (auth.uid() = created_by)
  WITH CHECK (
    auth.uid() = created_by
    AND EXISTS (SELECT 1 FROM public.clients c WHERE c.id = client_id AND c.created_by = auth.uid())
  );
