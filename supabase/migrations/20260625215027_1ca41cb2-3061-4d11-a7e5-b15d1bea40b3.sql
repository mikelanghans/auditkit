
-- 1) Remove overly permissive SELECT policy on finding_audit_log (owner-scoped policy already exists)
DROP POLICY IF EXISTS "Auditors read finding_audit_log" ON public.finding_audit_log;

-- 2) Replace INSERT policy with audit-ownership check
DROP POLICY IF EXISTS "Auditors insert finding_audit_log" ON public.finding_audit_log;
CREATE POLICY "Auditors insert finding_audit_log"
  ON public.finding_audit_log
  FOR INSERT TO authenticated
  WITH CHECK (
    (performed_by = auth.uid() OR performed_by IS NULL)
    AND EXISTS (
      SELECT 1 FROM public.audits a
      WHERE a.id = finding_audit_log.audit_id
        AND a.created_by = auth.uid()
    )
  );

-- 3) Lock down SECURITY DEFINER functions from direct API execution.
-- has_role is used inside RLS policies; authenticated needs EXECUTE, but anon/public do not.
REVOKE EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) FROM anon;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) TO authenticated, service_role;

-- handle_new_user and log_finding_status_change are trigger-only; nobody should call them directly.
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.log_finding_status_change() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.log_finding_status_change() FROM anon, authenticated;
