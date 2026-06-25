-- Restrict finding_audit_log SELECT to the audit owner
DROP POLICY IF EXISTS "Authenticated can view finding audit log" ON public.finding_audit_log;
DROP POLICY IF EXISTS "View finding audit log" ON public.finding_audit_log;
DROP POLICY IF EXISTS "finding_audit_log_select" ON public.finding_audit_log;

CREATE POLICY "Audit owners can view their finding audit log"
ON public.finding_audit_log
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.audits a
    WHERE a.id = finding_audit_log.audit_id
      AND a.created_by = auth.uid()
  )
);

-- Harden has_role: SECURITY DEFINER with fixed search_path
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role app_role)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO 'public'
AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role)
$$;

REVOKE ALL ON FUNCTION public.has_role(uuid, app_role) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, app_role) TO authenticated, service_role;