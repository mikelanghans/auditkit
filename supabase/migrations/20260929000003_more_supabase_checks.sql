-- Checklist items for the new Supabase scan checks. Titles must match the keys
-- in titleToResult in src/lib/supabase-scan.functions.ts exactly.
INSERT INTO public.checklist_items (category, title, severity, checklist_key, what_to_look_for, sort_order)
SELECT v.category, v.title, v.severity::public.severity, v.checklist_key, v.what_to_look_for, v.sort_order
FROM (VALUES
  (
    'Database Security',
    'No SECURITY DEFINER functions callable without auth',
    'high',
    'anon_callable_definer_functions',
    'SECURITY DEFINER functions run with their owner''s rights and skip RLS. Supabase grants EXECUTE on new functions to anon by default, so a definer function in the public schema is callable by anyone through /rest/v1/rpc. With a Management API PAT, list definer functions the anon role can execute. Each should have EXECUTE revoked from anon and PUBLIC and check auth.uid() itself.',
    13
  ),
  (
    'Database Security',
    'Storage files can''t be listed without auth',
    'high',
    'storage_anon_listing',
    'A bucket can be private and still leak through a permissive SELECT policy on storage.objects. Try listing each bucket with only the anon key; compare with the service role so an empty bucket isn''t mistaken for a protected one.',
    19
  ),
  (
    'API & Endpoint Security',
    'Edge functions verify their callers',
    'high',
    'edge_function_caller_verification',
    'Edge functions deployed with verify_jwt off accept requests without a Supabase login. That is correct for webhooks, but each such function must verify its caller itself (a provider signature or its own auth check). List functions with the Management API and review the code of every one with JWT verification off.',
    64
  ),
  (
    'Authentication & Sessions',
    'Leaked password protection enabled',
    'medium',
    'leaked_password_protection',
    'Leaked-password protection rejects passwords that appear in known breaches (HaveIBeenPwned). Read password_hibp_enabled from the Management API auth config.',
    54
  )
) AS v(category, title, severity, checklist_key, what_to_look_for, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.checklist_items c WHERE c.title = v.title);
