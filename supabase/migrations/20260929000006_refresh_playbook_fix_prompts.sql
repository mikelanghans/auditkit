-- Fix prompts for these items are now generated from remediation playbooks
-- (see src/lib/fix-playbooks.ts). Clear the cached prompts so the next request
-- writes a new one instead of serving the old generic text.
UPDATE public.audit_findings f
   SET lovable_prompt = NULL, cursor_prompt = NULL, claude_prompt = NULL
  FROM public.checklist_items c
 WHERE c.id = f.checklist_item_id
   AND (
     c.checklist_key IN (
       'csp_header', 'hsts_header', 'xframe_header', 'xcontent_type', 'referrer_policy', 'permissions_policy',
       'cors_policy', 'bundle_secrets', 'vite_exposure', 'anon_write_access',
       'anon_callable_definer_functions', 'storage_anon_listing'
     )
     OR c.title IN (
       'Security headers configured', 'Content Security Policy set', 'CORS policy configured correctly',
       'No service role key in client-side code', 'No secrets in client-side bundle', 'No secrets in git history',
       'RLS enabled on all tables', 'Anon key permissions scoped correctly', 'No direct table access without auth check',
       'Anon role cannot write to tables'
     )
   );
