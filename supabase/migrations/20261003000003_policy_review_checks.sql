-- Build plan 3.1: checklist items for the database policy review the
-- Supabase scan now runs (with a Management API PAT), plus their compliance
-- tags. Safe to re-run.

INSERT INTO public.checklist_items (category, title, severity, checklist_key, what_to_look_for, sort_order)
SELECT v.category, v.title, v.severity::public.severity, v.checklist_key, v.what_to_look_for, v.sort_order
FROM (VALUES
  (
    'Database Security',
    'RLS policies don''t grant blanket access',
    'critical',
    'rls_policy_review',
    'RLS being on is not enough: one permissive policy with USING (true) opens the whole table to the roles it names. Read every policy on public and storage tables. Fail any that admit every row to anon/public, let any signed-in user change or delete every row, or trust user_metadata (editable by the user). Policies that let any signed-in user read every row are fine only for genuinely shared data.',
    140
  ),
  (
    'Database Security',
    'SECURITY DEFINER functions pin search_path',
    'medium',
    'definer_search_path',
    'Every SECURITY DEFINER function in public should SET search_path (ideally to an empty string, with schema-qualified names). Without it, a caller can make the function resolve names to objects the caller created, while it runs with its owner''s rights.',
    141
  ),
  (
    'Database Security',
    'Exposed views respect RLS (security_invoker)',
    'high',
    'views_security_invoker',
    'A view runs with its owner''s rights unless security_invoker is on, so a view readable by anon or authenticated returns every row of the tables under it, ignoring their RLS. Check every public view the API can read.',
    142
  )
) AS v(category, title, severity, checklist_key, what_to_look_for, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.checklist_items c WHERE c.title = v.title OR c.checklist_key = v.checklist_key);

INSERT INTO public.checklist_item_controls (checklist_item_id, framework, control_id, control_title)
SELECT ci.id, v.framework, v.control_id, v.control_title
FROM (VALUES
  ('rls_policy_review', 'OWASP ASVS 4.0.3', 'V4.1.1', 'Access control enforced on a trusted service layer'),
  ('rls_policy_review', 'OWASP ASVS 4.0.3', 'V4.1.3', 'Principle of least privilege'),
  ('rls_policy_review', 'OWASP ASVS 4.0.3', 'V4.2.1', 'Protection against insecure direct object references'),
  ('rls_policy_review', 'SOC 2', 'CC6.1', 'Logical access security over protected information assets'),
  ('rls_policy_review', 'SOC 2', 'CC6.3', 'Access based on roles and least privilege'),
  ('rls_policy_review', 'HIPAA', '164.312(a)(1)', 'Access control'),
  ('definer_search_path', 'OWASP ASVS 4.0.3', 'V4.1.3', 'Principle of least privilege'),
  ('definer_search_path', 'SOC 2', 'CC6.1', 'Logical access security over protected information assets'),
  ('views_security_invoker', 'OWASP ASVS 4.0.3', 'V4.1.1', 'Access control enforced on a trusted service layer'),
  ('views_security_invoker', 'OWASP ASVS 4.0.3', 'V4.2.1', 'Protection against insecure direct object references'),
  ('views_security_invoker', 'SOC 2', 'CC6.1', 'Logical access security over protected information assets'),
  ('views_security_invoker', 'HIPAA', '164.312(a)(1)', 'Access control')
) AS v(checklist_key, framework, control_id, control_title)
JOIN public.checklist_items ci ON ci.checklist_key = v.checklist_key
ON CONFLICT (checklist_item_id, framework, control_id) DO NOTHING;
