-- Repo scan: current-code secret scan and code rules (build plan 3.4/3.5,
-- without the runner). New checklist items and their compliance tags.

INSERT INTO public.checklist_items (category, title, severity, checklist_key, what_to_look_for, sort_order)
SELECT v.category, v.title, v.severity::public.severity, v.checklist_key, v.what_to_look_for, v.sort_order
FROM (VALUES
  ('Environment & Secrets', 'No secrets in the current code', 'critical', 'repo_secrets_head',
   'Search every source and config file on the default branch (not just recent commits) for known secret formats: Stripe live keys, OpenAI/Anthropic keys, service-role keys, AWS keys, private keys, GitHub tokens. Anything found must be rotated, then moved to an environment variable or secret store.', 160),
  ('API & Endpoint Security', 'Webhooks verify their signatures', 'critical', 'webhook_signatures',
   'Every webhook handler (Stripe, Clerk, Resend, Svix, GitHub…) must verify the sender''s signature on the raw body before acting: stripe.webhooks.constructEvent, Webhook.verify, or an HMAC compared in constant time. Without it anyone can post "payment succeeded".', 161),
  ('Database Security', 'Service-role key not referenced in client code', 'critical', 'service_role_in_source',
   'No client-side file (components, pages, hooks, client libs) references the Supabase service-role key or an sb_secret_ key. Anything in client code ships to every browser and the service-role key bypasses RLS.', 162),
  ('API & Endpoint Security', 'No eval of dynamic values', 'medium', 'dynamic_code_eval',
   'No eval() or new Function() on values that aren''t constants. If any part can come from a user, a URL, the database or an AI response, it runs as code.', 163)
) AS v(category, title, severity, checklist_key, what_to_look_for, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.checklist_items c WHERE c.title = v.title OR c.checklist_key = v.checklist_key);

INSERT INTO public.checklist_item_controls (checklist_item_id, framework, control_id, control_title)
SELECT ci.id, v.framework, v.control_id, v.control_title
FROM (VALUES
  ('repo_secrets_head', 'OWASP ASVS 4.0.3', 'V6.4.1', 'Secrets managed securely, not in code or config'),
  ('repo_secrets_head', 'SOC 2', 'CC6.1', 'Logical access security over protected information assets'),
  ('webhook_signatures', 'OWASP ASVS 4.0.3', 'V4.1.1', 'Access control enforced on a trusted service layer'),
  ('webhook_signatures', 'SOC 2', 'CC6.1', 'Logical access security over protected information assets'),
  ('webhook_signatures', 'HIPAA', '164.312(c)(1)', 'Integrity'),
  ('webhook_signatures', 'HIPAA', '164.312(d)', 'Person or entity authentication'),
  ('service_role_in_source', 'OWASP ASVS 4.0.3', 'V6.4.1', 'Secrets managed securely, not in code or config'),
  ('service_role_in_source', 'SOC 2', 'CC6.1', 'Logical access security over protected information assets'),
  ('service_role_in_source', 'HIPAA', '164.312(a)(1)', 'Access control'),
  ('dynamic_code_eval', 'OWASP ASVS 4.0.3', 'V5.2.4', 'No eval() or dynamic code execution on untrusted input'),
  ('dynamic_code_eval', 'OWASP LLM Top 10 (2025)', 'LLM05', 'Improper Output Handling')
) AS v(checklist_key, framework, control_id, control_title)
JOIN public.checklist_items ci ON ci.checklist_key = v.checklist_key
ON CONFLICT (checklist_item_id, framework, control_id) DO NOTHING;
