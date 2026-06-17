INSERT INTO public.checklist_items (category, title, severity, checklist_key, what_to_look_for, sort_order)
VALUES (
  'Environment & Secrets',
  'No sensitive variables exposed via VITE_ prefix',
  'critical',
  'vite_exposure',
  'Vite automatically inlines any environment variable prefixed with VITE_ into the client bundle, making it publicly accessible to anyone who visits the site. Download the served JS bundles and search for VITE_ variable names containing sensitive keywords (SECRET, KEY, TOKEN, PASSWORD, PRIVATE, SERVICE_ROLE, ANON, API). If any are present, the secret is leaked to every visitor and must be rotated and moved to a server-only variable (no VITE_ prefix).',
  100
)
ON CONFLICT (checklist_key) DO UPDATE SET
  title = EXCLUDED.title,
  category = EXCLUDED.category,
  severity = EXCLUDED.severity,
  what_to_look_for = EXCLUDED.what_to_look_for;