
ALTER TABLE public.checklist_items ADD COLUMN IF NOT EXISTS checklist_key text UNIQUE;
ALTER TABLE public.audit_findings ADD COLUMN IF NOT EXISTS auto_scanned boolean NOT NULL DEFAULT false;

-- Backfill keys onto existing items
UPDATE public.checklist_items SET checklist_key = 'ssl_valid'             WHERE title = 'Custom domain with valid SSL';
UPDATE public.checklist_items SET checklist_key = 'csp_header'            WHERE title = 'Content Security Policy set';
UPDATE public.checklist_items SET checklist_key = 'error_verbosity'       WHERE title = 'Verbose error messages suppressed in production';
UPDATE public.checklist_items SET checklist_key = 'sensitive_url_params'  WHERE title = 'No sensitive data in URL parameters';
UPDATE public.checklist_items SET checklist_key = 'bundle_secrets'        WHERE title = 'No secrets in client-side bundle';
UPDATE public.checklist_items SET checklist_key = 'debug_mode'            WHERE title = 'No debug mode in production';

-- Insert new header-specific items (idempotent on checklist_key)
INSERT INTO public.checklist_items (title, category, severity, sort_order, description, what_to_look_for, checklist_key)
VALUES
  ('X-Frame-Options header set',         'Frontend Security', 'medium', 110, 'Prevents clickjacking via iframe embedding.',           'Response should include X-Frame-Options: DENY or SAMEORIGIN.',                   'xframe_header'),
  ('X-Content-Type-Options header set',  'Frontend Security', 'medium', 111, 'Prevents MIME-type sniffing.',                          'Response should include X-Content-Type-Options: nosniff.',                        'xcontent_type'),
  ('Referrer-Policy header set',         'Frontend Security', 'low',    112, 'Controls how much referrer info is sent on navigation.',  'Response should include a restrictive Referrer-Policy (e.g. no-referrer, strict-origin-when-cross-origin).', 'referrer_policy'),
  ('HSTS header configured',             'Frontend Security', 'high',   113, 'Enforces HTTPS for future requests.',                   'Response should include Strict-Transport-Security with a long max-age.',          'hsts_header'),
  ('Permissions-Policy header set',      'Frontend Security', 'low',    114, 'Restricts which browser features the site can use.',     'Response should include a Permissions-Policy header limiting unused features.',   'permissions_policy')
ON CONFLICT (checklist_key) DO NOTHING;
