-- Scanner coverage release.
-- 1. New checklist items for the new website and Supabase checks.
-- 2. Keys on existing items the scanners now fill in automatically.
-- 3. Retire two duplicate items, moving any findings onto the item that stays.
-- Idempotent: safe to run on a database that already has some of this.

-- 1. New items -------------------------------------------------------------
INSERT INTO public.checklist_items (category, title, severity, checklist_key, what_to_look_for, sort_order)
SELECT v.category, v.title, v.severity::public.severity, v.checklist_key, v.what_to_look_for, v.sort_order
FROM (VALUES
  (
    'Frontend Security',
    'Source maps not publicly served',
    'medium',
    'source_maps_exposed',
    'Production .map files hand anyone the original source: component names, comments, API calls and business logic. For each JavaScript bundle, request the file named in its sourceMappingURL comment and <bundle>.map. Only a JSON body with "mappings" counts; single-page apps answer every path with index.html.',
    116
  ),
  (
    'Frontend Security',
    'Cookies use Secure, HttpOnly and SameSite',
    'medium',
    'cookie_flags',
    'Session and auth cookies need Secure (HTTPS only) and HttpOnly (not readable by scripts); every cookie should set SameSite. The scan reads Set-Cookie on the anonymous page response; cookies set after sign-in must be checked in DevTools while signed in.',
    117
  ),
  (
    'Frontend Security',
    'No open redirects',
    'medium',
    'open_redirect',
    'A redirect/next/returnTo parameter that sends users to any site lets attackers send phishing links that start on the real domain. Probe common paths with an off-site target and check the Location header, and look for client code that assigns window.location from the query string.',
    118
  ),
  (
    'Infrastructure & Configuration',
    'No sensitive files served (.env, .git)',
    'critical',
    'exposed_files',
    'Request /.env, /.env.local, /.env.production, /.git/HEAD, /.git/config and /.DS_Store. Judge each on its content, not its status code: an exposed .env leaks every secret in it, and an exposed .git lets anyone download the full source and history.',
    39
  ),
  (
    'Database Security',
    'Supabase Security Advisor reports no issues',
    'high',
    'supabase_security_advisor',
    'Supabase''s own linter (Advisors → Security Advisor) flags tables without RLS, SECURITY DEFINER views, functions with a mutable search_path, extensions in public, long OTP expiry and more. With a Management API PAT, read it from /v1/projects/{ref}/advisors/security. Any ERROR or WARN is a finding.',
    20
  )
) AS v(category, title, severity, checklist_key, what_to_look_for, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.checklist_items c WHERE c.title = v.title OR c.checklist_key = v.checklist_key);

-- 2. Keys for existing items now filled in by a scanner ----------------------
UPDATE public.checklist_items c
   SET checklist_key = v.checklist_key
  FROM (VALUES
    ('Security headers configured', 'security_headers'),
    ('Third-party scripts reviewed', 'third_party_scripts'),
    ('XSS protections in place', 'xss_protections'),
    ('JWT expiry set appropriately', 'jwt_expiry'),
    ('OAuth redirect URIs locked down', 'oauth_redirect_urls'),
    ('Auth provider configured correctly', 'auth_providers'),
    ('Password reset flow validated', 'password_reset_flow'),
    ('Database backups configured', 'database_backups'),
    ('Sensitive columns encrypted at rest', 'sensitive_columns')
  ) AS v(title, checklist_key)
 WHERE c.title = v.title
   AND c.checklist_key IS NULL
   AND NOT EXISTS (SELECT 1 FROM public.checklist_items k WHERE k.checklist_key = v.checklist_key);

-- 3. Retire duplicates -------------------------------------------------------
-- keep: the keyed item. drop: the unkeyed copy. Findings on the dropped item
-- move to the kept one unless the audit already has a finding there.
DO $$
DECLARE
  pair record;
  keep_id uuid;
  drop_id uuid;
BEGIN
  FOR pair IN
    SELECT * FROM (VALUES
      ('dep_vulns', 'Dependency vulnerabilities scanned'),
      ('cors_policy', 'CORS policy configured correctly')
    ) AS t(keep_key, drop_title)
  LOOP
    SELECT id INTO keep_id FROM public.checklist_items WHERE checklist_key = pair.keep_key;
    SELECT id INTO drop_id FROM public.checklist_items
     WHERE title = pair.drop_title AND checklist_key IS NULL AND is_active
     ORDER BY created_at LIMIT 1;
    CONTINUE WHEN keep_id IS NULL OR drop_id IS NULL OR keep_id = drop_id;

    UPDATE public.audit_findings f
       SET checklist_item_id = keep_id
     WHERE f.checklist_item_id = drop_id
       AND NOT EXISTS (
         SELECT 1 FROM public.audit_findings k
          WHERE k.audit_id = f.audit_id AND k.checklist_item_id = keep_id
       );
    UPDATE public.code_audit_findings SET checklist_item_id = keep_id WHERE checklist_item_id = drop_id;
    UPDATE public.checklist_items SET is_active = false WHERE id = drop_id;
  END LOOP;
END;
$$;
