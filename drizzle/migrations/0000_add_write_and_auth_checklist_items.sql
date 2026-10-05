-- Add checklist items for the Supabase-scan results that were previously computed
-- but never mapped to a checklist item (so they were silently discarded), plus the
-- new authoritative anon write-access check.
--
-- Titles here must match the keys in titleToResult in
-- src/lib/supabase-scan.functions.ts exactly — the scan matches findings to
-- checklist items by title.

INSERT INTO public.checklist_items (category, title, severity, checklist_key, what_to_look_for, sort_order)
VALUES
  (
    'Database Security',
    'Anon role cannot write to tables',
    'critical',
    'anon_write_access',
    'The most common critical failure in these apps is an unauthenticated WRITE, not read: the anon role holds an INSERT/UPDATE/DELETE grant on a table whose RLS is disabled, so anyone with the public anon key can modify or delete data. Using a Management API PAT, list the anon role''s write privileges on every public table and cross-check RLS. Any table with an anon write grant and RLS off is a critical hole; a write grant with RLS on needs its policy reviewed.',
    12
  ),
  (
    'Authentication & Sessions',
    'Minimum password length enforced',
    'high',
    'password_min_length',
    'Weak password policies let users (and attackers) set trivially guessable passwords. Confirm the project enforces a minimum length and, ideally, leaked-password protection. This is verified with an active probe (a real signup) or by reading the auth config, so it only runs with consent or a Management API PAT.',
    52
  ),
  (
    'Authentication & Sessions',
    'Email confirmation required for signup',
    'high',
    'email_confirmation_required',
    'When email auto-confirm is on (mailer_autoconfirm = true), new signups are confirmed without verifying the address — anyone can register as any email, enabling impersonation and spam. Confirm email confirmation is required. Read from the Management API auth config.',
    53
  ),
  (
    'Database Security',
    'No public storage buckets',
    'medium',
    'no_public_buckets',
    'Storage buckets marked public serve their objects to anyone with the URL. Enumerate buckets and flag any that are public; confirm nothing sensitive is stored there, and prefer private buckets served through signed URLs.',
    18
  ),
  (
    'Frontend Security',
    'CORS policy is scoped',
    'medium',
    'cors_policy',
    'A permissive CORS policy — Access-Control-Allow-Origin: * — lets any website read responses from the endpoint; combined with Access-Control-Allow-Credentials: true it allows credentialed cross-origin reads, which is a serious leak. Check the response headers and confirm the allowed origin is scoped to trusted hosts rather than a wildcard. Auto-populated by the surface scan.',
    115
  )
ON CONFLICT (checklist_key) DO UPDATE SET
  title = EXCLUDED.title,
  category = EXCLUDED.category,
  severity = EXCLUDED.severity,
  what_to_look_for = EXCLUDED.what_to_look_for;