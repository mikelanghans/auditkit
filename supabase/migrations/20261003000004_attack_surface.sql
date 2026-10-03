-- Build plan 3.7: attack surface map (certificate-transparency subdomains,
-- SPF/DMARC, dangling CNAMEs). New scanner name and checklist items.

ALTER TABLE public.scan_runs DROP CONSTRAINT IF EXISTS scan_runs_scanner_check;
ALTER TABLE public.scan_runs ADD CONSTRAINT scan_runs_scanner_check
  CHECK (scanner IN ('website', 'surface', 'supabase', 'repo', 'dependencies', 'ai_endpoint', 'code_audit', 'full'));

INSERT INTO public.checklist_items (category, title, severity, checklist_key, what_to_look_for, sort_order)
SELECT v.category, v.title, v.severity::public.severity, v.checklist_key, v.what_to_look_for, v.sort_order
FROM (VALUES
  (
    'Infrastructure & Configuration',
    'SPF record published',
    'medium',
    'email_spf',
    'The domain publishes exactly one SPF TXT record ending in -all or ~all, so receivers can reject mail that claims to come from it. Missing, duplicate or +all records let anyone send as the domain (phishing your users).',
    150
  ),
  (
    'Infrastructure & Configuration',
    'DMARC policy enforced',
    'medium',
    'email_dmarc',
    '_dmarc.<domain> has a DMARC record with p=quarantine or p=reject. p=none only monitors: spoofed mail is still delivered.',
    151
  ),
  (
    'Infrastructure & Configuration',
    'No dangling subdomains (takeover risk)',
    'high',
    'subdomain_takeover',
    'List every hostname in certificate-transparency logs. Any CNAME pointing at a hosting service (Heroku, GitHub Pages, Netlify, Azure, S3…) whose target no longer exists can be claimed by anyone, who then serves content, steals cookies scoped to the parent domain, or passes your CSP. Remove the record or reclaim the name.',
    152
  )
) AS v(category, title, severity, checklist_key, what_to_look_for, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.checklist_items c WHERE c.title = v.title OR c.checklist_key = v.checklist_key);
