-- Header fix prompts now follow stricter placement rules (TanStack Start
-- middleware must read Content-Type from next()'s Response, no meta-tag or
-- ignored-config fallbacks), warn that a Report-Only CSP still fails the scan,
-- and end with a publish + re-scan reminder. Clear cached prompts for header
-- findings so they regenerate with the new rules.
UPDATE public.audit_findings f
SET lovable_prompt = NULL, cursor_prompt = NULL, claude_prompt = NULL
FROM public.checklist_items c
WHERE f.checklist_item_id = c.id
  AND (
    c.checklist_key IN (
      'csp_header', 'xframe_header', 'permissions_policy', 'hsts_header',
      'xcontent_type', 'referrer_policy', 'security_headers'
    )
    OR c.title = 'Security headers configured'
  );
