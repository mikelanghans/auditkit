-- Lovable fix prompts are now written as instructions to Lovable (it finds the
-- files and checks what the app uses) instead of steps for the founder. Clear
-- cached Lovable prompts so they regenerate in the new style.
UPDATE public.audit_findings SET lovable_prompt = NULL WHERE lovable_prompt IS NOT NULL;
