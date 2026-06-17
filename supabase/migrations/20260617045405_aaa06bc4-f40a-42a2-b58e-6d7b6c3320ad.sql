ALTER TABLE public.audit_findings
  ADD COLUMN IF NOT EXISTS explanation text,
  ADD COLUMN IF NOT EXISTS cursor_prompt text,
  ADD COLUMN IF NOT EXISTS claude_prompt text;