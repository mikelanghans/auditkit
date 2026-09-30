-- Live progress for deep code audits, posted by the runner while it works.
ALTER TABLE public.code_audit_runs
  ADD COLUMN IF NOT EXISTS progress jsonb,
  ADD COLUMN IF NOT EXISTS progress_at timestamptz;
