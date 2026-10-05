ALTER TABLE public.public_checks
  ADD COLUMN IF NOT EXISTS report_sent_at timestamptz,
  ADD COLUMN IF NOT EXISTS owner_notified_at timestamptz;