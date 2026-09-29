-- The /check report is emailed rather than shown on screen (so only a real
-- address gets it), once per check, and the owner gets a lead alert.
ALTER TABLE public.public_checks
  ADD COLUMN IF NOT EXISTS report_sent_at timestamptz,
  ADD COLUMN IF NOT EXISTS owner_notified_at timestamptz;
