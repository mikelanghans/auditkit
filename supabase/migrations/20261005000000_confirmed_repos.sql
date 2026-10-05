-- Repos the auditor has confirmed belong to this audit's website. A repo here
-- skips the "Is this the right repo?" warning on later scans (for apps whose
-- custom domain lives in a hosting dashboard, not in the code). Stored as
-- lowercase "owner/repo".
ALTER TABLE public.audits
  ADD COLUMN IF NOT EXISTS confirmed_repos text[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(confirmed_repos) <= 50);
