ALTER TABLE public.clients
  ADD COLUMN IF NOT EXISTS industry TEXT,
  ADD COLUMN IF NOT EXISTS annual_revenue_range TEXT,
  ADD COLUMN IF NOT EXISTS user_count_range TEXT;