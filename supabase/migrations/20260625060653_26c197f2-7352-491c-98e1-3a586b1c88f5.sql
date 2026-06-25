DO $$ BEGIN
  CREATE TYPE public.engagement_type AS ENUM ('prospect','one_time','retainer');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE public.clients
  ADD COLUMN IF NOT EXISTS engagement_type public.engagement_type NOT NULL DEFAULT 'prospect';