
-- Convert single app_url to an array of websites
ALTER TABLE public.clients ADD COLUMN websites text[] NOT NULL DEFAULT '{}';
UPDATE public.clients SET websites = ARRAY[app_url] WHERE app_url IS NOT NULL AND app_url <> '';
ALTER TABLE public.clients DROP COLUMN app_url;

-- Audits target a specific website URL
ALTER TABLE public.audits ADD COLUMN website_url text;
