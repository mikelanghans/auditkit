-- Public "Is your app leaking keys?" check (/check). Anonymous visitors scan a
-- URL; results are stored here and unlocked in full by leaving an email.
--
-- Only the server (service role) reads or writes this table. Visitors never
-- get a Supabase session. Admins can read it for lead follow-up.

CREATE TABLE IF NOT EXISTS public.public_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  -- Salted SHA-256 of the requester IP. The raw IP is never stored.
  ip_hash text NOT NULL,
  url text NOT NULL,
  hostname text NOT NULL,
  status text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'failed')),
  -- Counts by severity plus coverage; safe to show before email capture.
  summary jsonb,
  -- Masked findings (never full secret values).
  findings jsonb,
  error text,
  email text,
  email_captured_at timestamptz,
  marketing_consent boolean NOT NULL DEFAULT false,
  lead_status text NOT NULL DEFAULT 'new' CHECK (lead_status IN ('new', 'contacted', 'qualified', 'won', 'lost', 'ignored'))
);

CREATE INDEX IF NOT EXISTS public_checks_ip_time ON public.public_checks (ip_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS public_checks_host_time ON public.public_checks (hostname, created_at DESC);
CREATE INDEX IF NOT EXISTS public_checks_leads ON public.public_checks (email_captured_at DESC) WHERE email IS NOT NULL;

ALTER TABLE public.public_checks ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.public_checks FROM anon, authenticated;
-- Admins (via the policies below) may read, and may change only the lead
-- workflow column, never the scan record itself.
GRANT SELECT ON public.public_checks TO authenticated;
GRANT UPDATE (lead_status) ON public.public_checks TO authenticated;
GRANT ALL ON public.public_checks TO service_role;

CREATE POLICY public_checks_admin_select ON public.public_checks
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY public_checks_admin_update ON public.public_checks
  FOR UPDATE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- Reserve a check slot atomically. Limits:
--   per requester: 5 per hour, 20 per day
--   per target hostname: 10 per day (don't let the tool hammer one site)
--   global: 500 per day (spend and abuse ceiling)
-- Returns {allowed, id} or {allowed:false, reason}.
CREATE OR REPLACE FUNCTION public.begin_public_check(p_ip_hash text, p_url text, p_hostname text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_id uuid;
  v_ip_hour int;
  v_ip_day int;
  v_host_day int;
  v_global_day int;
BEGIN
  IF p_ip_hash IS NULL OR length(p_ip_hash) < 16 OR p_url IS NULL OR p_hostname IS NULL THEN
    RETURN jsonb_build_object('allowed', false, 'reason', 'invalid');
  END IF;

  -- Serialise per requester and per host so parallel requests can't overshoot.
  PERFORM pg_advisory_xact_lock(hashtext('public_check_ip:' || p_ip_hash));
  PERFORM pg_advisory_xact_lock(hashtext('public_check_host:' || lower(p_hostname)));

  SELECT count(*) FILTER (WHERE created_at > now() - interval '1 hour'),
         count(*)
    INTO v_ip_hour, v_ip_day
    FROM public.public_checks
   WHERE ip_hash = p_ip_hash AND created_at > now() - interval '1 day';
  IF v_ip_hour >= 5 OR v_ip_day >= 20 THEN
    RETURN jsonb_build_object('allowed', false, 'reason', 'ip_limit');
  END IF;

  SELECT count(*) INTO v_host_day
    FROM public.public_checks
   WHERE hostname = lower(p_hostname) AND created_at > now() - interval '1 day';
  IF v_host_day >= 10 THEN
    RETURN jsonb_build_object('allowed', false, 'reason', 'host_limit');
  END IF;

  SELECT count(*) INTO v_global_day
    FROM public.public_checks
   WHERE created_at > now() - interval '1 day';
  IF v_global_day >= 500 THEN
    RETURN jsonb_build_object('allowed', false, 'reason', 'global_limit');
  END IF;

  INSERT INTO public.public_checks (ip_hash, url, hostname)
  VALUES (p_ip_hash, left(p_url, 2048), lower(p_hostname))
  RETURNING id INTO v_id;

  RETURN jsonb_build_object('allowed', true, 'id', v_id);
END;
$$;

REVOKE ALL ON FUNCTION public.begin_public_check(text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.begin_public_check(text, text, text) TO service_role;