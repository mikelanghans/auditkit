-- AuditKit is a single-operator tool. Lock it to the owner's account and
-- require two-factor login, enforced in the database so it holds no matter
-- which client, server function or dashboard setting is involved:
--
-- 1. Only allowlisted emails can create an account (trigger on auth.users),
--    even if "Allow new users to sign up" is switched back on.
-- 2. Every app table gets a RESTRICTIVE policy: rows are visible and writable
--    only for an allowlisted, email-confirmed user whose session passed a
--    second factor (JWT aal = aal2). Existing owner policies still apply.
-- 3. consume_quota refuses anyone else, so no AI or scan spend happens either.
--
-- The service role (webhooks, the public /check page) is unaffected.
--
-- Locked out of your authenticator? In the SQL editor:
--   delete from auth.mfa_factors where user_id =
--     (select id from auth.users where email = '<your email>');
-- then sign in and enrol again.

CREATE TABLE IF NOT EXISTS public.app_owners (
  email text PRIMARY KEY CHECK (email = lower(email)),
  added_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.app_owners ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.app_owners FROM anon, authenticated;

INSERT INTO public.app_owners (email) VALUES ('mistermikelanghans@gmail.com') ON CONFLICT DO NOTHING;

-- Is the caller an allowlisted, email-confirmed account? (Any session level.)
CREATE OR REPLACE FUNCTION public.am_i_app_owner()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM auth.users u
      JOIN public.app_owners o ON o.email = lower(u.email)
     WHERE u.id = auth.uid()
       AND u.email_confirmed_at IS NOT NULL
  );
$$;

-- Owner AND a session that passed two-factor verification.
CREATE OR REPLACE FUNCTION public.is_app_owner_session()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT coalesce(auth.jwt() ->> 'aal', '') = 'aal2' AND public.am_i_app_owner();
$$;

REVOKE ALL ON FUNCTION public.am_i_app_owner() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.is_app_owner_session() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.am_i_app_owner() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_app_owner_session() TO authenticated;

-- 1. Refuse account creation for anyone not on the allowlist.
CREATE OR REPLACE FUNCTION public.enforce_owner_signup()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.app_owners WHERE email = lower(NEW.email)) THEN
    RAISE EXCEPTION 'Sign-ups are closed.' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.enforce_owner_signup() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS enforce_owner_signup ON auth.users;
CREATE TRIGGER enforce_owner_signup
  BEFORE INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.enforce_owner_signup();

-- Changing an account's email to one that isn't allowlisted is refused too.
DROP TRIGGER IF EXISTS enforce_owner_email_change ON auth.users;
CREATE TRIGGER enforce_owner_email_change
  BEFORE UPDATE OF email ON auth.users
  FOR EACH ROW WHEN (NEW.email IS DISTINCT FROM OLD.email)
  EXECUTE FUNCTION public.enforce_owner_signup();

-- 2. Restrictive owner + MFA policy on every app table.
DO $$
DECLARE
  t text;
BEGIN
  FOR t IN
    SELECT tablename FROM pg_tables
     WHERE schemaname = 'public' AND rowsecurity AND tablename <> 'app_owners'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS owner_mfa_required ON public.%I', t);
    EXECUTE format(
      'CREATE POLICY owner_mfa_required ON public.%I AS RESTRICTIVE FOR ALL TO public '
      'USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()))',
      t
    );
  END LOOP;
END;
$$;

-- 3. No quota (and so no AI calls or scans) without an owner MFA session.
CREATE OR REPLACE FUNCTION public.consume_quota(p_kind text, p_amount integer DEFAULT 1)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_day date := (now() AT TIME ZONE 'utc')::date;
  v_limit integer;
  v_used integer;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;
  IF NOT public.is_app_owner_session() THEN
    RETURN jsonb_build_object('allowed', false, 'reason', 'not_owner_mfa');
  END IF;
  IF p_amount IS NULL OR p_amount < 1 OR p_amount > 50 THEN
    RAISE EXCEPTION 'invalid quota amount';
  END IF;

  -- Daily limits (UTC day). With a single operator these are a safety net
  -- against a stolen session or a runaway loop, not a product limit.
  v_limit := CASE p_kind
    WHEN 'llm' THEN 150        -- Claude calls. A "full" AI Assist run uses up to 12.
    WHEN 'scan' THEN 60        -- website / Supabase / repo / AI-endpoint scans
    WHEN 'code_audit' THEN 3   -- deep code audits (dozens of agents each)
    ELSE NULL
  END;
  IF v_limit IS NULL THEN
    RAISE EXCEPTION 'unknown quota kind: %', p_kind;
  END IF;
  IF public.has_role(v_uid, 'admin') THEN
    v_limit := v_limit * 10;
  END IF;

  INSERT INTO public.usage_counters (user_id, day, kind, count)
  VALUES (v_uid, v_day, p_kind, 0)
  ON CONFLICT (user_id, day, kind) DO NOTHING;

  UPDATE public.usage_counters
     SET count = count + p_amount
   WHERE user_id = v_uid AND day = v_day AND kind = p_kind
     AND count + p_amount <= v_limit
  RETURNING count INTO v_used;

  IF v_used IS NULL THEN
    SELECT count INTO v_used FROM public.usage_counters
     WHERE user_id = v_uid AND day = v_day AND kind = p_kind;
    RETURN jsonb_build_object('allowed', false, 'used', v_used, 'limit', v_limit);
  END IF;
  RETURN jsonb_build_object('allowed', true, 'used', v_used, 'limit', v_limit);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.consume_quota(text, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.consume_quota(text, integer) FROM anon;
GRANT EXECUTE ON FUNCTION public.consume_quota(text, integer) TO authenticated;
