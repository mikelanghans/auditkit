CREATE TABLE IF NOT EXISTS public.app_owners (
  email text PRIMARY KEY CHECK (email = lower(email)),
  added_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.app_owners ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.app_owners FROM anon, authenticated;
GRANT ALL ON public.app_owners TO service_role;

INSERT INTO public.app_owners (email) VALUES ('mistermikelanghans@gmail.com') ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION public.am_i_app_owner()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM auth.users u
      JOIN public.app_owners o ON o.email = lower(u.email)
     WHERE u.id = auth.uid() AND u.email_confirmed_at IS NOT NULL
  );
$$;

CREATE OR REPLACE FUNCTION public.is_app_owner_session()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT coalesce(auth.jwt() ->> 'aal', '') = 'aal2' AND public.am_i_app_owner();
$$;

REVOKE ALL ON FUNCTION public.am_i_app_owner() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.is_app_owner_session() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.am_i_app_owner() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_app_owner_session() TO authenticated;

DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND rowsecurity AND tablename <> 'app_owners'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS owner_mfa_required ON public.%I', t);
    EXECUTE format(
      'CREATE POLICY owner_mfa_required ON public.%I AS RESTRICTIVE FOR ALL TO public '
      'USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()))', t);
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION public.consume_quota(p_kind text, p_amount integer DEFAULT 1)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_day date := (now() AT TIME ZONE 'utc')::date;
  v_limit integer;
  v_used integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not authenticated'; END IF;
  IF NOT public.is_app_owner_session() THEN
    RETURN jsonb_build_object('allowed', false, 'reason', 'not_owner_mfa');
  END IF;
  IF p_amount IS NULL OR p_amount < 1 OR p_amount > 50 THEN RAISE EXCEPTION 'invalid quota amount'; END IF;
  v_limit := CASE p_kind WHEN 'llm' THEN 150 WHEN 'scan' THEN 60 WHEN 'code_audit' THEN 3 ELSE NULL END;
  IF v_limit IS NULL THEN RAISE EXCEPTION 'unknown quota kind: %', p_kind; END IF;
  IF public.has_role(v_uid, 'admin') THEN v_limit := v_limit * 10; END IF;
  INSERT INTO public.usage_counters (user_id, day, kind, count) VALUES (v_uid, v_day, p_kind, 0)
  ON CONFLICT (user_id, day, kind) DO NOTHING;
  UPDATE public.usage_counters SET count = count + p_amount
   WHERE user_id = v_uid AND day = v_day AND kind = p_kind AND count + p_amount <= v_limit
  RETURNING count INTO v_used;
  IF v_used IS NULL THEN
    SELECT count INTO v_used FROM public.usage_counters WHERE user_id = v_uid AND day = v_day AND kind = p_kind;
    RETURN jsonb_build_object('allowed', false, 'used', v_used, 'limit', v_limit);
  END IF;
  RETURN jsonb_build_object('allowed', true, 'used', v_used, 'limit', v_limit);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.consume_quota(text, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.consume_quota(text, integer) TO authenticated;