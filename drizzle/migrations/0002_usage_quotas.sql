-- Per-user daily quotas on the expensive actions: Claude calls (paid with the
-- operator's Anthropic key) and outbound scans (run from our infrastructure).
-- Without these, any signed-in account could spend unlimited Anthropic credit.
--
-- Limits live in consume_quota() below. Change them there.

CREATE TABLE IF NOT EXISTS public.usage_counters (
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  day date NOT NULL,
  kind text NOT NULL CHECK (kind IN ('llm', 'scan')),
  count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day, kind)
);

ALTER TABLE public.usage_counters ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own usage" ON public.usage_counters;
CREATE POLICY "Users can view their own usage"
  ON public.usage_counters FOR SELECT TO authenticated
  USING (user_id = auth.uid());

-- Counters are only ever changed by consume_quota().
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.usage_counters FROM anon, authenticated;

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
  IF p_amount IS NULL OR p_amount < 1 OR p_amount > 50 THEN
    RAISE EXCEPTION 'invalid quota amount';
  END IF;

  -- Daily limits per user (UTC day).
  v_limit := CASE p_kind
    WHEN 'llm' THEN 150   -- Claude calls. A "full" AI Assist run uses up to 12.
    WHEN 'scan' THEN 60   -- website / Supabase / repo / AI-endpoint scans
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

  -- Atomic check-and-increment: concurrent requests can't overshoot the limit.
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