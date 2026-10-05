-- Deep code audits: runs of Cloudflare's security-audit skill on a separate
-- runner (Fly.io machine per job). AuditKit is the control plane: it queues a
-- run, the runner posts results back to a signed webhook, and the auditor
-- reviews the records here.
--
-- Rule that keeps this honest: a confirmed finding may mark a checklist item
-- FAIL. The absence of findings never becomes a pass.

CREATE TABLE IF NOT EXISTS public.code_audit_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  created_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  repo_url text NOT NULL,
  git_ref text,
  profile text NOT NULL CHECK (profile IN ('quick', 'standard', 'deep')),
  budget_agents integer NOT NULL CHECK (budget_agents BETWEEN 10 AND 400),
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'dispatching', 'running', 'done', 'incomplete', 'failed', 'cancelled')),
  runner_machine_id text,
  started_at timestamptz,
  finished_at timestamptz,
  error text,
  source_commit text,
  agents_used integer,
  incomplete_reason text,
  coverage jsonb,
  report_md text,
  findings_detail_md text,
  needs_validation_md text,
  confirmed_count integer NOT NULL DEFAULT 0,
  needs_validation_count integer NOT NULL DEFAULT 0,
  rejected_count integer NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS code_audit_runs_audit ON public.code_audit_runs (audit_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.code_audit_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id uuid NOT NULL REFERENCES public.code_audit_runs(id) ON DELETE CASCADE,
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  fingerprint text NOT NULL,
  verdict text NOT NULL CHECK (verdict IN ('confirmed', 'needs_validation', 'rejected')),
  severity text CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  title text NOT NULL,
  description text,
  root_cause text,
  trace jsonb,
  evidence jsonb,
  remediation jsonb,
  blockers jsonb,
  validation_plan jsonb,
  raw jsonb NOT NULL,
  -- Auditor review. Only these columns are writable by the owner.
  review_state text NOT NULL DEFAULT 'pending' CHECK (review_state IN ('pending', 'accepted', 'dismissed')),
  include_in_report boolean NOT NULL DEFAULT false,
  checklist_item_id uuid REFERENCES public.checklist_items(id) ON DELETE SET NULL,
  reviewer_note text,
  UNIQUE (run_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS code_audit_findings_audit ON public.code_audit_findings (audit_id, verdict);

ALTER TABLE public.code_audit_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.code_audit_findings ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.code_audit_runs FROM anon, authenticated;
REVOKE ALL ON public.code_audit_findings FROM anon, authenticated;
GRANT ALL ON public.code_audit_runs, public.code_audit_findings TO service_role;

-- Owners read their runs. Runs are created and updated by server code only
-- (the start function and the signed webhook use the service role).
GRANT SELECT ON public.code_audit_runs TO authenticated;
CREATE POLICY code_audit_runs_owner_select ON public.code_audit_runs
  FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = code_audit_runs.audit_id AND a.created_by = auth.uid()));

-- Owners read findings and may change only the review columns.
GRANT SELECT ON public.code_audit_findings TO authenticated;
GRANT UPDATE (review_state, include_in_report, checklist_item_id, reviewer_note) ON public.code_audit_findings TO authenticated;
CREATE POLICY code_audit_findings_owner_select ON public.code_audit_findings
  FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = code_audit_findings.audit_id AND a.created_by = auth.uid()));
CREATE POLICY code_audit_findings_owner_update ON public.code_audit_findings
  FOR UPDATE TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = code_audit_findings.audit_id AND a.created_by = auth.uid()))
  WITH CHECK (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = code_audit_findings.audit_id AND a.created_by = auth.uid()));

-- Deep audits are expensive: add a separate daily quota kind.
ALTER TABLE public.usage_counters DROP CONSTRAINT IF EXISTS usage_counters_kind_check;
ALTER TABLE public.usage_counters
  ADD CONSTRAINT usage_counters_kind_check CHECK (kind IN ('llm', 'scan', 'code_audit'));

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