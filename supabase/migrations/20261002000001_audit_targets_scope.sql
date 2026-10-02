-- Build plan, phase 1a: what an audit covers and what it is allowed to do.
--
-- audit_targets: every system under test, entered once per audit and reused by
-- every scanner (and later by the full-audit run and schedules). Values are
-- locations, never credentials. Keys and tokens are still entered per run.
--
-- audit_scope: the written authorization for the audit. Active tests (write
-- probes, cross-account tests, rate-limit bursts) check it before running, and
-- it prints in the report's scope section.

CREATE TABLE IF NOT EXISTS public.audit_targets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  audit_id uuid NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('website', 'repo', 'supabase', 'ai_endpoint', 'api')),
  value text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
  label text CHECK (label IS NULL OR length(label) <= 200),
  -- Non-secret details per kind, e.g. { "prompt_field": "message" } for an AI
  -- endpoint or { "branch": "main" } for a repo.
  meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  in_scope boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (audit_id, kind, value)
);
CREATE INDEX IF NOT EXISTS audit_targets_audit ON public.audit_targets (audit_id, kind);
CREATE TRIGGER audit_targets_updated_at BEFORE UPDATE ON public.audit_targets
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE IF NOT EXISTS public.audit_scope (
  audit_id uuid PRIMARY KEY REFERENCES public.audits(id) ON DELETE CASCADE,
  environment text NOT NULL DEFAULT 'unknown'
    CHECK (environment IN ('production', 'staging', 'development', 'unknown')),
  -- Allows tests that create, change or delete data, or stress the target
  -- (weak-password sign-up, sign-in bursts, cross-account write attempts).
  write_tests_allowed boolean NOT NULL DEFAULT false,
  authorized_by text CHECK (authorized_by IS NULL OR length(authorized_by) <= 200),
  authorized_at date,
  -- Where the authorization lives: a signed SOW, an email, a ticket.
  authorization_ref text CHECK (authorization_ref IS NULL OR length(authorization_ref) <= 500),
  testing_window text CHECK (testing_window IS NULL OR length(testing_window) <= 200),
  out_of_scope text CHECK (out_of_scope IS NULL OR length(out_of_scope) <= 4000),
  notes text CHECK (notes IS NULL OR length(notes) <= 4000),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER audit_scope_updated_at BEFORE UPDATE ON public.audit_scope
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE public.audit_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_scope ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.audit_targets, public.audit_scope FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.audit_targets, public.audit_scope TO authenticated;
GRANT ALL ON public.audit_targets, public.audit_scope TO service_role;

CREATE POLICY audit_targets_owner_all ON public.audit_targets FOR ALL TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()))
  WITH CHECK (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY audit_scope_owner_all ON public.audit_scope FOR ALL TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()))
  WITH CHECK (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));

-- Same owner + two-factor lock as every other app table (20260929000002).
CREATE POLICY owner_mfa_required ON public.audit_targets AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));
CREATE POLICY owner_mfa_required ON public.audit_scope AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));

-- Existing audits: carry the website URL over as the first target.
INSERT INTO public.audit_targets (audit_id, kind, value)
SELECT id, 'website', website_url FROM public.audits
 WHERE website_url IS NOT NULL AND btrim(website_url) <> ''
ON CONFLICT (audit_id, kind, value) DO NOTHING;
